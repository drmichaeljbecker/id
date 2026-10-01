// Signed stamps: what you post, signed with a key only your browser holds, checkable by anyone against your DID.
//
// The pieces, each a W3C standard so any verifier can check a stamp without Praxamark:
// - the key: Ed25519, made by the browser's own Web Crypto and kept non-extractable in IndexedDB, so the browser signs
//   with it but hands the private half to no one, this code included. Its public half is written as a Multikey
//   (multicodec ed25519-pub, 0xed01, in base58btc: the z6Mk… string a did:key is made of);
// - the stamp: a Verifiable Credential 2.0 saying these words, from this source, on this network, at this time, with
//   a Data Integrity proof, cryptosuite eddsa-jcs-2022 (JSON canonicalised by RFC 8785, hashed, signed; no JSON-LD
//   processing, so no library);
// - the identity: your did:web. Its did.json lists the public key (the Helper writes and publishes it), so a reader
//   fetches the key from your own domain, and a copycat who pastes your DID cannot sign as you.
//
// Each stamp names the hash of the one before it, so your stamps form a personal ledger: none can be dropped or
// back-dated unnoticed. The top half of this file runs anywhere (the verify page on your domain uses it as it is);
// the bottom half (key, ledger, publishing) only in the extension.
const Stamps = {
  NORMALISATION: 'praxamark-text-1',
  VC_CONTEXT: 'https://www.w3.org/ns/credentials/v2',
  B58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',

  // ---------------------------------------------------------------- encodings
  // Base58 (Bitcoin's alphabet, no 0 O I l): each leading zero byte is a leading '1', the rest a base-58 number.
  b58(bytes) {
    bytes = Uint8Array.from(bytes);
    let zeros = 0; while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
    const digits = [];
    for (let i = zeros; i < bytes.length; i++) {
      let carry = bytes[i];
      for (let j = 0; j < digits.length; j++) { carry += digits[j] * 256; digits[j] = carry % 58; carry = Math.floor(carry / 58); }
      while (carry) { digits.push(carry % 58); carry = Math.floor(carry / 58); }
    }
    return '1'.repeat(zeros) + digits.reverse().map((d) => Stamps.B58[d]).join('');
  },
  unb58(s) {
    s = String(s);
    let zeros = 0; while (zeros < s.length && s[zeros] === '1') zeros++;
    const bytes = [];
    for (let i = zeros; i < s.length; i++) {
      let carry = Stamps.B58.indexOf(s[i]); if (carry < 0) throw new Error('not base58');
      for (let j = 0; j < bytes.length; j++) { carry += bytes[j] * 58; bytes[j] = carry & 0xff; carry >>= 8; }
      while (carry) { bytes.push(carry & 0xff); carry >>= 8; }
    }
    return Uint8Array.from([...new Array(zeros).fill(0), ...bytes.reverse()]);
  },
  hex(buf) { return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join(''); },
  bytes(s) { return new TextEncoder().encode(s); },
  async sha256(data) { return new Uint8Array(await crypto.subtle.digest('SHA-256', typeof data === 'string' ? Stamps.bytes(data) : data)); },
  // JSON Canonicalisation Scheme (RFC 8785): keys sorted by UTF-16 code units, no spaces, and strings and numbers as
  // ECMAScript's JSON.stringify writes them, which is what the RFC specifies.
  jcs(v) {
    if (v === null || typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return `[${v.map((x) => Stamps.jcs(x === undefined ? null : x)).join(',')}]`;
    return `{${Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${Stamps.jcs(v[k])}`).join(',')}}`;
  },
  // Crockford's base32 (no I, L, O, U): a stamp's short name in its link, easy to read aloud or type.
  b32(bytes, n = 8) {
    const A = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; let bits = 0, val = 0, out = '';
    for (const b of bytes) { val = (val << 8) | b; bits += 8; while (bits >= 5 && out.length < n) { out += A[(val >>> (bits - 5)) & 31]; bits -= 5; } if (out.length >= n) break; }
    return out;
  },
  multikey(raw) { return 'z' + Stamps.b58([0xed, 0x01, ...new Uint8Array(raw)]); },
  rawOfMultikey(mk) {
    if (!/^z6Mk/.test(String(mk))) throw new Error('not an Ed25519 Multikey');
    const b = Stamps.unb58(String(mk).slice(1));
    if (b.length !== 34 || b[0] !== 0xed || b[1] !== 0x01) throw new Error('not an Ed25519 Multikey');
    return b.slice(2);
  },
  // Four groups of four hex digits of the key's hash: what Settings shows, short enough to compare by eye.
  async fingerprint(mk) { return Stamps.hex(await Stamps.sha256(mk)).slice(0, 16).match(/.{4}/g).join(' '); },

  // ---------------------------------------------------------------- the words
  // What is signed is the words, normalised so that invisible differences do not break a stamp: Unicode NFC, line
  // endings as \n, no spaces at line ends, at most one blank line in a row, nothing at either end. Networks that
  // shorten links or cut long posts still change the words; that shows as a mismatch, which is the honest answer.
  normalise(text) {
    return String(text || '').normalize('NFC').replace(/\r\n?/g, '\n').replace(/[ \t ]+$/gm, '').replace(/\n{3,}/g, '\n\n').trim();
  },
  async textHash(text) { return Stamps.hex(await Stamps.sha256(Stamps.normalise(text))); },
  // The line a stamped post carries, and how to find it again in a pasted copy (to check the words without it).
  LINE: '✓ Signed: ',
  lineFor(link) { return `${Stamps.LINE}${link}`; },
  withoutLine(text) { return String(text || '').split(/\r?\n/).filter((l) => !l.trim().startsWith(Stamps.LINE.trim())).join('\n'); },

  // ---------------------------------------------------------------- eddsa-jcs-2022 (W3C VC Data Integrity EdDSA)
  // Sign: hash the canonical proof options (with the document's @context) and the canonical document, sign the two
  // hashes together, and add the proof. Verify: the same hashes, the signature against the public key.
  async hashData(doc, proofConfig) {
    const a = await Stamps.sha256(Stamps.jcs(proofConfig)), b = await Stamps.sha256(Stamps.jcs(doc));
    const out = new Uint8Array(a.length + b.length); out.set(a); out.set(b, a.length); return out;
  },
  async addProof(doc, { privateKey, verificationMethod, created }) {
    const proof = { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', created: created || Stamps.now(), verificationMethod, proofPurpose: 'assertionMethod' };
    if (doc['@context']) proof['@context'] = doc['@context'];
    const sig = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, await Stamps.hashData(doc, proof));
    return { ...doc, proof: { ...proof, proofValue: 'z' + Stamps.b58(new Uint8Array(sig)) } };
  },
  async verifyProof(vc, publicKeyMultibase) {
    try {
      const { proof, ...doc } = vc || {};
      if (!proof || proof.type !== 'DataIntegrityProof' || proof.cryptosuite !== 'eddsa-jcs-2022' || !/^z/.test(proof.proofValue || '')) return false;
      const { proofValue, ...config } = proof;
      if (doc['@context'] && Stamps.jcs(config['@context']) !== Stamps.jcs(doc['@context'])) return false;
      const key = await crypto.subtle.importKey('raw', Stamps.rawOfMultikey(publicKeyMultibase), { name: 'Ed25519' }, false, ['verify']);
      return await crypto.subtle.verify({ name: 'Ed25519' }, key, Stamps.unb58(proofValue.slice(1)), await Stamps.hashData(doc, config));
    } catch { return false; }
  },
  now() { return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'); },

  // ---------------------------------------------------------------- DIDs
  validDidWeb(s) { return /^did:web:[a-z0-9-]+(\.[a-z0-9-]+)+(%3A\d+)?(:[A-Za-z0-9._~-]+)*$/i.test(String(s || '').trim()); },
  // did:web:host:a:b → https://host/a/b/ (where did.json and the stamps live); did:web:host → https://host/
  didWebBase(did) {
    if (!Stamps.validDidWeb(did)) return '';
    const [host, ...path] = String(did).trim().slice(8).split(':');
    return `https://${decodeURIComponent(host)}/${path.map((p) => p + '/').join('')}`;
  },
  didWebUrl(did) { const base = Stamps.didWebBase(did); if (!base) return ''; return /^did:web:[^:]+$/.test(did.trim()) ? `${base}.well-known/did.json` : `${base}did.json`; },
  // Who signed, resolved: the public key a verification method names, if the DID document lists it for signing
  // claims (assertionMethod). did:key needs no lookup: the identifier is the key.
  async resolveKey(verificationMethod, fetcher = fetch) {
    const vm = String(verificationMethod || ''); const did = vm.split('#')[0];
    if (/^did:key:z6Mk/.test(did)) return { ok: vm === `${did}#${did.slice(8)}`, key: did.slice(8), did };
    const url = Stamps.didWebUrl(did);
    if (!url) return { ok: false, error: 'unsupported', did };
    let doc; try { const r = await fetcher(url, { cache: 'no-store' }); if (!r.ok) return { ok: false, error: 'unreachable', status: r.status, url, did }; doc = await r.json(); } catch (e) { return { ok: false, error: 'unreachable', url, did, detail: String(e?.message || e) }; }
    if (doc.id !== did) return { ok: false, error: 'wrongdoc', url, did };
    const abs = (id) => (String(id).startsWith('#') ? did + id : String(id));
    const m = (doc.verificationMethod || []).find((x) => abs(x.id) === vm);
    const listed = (doc.assertionMethod || []).some((x) => abs(typeof x === 'string' ? x : x.id) === vm);
    if (!m || !listed || !m.publicKeyMultibase) return { ok: false, error: 'nokey', url, did, doc };
    return { ok: true, key: m.publicKeyMultibase, url, did, doc, retired: !(doc.authentication || []).some((x) => abs(typeof x === 'string' ? x : x.id) === vm) };
  },
  // The whole check, for the verify page and the tests: the key from the DID, the signature, and that the words the
  // stamp carries are the words it hashed. { state: 'ok' | 'badsig' | 'nokey' | 'unreachable' | 'unsupported' | 'wrongdoc' | 'mismatch' | 'notastamp' }
  async check(vc, fetcher = fetch) {
    const vm = vc?.proof?.verificationMethod, issuer = typeof vc?.issuer === 'string' ? vc.issuer : vc?.issuer?.id;
    if (!vm || !issuer || String(vm).split('#')[0] !== issuer) return { state: 'notastamp' };
    const k = await Stamps.resolveKey(vm, fetcher);
    if (!k.ok) return { state: k.error || 'nokey', ...k };
    if (!(await Stamps.verifyProof(vc, k.key))) return { state: 'badsig', ...k };
    const post = vc.credentialSubject?.post;
    if (post && post.text != null && (await Stamps.textHash(post.text)) !== post.textSha256) return { state: 'mismatch', ...k };
    return { state: 'ok', ...k };
  },
  // A pasted copy of the post, checked against the stamp: the stamp's own line and the source link are set aside.
  async sameWords(vc, pasted) {
    const src = vc?.credentialSubject?.source?.url || '';
    const lines = Stamps.withoutLine(pasted).split('\n').filter((l) => !src || l.trim() !== src);
    return (await Stamps.textHash(lines.join('\n'))) === vc?.credentialSubject?.post?.textSha256;
  },

  // ================================================================ extension only
  // ---------------------------------------------------------------- your key
  // One signing key at a time; a new one retires the old, which stays in your DID document (listed for claims, not
  // for signing in), so stamps made with it still verify. Read afresh each time (no cache): Settings, the popup and
  // the background each have their own copy of this code, and a new key made in one must be the key the others use.
  async key({ create = true } = {}) {
    let k = await TwinAPI.idbGet('stampKey').catch(() => null);
    if (!k && !create) return null;
    if (!k) {
      const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
      k = { privateKey: pair.privateKey, publicKey: pair.publicKey, created: Stamps.now() };
      await TwinAPI.idbSet('stampKey', k);
    }
    const raw = await crypto.subtle.exportKey('raw', k.publicKey);   // a public key is always exportable
    const mk = Stamps.multikey(raw);
    return { privateKey: k.privateKey, multikey: mk, created: k.created, fingerprint: await Stamps.fingerprint(mk) };
  },
  async retiredKeys() { const { stampKeysRetired = [] } = await chrome.storage.local.get('stampKeysRetired'); return stampKeysRetired; },
  async newKey() {
    const old = await Stamps.key({ create: false });
    if (old) await chrome.storage.local.set({ stampKeysRetired: [...(await Stamps.retiredKeys()), { multikey: old.multikey, created: old.created, retired: Stamps.now() }] });
    await TwinAPI.idbSet('stampKey', null);
    return Stamps.key();
  },
  // The DID stamps are signed as: your did:web when Settings has one, else the key's own did:key (checkable, but
  // not tied to you by anything but the key).
  didOf(settings, mk) { return Stamps.validDidWeb(settings?.did) ? settings.did.trim() : `did:key:${mk}`; },
  vmOf(did, mk) { return `${did}#${mk}`; },

  // ---------------------------------------------------------------- stamping
  // Ready to stamp a shared post: switched on, a did:web, and a folder the Helper publishes from (the stamp's link
  // must lead somewhere). Returns '' when ready, else what is missing.
  missing(settings) {
    if (!settings?.stampShares) return 'off';
    if (!Stamps.validDidWeb(settings.did)) return 'did';
    if (!String(settings.stampFolder || '').trim()) return 'folder';
    return '';
  },
  appliesTo(settings, network) {
    const n = TwinAPI.SHARE_NETWORKS[network];
    return !!n && !n.urlOnly && !n.copyOnly && !n.mailto && TwinAPI.audienceOfNetwork(network) === 'public' && !Stamps.missing(settings);
  },
  // The characters a stamp adds to a post, for the count: the line, and its link as the network counts links.
  reserve(settings, network) {
    const n = TwinAPI.SHARE_NETWORKS[network]; if (!n) return 0;
    return 2 + Stamps.LINE.length + (n.linkChars || (Stamps.didWebBase(settings.did) + 's/XXXXXXXX').length);
  },
  async ledger() { const { stamps = [] } = await chrome.storage.local.get('stamps'); return stamps; },
  // Sign a post. The stamp is kept on this computer (the ledger) and its short name made from its own hash.
  async make({ text, url, title, network, audience = 'public', settings }) {
    const k = await Stamps.key();
    const did = Stamps.didOf(settings, k.multikey);
    const ledger = await Stamps.ledger(); const prev = ledger[ledger.length - 1];
    const words = Stamps.normalise(text);
    const doc = {
      '@context': [Stamps.VC_CONTEXT],
      id: `urn:uuid:${crypto.randomUUID()}`,
      type: ['VerifiableCredential', 'PraxamarkStamp'],
      issuer: settings?.contributor ? { id: did, name: String(settings.contributor) } : did,
      validFrom: Stamps.now(),
      credentialSubject: {
        id: did,
        post: { text: words, textSha256: await Stamps.textHash(words), normalisation: Stamps.NORMALISATION, network: TwinAPI.SHARE_NETWORKS[network]?.label || String(network || ''), audience },
        ...(url ? { source: { url: String(url), ...(title ? { title: String(title) } : {}) } } : {}),
        sequence: ledger.length + 1,
        ...(prev ? { previous: prev.hash } : {}),
      },
    };
    const vc = await Stamps.addProof(doc, { privateKey: k.privateKey, verificationMethod: Stamps.vmOf(did, k.multikey), created: doc.validFrom });
    const hash = Stamps.hex(await Stamps.sha256(Stamps.jcs(vc)));
    const id = Stamps.b32(Stamps.unhex(hash));
    const base = Stamps.didWebBase(did);
    const entry = { id, hash, at: doc.validFrom, network: doc.credentialSubject.post.network, url: url || '', link: base ? `${base}s/${id}` : '', published: false };
    await chrome.storage.local.set({ stamps: [...ledger, entry], [`stamp:${id}`]: vc });
    return { vc, id, hash, link: entry.link };
  },
  unhex(h) { return Uint8Array.from(String(h).match(/../g).map((x) => parseInt(x, 16))); },
  // A post about to be handed to a network: signed when stamping applies (and `want` is not false, the popup's tick),
  // the ✓ Signed line added after the words. What is signed is the words alone: not the line, not the page's link,
  // which the network adds or shortens as it likes. Returns { text, stamp } (stamp null when not signed).
  async forShare({ text, url, title, network, settings, want = true }) {
    if (!want || !String(text || '').trim() || !Stamps.appliesTo(settings, network)) return { text, stamp: null };
    const stamp = await Stamps.make({ text, url, title, network, audience: 'public', settings });
    return { text: `${String(text).trim()}\n\n${Stamps.lineFor(stamp.link)}`, stamp };
  },
  // What is wrong with a DID typed in Settings, in words ('' when it is a did:web).
  didProblem(did) {
    const d = String(did || '').trim();
    if (Stamps.validDidWeb(d)) return '';
    if (!d) return 'Type your DID first, e.g. did:web:id.example.com:you.';
    if (/^https?:\/\//i.test(d)) return 'Type the DID, not its web address: https://id.example.com/you/did.json is did:web:id.example.com:you.';
    if (/\s/.test(d)) return 'Your DID has a space in it; a DID has none.';
    const m = d.match(/^did:([a-z0-9]+):/i);
    if (m && m[1].toLowerCase() !== 'web') return `That is a did:${m[1]}. Signing needs a did:web, which lives on a domain you control, so a reader can fetch your key from it.`;
    return 'That is not a did:web. It should look like did:web:id.example.com:you (your domain, then each folder after a colon).';
  },
  // What went wrong with publishing, in words for Settings and a notification.
  explain(r) {
    const e = r?.error;
    return {
      off: 'Signing is off in Settings → Identity & data.',
      did: 'Your DID must be a did:web (Settings → Identity & data).',
      folder: 'Choose your identity folder in Settings → Identity & data.',
      helper: 'The Praxamark Helper is not installed on this Mac: Settings → Configuration → Mac Helper installs it.',
      'helper-old': `Publishing needs Helper version ${Stamps.STAMP_HELPER_VERSION} (this one is ${r?.have}): Settings → Configuration → Mac Helper updates it.`,
      didjson: `Your did.json could not be read as JSON, so it was left as it is: ${r?.path || ''}`,
      notgit: 'Your identity folder is not a git repository, so it cannot be published. The files are written; upload them yourself, or make the folder a clone of your site’s repository.',
      nogit: 'git is not installed on this Mac (xcode-select --install installs it).',
      add: `git could not add the files: ${r?.detail || ''}`,
      commit: `git could not commit: ${r?.detail || ''}`,
      push: `Committed, but git push failed: ${r?.detail || ''}. Push the folder yourself once, then Publish again.`,
      write: `Could not write the files: ${r?.detail || ''}`,
    }[e] || String(r?.detail || e || 'Unknown error');
  },

  // ---------------------------------------------------------------- your DID document
  // Your did.json, with this browser's key in it: whatever the file already says (alsoKnownAs, services, other keys)
  // is kept; the key is listed as a Multikey, for signing claims (assertionMethod) and, while current, for proving
  // it is you (authentication). Retired keys stay for claims only, so their stamps still verify.
  async didDocument(settings, existing = null) {
    const k = await Stamps.key();
    const did = settings.did.trim();
    const doc = existing && existing.id === did ? JSON.parse(JSON.stringify(existing)) : { id: did };
    const ctx = ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'];
    doc['@context'] = [...new Set([...ctx, ...[].concat(doc['@context'] || []).filter((c) => typeof c === 'string')])];
    const ours = [k.multikey, ...(await Stamps.retiredKeys()).map((r) => r.multikey)];
    const vm = (mk) => ({ id: Stamps.vmOf(did, mk), type: 'Multikey', controller: did, publicKeyMultibase: mk });
    const abs = (id) => (String(id).startsWith('#') ? did + id : String(id));
    const oursIds = new Set(ours.map((mk) => Stamps.vmOf(did, mk)));
    const others = (doc.verificationMethod || []).filter((m) => !oursIds.has(abs(m.id)));
    doc.verificationMethod = [...ours.map(vm), ...others];
    const keepRefs = (list) => (list || []).filter((x) => !oursIds.has(abs(typeof x === 'string' ? x : x.id)));
    doc.assertionMethod = [...ours.map((mk) => Stamps.vmOf(did, mk)), ...keepRefs(doc.assertionMethod)];
    doc.authentication = [Stamps.vmOf(did, k.multikey), ...keepRefs(doc.authentication)];
    const aka = [...(doc.alsoKnownAs || []), ...(settings.alsoKnownAs || []), ...(settings.orcid ? [`https://orcid.org/${settings.orcid}`] : [])];
    if (aka.length) doc.alsoKnownAs = [...new Set(aka)];
    const order = ['@context', 'id', 'alsoKnownAs', 'verificationMethod', 'authentication', 'assertionMethod'];
    return Object.fromEntries([...order.filter((x) => x in doc), ...Object.keys(doc).filter((x) => !order.includes(x))].map((x) => [x, doc[x]]));
  },

  // ---------------------------------------------------------------- publishing, through the Helper
  // Your identity folder is the local copy of the repository your domain serves (for did:web:id.example.com:you,
  // the folder whose you/did.json appears at https://id.example.com/you/did.json). The Helper writes into it and,
  // when it is a git repository, commits and pushes with your own git sign-in (a git static host). A folder that is
  // not one is served as it is (your Mac through Tailscale Funnel, or a host that syncs it), so writing publishes it.
  // Praxamark keeps no password or token.
  get STAMP_HELPER_VERSION() { return TwinAPI.HELPER_VERSION_REQUIRED; },   // one version for everything the Helper does
  folderPaths(settings) {
    const root = String(settings.stampFolder || '').trim().replace(/\/+$/, '');
    const path = String(settings.did).trim().slice(8).split(':').slice(1);
    const sub = path.join('/');
    return { root, sub, did: sub ? `${sub}/did.json` : '.well-known/did.json', dir: sub ? `${sub}/` : '' };
  },
  recordPage(vc, id) {
    const json = JSON.stringify(vc, null, 2).replace(/</g, '\\u003c');
    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Signed post ${id}</title><meta name="robots" content="noindex">
<link rel="alternate" type="application/vc+ld+json" href="${id}.json"></head>
<body><main id="out"><noscript>This page checks a signed post in your browser, with JavaScript. The signed record itself is <a href="${id}.json">${id}.json</a>.</noscript></main>
<script type="application/json" id="stamp">${json}</script>
<script src="../stamps.js"></script><script src="../stamp-page.js"></script></body></html>
`;
  },
  async ownFile(name) { return (await fetch(chrome.runtime.getURL(name))).text(); },
  // Write the DID document (merged with what is there), the verify page's two scripts, and any stamps not yet
  // published; then commit and push. Returns { ok, published: [ids], pushed, error }.
  async publish(settings, { only } = {}) {
    const miss = Stamps.missing({ ...settings, stampShares: true });
    if (miss) return { ok: false, error: miss };
    const ping = await TwinAPI.helperFilesPing().catch(() => null);
    if (!ping?.ok) return { ok: false, error: 'helper' };
    if (TwinAPI.helperVersionOf(ping) < Stamps.STAMP_HELPER_VERSION) return { ok: false, error: 'helper-old', have: TwinAPI.helperVersionOf(ping) };
    const p = Stamps.folderPaths(settings);
    const files = [];
    const write = async (rel, content) => {
      const r = await TwinAPI.helperFiles('write', { path: `${p.root}/${rel}`, content, overwrite: true });
      if (!r.ok) throw new Error(`${rel}: ${r.error || 'could not write'}`);
      files.push(rel);
    };
    try {
      const cur = await TwinAPI.helperFiles('read', { path: `${p.root}/${p.did}` }).catch(() => null);
      let existing = null; if (cur?.ok) { try { existing = JSON.parse(cur.content); } catch { return { ok: false, error: 'didjson', path: `${p.root}/${p.did}` }; } }
      await write(p.did, JSON.stringify(await Stamps.didDocument(settings, existing), null, 2) + '\n');
      await write(`${p.dir}stamps.js`, await Stamps.ownFile('stamps.js'));
      await write(`${p.dir}stamp-page.js`, await Stamps.ownFile('stamp-page.js'));
      const ledger = await Stamps.ledger();
      const todo = ledger.filter((e) => !e.published && (!only || only.includes(e.id)));
      for (const e of todo) {
        const vc = (await chrome.storage.local.get(`stamp:${e.id}`))[`stamp:${e.id}`]; if (!vc) continue;
        await write(`${p.dir}s/${e.id}.json`, JSON.stringify(vc, null, 2) + '\n');
        await write(`${p.dir}s/${e.id}.html`, Stamps.recordPage(vc, e.id));
      }
      const git = await TwinAPI.helperFiles('exists', { path: `${p.root}/.git` }).catch(() => null);
      const r = git?.ok && !git.exists ? { ok: true, served: true } : await chrome.runtime.sendNativeMessage(TwinAPI.TINDERBOX_HOST, { op: 'files', action: 'publish', path: p.root, files, message: todo.length ? `Praxamark: signed post${todo.length > 1 ? 's' : ''} ${todo.map((e) => e.id).join(', ')}` : 'Praxamark: DID document' });
      if (!r?.ok) return { ok: false, error: r?.error || 'publish', detail: r?.detail || '', written: files };
      const done = new Set(todo.map((e) => e.id));
      const now = await Stamps.ledger();
      await chrome.storage.local.set({ stamps: now.map((e) => (done.has(e.id) ? { ...e, published: true } : e)) });
      return { ok: true, published: [...done], pushed: !!r.pushed, committed: !!r.committed, served: !!r.served };
    } catch (e) { return { ok: false, error: 'write', detail: String(e?.message || e), written: files }; }
  },
};
if (typeof window !== 'undefined') window.Stamps = Stamps;
