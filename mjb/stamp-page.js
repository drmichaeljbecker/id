// The verify page for a signed post, published on the signer's own domain beside their did.json (Praxamark writes it
// there with each stamp). It runs entirely in the reader's browser: it reads the stamp embedded in the page, fetches
// the signer's DID document from their domain, and checks the signature with Web Crypto (stamps.js). Nothing is sent
// anywhere else, and no Identity Praxis server is involved.
(async () => {
  const out = document.getElementById('out');
  const style = document.createElement('style');
  style.textContent = `
    :root { --bg:#fbfbf9; --fg:#1c1c1a; --muted:#5f5f5a; --card:#fff; --line:#e3e2dc; --ok:#2e7d4f; --okbg:#e8f5ec; --bad:#b3372f; --badbg:#fcebea; --warn:#8a5a00; --warnbg:#fff4dc; }
    @media (prefers-color-scheme: dark) { :root { --bg:#161615; --fg:#ecebe6; --muted:#a3a29b; --card:#1f1f1d; --line:#353431; --ok:#6fcf97; --okbg:#173323; --bad:#f08a80; --badbg:#3a1c19; --warn:#f2c46b; --warnbg:#3a2e12; } }
    body { margin:0; background:var(--bg); color:var(--fg); font:16px/1.5 -apple-system, system-ui, "Segoe UI", sans-serif; }
    main { max-width:680px; margin:0 auto; padding:28px 16px 48px; }
    h1 { font-size:22px; margin:0 0 14px; }
    .status { border-radius:10px; padding:14px 16px; font-weight:600; margin-bottom:18px; }
    .status small { display:block; font-weight:400; margin-top:4px; }
    .ok { background:var(--okbg); color:var(--ok); } .bad { background:var(--badbg); color:var(--bad); } .warn { background:var(--warnbg); color:var(--warn); }
    blockquote { background:var(--card); border:1px solid var(--line); border-radius:10px; margin:0 0 18px; padding:14px 16px; white-space:pre-wrap; overflow-wrap:anywhere; }
    dl { display:grid; grid-template-columns:max-content 1fr; gap:6px 14px; margin:0 0 20px; }
    dt { color:var(--muted); } dd { margin:0; overflow-wrap:anywhere; }
    code { font:13px ui-monospace, Menlo, monospace; }
    textarea { width:100%; box-sizing:border-box; min-height:110px; font:inherit; padding:10px; border-radius:8px; border:1px solid var(--line); background:var(--card); color:var(--fg); }
    button { font:inherit; padding:7px 14px; border-radius:8px; border:1px solid var(--line); background:var(--card); color:var(--fg); cursor:pointer; margin-top:8px; }
    #same { margin-left:10px; font-weight:600; }
    a { color:inherit; } .muted { color:var(--muted); font-size:14px; }
    h2 { font-size:17px; margin:26px 0 8px; }`;
  document.head.appendChild(style);
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  let vc;
  try { vc = JSON.parse(document.getElementById('stamp').textContent); } catch { out.innerHTML = '<h1>Signed post</h1><div class="status bad">This page holds no readable stamp.</div>'; return; }
  const r = await Stamps.check(vc);
  const s = vc.credentialSubject || {}, post = s.post || {}, src = s.source || {};
  const name = typeof vc.issuer === 'object' ? vc.issuer.name : '';
  const did = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer?.id;
  const when = (() => { try { return new Date(vc.validFrom).toLocaleString(undefined, { dateStyle: 'long', timeStyle: 'short' }); } catch { return vc.validFrom; } })();
  const says = {
    ok: ['ok', `✓ Signed by ${esc(name || did)}`, `The signature matches the key published at ${esc(r.url || did)}, and not a word has changed since it was signed.${r.retired ? ' (Signed with an earlier key, since retired: still valid for what it signed then.)' : ''}`],
    badsig: ['bad', '✗ The signature does not match', 'This record was changed after it was signed, or was not signed by the key its signer publishes. Do not trust it as theirs.'],
    mismatch: ['bad', '✗ The words do not match the signature', 'The text shown here is not the text that was signed.'],
    nokey: ['bad', '✗ The signer’s DID document does not list this key', `The key that made this signature is not in ${esc(r.url || 'the DID document')}. It may have been removed after a compromise, or never belonged to this DID.`],
    wrongdoc: ['bad', '✗ The DID document is for someone else', `${esc(r.url || '')} does not describe ${esc(did)}.`],
    unreachable: ['warn', 'Could not reach the signer’s DID document', `${esc(r.url || did)} did not answer${r.status ? ` (${r.status})` : ''}. Try again later; until then this cannot be checked.`],
    unsupported: ['warn', 'This kind of identifier cannot be checked here', esc(did)],
    notastamp: ['bad', '✗ Not a signed post', 'The record does not name a signer and the key it was signed with.'],
  }[r.state] || ['warn', 'Could not check this post', esc(r.state)];
  out.innerHTML = `
    <h1>Signed post</h1>
    <div class="status ${says[0]}">${says[1]}<small>${says[2]}</small></div>
    <blockquote>${esc(post.text)}</blockquote>
    <dl>
      <dt>Signed by</dt><dd>${name ? esc(name) + '<br>' : ''}<code>${esc(did)}</code></dd>
      <dt>When</dt><dd>${esc(when)}</dd>
      ${post.network ? `<dt>Posted to</dt><dd>${esc(post.network)}</dd>` : ''}
      ${src.url ? `<dt>About</dt><dd><a href="${esc(src.url)}" rel="noopener nofollow">${esc(src.title || src.url)}</a></dd>` : ''}
      ${s.sequence ? `<dt>Stamp</dt><dd>No. ${esc(s.sequence)} from this signer${s.previous ? ', linked to the one before' : ''}</dd>` : ''}
    </dl>
    <h2>Check a copy</h2>
    <p class="muted">Paste the post as you saw it. The ✓ Signed line and the link to the source are set aside; every other character must match.</p>
    <textarea id="copy" placeholder="Paste the post here"></textarea>
    <div><button type="button" id="check">Check</button><span id="same"></span></div>
    <h2>What this proves</h2>
    <p class="muted">That whoever holds the key listed in <a href="${esc(r.url || '#')}">${esc(did)}</a>’s DID document signed exactly these words at this time. Anyone can copy a name or a DID; only that key can make this signature. It does not prove the words are true, nor that no AI helped write them: it is the signer’s own statement, which they cannot later deny made.</p>
    <p class="muted">The signed record: <a href="${esc(location.pathname.replace(/(\.html)?$/, '.json'))}">JSON</a> (a W3C Verifiable Credential, proof <code>eddsa-jcs-2022</code>). Signed with Praxamark™.</p>`;
  document.title = `${says[1].replace(/^[✓✗] /, '')} · Signed post`;
  document.getElementById('check').addEventListener('click', async () => {
    const t = document.getElementById('copy').value, el = document.getElementById('same');
    if (!t.trim()) { el.textContent = ''; return; }
    const same = await Stamps.sameWords(vc, t);
    el.textContent = same ? '✓ Same words' : '✗ Not the words that were signed';
    el.style.color = same ? 'var(--ok)' : 'var(--bad)';
  });
})();
