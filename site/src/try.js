// "Try the lock": the app's real cryptography (shared/crypto.js) running in the visitor's browser.
// Nothing here talks to a server; the "server" that refuses to release the card is a simulation and says so.
import * as C from '../../shared/crypto.js';

const NAMES = ['Ana', 'Ben', 'Cy', 'Dee', 'Eli'];
const K = 3; // trustees needed
const NEED = 51; // the release number
const el = (tag, attrs = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) { if (k.startsWith('on')) e.addEventListener(k.slice(2), v); else if (k === 'class') e.className = v; else if (k in e) e[k] = v; else e.setAttribute(k, v); }
  e.append(...kids.flat().filter((x) => x != null));
  return e;
};
const flip = (s) => s.slice(0, -2) + (s.at(-2) === 'A' ? 'B' : 'A') + s.at(-1);

export async function mount(root) {
  await C.ready;
  const trustees = NAMES.map((name, i) => ({ name, index: i + 1, keys: C.newKeypairs() }));
  const S = { enc: null, present: new Set([1, 2]), signed: 37, tamper: false, result: null };
  const ctx = () => ({ campaignId: 'demo', templateVersion: 'card-v1', ciphertext: S.tamper ? flip(S.enc.ciphertext) : S.enc.ciphertext, nonce: S.enc.nonce });

  const text = el('input', { type: 'text', value: 'Alex Rivera, alex@example.org, 555-0100', 'aria-label': 'A fake card', maxLength: 120 });
  const stage = el('div', { class: 'stage' });
  root.append(
    el('p', {}, el('strong', {}, '1. The card.'), ' Use fake details. It is sealed in your browser with a fresh key, and that key is split among five trustees so that any ', el('strong', {}, `${K} of 5`), ' can rebuild it.'),
    text,
    el('div', { class: 'row' }, el('button', { class: 'btn primary', type: 'button', onclick: seal }, 'Seal the card')),
    stage);

  async function seal() {
    S.enc = await C.encryptCard({
      campaignId: 'demo', templateVersion: 'card-v1', payload: { card: text.value.trim() || '(empty)' },
      trustees: trustees.map((t) => ({ index: t.index, boxPublicKey: t.keys.boxPublicKey })), k: K,
    });
    S.result = null;
    draw();
    stage.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }

  async function attempt() {
    if (S.signed < NEED) {
      S.result = { ok: false, msg: `The server refused to hand over the sealed card: ${S.signed} of the ${NEED} people needed have signed and been confirmed. There is nothing to decrypt, even with all five trustees in the room.` };
      return draw();
    }
    const shares = [...S.present].map((i) => { const t = trustees[i - 1]; return C.openShare(S.enc.sealedShares.find((s) => s.trusteeIndex === i).sealed, t.keys.boxPublicKey, t.keys.boxSecretKey); });
    try {
      const p = await C.decryptCard(ctx(), shares);
      S.result = { ok: true, msg: `Opened: "${p.card}". ${S.present.size} trustees together were enough (${K} are needed).` };
    } catch {
      S.result = { ok: false, msg: S.tamper
        ? 'Could not open it. The stored card was changed after it was sealed, and authenticated encryption noticed.'
        : `Could not open it. ${S.present.size} trustee${S.present.size === 1 ? '' : 's'} cannot rebuild the key: ${K} are needed, and with fewer the math reveals nothing about the card.` };
    }
    draw();
  }

  function draw() {
    if (!S.enc) return stage.replaceChildren();
    const chip = (t) => el('label', { class: 'chip' }, el('input', { type: 'checkbox', checked: S.present.has(t.index), onchange: (e) => { e.target.checked ? S.present.add(t.index) : S.present.delete(t.index); S.result = null; draw(); } }), t.name);
    const range = el('input', { type: 'range', min: 0, max: 80, value: S.signed, 'aria-label': 'People who have signed', oninput: (e) => { S.signed = Number(e.target.value); S.result = null; draw(); } });
    stage.replaceChildren(
      el('p', {}, el('strong', {}, '2. What the server holds.'), ' Only this. It cannot read the card.'),
      el('pre', { class: 'code' }, `sealed card   ${S.enc.ciphertext.slice(0, 60)}...\n` + trustees.map((t) => `share for ${t.name.padEnd(3)}  ${S.enc.sealedShares[t.index - 1].sealed.slice(0, 40)}...`).join('\n')),
      el('p', {}, el('strong', {}, '3. Who is in the room?'), ` ${S.present.size} of ${K} needed.`),
      el('div', { class: 'row' }, trustees.map(chip)),
      el('p', {}, el('strong', {}, '4. The release number.'), ` The campaign was set up to keep cards sealed until ${NEED} people have signed. So far: `, el('strong', {}, String(S.signed)), '. (A simulated server.)'),
      range,
      el('div', { class: 'row' }, el('label', { class: 'chip' }, el('input', { type: 'checkbox', checked: S.tamper, onchange: (e) => { S.tamper = e.target.checked; S.result = null; draw(); } }), 'Tamper with the stored card first')),
      el('div', { class: 'row' }, el('button', { class: 'btn primary', type: 'button', onclick: attempt }, 'Ask the server, then try to open it')),
      S.result ? el('div', { class: `result ${S.result.ok ? 'ok' : 'bad'}`, role: 'status' }, S.result.msg) : null,
      el('p', { class: 'small muted' }, 'Try: two trustees (fails), then three (opens), then slide the signatures below the number (the server refuses first), then tamper with the card.'));
  }
}
