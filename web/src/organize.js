// The organizing side: start a campaign, enroll trustees, sign a card, follow progress, keep a private record.
// Every secret is created in this browser; the server is only ever given ciphertext and hashes.
import * as C from '../../shared/crypto.js';
import { authenticate, checkEnrollment, RosterError, isCommit } from '../../shared/roster.js';
import qrcode from 'qrcode-generator';
import { api, bearer, ApiError, friendly } from './api.js';
import { store } from './store.js';
import { t, getLang, LANGS } from './i18n.js';
import { PACKS, packOf, markersFor } from './packs.js';
import { addCalendar, daysBetween } from '../../shared/deadlines.js';
import {
  div, span, p, a, img, ul, li, h1, h2, h3, strong, em, small, input, label, textarea, select, option, details, summary, table, thead, tbody, tr, td, th,
  btn, callout, badge, field, textInput, selectBox, linkBtn, shell, setTitle, view, fragment, scrubFragment, go, act, toast, copy, share, download, md, fill, cardBody, readAloud, svg, pct, fmtDate, ago, wipers, setKids,
} from './ui.js';

export const linkTo = (path, params) => `${location.origin}${path}#${new URLSearchParams(params)}`;
const wait = (ms = 40) => new Promise((r) => setTimeout(r, ms)); // lets the screen show "working" before a heavy computation
export const waiting = (n) => (n === 1 ? t('One more is waiting to be confirmed in person.') : t('{n} more are waiting to be confirmed in person.', { n }));
export const isLocal = () => ['localhost', '127.0.0.1'].includes(location.hostname);

export async function loadMeta(c, k, auth) {
  const raw = await api('GET', `/api/campaigns/${c}/meta`, { auth });
  let meta;
  try { meta = C.decryptMeta(k, { nonce: raw.metaNonce, ciphertext: raw.metaCiphertext }, c); } catch { throw new ApiError(0, 'bad_key'); }
  return { raw, meta };
}

// ---------- shared pieces ----------
// Add the campaign's release number to the progress markers, so everyone can see where the lock opens.
export function withRelease(markers, releaseMin, size) {
  if (!releaseMin || releaseMin <= 1 || !size) return markers;
  return [...markers, { pct: Math.min(1, releaseMin / size), label: t('{n} people: the earliest the cards can be opened', { n: releaseMin }), release: true }].sort((a, b) => a.pct - b.pct);
}
export function progressView({ count, size, markers }) {
  const frac = size ? Math.min(1, count / size) : 0;
  return div({ class: 'progress-wrap' },
    div({ class: 'progress', role: 'progressbar', 'aria-valuemin': 0, 'aria-valuemax': size, 'aria-valuenow': count, 'aria-label': t('Cards signed') },
      div({ class: 'track' },
        div({ class: 'fill', style: { width: pct(frac) } }),
        markers.map((m) => div({ class: `tick ${m.release ? 'gate' : ''}`, style: { left: pct(m.pct) } }, span({ class: 'tick-n' }, pct(m.pct)))))),
    p({ class: 'progress-cap' }, strong(count), ' ', t('of about {size} coworkers have signed ({p})', { size, p: pct(frac) })),
    ul({ class: 'legend' }, markers.map((m) => li({ class: frac >= m.pct ? 'reached' : '' }, (frac >= m.pct ? '✓ ' : '○ ') + t(m.label)))));
}

// A sparkline of cumulative cards, plus a plain-language projection to the target.
export function momentum(history, size, targetPct = 0.7) {
  if (!history || history.length < 2) return null;
  let cum = 0;
  const pts = history.map((h) => ({ day: h.day, n: (cum += h.count) }));
  const w = 300, hgt = 56, max = Math.max(1, pts.at(-1).n);
  const spanDays = Math.max(1, daysBetween(pts[0].day, pts.at(-1).day));
  const xy = pts.map((q) => `${(daysBetween(pts[0].day, q.day) / spanDays) * w},${hgt - (q.n / max) * (hgt - 6) - 3}`).join(' ');
  const rate = pts.at(-1).n / spanDays;
  const need = Math.ceil(targetPct * size) - pts.at(-1).n;
  return div({ class: 'momentum' },
    svg('svg', { viewBox: `0 0 ${w} ${hgt}`, class: 'spark', role: 'img', 'aria-label': t('Cards signed over time') }, svg('polyline', { points: xy, fill: 'none', stroke: 'currentColor', 'stroke-width': 2 })),
    need > 0 && rate > 0 ? p({ class: 'small muted' }, t('At the pace so far, about {d} more days to reach {p}. This is only a rough guess.', { d: Math.ceil(need / rate), p: pct(targetPct) })) : null);
}

// A QR code is the safest way to hand over an invite in person: nothing is sent, so no message trail is left on either phone.
function qrImage(text) {
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  return img({ class: 'qr', src: qr.createDataURL(5, 3), alt: t('QR code for the invitation link') }); // a data: image, allowed by our CSP
}
export function inviteBox({ link, employer, kind }) {
  const holder = div({ class: 'qr-holder' });
  const toggle = btn(t('Show QR code'), () => {
    if (holder.firstChild) { holder.replaceChildren(); toggle.textContent = t('Show QR code'); }
    else { holder.append(qrImage(link), p({ class: 'small muted' }, t('Show this only to the person you are inviting.'))); toggle.textContent = t('Hide QR code'); }
  }, { kind: 'secondary' });
  const msg = t('Hi, some of us at {employer} are forming a union. Please sign a card with this link, on your own phone and not at work: ', { employer });
  return div({ class: 'invite-box' },
    kind === 'group' ? callout('warn', t('Anyone who gets this link can sign, but their card will not count until you confirm them in person.')) : null,
    div({ class: 'link-box', tabindex: 0 }, link),
    div({ class: 'row' },
      btn(t('Share'), () => share({ title: 'Project Ludlow', text: msg, url: link }), { kind: 'primary' }),
      btn(t('Copy link'), () => copy(link), { kind: 'secondary' }),
      btn(t('Copy a message to send'), () => copy(msg + link), { kind: 'secondary' }), toggle),
    holder);
}

// Choose a saved key file (or upload one) and unlock it with its passphrase. Used by trustees and members.
export function keyFilePicker({ prefix, format, describe, onUnlock, exclude = () => false, cta }) {
  const stored = store.keys(prefix).map((k) => store.get(k)).filter((f) => f?.format === format && !exclude(f));
  let chosen = stored[0] || null;
  const pass = input({ type: 'password', autocomplete: 'current-password', 'aria-label': t('Passphrase') });
  const fileIn = input({
    type: 'file', accept: '.json,application/json', 'aria-label': t('Choose a key file'),
    onchange: async (e) => {
      const f = e.target.files[0];
      if (!f) return;
      try { const j = JSON.parse(await f.text()); if (j.format !== format || exclude(j)) throw new Error('x'); chosen = j; toast(t('Key file loaded.')); } catch { toast(t('That is not a usable key file.'), 'bad'); }
    },
  });
  const unlock = btn(cta || t('Unlock'), act(async () => {
    if (!chosen) return toast(t('Choose a key file first.'), 'bad');
    await wait();
    let secrets;
    try { secrets = C.openKeyFile(chosen, pass.value); } catch (e) { return toast(e.message === 'wrong_passphrase' ? t('That passphrase is not right.') : t('That is not a usable key file.'), 'bad'); }
    pass.value = '';
    await onUnlock(chosen, secrets);
  }), { kind: 'primary' });
  return div({ class: 'stack' },
    stored.length ? div({ class: 'stack' }, stored.map((f, i) => label({ class: 'radio' }, input({ type: 'radio', name: 'kf', checked: i === 0, onchange: () => (chosen = f) }), span(describe(f))))) : p({ class: 'muted' }, t('No key file is saved on this device.')),
    field(t('Or choose a key file from your device'), fileIn),
    field(t('Passphrase'), pass), unlock);
}

const passphraseNote = () => callout('info', strong(t('Two things protect your key:')), ' ', t('the key file, and the passphrase that unlocks it. Lose either one and the cards it guards can never be opened by you.'));

// ---------- start a campaign ----------
export function StartPage() {
  setTitle('Start a campaign', true);
  const S = { step: 0, pack: 'us-nlra', union: '', employer: '', address: '', unit: '', size: '', legalPct: '', release: '', n: 3, k: 2, names: ['', '', ''], done: null };
  const total = 8;
  const clamp = () => { S.k = Math.max(2, Math.min(S.k, S.n)); };
  const valid = () => {
    if (S.step === 1) return S.union.trim().length >= 2;
    if (S.step === 2) return S.employer.trim().length >= 2;
    if (S.step === 3) return S.unit.trim().length >= 5;
    if (S.step === 4) return Number(S.size) >= 2;
    if (S.step === 5) return Number(S.release) >= 1 && Number(S.release) <= 100000;
    return true;
  };
  async function create() {
    await C.ready;
    const id = C.uuid(), campaignKey = C.newCampaignKey();
    const tokens = Array.from({ length: S.n }, C.newToken);
    const meta = {
      unionName: S.union.trim(), employerName: S.employer.trim(), ...(S.address.trim() ? { employerAddress: S.address.trim() } : {}), unitDescription: S.unit.trim(),
      estimatedUnitSize: Number(S.size), releaseMin: Number(S.release), jurisdiction: S.pack, ...(S.legalPct ? { legalThresholdPct: Number(S.legalPct) } : {}),
      trusteeNames: S.names.map((d, i) => ({ index: i + 1, displayName: d.trim() || t('Trustee {n}', { n: i + 1 }) })), createdAt: new Date().toISOString(),
    };
    const box = C.encryptMeta(campaignKey, meta, id);
    await api('POST', '/api/campaigns', { body: { id, k: S.k, n: S.n, releaseMin: Number(S.release), metaCiphertext: box.ciphertext, metaNonce: box.nonce, templateVersion: 'card-v1', enrollTokenHashes: tokens.map(C.hashToken) } });
    store.set(`plan.${id}`, { k: S.k, n: S.n }); // what the founder chose; the committee is only confirmed with these numbers (shared/roster.js)
    S.done = { meta, links: tokens.map((tok) => linkTo('/t', { e: tok, k: campaignKey, c: id })) };
  }
  const body = view((update) => {
    if (S.done) return doneView(S.done);
    const pack = packOf(S.pack);
    const next = () => { if (!valid()) return toast(t('Please fill this in first.'), 'bad'); S.step++; update(); };
    const cardText = fill(cardBody(pack.cards.en), { employerName: S.employer || t('[your employer]'), unionName: S.union || t('[your union]') });
    const steps = [
      () => div(h2(t('Where do you work?')), p(t('This sets the legal steps, the card wording and the goals shown on your progress bar.')),
        div({ class: 'stack' }, Object.values(PACKS).map((k) => label2(k.id, S.pack, () => { S.pack = k.id; update(); }, k.name, k.blurb)))),
      () => div(h2(t('What will your union be called?')), p(t('You can start your own independent union, or organize with one that already exists. Use the name your coworkers will recognize.')),
        field(t('Union name'), textInput({ value: S.union, placeholder: t('e.g. Riverside Baristas United'), oninput: (e) => (S.union = e.target.value) }))),
      () => div(h2(t('Who is your employer?')), p(t('Use the legal name if you can. Check your paystub or tax form.')),
        field(t('Employer\'s legal name'), textInput({ value: S.employer, oninput: (e) => (S.employer = e.target.value) })),
        field(t('Address (optional)'), textInput({ value: S.address, oninput: (e) => (S.address = e.target.value) }))),
      () => div(h2(t('Who is in your group?')), p(t('Describe the coworkers who would be in the union. People with similar jobs, skills, supervisors and location usually belong together. Supervisors and managers usually do not.')),
        field(t('Who is included?'), textarea({ rows: 3, value: S.unit, placeholder: t('e.g. All baristas and shift leads at the Main Street location'), oninput: (e) => (S.unit = e.target.value) }))),
      () => div(h2(t('About how many people is that?')), p(t('A rough number is fine. Your progress bar uses it.')),
        field(t('Number of coworkers'), textInput({ type: 'number', inputmode: 'numeric', min: 2, value: S.size, oninput: (e) => (S.size = e.target.value) })),
        pack.id === 'generic' ? field(t('Legal threshold (optional)'), textInput({ type: 'number', min: 1, max: 99, value: S.legalPct, oninput: (e) => (S.legalPct = e.target.value) }), t('If you know what share of coworkers your local law needs (in percent), enter it. Ask a local union or lawyer.')) : null),
      () => {
        const size = Number(S.size);
        const choices = pack.markers.map((m) => ({ n: Math.max(1, m.pct === 0.5 ? Math.floor(size / 2) + 1 : Math.ceil(size * m.pct)), label: m.label })).filter((c, i, a) => a.findIndex((x) => x.n === c.n) === i);
        if (!S.release) S.release = String(choices.find((c) => c.n === Math.floor(size / 2) + 1)?.n ?? Math.floor(size / 2) + 1); // default: a majority
        return div(h2(t('When should the cards be allowed to open?')),
          p(t('This is a safety lock. Until at least this many people have signed and been counted, the cards stay sealed: nobody can open them, not even all your trustees together, and this website will not hand them over. It is a safety catch, not a guarantee: it counts the cards the system accepted, anyone who can invite people can add cards, and until every trustee has joined and you have confirmed the committee, you alone hold the key.')),
          div({ class: 'stack' }, choices.map((c) => label2(String(c.n), S.release, () => { S.release = String(c.n); update(); }, t('{n} people', { n: c.n }), t(c.label)))),
          field(t('Or choose your own number'), textInput({ type: 'number', min: 1, value: S.release, oninput: (e) => { S.release = e.target.value; } })),
          Number(S.release) > size ? callout('warn', t('That is more than the {n} people you said are in your group. The cards would stay locked until more than everyone has signed.', { n: size })) : null,
          callout('info', t('Trustees can raise this number later on their own. Lowering it takes several of them agreeing.')));
      },
      () => div(h2(t('Your committee of trustees')),
        callout('ok', strong(t('You can start with just yourself.')), ' ', t('You will be able to invite coworkers as soon as you have made your key. Add the other trustees whenever they are ready.')),
        p(t('Trustees are trusted coworkers who hold the keys. Once every trustee has joined and you have confirmed the committee, any {k} of the {n} together can open the cards (once the number above is reached). After that, no one can alone, and neither can this website.', { k: S.k, n: S.n })),
        callout('warn', t('Until every trustee has joined and you have confirmed the committee, only you can open the cards. That is fine for the first days, but add trustees soon, and keep your key file safe: it is the only way to open the cards until then, and it still opens any copy of the early cards made before you lock them to the committee.')),
        field(t('How many trustees do you plan to have?'), selectBox([['3', t('3 trustees (recommended)')], ['5', t('5 trustees')], ['4', '4'], ['2', '2'], ['6', '6'], ['7', '7']], String(S.n), (v) => { S.n = Number(v); S.k = Math.floor(S.n / 2) + 1; clamp(); S.names = Array.from({ length: S.n }, (_, i) => S.names[i] || ''); update(); })),
        field(t('How many must be together to open the cards?'), selectBox(Array.from({ length: S.n - 1 }, (_, i) => [String(i + 2), t('{k} of {n}', { k: i + 2, n: S.n })]), String(S.k), (v) => { S.k = Number(v); update(); }), t('A majority of your trustees is a good choice. You can change this plan later.')),
        S.names.map((nm, i) => field(i === 0 ? t('Your first name or nickname') : t('Trustee {n}: first name or nickname (optional)', { n: i + 1 }), textInput({ value: nm, oninput: (e) => (S.names[i] = e.target.value) })))),
      () => div(h2(t('Read the card your coworkers will sign')), p(t('This is the exact wording. It is a draft that a labor attorney should review before you use it.')),
        div({ class: 'paper' }, div({ class: 'paper-h' }, S.union || t('[your union]')), md(cardText)),
        callout('info', t('Your union name, employer and group are encrypted here on your device before anything is sent. The website will not be able to read them.')),
        btn(t('Create my campaign'), act(async () => { await create(); update(); }), { kind: 'primary block' })),
    ];
    return div(
      p({ class: 'small muted' }, t('Step {i} of {n}', { i: S.step + 1, n: total })),
      steps[S.step](),
      div({ class: 'row between' },
        S.step > 0 ? btn(t('Back'), () => { S.step--; update(); }, { kind: 'secondary' }) : span(),
        S.step < total - 1 ? btn(t('Next'), next, { kind: 'primary' }) : null));
  });
  return shell(div({ class: 'wrap' }, body));
}
const label2 = (id, cur, onpick, title, desc) => div({ class: `choice ${cur === id ? 'on' : ''}`, role: 'radio', 'aria-checked': cur === id, tabindex: 0, onclick: onpick, onkeydown: (e) => { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); onpick(); } } }, strong(title), p({ class: 'small muted' }, desc));

function doneView({ meta, links }) {
  return div(
    h1(t('Your campaign is ready')),
    p({ class: 'lead' }, t('Next, make your key. As soon as you have, you can invite coworkers to sign. You do not have to wait for anyone else.')),
    div({ class: 'card' }, h3(t('Trustee 1: {name} (you)', { name: meta.trusteeNames[0].displayName })), p(t('Your key file is the only way to open the cards until other trustees join. Guard it.')), linkBtn(t('Set up my key'), links[0].replace(location.origin, ''), 'primary')),
    meta.trusteeNames.length > 1 ? p({ class: 'small muted' }, t('Once your key is set up, invite your other trustees from your dashboard. Their invitations carry a check of your key, so that everyone who signs can make sure they are sealing to the real committee.')) : null);
}
export function trusteeInvite(link, name, meta) {
  const msg = t('Hi {name}, I would like you to be a trustee for our union campaign at {employer}. Open this link on your personal phone and follow the steps: ', { name, employer: meta.employerName });
  return div({ class: 'invite-box' }, div({ class: 'link-box', tabindex: 0 }, link),
    div({ class: 'row' }, btn(t('Share'), () => share({ title: 'Project Ludlow', text: msg, url: link }), { kind: 'primary' }), btn(t('Copy link'), () => copy(link), { kind: 'secondary' }), btn(t('Copy a message to send'), () => copy(msg + link), { kind: 'secondary' })));
}

// ---------- trustee enrollment ----------
export async function EnrollPage() {
  setTitle('Become a trustee', true);
  await C.ready;
  const f = fragment(), e = f.get('e'), k = f.get('k'), c = f.get('c'), founderLink = f.get('f');
  if (!e || !k || !c) return shell(div({ class: 'wrap' }, callout('danger', t('This link is incomplete. Ask for it to be sent again, and make sure the whole link is copied.'))));
  scrubFragment(); // the secrets are in memory now; don't leave them in the address bar and the browser's history
  let raw, meta;
  try { ({ raw, meta } = await loadMeta(c, k, bearer(e))); } catch (err) {
    if (err.status === 401) return shell(div({ class: 'wrap' }, h1(t('This link was already used')), p(t('If you already set up your key, go to your trustee dashboard.')), linkBtn(t('Trustee dashboard'), '/t/dashboard', 'primary')));
    throw err;
  }
  const idx = raw.yourTrusteeIndex;
  try { checkEnrollment(raw, idx, founderLink); } catch (err) { // the seat comes from the server: a trustee's link never opens the founder's seat, or names a different founder
    if (!(err instanceof RosterError)) throw err;
    return shell(div({ class: 'wrap' }, h1(t('This invitation does not check out')), callout('danger', t(friendly(err)))));
  }
  const myName = meta.trusteeNames.find((x) => x.index === idx)?.displayName || '';
  const S = { pass: C.generatePassphrase(), own: false, made: null, saved: false, enrolled: null };
  return shell(div({ class: 'wrap' }, view((update) => {
    if (S.enrolled) {
      const done = S.enrolled.committeeComplete;
      return div(h1(t('You are enrolled')), callout('ok', t('{x} of {n} trustees have set up their keys.', { x: S.enrolled.enrolledCount, n: raw.n })),
        div({ class: 'keycheck' }, strong(t('Your key words')),
          p({ class: 'small muted' }, t('Read these to trustee 1 by phone or in person. They check them before the cards are locked to the committee, so nobody can slip in a different key.')),
          div({ class: 'keywords', lang: 'en' }, C.keyWords(S.made.pub.boxPublicKey))),
        done ? p(t('Everyone has joined. Trustee 1 now checks each trustee\'s key words with them and confirms the committee. After that, any {k} of the {n} trustees together can open the cards.', { k: raw.k, n: raw.n }))
          : idx === 1 ? callout('warn', strong(t('You can start inviting coworkers now.')), ' ', t('Until every trustee has joined and you have confirmed the committee, only you can open the cards. Add trustees from your dashboard when they are ready.'))
            : p(t('Thank you. Trustee 1 will confirm the committee, and lock the early cards to it, once everyone has joined.')),
        linkBtn(t('Go to my trustee dashboard'), '/t/dashboard', 'primary'));
    }
    return div(
      h1(t('Become a trustee for {union}', { union: meta.unionName })),
      p({ class: 'lead' }, t('You hold one of {n} keys. Once everyone has joined and trustee 1 has confirmed the committee, any {k} of the trustees together can open the signed cards, and nobody can do it alone, including this website. Until then, trustee 1 alone can open them.', { n: raw.n, k: raw.k })),
      p(t('You are trustee {i}{name}.', { i: idx, name: myName ? ` (${myName})` : '' })),
      passphraseNote(),
      idx !== 1 && !isCommit(founderLink) ? callout('warn', t('This invitation is from an older version and has no check of the founder\'s key, so this device will not be able to verify the committee. You can still be a trustee.')) : null,
      idx === 1 && raw.n > 1 ? callout('warn', strong(t('You are the founder.')), ' ', t('Until the other trustees join, this key file is the only way to open the cards. Back it up somewhere safe as well.')) : null,
      div({ class: 'card' }, h2(t('1. Choose a passphrase')),
        S.own
          ? div(field(t('Your passphrase (at least 14 characters)'), input({ type: 'password', autocomplete: 'new-password', oninput: (ev) => (S.pass = ev.target.value) })), btn(t('Use a generated one instead'), () => { S.own = false; S.pass = C.generatePassphrase(); update(); }, { kind: 'secondary small' }))
          : div(div({ class: 'passphrase', tabindex: 0 }, S.pass), div({ class: 'row' }, btn(t('Copy'), () => copy(S.pass), { kind: 'secondary small' }), btn(t('Another one'), () => { S.pass = C.generatePassphrase(); update(); }, { kind: 'secondary small' }), btn(t('I will choose my own'), () => { S.own = true; S.pass = ''; update(); }, { kind: 'secondary small' }))),
        p({ class: 'small muted' }, t('Write the generated passphrase down or save it in a password manager.'))),
      div({ class: 'card' }, h2(t('2. Create and save your key file')),
        btn(S.made ? t('Download the key file again') : t('Create my key file'), act(async () => {
          if (!C.passphraseOk(S.pass)) return toast(t('Your passphrase must be at least 14 characters.'), 'bad');
          if (!S.made) {
            await wait(60);
            const keys = C.newKeypairs();
            const file = C.makeKeyFile({ format: 'trustee-keyfile-v1', header: { campaignId: c, trusteeIndex: idx }, secrets: { ...keys, campaignKey: k, founder: idx === 1 ? C.founderCommit(keys.boxPublicKey, keys.signPublicKey) : (isCommit(founderLink) ? founderLink : null) }, passphrase: S.pass });
            S.made = { file, pub: { boxPublicKey: keys.boxPublicKey, signPublicKey: keys.signPublicKey } };
            store.set(`tk.${c}.${idx}`, file);
          }
          download(`project-ludlow-trustee-${idx}-key.json`, JSON.stringify(S.made.file, null, 2), 'application/json');
          update();
        }), { kind: 'primary' }),
        S.made ? div(callout('ok', t('Key file created and downloaded. A copy is also saved in this browser, but it still needs your passphrase.')),
          label3(t('I saved my key file and my passphrase somewhere safe.'), S.saved, (v) => { S.saved = v; update(); })) : null),
      S.made ? div({ class: 'card' }, h2(t('3. Finish')),
        btn(t('Finish enrollment'), act(async () => {
          if (!S.saved) return toast(t('Please confirm you saved your key file and passphrase.'), 'bad');
          S.enrolled = await api('POST', '/api/trustees/enroll', { body: { campaignId: c, enrollToken: e, boxPublicKey: S.made.pub.boxPublicKey, signPublicKey: S.made.pub.signPublicKey } });
          update();
        }), { kind: 'primary', disabled: !S.saved })) : null);
  })));
}
export const label3 = (text, checked, onchange) => div({ class: 'check' }, input({ type: 'checkbox', checked, onchange: (e) => onchange(e.target.checked) }), span(text));

// ---------- signing a card ----------
const SSN = /\b\d{3}[- ]?\d{2}[- ]?\d{4}\b/;
const DOB = /\b(\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|\d{4}-\d{2}-\d{2})\b|\b(born|dob|birth)/i;
export function normalizePhone(raw) {
  const s = String(raw).trim(), d = s.replace(/\D/g, '');
  if (s.startsWith('+')) return d.length >= 8 && d.length <= 15 ? '+' + d : null;
  if (d.length === 10) return '+1' + d;
  if (d.length === 11 && d[0] === '1') return '+' + d;
  return null;
}
const sameName = (a, b) => a.trim().replace(/\s+/g, ' ').toLowerCase() === b.trim().replace(/\s+/g, ' ').toLowerCase();

export async function JoinPage() {
  setTitle('Sign a card', true);
  await C.ready;
  const f = fragment(), i = f.get('i'), k = f.get('k'), c = f.get('c'), fc = f.get('f');
  const bad = (msg) => shell(div({ class: 'wrap' }, callout('danger', msg)));
  if (!i || !k || !c) return bad(t('This link is incomplete. Ask for it to be sent again, and make sure the whole link is copied.'));
  scrubFragment(); // the secrets are in memory now; don't leave them in the address bar and the browser's history
  let info, raw, meta;
  try { info = await api('POST', '/api/invites/resolve', { body: { token: i } }); ({ raw, meta } = await loadMeta(c, k, bearer(i))); } catch { return bad(t('This invitation is no longer valid. It may have expired, been used, or been withdrawn. Ask the person who sent it for a new one.')); }
  // The server told us who the trustees are. Do not take its word: check the founder's keys against this invitation and, once the founder has signed it, the
  // committee against the roster. A mismatch means the website (or the link) was altered, so nothing is asked of the person and nothing is sealed.
  let sealTo;
  try { sealTo = authenticate(raw, fc, c); } catch (err) { if (err instanceof RosterError) return shell(div({ class: 'wrap' }, h1(t('Your card was not signed')), callout('danger', strong(t('Stop.')), ' ', t(friendly(err))))); throw err; }
  const pack = packOf(meta.jurisdiction);
  const langs = Object.keys(pack.cards);
  const F = { step: 'intro', blocked: null, name: '', email: '', phone: '', job: '', shift: '', lang: getLang() === 'es' ? 'Español' : '', sign: '', consent: false, cardLang: langs.includes(getLang()) ? getLang() : 'en', result: null };
  return shell(div({ class: 'wrap' }, view((update) => {
    if (F.blocked) return div(h1(t('Your card was not signed')), callout('danger', strong(t('Stop.')), ' ', t(friendly({ code: F.blocked }))));
    const cardText = fill(cardBody(pack.cards[F.cardLang] || pack.cards.en), { employerName: meta.employerName, unionName: meta.unionName });
    if (F.step === 'intro') {
      return div(
        h1(t('{union}', { union: meta.unionName })),
        p({ class: 'lead' }, t('Coworkers at {employer} are forming a union, and you have been invited to sign an authorization card.', { employer: meta.employerName })),
        callout('ok', strong(t('Your information is encrypted on your phone before it is sent. This website cannot read it.'))),
        raw.releaseMin > 1 ? callout('info', t('Your card stays sealed. Until at least {n} people have signed and been counted, nobody can open it: not the trustees, and not this website.', { n: raw.releaseMin })) : null,
        div({ class: 'card' }, h2(t('Before you sign')), ul(li(t('Use your own phone, on your mobile data, and not at work.')), li(t('Signing is your choice. Nobody can make you.')), li(t('You will get a confirmation email. If you did not sign, you can tell us.')), li(t('The law protects your right to organize.'), ' ', a({ href: '/rights', target: '_blank', rel: 'noopener' }, t('Read about your rights'))))),
        btn(t('Read the card'), () => { F.step = 'card'; update(); }, { kind: 'primary block' }));
    }
    if (F.step === 'card') {
      const errs = () => {
        if (F.name.trim().length < 2) return t('Please enter your full legal name.');
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(F.email.trim())) return t('Please enter a valid personal email address.');
        if (!normalizePhone(F.phone)) return pack.id === 'us-nlra' ? t('Please enter a phone number with 10 digits.') : t('Please enter your phone number with the country code, like +44 7700 900123.');
        for (const v of [F.job, F.shift, F.lang]) if (SSN.test(v) || DOB.test(v)) return t('Please do not enter dates of birth, Social Security numbers or ID numbers. They are not needed and must not be included.');
        if (!sameName(F.sign, F.name)) return t('Type your full name exactly as above to sign.');
        if (!F.consent) return t('Please check the box to agree to the card.');
        return null;
      };
      const submit = async () => {
        const e = errs();
        if (e) return toast(e, 'bad');
        const cardId = C.uuid(), secret = C.newToken();
        const { authToken, lockerKey } = C.deriveMember(secret);
        C.wipe(lockerKey);
        const disavowToken = C.newToken();
        const payload = {
          legalName: F.name.trim(), personalEmail: F.email.trim(), phone: normalizePhone(F.phone), employerName: meta.employerName, unionName: meta.unionName,
          cardText, cardTextSha256: C.sha256Hex(cardText), typedSignature: F.sign.trim(), consentChecked: true, clientSignedAt: new Date().toISOString(), jurisdiction: pack.id,
          ...(F.job.trim() ? { jobTitle: F.job.trim() } : {}), ...(F.shift.trim() ? { shiftOrDepartment: F.shift.trim() } : {}), ...(F.lang.trim() ? { preferredLanguage: F.lang.trim() } : {}),
        };
        const templateVersion = F.cardLang === 'en' ? 'card-v1' : `card-v1-${F.cardLang}`;
        // Sealed to the founder alone until the founder has signed the roster of the whole committee, then split k-of-n among the keys the founder signed.
        const seal = async () => (sealTo.mode === 'shamir'
          ? C.encryptCard({ campaignId: c, templateVersion, payload, trustees: sealTo.seats, k: sealTo.k })
          : C.encryptCardSolo({ campaignId: c, templateVersion, payload, founder: sealTo.seats[0] }));
        const vouch = info.kind === 'group' ? C.vouchCode() : null;
        const post = async () => api('POST', '/api/cards', { body: { cardId, inviteToken: i, ...(await seal()), memberTokenHash: C.hashToken(authToken), disavowTokenHash: C.hashToken(disavowToken), vouchCodeHash: vouch ? C.vouchHash(cardId, vouch) : undefined } });
        try { await post(); } catch (e) {
          if (e.code !== 'committee_changed') throw e;
          ({ raw } = await loadMeta(c, k, bearer(i))); // the committee changed while they typed: check it again, and seal it again
          try { sealTo = authenticate(raw, fc, c); } catch (err) { if (err instanceof RosterError) { F.blocked = err.code; update(); return; } throw err; }
          await post();
        }
        store.set(`member.${c}`, { secret, campaignKey: k, vouch, cardId, founder: fc }); // the founder's key check stays with the member, for sharing with the committee later
        const sendConfirmation = () => api('POST', `/api/cards/${cardId}/confirm`, { auth: bearer(authToken), body: { to: payload.personalEmail, legalName: payload.legalName, phone: payload.phone, employerName: payload.employerName, unionName: payload.unionName, cardText, disavowToken } });
        let confirmed = false;
        try { await sendConfirmation(); confirmed = true; } catch { /* the done screen offers a retry */ }
        F.result = { kind: info.kind, vouch, secret, confirmed, sendConfirmation, email: payload.personalEmail };
        F.step = 'done';
        update();
      };
      return div(
        h1(t('Your authorization card')),
        langs.length > 1 ? field(t('Card language'), selectBox(langs.map((l) => [l, LANGS[l] || l]), F.cardLang, (v) => { F.cardLang = v; update(); })) : null,
        div({ class: 'paper' }, div({ class: 'paper-h' }, meta.unionName), md(cardText), div({ class: 'sig' }, span({ class: 'sig-line' }, F.sign || ' '), small(t('Signature (type your name below)'))), p({ class: 'small muted' }, t('Date: recorded by the server when you sign.'))),
        readAloud(cardText),
        p({ class: 'small' }, span({ class: 'lock' }, '🔒 '), t('Encrypted on your device. This site can\'t read it.'), ' ', a({ href: '/protected', target: '_blank', rel: 'noopener' }, t('How your data is protected'))),
        details(summary(t('Check who this is sealed to')), p({ class: 'small muted' }, t('Your card is sealed so that only the founder of this campaign (and, once they confirm it, the committee they name) can open it. These words identify the founder\'s key. To be sure, ask the founder to read theirs to you.')), div({ class: 'keywords', lang: 'en' }, C.keyWords(sealTo.founder.boxPublicKey))),
        div({ class: 'card' },
          field(t('Full legal name'), textInput({ value: F.name, autocomplete: 'name', oninput: (e) => (F.name = e.target.value) })),
          field(t('Personal email'), textInput({ type: 'email', value: F.email, autocomplete: 'email', inputmode: 'email', oninput: (e) => (F.email = e.target.value) }), t('Not your work email. We send a confirmation here, as the law requires.')),
          field(t('Mobile phone'), textInput({ type: 'tel', value: F.phone, autocomplete: 'tel', inputmode: 'tel', oninput: (e) => (F.phone = e.target.value) })),
          details(summary(t('Optional details')),
            field(t('Job title'), textInput({ value: F.job, oninput: (e) => (F.job = e.target.value) })),
            field(t('Shift or department'), textInput({ value: F.shift, oninput: (e) => (F.shift = e.target.value) })),
            field(t('Preferred language'), textInput({ value: F.lang, oninput: (e) => (F.lang = e.target.value) })),
            p({ class: 'small muted' }, t('Please do not enter your date of birth, Social Security number or any ID number.'))),
          field(t('Type your full name to sign'), textInput({ value: F.sign, autocomplete: 'off', oninput: (e) => { F.sign = e.target.value; document.querySelector('.sig-line').textContent = F.sign || ' '; } })),
          label3(t('I have read the card above and I agree to it.'), F.consent, (v) => (F.consent = v))),
        btn(t('Sign the card'), act(submit), { kind: 'primary block' }),
        btn(t('Back'), () => { F.step = 'intro'; update(); }, { kind: 'secondary' }));
    }
    const R = F.result;
    const memberLink = linkTo('/m', { s: R.secret, k, c, f: fc });
    return div(
      h1(R.kind === 'group' ? t('Almost done') : t('Your card is signed and counted')),
      R.kind === 'group' ? callout('warn', h3(t('Tell this code, in person, to the coworker who invited you:')), div({ class: 'code' }, R.vouch), p(t('Your card counts once they enter it. Do not send it in a message.'))) : callout('ok', t('Thank you. Your card is counted.')),
      R.confirmed
        ? callout('ok', t('We sent a confirmation email to {email}. If you did not sign, the email has a link to tell us.', { email: R.email }))
        : callout('warn', t('Your card is saved, but we could not send the confirmation email.'), ' ', btn(t('Try again'), act(async () => { await R.sendConfirmation(); R.confirmed = true; update(); }), { kind: 'secondary small' })),
      div({ class: 'card' }, h2(t('Save your member link')),
        p(t('This link is how you come back to see progress, invite others, and keep your private record. Anyone who has it can act as you, so keep it private, for example in a password manager or a Signal "Note to Self". Nobody, including us, can recover it for you.')),
        div({ class: 'link-box', tabindex: 0 }, memberLink),
        div({ class: 'row' }, btn(t('Copy my link'), () => copy(memberLink), { kind: 'primary' }), btn(t('Share it to myself'), () => share({ title: 'Project Ludlow', text: t('My member link (keep private):'), url: memberLink }), { kind: 'secondary' }), linkBtn(t('Open my page'), '/m', 'secondary'))),
      div({ class: 'card' }, h3(t('What happens next')), ul(li(t('Your coworkers may invite you to help. You decide.')), li(t('Nothing is sent to your employer. The trustees decide together when to go public.')), li(t('If your employer asks about the union, you never have to answer, and you can write it down privately on your member page.')))),
      isLocal() ? p({ class: 'small muted' }, t('Testing on your own computer: '), a({ href: '/dev/outbox', target: '_blank', rel: 'noopener' }, t('open the test outbox'))) : null);
  })));
}

// ---------- member page ----------
const INCIDENTS = [
  ['asked', 'Asked whether I or others support the union'], ['threat', 'Threatened me or others'], ['promise', 'Promised a benefit to drop the union'],
  ['watched', 'Watched or followed union activity'], ['discipline', 'Disciplined, fired or cut my hours'], ['meeting', 'Required me to attend an anti-union meeting'], ['other', 'Something else'],
];
const addMonths = (iso, m) => { const d = new Date(iso + 'T00:00:00Z'); d.setUTCMonth(d.getUTCMonth() + m); return d.toISOString().slice(0, 10); };

export async function MemberPage() {
  setTitle('My card', true);
  await C.ready;
  const f = fragment();
  let s = f.get('s'), k = f.get('k'), c = f.get('c');
  const fcLink = f.get('f');
  if (s && k && c) { store.set(`member.${c}`, { ...(store.get(`member.${c}`) || {}), secret: s, campaignKey: k, ...(isCommit(fcLink) ? { founder: fcLink } : {}) }); history.replaceState(null, '', '/m'); }
  else { const key = store.keys('member.')[0]; if (key) { c = key.slice(7); ({ secret: s, campaignKey: k } = store.get(key)); } }
  if (!s) return shell(div({ class: 'wrap' }, h1(t('No card on this device')), p(t('Open the member link you saved when you signed. If you lost it, ask the person who invited you to send a new invitation.'))));
  const saved = store.get(`member.${c}`) || {};
  const { authToken, lockerKey } = C.deriveMember(s);
  wipers.push(() => C.wipe(lockerKey));
  const auth = bearer(authToken);
  let me;
  try { me = await api('GET', '/api/cards/me', { auth }); } catch (e) {
    if (e.status === 401) { store.del(`member.${c}`); return shell(div({ class: 'wrap' }, h1(t('This card no longer exists')), p(t('It may have been withdrawn or the campaign may have ended. Your data is gone from the server.')))); }
    throw e;
  }
  let raw, meta;
  ({ raw, meta } = await loadMeta(c, k, auth));
  const pack = packOf(meta.jurisdiction);
  if (me.status === 'pending') {
    return shell(div({ class: 'wrap' },
      h1(meta.unionName),
      callout('warn', h3(t('Your card is waiting to be confirmed by the coworker who invited you.')), saved.vouch ? div(p(t('Tell them this code, in person:')), div({ class: 'code' }, saved.vouch)) : null),
      p(t('Once they confirm you, your card counts and you will see progress here. Nothing else is needed from you.')),
      withdrawBtn(auth, c)));
  }
  const prog = await api('GET', `/api/campaigns/${c}/progress`, { auth });
  const pend = await api('GET', `/api/campaigns/${c}/pending-vouches`, { auth });
  const S = { links: [] };
  return shell(div({ class: 'wrap' }, view((update) => div(
    h1(meta.unionName),
    p({ class: 'lead' }, t('You are signed on at {employer}. Thank you.', { employer: meta.employerName })),
    div({ class: 'card' }, h2(t('Where we are')), progressView({ count: prog.vouched, size: meta.estimatedUnitSize, markers: withRelease(markersFor(pack, meta), prog.releaseMin, meta.estimatedUnitSize) }), momentum(prog.history, meta.estimatedUnitSize), prog.pending ? p({ class: 'small muted' }, waiting(prog.pending)) : null,
      prog.releaseMin > 1 ? p({ class: 'small' }, '🔒 ' + (prog.vouched >= prog.releaseMin ? t('The number is met, so the trustees can open the cards when they decide together to go public.') : t('The cards stay sealed until {n} people have signed. Nobody can open them before then, not even the trustees together.', { n: prog.releaseMin }))) : null,
      raw.status === 'frozen' ? callout('warn', t('The trustees have paused this campaign. No new cards can be signed for now.')) : null),
    raw.status === 'active' ? div({ class: 'card' }, h2(t('Bring in a coworker')),
      p(t('Invite people you know and trust, one at a time. Do it in person or through an app you trust.')),
      div({ class: 'row' },
        btn(t('Invite one person'), act(async () => { S.links.unshift({ kind: 'direct', link: await makeInvite('direct') }); update(); }), { kind: 'primary' }),
        btn(t('Create a group link'), act(async () => { S.links.unshift({ kind: 'group', link: await makeInvite('group') }); update(); }), { kind: 'secondary' })),
      S.links.map((l) => inviteBox({ link: l.link, employer: meta.employerName, kind: l.kind }))) : null,
    pend.pending.length ? div({ class: 'card' }, h2(t('People waiting for you to confirm')), p(t('Ask each person for the two-word code they were shown. Only enter it if you met them in person.')), pend.pending.map((q, n) => vouchRow(auth, q, n + 1, update))) : null,
    lockerSection({ auth, lockerKey, c, raw, meta, pack, k, founder: saved.founder }),
    div({ class: 'card' }, h3(t('Your member link')), p({ class: 'small muted' }, t('Keep it private. It is how you get back here.')),
      div({ class: 'row' }, btn(t('Copy my link'), () => copy(linkTo('/m', { s, k, c, ...(isCommit(saved.founder) ? { f: saved.founder } : {}) })), { kind: 'secondary small' }),
        // Quick exit only leaves the page. This device keeps your sign-in so you can come back; this removes it (nothing is deleted from the server).
        btn(t('Forget this device'), () => { if (confirm(t('Remove your saved sign-in from this device? To come back you will need the member link you saved. Nothing is deleted from the server.'))) { store.del(`member.${c}`); go('/'); } }, { kind: 'secondary small' }))),
    withdrawBtn(auth, c))))); // a pending member sees only the waiting screen; the rest is for counted members

  async function makeInvite(kind) {
    const token = C.newToken();
    // An invitation carries the founder's key check, which is how the person who signs knows they are sealing to the real committee. Without it we cannot make one.
    if (!isCommit(saved.founder)) throw new RosterError('no_commit');
    await api('POST', '/api/invites', { auth, body: { campaignId: c, tokenHash: C.hashToken(token), kind } });
    return linkTo('/j', { i: token, k, c, f: saved.founder });
  }
}
function vouchRow(auth, q, n, update) {
  const code = input({ type: 'text', autocomplete: 'off', autocapitalize: 'characters', placeholder: 'MAPLE-RIVER', 'aria-label': t('Code') });
  return div({ class: 'row vouch' }, span(t('Signer #{n}, {when}', { n, when: ago(q.createdAt) })), code,
    btn(t('Confirm'), act(async (ev) => {
      try { await api('POST', `/api/cards/${q.cardId}/vouch`, { auth, body: { code: code.value } }); toast(t('Confirmed. Their card now counts.')); location.reload(); }
      catch (e) { if (e.code === 'wrong_code') return toast(t('That code is not right. {n} tries left.', { n: e.extra?.attemptsLeft ?? 0 }), 'bad'); throw e; }
    }), { kind: 'primary small' }));
}
function withdrawBtn(auth, c) {
  return btn(t('Withdraw my card'), act(async () => {
    if (!confirm(t('Withdraw your card? It is permanently deleted from the server and no longer counts. This cannot be undone.'))) return;
    await api('DELETE', '/api/cards/me', { auth });
    store.del(`member.${c}`);
    toast(t('Your card was deleted.'));
    go('/');
  }), { kind: 'danger small' });
}

// ---------- the private record ("retaliation shield") ----------
function lockerSection({ auth, lockerKey, c, raw, meta, pack, k, founder }) {
  const box = div({ class: 'card' }, h2(t('My private record')), p({ class: 'muted' }, t('Loading...')));
  const S = { entries: [], adding: false, sharing: null };
  const today = new Date().toISOString().slice(0, 10);
  async function refresh() {
    const { entries } = await api('GET', '/api/locker', { auth });
    S.entries = entries.map((e) => { try { return { ...e, data: C.openJson(lockerKey, e, 'locker|' + e.id) }; } catch { return null; } }).filter(Boolean).sort((a, b) => (b.data.occurredOn || '').localeCompare(a.data.occurredOn || ''));
    draw();
  }
  function ulp(occurredOn) {
    if (!pack.ulpMonths || !occurredOn) return null;
    const left = daysBetween(today, addMonths(occurredOn, pack.ulpMonths));
    return left < 0 ? badge(t('Deadline to file may have passed. Ask soon.'), 'bad') : badge(t('Time limit to file a charge: about {n} days left', { n: left }), left < 30 ? 'warn' : '');
  }
  function draw() {
    const form = () => {
      const F = { kind: 'asked', occurredOn: today, what: '', who: '', witnesses: '' };
      return div({ class: 'stack' },
        field(t('What happened?'), selectBox(INCIDENTS.map(([v, l]) => [v, t(l)]), F.kind, (v) => (F.kind = v))),
        field(t('Date'), input({ type: 'date', value: F.occurredOn, max: today, onchange: (e) => (F.occurredOn = e.target.value) })),
        field(t('What was said or done?'), textarea({ rows: 4, oninput: (e) => (F.what = e.target.value) }), t('Write what you saw and heard, in your own words. Facts, not opinions.')),
        field(t('Who was involved?'), textInput({ oninput: (e) => (F.who = e.target.value) })),
        field(t('Who else saw it?'), textInput({ oninput: (e) => (F.witnesses = e.target.value) })),
        div({ class: 'row' }, btn(t('Save privately'), act(async () => {
          if (F.what.trim().length < 3) return toast(t('Please describe what happened.'), 'bad');
          const id = C.uuid();
          await api('POST', '/api/locker', { auth, body: { id, ...C.sealJson(lockerKey, { ...F, savedAt: new Date().toISOString() }, 'locker|' + id) } });
          S.adding = false; await refresh();
        }), { kind: 'primary' }), btn(t('Cancel'), () => { S.adding = false; draw(); }, { kind: 'secondary' })));
    };
    const shareForm = (e) => {
      const N = { name: '' };
      return div({ class: 'callout info' }, p(t('This sends a copy to your trustees only. Any one of them can read it. It is not linked to your card. Add your name only if you want them to know it is you.')),
        field(t('Your name (optional)'), textInput({ oninput: (ev) => (N.name = ev.target.value) })),
        div({ class: 'row' }, btn(t('Share with the committee'), act(async () => {
          const rid = C.uuid();
          // Sealed only to keys we can authenticate: the founder's, and the whole committee once the founder has signed the roster.
          const send = async () => {
            const sealTo = authenticate(raw, founder, c);
            const rep = C.sealForTrustees({ ...e.data, from: N.name.trim() || null, sharedAt: new Date().toISOString() }, sealTo.seats, rid);
            await api('POST', '/api/reports', { auth, body: { id: rid, ...rep } });
          };
          try { await send(); } catch (err) {
            if (err?.code !== 'committee_changed') throw err;
            ({ raw } = await loadMeta(c, k, auth)); // the committee changed since this page loaded: check it again
            await send();
          }
          S.sharing = null; toast(t('Shared with the committee.')); draw();
        }), { kind: 'primary small' }), btn(t('Cancel'), () => { S.sharing = null; draw(); }, { kind: 'secondary small' })));
    };
    setKids(box,
      h2(t('My private record')),
      p(t('Write down anything that looks like punishment for organizing. Only you can read it. Not the trustees, not this website, unless you choose to share an entry.')),
      S.adding ? form() : btn(t('Add something that happened'), () => { S.adding = true; draw(); }, { kind: 'primary' }),
      S.entries.map((e) => div({ class: 'entry' },
        div({ class: 'row between' }, strong(t(INCIDENTS.find(([v]) => v === e.data.kind)?.[1] || 'Something else')), span({ class: 'small muted' }, fmtDate(e.data.occurredOn))),
        ulp(e.data.occurredOn), p({ class: 'pre' }, e.data.what), e.data.who ? p({ class: 'small' }, t('Involved: {x}', { x: e.data.who })) : null, e.data.witnesses ? p({ class: 'small' }, t('Also saw it: {x}', { x: e.data.witnesses })) : null,
        S.sharing === e.id ? shareForm(e) : div({ class: 'row' },
          btn(t('Share with the committee'), () => { S.sharing = e.id; draw(); }, { kind: 'secondary small' }),
          btn(t('Delete'), act(async () => { if (confirm(t('Delete this entry for good?'))) { await api('DELETE', `/api/locker/${e.id}`, { auth }); await refresh(); } }), { kind: 'danger small' })))),
      S.entries.length ? btn(t('Download my record'), () => download('my-private-record.txt', S.entries.map((e) => `${e.data.occurredOn}  ${e.data.kind}\n${e.data.what}\nInvolved: ${e.data.who || ''}\nAlso saw it: ${e.data.witnesses || ''}\n`).join('\n---\n'), 'text/plain'), { kind: 'secondary small' }) : null,
      pack.ulpMonths ? p({ class: 'small muted' }, t('Time limits are general guidance, not legal advice. A lawyer or the labor board can tell you the exact deadline.')) : null);
  }
  draw();
  refresh().catch(() => box.replaceChildren(p(t('Could not load your record.'))));
  return box;
}

// ---------- disavow ----------
export function DisavowPage() {
  setTitle('I did not sign', true);
  const f = fragment(), tok = f.get('t'), card = f.get('c');
  if (tok && card) scrubFragment(); // the token is in memory now; don't leave it in the address bar and the browser's history
  let done = false;
  return shell(div({ class: 'wrap' }, view((update) => {
    if (!tok || !card) return callout('danger', t('This link is incomplete.'));
    if (done) return div(h1(t('Thank you')), p(t('We have recorded that you did not sign this card. It will be flagged for the organizers.')));
    return div(h1(t('I did not sign this card')), p(t('If you did not sign a union authorization card, tell us here. The card will be marked so it is not counted or used.')),
      btn(t('I did not sign this card'), act(async () => { await api('POST', '/api/cards/disavow', { body: { cardId: card, token: tok } }); done = true; update(); }), { kind: 'danger' }),
      p({ class: 'small muted' }, t('If you did sign it and everything is fine, you can close this page.')));
  })));
}
