// The trustee side: dashboard, the unlock-and-export ceremony, and the committee's inbox of reports.
import * as C from '../../shared/crypto.js';
import { api, tcall } from './api.js';
import { store } from './store.js';
import { t } from './i18n.js';
import { packOf, markersFor } from './packs.js';
import { buildPackage } from './exportpkg.js';
import { FoundingPanel } from './founding.js';
import { loadMeta, progressView, momentum, inviteBox, keyFilePicker, linkTo, label3, waiting, withRelease, trusteeInvite } from './organize.js';
import {
  div, span, p, a, ul, li, h1, h2, h3, strong, input, details, summary, table, thead, tbody, tr, td, th,
  btn, callout, badge, field, textInput, selectBox, shell, setTitle, view, act, toast, download, fill, wipers, fmtDate, fmtDateTime, ago, linkBtn, render, copy,
} from './ui.js';

let T = null; // the unlocked trustee: { campaignId, index, keys, campaignKey }
wipers.push(() => { T = null; });
const session = (file, s) => ({ campaignId: file.campaignId, index: file.trusteeIndex, keys: s, campaignKey: s.campaignKey });
const describeKey = (f) => t('Trustee {n} key file (campaign …{id})', { n: f.trusteeIndex, id: f.campaignId.slice(-4) });

async function fingerprint() {
  try {
    const bytes = new Uint8Array(await (await fetch('/app.js', { cache: 'no-store' })).arrayBuffer());
    return C.sha256HexBytes(bytes);
  } catch { return ''; }
}

export async function TrusteeDashboard() {
  setTitle('Trustee dashboard', true);
  await C.ready;
  if (!T) {
    return shell(div({ class: 'wrap' }, h1(t('Trustee dashboard')), p(t('Unlock your key file to continue. Your key never leaves this device.')),
      keyFilePicker({ prefix: 'tk.', format: 'trustee-keyfile-v1', describe: describeKey, onUnlock: (file, s) => { T = session(file, s); render(); } })));
  }
  const raw = await tcall(T, 'GET /api/campaigns/:id/meta');
  const meta = C.decryptMeta(T.campaignKey, { nonce: raw.metaNonce, ciphertext: raw.metaCiphertext }, T.campaignId);
  const pack = packOf(meta.jurisdiction);
  const active = raw.status !== 'draft';
  const prog = active ? await tcall(T, 'GET /api/campaigns/:id/progress') : null;
  const pending = active ? (await tcall(T, 'GET /api/campaigns/:id/pending-vouches')).pending : [];
  const S = { links: [], reports: null, slotLinks: {} };
  const myName = meta.trusteeNames.find((x) => x.index === T.index)?.displayName || '';
  const makeInvite = async (kind) => {
    const token = C.newToken();
    await tcall(T, 'POST /api/invites', { body: { campaignId: T.campaignId, tokenHash: C.hashToken(token), kind } });
    return linkTo('/j', { i: token, k: T.campaignKey, c: T.campaignId });
  };
  return shell(div({ class: 'wrap' }, view((update) => div(
    div({ class: 'row between' }, h1(meta.unionName), badge(raw.status === 'active' ? t('Active') : raw.status === 'frozen' ? t('Paused') : t('Setting up'), raw.status === 'active' ? 'ok' : 'warn')),
    p({ class: 'muted' }, t('{employer}. You are trustee {i}{name}. Any {k} of {n} trustees together can open the cards.', { employer: meta.employerName, i: T.index, name: myName ? ` (${myName})` : '', k: raw.k, n: raw.n })),
    raw.inactivityWarn ? callout('warn', t('This campaign has been quiet for a while. If nothing happens in {d} days it will be deleted automatically.', { d: raw.inactivityDaysLeft })) : null,
    !active ? div({ class: 'card' }, h2(t('Waiting for trustees')), ul(raw.trustees.map((x) => li((meta.trusteeNames.find((n) => n.index === x.index)?.displayName || t('Trustee {n}', { n: x.index })) + ': ' + (x.enrolled ? '✓ ' + t('ready') : t('has not set up a key yet')))))) : null,
    active ? div({ class: 'card' }, h2(t('Where we are')), progressView({ count: prog.vouched, size: meta.estimatedUnitSize, markers: withRelease(markersFor(pack, meta), prog.releaseMin, meta.estimatedUnitSize) }), momentum(prog.history, meta.estimatedUnitSize), p({ class: 'small muted' }, waiting(prog.pending))) : null,
    active ? committeeCard(raw, meta, prog, S, update) : null,
    raw.status === 'active' ? div({ class: 'card' }, h2(t('Invite coworkers')),
      div({ class: 'row' },
        btn(t('Invite one person'), act(async () => { S.links.unshift({ kind: 'direct', link: await makeInvite('direct') }); update(); }), { kind: 'primary' }),
        btn(t('Create a group link'), act(async () => { S.links.unshift({ kind: 'group', link: await makeInvite('group') }); update(); }), { kind: 'secondary' })),
      S.links.map((l) => inviteBox({ link: l.link, employer: meta.employerName, kind: l.kind }))) : null,
    pending.length ? div({ class: 'card' }, h2(t('Cards waiting to be confirmed')), p({ class: 'small muted' }, t('Enter the two-word code only if you have confirmed the person in person.')), pending.map((q, n) => trusteeVouch(q, n + 1))) : null,
    active ? reportsCard(prog.reports, meta, pack, S, update) : null,
    active ? div({ class: 'card' }, h2(t('Open the cards')),
      prog.vouched < prog.releaseMin
        ? callout('warn', strong(t('The cards are locked.')), ' ', t('{have} of the {need} people needed have signed and been confirmed. Until then nobody can open them, not even all the trustees together.', { have: prog.vouched, need: prog.releaseMin }))
        : p(t('The number is met. When you decide together to go public, {k} trustees meet, ideally in person, and open the cards on one device.', { k: raw.k })),
      prog.vouched < prog.releaseMin ? btn(t('Unlock and export'), () => {}, { kind: 'primary', disabled: true }) : linkBtn(t('Unlock and export'), '/t/unlock', 'primary')) : null,
    active ? releaseCard(prog, raw) : null,
    active ? div({ class: 'card' }, h2(t('Safety controls')),
      div({ class: 'row' },
        btn(raw.status === 'frozen' ? t('Resume signing') : t('Pause signing'), act(async () => { await tcall(T, 'POST /api/campaigns/:id/freeze', { body: { frozen: raw.status !== 'frozen' } }); render(); }), { kind: 'secondary' }),
        btn(t('Vote to destroy this campaign'), act(async () => {
          if (!confirm(t('Destroying deletes every card and the whole campaign for good. It needs {k} trustees to agree. Vote to destroy?', { k: raw.k }))) return;
          const r = await tcall(T, 'POST /api/campaigns/:id/destroy-approve');
          toast(r.destroyed ? t('The campaign was destroyed.') : t('Your vote is recorded ({a} of {k}).', { a: r.approvals, k: r.needed }));
          if (r.destroyed) { store.del(`tk.${raw.id}.${T.index}`); T = null; }
          render();
        }), { kind: 'danger' })),
      p({ class: 'small muted' }, t('Pausing stops new signatures (for example if a link leaked). Destroying deletes everything. Destroy after you have moved to a workspace.'), ' ', t('Votes to destroy so far: {a} of {k}.', { a: prog?.destroyApprovals ?? 0, k: raw.k }))) : null,
    btn(t('Lock this dashboard'), () => { T = null; render(); }, { kind: 'secondary small' })))));

  function trusteeVouch(q, n) {
    const code = input({ type: 'text', autocomplete: 'off', autocapitalize: 'characters', placeholder: 'MAPLE-RIVER', 'aria-label': t('Code') });
    return div({ class: 'row vouch' }, span(t('Signer #{n}, {when}', { n, when: ago(q.createdAt) })), code,
      btn(t('Confirm'), act(async () => {
        try { await tcall(T, 'POST /api/cards/:id/vouch', { params: { id: q.cardId }, body: { code: code.value } }); toast(t('Confirmed.')); render(); }
        catch (e) { if (e.code === 'wrong_code') return toast(t('That code is not right. {n} tries left.', { n: e.extra?.attemptsLeft ?? 0 }), 'bad'); throw e; }
      }), { kind: 'primary small' }));
  }
}

// The committee: who has joined, invitations, changing the plan, and locking early cards to the whole committee.
function committeeCard(raw, meta, prog, S, update) {
  const joined = raw.trustees.filter((x) => x.enrolled).length, complete = joined === raw.n, founder = T.index === 1;
  const nm = (i) => meta.trusteeNames.find((x) => x.index === i)?.displayName || t('Trustee {n}', { n: i });
  const P = (S.plan ||= { n: raw.n, k: raw.k });
  const lock = async () => {
    const { cards } = await tcall(T, 'GET /api/campaigns/:id/reshare-bundle');
    const trustees = raw.trustees.map((x) => ({ index: x.index, boxPublicKey: x.boxPublicKey }));
    const out = [];
    for (const c of cards) out.push({ cardId: c.id, sealedShares: await C.reshareCard(c.sealedShares.find((s) => s.trusteeIndex === T.index).sealed, T.keys, trustees, raw.k) });
    for (let i = 0; i < out.length; i += 200) await tcall(T, 'POST /api/campaigns/:id/reshare', { body: { cards: out.slice(i, i + 200) } });
    toast(t('Done. Any {k} of {n} trustees are now needed to open the cards.', { k: raw.k, n: raw.n }));
    render();
  };
  return div({ class: 'card' }, h2(t('Your committee')),
    complete
      ? (prog.solo ? callout('warn', strong(t('Everyone has joined. Now lock your early cards to the committee.')), ' ', t('{n} card(s) are still sealed to the founder alone.', { n: prog.solo }))
        : callout('ok', t('Any {k} of {n} trustees together can open the cards.', { k: raw.k, n: raw.n })))
      : callout('warn', strong(t('Only trustee 1 can open the cards right now.')), ' ', t('Invite the other trustees below. When all {n} have joined, lock the cards to the committee so that {k} of them are needed.', { n: raw.n, k: raw.k })),
    ul(raw.trustees.map((x) => li(strong(nm(x.index)), x.index === T.index ? ' ' + t('(you)') : '', ' ',
      x.enrolled ? badge(t('joined'), 'ok') : [badge(t('not joined yet'), 'warn'), ' ', btn(t('Get invite link'), act(async () => {
        const token = C.newToken();
        await tcall(T, 'POST /api/campaigns/:id/trustees/reset', { body: { index: x.index, tokenHash: C.hashToken(token) } }); // any older link for this seat stops working
        S.slotLinks[x.index] = linkTo('/t', { e: token, k: T.campaignKey, c: T.campaignId });
        update();
      }), { kind: 'secondary small' })],
      S.slotLinks[x.index] ? trusteeInvite(S.slotLinks[x.index], nm(x.index), meta) : null))),
    complete && prog.solo && founder ? btn(t('Lock {n} existing card(s) to the committee', { n: prog.solo }), act(lock), { kind: 'primary' }) : null,
    complete && prog.solo && !founder ? p({ class: 'small muted' }, t('Only trustee 1 holds the keys to these cards, so trustee 1 does this step.')) : null,
    !complete && founder ? details(summary(t('Change the plan')),
      p({ class: 'small muted' }, t('You can change how many trustees you plan to have, and how many must be together to open the cards, until everyone has joined.')),
      div({ class: 'row' },
        field(t('Trustees'), selectBox(Array.from({ length: 6 }, (_, i) => i + 2).filter((n) => n >= joined).map((n) => [String(n), String(n)]), String(P.n), (v) => { P.n = Number(v); P.k = Math.min(P.k, P.n); update(); })),
        field(t('Needed together'), selectBox(Array.from({ length: P.n - 1 }, (_, i) => i + 2).map((n) => [String(n), String(n)]), String(P.k), (v) => { P.k = Number(v); update(); }))),
      btn(t('Save the plan'), act(async () => { await tcall(T, 'POST /api/campaigns/:id/committee', { body: { n: P.n, k: P.k } }); render(); }), { kind: 'secondary small' })) : null);
}

// The lock: the number of confirmed cards below which the server will not hand the sealed cards to anyone.
function releaseCard(prog, raw) {
  const V = { value: String(prog.releaseMin) };
  return div({ class: 'card' }, h3(t('The lock')),
    p({ class: 'small muted' }, t('The cards stay sealed until this many people have signed and been confirmed. Any trustee can raise the number. Lowering it takes {k} trustees agreeing on the same number.', { k: raw.k })),
    div({ class: 'row' }, textInput({ type: 'number', min: 1, value: V.value, 'aria-label': t('Number of people'), oninput: (e) => (V.value = e.target.value) }),
      btn(t('Set the number'), act(async () => {
        const r = await tcall(T, 'POST /api/campaigns/:id/release-min', { body: { value: Number(V.value) } });
        toast(r.applied ? t('The number is now {n}.', { n: r.releaseMin }) : t('Your vote to lower it to {n} is recorded ({a} of {k}).', { n: V.value, a: r.approvals, k: r.needed }));
        render();
      }), { kind: 'secondary small' })),
    Object.entries(prog.releaseVotes || {}).map(([v, c]) => p({ class: 'small' }, t('{c} trustee(s) have voted to lower it to {v}.', { c, v }))));
}

// Reports coworkers chose to share. Each is sealed to every trustee, so any one of you can read it.
function reportsCard(count, meta, pack, S, update) {
  const open = async () => {
    const { reports } = await tcall(T, 'GET /api/campaigns/:id/reports');
    S.reports = reports.map((r) => { try { return { ...r, data: C.openReport(r, T.index, T.keys.boxPublicKey, T.keys.boxSecretKey) }; } catch { return null; } }).filter(Boolean);
    update();
  };
  const worksheet = () => {
    if (!pack.docs.ulp) return;
    const text = S.reports.map((r, i) => `${i + 1}. ${r.data.occurredOn}: ${r.data.kind}\n   ${r.data.what}\n   Involved: ${r.data.who || 'unknown'}. Witnesses: ${r.data.witnesses || 'none listed'}.`).join('\n\n');
    download('unfair-labor-practice-worksheet-DRAFT.md', fill(pack.docs.ulp, { employerName: meta.employerName, unionName: meta.unionName, incidents: text || '(none)' }), 'text/markdown');
  };
  return div({ class: 'card' }, h2(t('Reports from coworkers')),
    p({ class: 'small muted' }, t('Coworkers can choose to share something that happened to them. You can read these; the website cannot.')),
    S.reports === null
      ? btn(count ? t('Read {n} report(s)', { n: count }) : t('No reports yet'), act(open), { kind: 'secondary', disabled: !count })
      : div(S.reports.map((r) => div({ class: 'entry' }, div({ class: 'row between' }, strong(r.data.kind), span({ class: 'small muted' }, fmtDate(r.data.occurredOn))), p({ class: 'pre' }, r.data.what),
        r.data.who ? p({ class: 'small' }, t('Involved: {x}', { x: r.data.who })) : null, p({ class: 'small muted' }, r.data.from ? t('From: {x}', { x: r.data.from }) : t('Shared without a name.')),
        btn(t('Mark handled and delete'), act(async () => { await tcall(T, 'POST /api/campaigns/:id/reports/delete', { body: { reportId: r.id } }); await open(); }), { kind: 'secondary small' }))),
      pack.docs.ulp && S.reports.length ? btn(t('Prepare a charge worksheet (draft)'), worksheet, { kind: 'secondary' }) : null));
}

// ---------- the unlock ceremony ----------
export async function UnlockPage() {
  setTitle('Open the cards', true);
  await C.ready;
  const fp = await fingerprint();
  const U = { stage: 'intro', campaignId: null, raw: null, meta: null, prog: null, bundle: [], loaded: [], shares: new Map(), solo: new Map(), blocked: null, cards: [], failed: [], include: false };
  let rerender = () => {}; // set by the view below
  FoundingPanel.state = null; // never carry a previous ceremony's roster choices into this one
  return shell(div({ class: 'wrap wide' }, view((update) => {
    rerender = update; // contributions re-draw this ceremony, not the whole route (which would reset it)
    if (U.stage === 'intro') {
      return div(h1(t('Open the cards')),
        p({ class: 'lead' }, t('This is the ceremony. Trustees load their key files one at a time on this device. When enough have contributed, the cards are opened here, in this browser. Nothing decrypted is ever sent to the server.')),
        callout('info', strong(t('First, check the software.')), ' ', t('Compare this fingerprint with the other trustees\' screens and with the published release before you go on. If they differ, stop.'), div({ class: 'link-box' }, fp || t('(could not read)')), p({ class: 'small' }, a({ href: '/verify', target: '_blank', rel: 'noopener' }, t('What is this?')))),
        callout('warn', t('Do this on a private device you trust, not a work computer. When you are finished, close the tab.')),
        btn(t('Begin'), () => { U.stage = 'load'; update(); }, { kind: 'primary block' }));
    }
    if (U.stage === 'load') {
      const hasSolo = U.bundle.some((c) => c.sealMode === 'solo'), hasShamir = U.bundle.some((c) => c.sealMode !== 'solo');
      const enough = !!U.raw && U.loaded.length >= 1 && (!hasSolo || U.loaded.includes(1)) && (!hasShamir || U.loaded.length >= U.raw.k);
      const k = U.raw?.k || '?';
      return div(h1(hasSolo && !hasShamir ? t('Founder key') : t('Trustee {i} of {k}', { i: Math.min(U.loaded.length + 1, k), k })),
        U.blocked ? callout('danger', strong(t('The cards are still locked.')), ' ', t('{have} of the {need} people needed have signed and been confirmed. Nothing can be opened until then, not even by all the trustees together.', U.blocked), p(linkBtn(t('Back to the dashboard'), '/t/dashboard', 'secondary'))) : null,
        U.meta ? p(t('{union}: {n} signed cards.', { union: U.meta.unionName, n: U.bundle.length })) : null,
        hasSolo ? callout('warn', t('Some cards were signed before your committee was complete, so only trustee 1 can open them. Load trustee 1\'s key file.')) : null,
        U.loaded.length ? callout('ok', t('Contributed so far: trustees {list}.', { list: U.loaded.join(', ') })) : null,
        enough
          ? div(callout('ok', t('Enough trustees have contributed.')), btn(t('Open the cards'), act(open), { kind: 'primary block' }))
          : U.blocked ? null : div({ class: 'card' }, h2(t('Load your key file')), keyFilePicker({ prefix: 'tk.', format: 'trustee-keyfile-v1', describe: describeKey, exclude: (f) => U.loaded.includes(f.trusteeIndex) || (U.campaignId && f.campaignId !== U.campaignId), onUnlock: contribute, cta: t('Contribute my key') })));
    }
    return review(update);
  })));

  async function contribute(file, s) {
    const S = session(file, s);
    if (!U.campaignId) {
      U.campaignId = S.campaignId;
      try {
        U.raw = await tcall(S, 'GET /api/campaigns/:id/meta');
        U.meta = C.decryptMeta(S.campaignKey, { nonce: U.raw.metaNonce, ciphertext: U.raw.metaCiphertext }, S.campaignId);
        U.prog = await tcall(S, 'GET /api/campaigns/:id/progress');
        if (U.prog.vouched * 2 <= U.meta.estimatedUnitSize && !confirm(t('You are below a majority. Opening now means the names exist in readable form on this device, before you have the support you planned for. Continue?'))) { U.campaignId = null; return; }
        U.bundle = (await tcall(S, 'GET /api/campaigns/:id/export-bundle')).cards; // the server refuses this until the release number is met
      } catch (e) {
        U.campaignId = null;
        if (e.code === 'threshold_not_met') { U.blocked = { have: e.extra.have, need: e.extra.need }; rerender(); return; }
        throw e;
      }
    }
    for (const card of U.bundle) {
      const entry = card.sealedShares.find((x) => x.trusteeIndex === S.index);
      if (!entry) continue; // a founder-held card has no share for anyone else
      try {
        const opened = C.openShare(entry.sealed, s.boxPublicKey, s.boxSecretKey);
        if (card.sealMode === 'solo') U.solo.set(card.id, opened); else U.shares.set(card.id, [...(U.shares.get(card.id) || []), opened]);
      } catch { /* not a share for this key: the card will be reported as failed */ }
    }
    U.loaded.push(S.index);
    rerender();
  }
  async function open() {
    const ok = [], failed = [];
    for (const c of U.bundle) {
      const ctx = { campaignId: U.campaignId, templateVersion: c.templateVersion, ciphertext: c.ciphertext, nonce: c.nonce };
      try { ok.push({ ...c, payload: c.sealMode === 'solo' ? C.decryptSoloCard(ctx, U.solo.get(c.id)) : await C.decryptCard(ctx, U.shares.get(c.id) || []) }); } catch { failed.push(c); }
    }
    for (const arr of U.shares.values()) C.wipe(...arr);
    for (const key of U.solo.values()) C.wipe(key);
    U.shares.clear(); U.solo.clear();
    U.cards = ok; U.failed = failed; U.stage = 'review';
    rerender();
  }
  function review(update) {
    rerender = update;
    const pack = packOf(U.meta.jurisdiction);
    const use = U.include ? U.cards : U.cards.filter((c) => !c.disavowedAt);
    const disavowed = U.cards.filter((c) => c.disavowedAt).length;
    const noConfirm = U.cards.filter((c) => !c.confirmationSentAt).length;
    const emails = new Map(), phones = new Map();
    for (const c of U.cards) { const e = c.payload.personalEmail.toLowerCase(), p = c.payload.phone.replace(/\D/g, ''); emails.set(e, (emails.get(e) || 0) + 1); phones.set(p, (phones.get(p) || 0) + 1); }
    const dupes = [...emails.values(), ...phones.values()].filter((n) => n > 1).length;
    const size = U.meta.estimatedUnitSize, pctOf = Math.round((use.length / size) * 100);
    return div(
      h1(t('The cards are open')),
      callout('warn', t('The names are now readable on this screen. Do not leave this page open on a shared device.')),
      div({ class: 'card' }, h2(t('Summary')),
        ul(li(strong(U.cards.length), ' ', t('cards opened')), li(strong(use.length), ' ', t('will be in the package ({p}% of about {size})', { p: pctOf, size })),
          li(strong(disavowed), ' ', t('disavowed by the signer (excluded unless you include them)')), li(strong(noConfirm), ' ', t('without a confirmation email sent')), li(strong(dupes), ' ', t('possible duplicate emails or phone numbers to check by hand'))),
        U.failed.length ? callout('danger', t('{n} card(s) could not be opened. Check that the right key files were used, or that the card was not damaged.', { n: U.failed.length })) : null,
        use.length * 2 <= size ? callout('warn', t('This is not yet a majority. The letter in the package will say so and should not be sent as written.')) : null,
        label3(t('Include disavowed cards (marked) for review'), U.include, (v) => { U.include = v; update(); })),
      div({ class: 'card' }, h2(t('Download the package')), p(t('A ZIP with the roster, the cards as a PDF, a confirmations log, and draft documents for your attorney to review. It is built here on your device.')),
        btn(t('Download package (ZIP)'), act(async () => {
          const pkg = await buildPackage({ meta: U.meta, pack, cards: U.cards, includeDisavowed: U.include, lang: 'en', unitSize: size });
          download(pkg.name, new Blob([pkg.bytes], { type: 'application/zip' }));
          toast(t('Package downloaded. Keep it private.'));
        }), { kind: 'primary' })),
      details({ class: 'card' }, summary(t('Preview the roster')), div({ class: 'table-wrap' }, table({ class: 'table' }, thead(tr(th('#'), th(t('Name')), th(t('Signed')), th(t('Confirmation')))),
        tbody(use.map((c, i) => tr(td(i + 1), td(c.payload.legalName), td(fmtDate(c.createdAt)), td(c.confirmationSentAt ? '✓' : '—'))))))),
      FoundingPanel({ cards: U.cards, meta: U.meta, pack, update }),
      div({ class: 'card' }, h3(t('When you are done')), p(t('Close this tab. To delete the campaign, go back to the trustee dashboard and vote to destroy it.')), linkBtn(t('Trustee dashboard'), '/t/dashboard', 'secondary')));
  }
}
