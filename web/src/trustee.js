// The trustee side: dashboard, the unlock-and-export ceremony, and the committee's inbox of reports.
import * as C from '../../shared/crypto.js';
import { api, tcall, friendly } from './api.js';
import { authenticate, checkMySeat, rosterToSign, RosterError, isCommit } from '../../shared/roster.js';
import { store } from './store.js';
import { nextStepCard } from './guide.js';
import { organizeStep } from '../../shared/guide.js';
import { cardTextMatches } from '../../shared/verify.js';
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
// `founder` is the founder's key check that goes into every invitation this trustee makes. The founder's is worked out from their own keys; anyone else's came from their
// own invitation (an older key file has none, and then cannot make invitations that carry one).
const session = (file, s) => ({ campaignId: file.campaignId, index: file.trusteeIndex, keys: s, campaignKey: s.campaignKey,
  founder: file.trusteeIndex === 1 ? C.founderCommit(s.boxPublicKey, s.signPublicKey) : (isCommit(s.founder) ? s.founder : null) });
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
    if (!T.founder) throw new RosterError('no_commit'); // an invitation must carry the founder's key check, or the person who signs cannot verify the committee
    const token = C.newToken();
    await tcall(T, 'POST /api/invites', { body: { campaignId: T.campaignId, tokenHash: C.hashToken(token), kind } });
    return linkTo('/j', { i: token, k: T.campaignKey, c: T.campaignId, f: T.founder });
  };
  return shell(div({ class: 'wrap' }, view((update) => div(
    div({ class: 'row between' }, h1(meta.unionName), badge(raw.status === 'active' ? t('Active') : raw.status === 'frozen' ? t('Paused') : t('Setting up'), raw.status === 'active' ? 'ok' : 'warn')),
    p({ class: 'muted' }, t('{employer}. You are trustee {i}{name}. Any {k} of {n} trustees together can open the cards.', { employer: meta.employerName, i: T.index, name: myName ? ` (${myName})` : '', k: raw.k, n: raw.n })),
    active ? nextStepCard(organizeStep({ status: raw.status, isFounder: T.index === 1, n: raw.n, joined: raw.trustees.filter((x) => x.enrolled).length, confirmed: !!raw.roster,
      solo: prog.solo || 0, pending: pending.length, vouched: prog.vouched, releaseMin: prog.releaseMin, k: raw.k }), `t.${T.campaignId}`) : null,
    raw.inactivityWarn ? callout('warn', t('This campaign has been quiet for a while. If nothing happens in {d} days it will be deleted automatically.', { d: raw.inactivityDaysLeft })) : null,
    !active ? div({ class: 'card' }, h2(t('Waiting for trustees')), ul(raw.trustees.map((x) => li((meta.trusteeNames.find((n) => n.index === x.index)?.displayName || t('Trustee {n}', { n: x.index })) + ': ' + (x.enrolled ? '✓ ' + t('ready') : t('has not set up a key yet')))))) : null,
    active ? div({ class: 'card' }, h2(t('Where we are')), progressView({ count: prog.vouched, size: meta.estimatedUnitSize, markers: withRelease(markersFor(pack, meta), prog.releaseMin, meta.estimatedUnitSize) }), momentum(prog.history, meta.estimatedUnitSize), p({ class: 'small muted' }, waiting(prog.pending))) : null,
    active ? committeeCard(raw, meta, prog, S, update) : null,
    raw.status === 'active' ? div({ class: 'card', id: 'g-invite' }, h2(t('Invite coworkers')),
      div({ class: 'row' },
        btn(t('Invite one person'), act(async () => { S.links.unshift({ kind: 'direct', link: await makeInvite('direct') }); update(); }), { kind: 'primary' }),
        btn(t('Create a group link'), act(async () => { S.links.unshift({ kind: 'group', link: await makeInvite('group') }); update(); }), { kind: 'secondary' })),
      S.links.map((l) => inviteBox({ link: l.link, employer: meta.employerName, kind: l.kind }))) : null,
    pending.length ? div({ class: 'card', id: 'g-pending' }, h2(t('Cards waiting to be confirmed')), p({ class: 'small muted' }, t('Enter the two-word code only if you have confirmed the person in person.')), pending.map((q, n) => trusteeVouch(q, n + 1))) : null,
    active ? reportsCard(prog.reports, meta, pack, S, update) : null,
    active ? div({ class: 'card', id: 'g-open' }, h2(t('Open the cards')),
      prog.vouched < prog.releaseMin
        ? callout('warn', strong(t('The cards are locked.')), ' ', t('{have} of the {need} people needed have signed and been counted. Until then nobody can open them, not even all the trustees together.', { have: prog.vouched, need: prog.releaseMin }))
        : p(t('The number is met. When you decide together to go public, {k} trustees meet, ideally in person, and open the cards on one device.', { k: raw.k })),
      prog.vouched < prog.releaseMin ? btn(t('Unlock and export'), () => {}, { kind: 'primary', disabled: true }) : linkBtn(t('Unlock and export'), '/t/unlock', 'primary')) : null,
    active ? releaseCard(prog, raw) : null,
    active ? div({ class: 'card', id: 'g-safety' }, h2(t('Safety controls')),
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

// The committee: who has joined, invitations, changing the plan, confirming the committee, and locking early cards to it.
function committeeCard(raw, meta, prog, S, update) {
  const joined = raw.trustees.filter((x) => x.enrolled).length, complete = joined === raw.n, founder = T.index === 1;
  const confirmed = !!raw.roster;
  const nm = (i) => meta.trusteeNames.find((x) => x.index === i)?.displayName || t('Trustee {n}', { n: i });
  const P = (S.plan ||= { n: raw.n, k: raw.k });
  // The trustees' public keys come from the server. Before confirming the committee, the founder checks each trustee's key words aloud (the trustee
  // reads them off their own screen), so a swapped key, or a seat taken by the wrong person, can never be signed for. A key that changes after the
  // tick no longer counts as checked.
  const words = (x) => C.keyWords(x.boxPublicKey);
  const checked = (x) => S.checked?.[x.index] === words(x);
  const allChecked = raw.trustees.every((x) => !x.enrolled || x.index === T.index || checked(x));
  const keyCheck = (x) => div({ class: 'keycheck' },
    p({ class: 'small muted' }, t('Ask {name} to read you the key words on their own screen.', { name: nm(x.index) })),
    div({ class: 'keywords', lang: 'en' }, words(x)),
    label3(t('These match what {name} read to me', { name: nm(x.index) }), checked(x), (v) => { (S.checked ||= {})[x.index] = v ? words(x) : null; update(); }));

  // Early cards are locked to the seats the founder SIGNED, never to whatever the server lists now.
  const relock = async (seats, k) => {
    const { cards } = await tcall(T, 'GET /api/campaigns/:id/reshare-bundle');
    const out = [];
    for (const c of cards) out.push({ cardId: c.id, sealedShares: await C.reshareCard(c.sealedShares.find((s) => s.trusteeIndex === T.index).sealed, T.keys, seats, k) });
    for (let i = 0; i < out.length; i += 200) await tcall(T, 'POST /api/campaigns/:id/reshare', { body: { cards: out.slice(i, i + 200) } });
  };
  // The founder signs the roster of the whole committee. From then on every signer's browser can check that it is sealing to the real committee, and new
  // cards are split k-of-n. Signing comes first, so the set of early cards stops growing before they are locked.
  // This device remembers the plan it made. Without it (another device), or when the website's numbers differ, the founder types the numbers they
  // chose from memory. The page never shows the website's numbers next to that box, so it cannot be answered by copying them; confirming is refused
  // unless they match (rosterToSign).
  const mine = store.get(`plan.${T.campaignId}`);
  const planOk = !!mine && mine.k === raw.k && mine.n === raw.n;
  const typed = (S.typedPlan ||= { k: '', n: '' });
  const planBox = () => planOk ? null : callout(mine ? 'danger' : 'warn',
    strong(mine ? t('The plan does not match.') : t('Type the plan you chose.')), ' ',
    mine ? t('This device remembers any {k} of {n} trustees, but the website shows a different plan. If you did not change the plan yourself, do not confirm: tell the other trustees.', { k: mine.k, n: mine.n })
      : t('This device does not remember the plan you made. From memory, not from this page: how many trustees did you choose, and how many must be together to open the cards?'),
    p({ class: 'small' }, mine ? t('If you changed it on another device, type the numbers you chose. Confirming is refused if they are not the website\'s numbers.') : t('Confirming is refused if they are not the website\'s numbers.')),
    div({ class: 'row' },
      field(t('Needed together'), textInput({ type: 'number', min: 2, value: typed.k, oninput: (e) => (typed.k = e.target.value) })),
      field(t('Trustees'), textInput({ type: 'number', min: 2, value: typed.n, oninput: (e) => (typed.n = e.target.value) }))));
  const confirm = async () => {
    if (!allChecked) return toast(t('First check each trustee\'s key words with them.'), 'bad');
    const plan = planOk ? mine : { k: Number(typed.k), n: Number(typed.n) };
    const roster = rosterToSign(raw, T.campaignId, T.keys, plan); // every seat filled, the founder's own seat is the founder's own keys, and k and n are the ones the founder chose
    await tcall(T, 'POST /api/campaigns/:id/roster', { body: { roster, signature: C.signRoster(T.keys.signSecretKey, roster) } });
    store.set(`plan.${T.campaignId}`, plan);
    if (prog.solo) await relock(roster.seats, roster.k);
    toast(prog.solo ? t('Done. The committee is confirmed and the early cards are locked to it: any {k} of {n} trustees are now needed to open them.', { k: raw.k, n: raw.n }) : t('Done. The committee is confirmed.'));
    render();
  };
  const lockRest = async () => { // the roster is already signed: lock whatever is still sealed to the founder alone
    const a = authenticate(raw, T.founder, T.campaignId);
    if (a.mode !== 'shamir') throw new RosterError('roster_invalid');
    await relock(a.seats, a.k);
    toast(t('Done. Any {k} of {n} trustees are now needed to open the cards.', { k: a.k, n: raw.n }));
    render();
  };

  // Does the roster on the server check out? The founder checks it against their own key; every other trustee checks the founder's signature and that THEIR key is in it.
  let status = confirmed ? 'ok' : 'unsigned';
  if (confirmed) {
    try { if (founder) authenticate(raw, T.founder, T.campaignId); else status = checkMySeat(raw, T.founder, T.campaignId, T.index, T.keys.boxPublicKey); }
    catch (e) { if (!(e instanceof RosterError)) throw e; status = { error: e.code }; }
  }
  const banner = () => {
    if (!complete) return callout('warn', strong(t('Only trustee 1 can open the cards right now.')), ' ', t('Invite the other trustees below. When all {n} have joined, trustee 1 confirms the committee so that {k} of them are needed.', { n: raw.n, k: raw.k }));
    if (!confirmed) {
      return founder
        ? callout('warn', strong(t('Everyone has joined. Now confirm the committee.')), ' ', t('Check each trustee\'s key words with them below, then confirm. That is what lets everyone who signs a card check that they are sealing to the real committee.'), prog.solo ? ' ' + t('{n} early card(s) are still sealed to you alone; confirming also locks them to the committee.', { n: prog.solo }) : '')
        : callout('info', strong(t('Everyone has joined.')), ' ', t('Trustee 1 is checking each trustee\'s key words and will confirm the committee. Until then, cards are sealed to trustee 1 alone.'));
    }
    if (status.error) return callout('danger', strong(t('The committee on the server does not check out.')), ' ', t(friendly({ code: status.error })));
    if (prog.solo) return callout('warn', strong(t('The committee is confirmed.')), ' ', t('{n} early card(s) are still sealed to the founder alone.', { n: prog.solo }));
    return callout('ok', t('The committee is confirmed: any {k} of {n} trustees together can open the cards.', { k: raw.k, n: raw.n }),
      founder ? '' : ' ' + (status === 'ok' ? t('Your key is in the roster the founder signed.') : t('(This device holds no key check from its invitation, so it could not verify the roster.)')));
  };
  return div({ class: 'card', id: 'g-committee' }, h2(t('Your committee')),
    banner(),
    !founder && !confirmed && T.keys?.boxPublicKey ? div({ class: 'keycheck' }, strong(t('Your key words')), // only while trustee 1 still has to check them
      p({ class: 'small muted' }, t('Read these to trustee 1 by phone or in person. They check them before the committee is confirmed, so nobody can slip in a different key.')),
      div({ class: 'keywords', lang: 'en' }, C.keyWords(T.keys.boxPublicKey))) : null,
    ul(raw.trustees.map((x) => li(strong(nm(x.index)), x.index === T.index ? ' ' + t('(you)') : '', ' ',
      x.enrolled ? [badge(t('joined'), 'ok'), founder && !confirmed && x.index !== T.index ? keyCheck(x) : null]
        : [badge(t('not joined yet'), 'warn'), ' ', founder ? btn(t('Get invite link'), act(async () => { // only the founder hands out seats
          if (!T.founder) throw new RosterError('no_commit');
          const token = C.newToken();
          await tcall(T, 'POST /api/campaigns/:id/trustees/reset', { body: { index: x.index, tokenHash: C.hashToken(token) } }); // any older link for this seat stops working
          S.slotLinks[x.index] = linkTo('/t', { e: token, k: T.campaignKey, c: T.campaignId, f: T.founder }); // the link carries the founder's key check
          update();
        }), { kind: 'secondary small' }) : span({ class: 'small muted' }, t('Trustee 1 sends this invitation.'))],
      S.slotLinks[x.index] ? trusteeInvite(S.slotLinks[x.index], nm(x.index), meta) : null))),
    complete && !confirmed && founder ? div(
      allChecked ? null : p({ class: 'small muted' }, t('First check each trustee\'s key words with them, above.')),
      planOk ? p(strong(t('You are signing this: any {k} of the {n} trustees together can open the cards.', { k: raw.k, n: raw.n })), ' ', t('If that is not what you chose, do not confirm.')) : planBox(),
      btn(prog.solo ? t('Confirm the committee and lock {n} early card(s)', { n: prog.solo }) : t('Confirm the committee'), act(confirm), { kind: 'primary', disabled: !allChecked })) : null,
    confirmed && status === 'ok' && prog.solo && founder ? btn(t('Lock {n} early card(s) to the committee', { n: prog.solo }), act(lockRest), { kind: 'primary' }) : null,
    confirmed && prog.solo && !founder ? p({ class: 'small muted' }, t('Only trustee 1 holds the keys to these cards, so trustee 1 does this step.')) : null,
    !complete && founder ? details(summary(t('Change the plan')),
      p({ class: 'small muted' }, t('You can change how many trustees you plan to have, and how many must be together to open the cards, until everyone has joined.')),
      div({ class: 'row' },
        field(t('Trustees'), selectBox(Array.from({ length: 6 }, (_, i) => i + 2).filter((n) => n >= joined).map((n) => [String(n), String(n)]), String(P.n), (v) => { P.n = Number(v); P.k = Math.min(P.k, P.n); update(); })),
        field(t('Needed together'), selectBox(Array.from({ length: P.n - 1 }, (_, i) => i + 2).map((n) => [String(n), String(n)]), String(P.k), (v) => { P.k = Number(v); update(); }))),
      btn(t('Save the plan'), act(async () => { await tcall(T, 'POST /api/campaigns/:id/committee', { body: { n: P.n, k: P.k } }); store.set(`plan.${T.campaignId}`, { k: P.k, n: P.n }); render(); }), { kind: 'secondary small' })) : null);
}

// The lock: the number of confirmed cards below which the server will not hand the sealed cards to anyone.
function releaseCard(prog, raw) {
  const V = { value: String(prog.releaseMin) };
  return div({ class: 'card' }, h3(t('The lock')),
    p({ class: 'small muted' }, t('The cards stay sealed until this many people have signed and been counted. Any trustee can raise the number. Lowering it takes {k} trustees agreeing on the same number.', { k: raw.k })),
    div({ class: 'row' }, textInput({ type: 'number', min: 1, value: V.value, 'aria-label': t('Number of people'), oninput: (e) => (V.value = e.target.value) }),
      btn(t('Set the number'), act(async () => {
        const r = await tcall(T, 'POST /api/campaigns/:id/release-min', { body: { value: Number(V.value) } });
        toast(r.applied ? t('The number is now {n}.', { n: r.releaseMin }) : t('Your vote to lower it to {n} is recorded ({a} of {k}).', { n: V.value, a: r.approvals, k: r.needed }));
        render();
      }), { kind: 'secondary small' })),
    Object.entries(prog.releaseVotes || {}).map(([v, c]) => p({ class: 'small' }, t('{c} trustee(s) have voted to lower it to {v}.', { c, v }))),
    prog.provenance ? provenanceView(prog.provenance) : null);
}
// Where the count comes from. A card from a direct invitation counts at once, so one person who invites many people (or makes many cards
// themselves) can move the count a long way. This shows whether that is happening; it names nobody who signed.
function provenanceView(pv) {
  const most = pv.byMembers && pv.mostFromOneMember > 1;
  return details(summary(t('Where the count comes from')),
    p({ class: 'small muted' }, t('A card from a direct invitation counts as soon as it is signed. If one person accounts for many of the cards, check with them before relying on the number.')),
    ul(Object.entries(pv.byTrustee).map(([i, c]) => li(t('{c} from invitations made by trustee {i}', { c, i }))),
      pv.byMembers ? li(t('{c} from invitations made by {m} member(s)', { c: pv.byMembers, m: pv.membersInviting }), most ? ' ' + t('(at most {n} from any one member)', { n: pv.mostFromOneMember }) : '') : null,
      pv.confirmedInPerson ? li(t('{c} from group links, confirmed in person', { c: pv.confirmedInPerson })) : null,
      pv.other ? li(t('{c} invited by a member who has since withdrawn', { c: pv.other })) : null));
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
        U.blocked ? callout('danger', strong(t('The cards are still locked.')), ' ', t('{have} of the {need} people needed have signed and been counted. Nothing can be opened until then, not even by all the trustees together.', U.blocked), p(linkBtn(t('Back to the dashboard'), '/t/dashboard', 'secondary'))) : null,
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
    const textMismatch = U.cards.filter((c) => !cardTextMatches(c.payload)).length; // made by altered code, or a bug: check these by hand
    const size = U.meta.estimatedUnitSize, pctOf = Math.round((use.length / size) * 100);
    return div(
      h1(t('The cards are open')),
      callout('warn', t('The names are now readable on this screen. Do not leave this page open on a shared device.')),
      div({ class: 'card' }, h2(t('Summary')),
        ul(li(strong(U.cards.length), ' ', t('cards opened')), li(strong(use.length), ' ', t('will be in the package ({p}% of about {size})', { p: pctOf, size })),
          li(strong(disavowed), ' ', t('disavowed by the signer (excluded unless you include them)')), li(strong(noConfirm), ' ', t('without a confirmation email sent')), li(strong(dupes), ' ', t('possible duplicate emails or phone numbers to check by hand')), textMismatch ? li(strong(textMismatch), ' ', t('whose card text does not match its fingerprint (marked in the package; check them by hand)')) : null),
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
