// Votes: secret ballots the committee counts in the browser, that any member can recount and check.
import * as C from '../../shared/crypto.js';
import { POLICY_FIELDS, evaluateVote } from '../../shared/constants.js';
import { store } from './store.js';
import { t } from './i18n.js';
import { keyFilePicker, label3 } from './organize.js';
import { WS, wcall, can, has, wsInfo, wsFrame, currency } from './wsbase.js';
import {
  div, span, p, a, ul, li, h1, h2, h3, strong, input, textarea, details, summary, btn, callout, badge, field, textInput, selectBox, linkBtn,
  setTitle, view, go, act, toast, fmtDate, fmtDateTime, money, render, copy,
} from './ui.js';

const TYPE_NAMES = {
  general: 'A question for the members', bylaws_amendment: 'Change a rule (bylaws)', ratification: 'Ratify a contract or agreement', dues_change: 'Set the dues',
  strike_authorization: 'Strike authorization', recall: 'Remove someone from a role (recall)',
};
const PASS_NAMES = { majority: 'A majority of votes cast', two_thirds: 'Two thirds of votes cast', plurality: 'The option with the most votes' };
const dollars = (v) => Math.round(Number(v) * 100);

const effectText = (e) => {
  if (!e) return null;
  if (e.kind === 'dues') return t('If this passes, dues become {amount}.', { amount: money(e.amountCents, currency()) });
  if (e.kind === 'policy') return t('If this passes, these rules change automatically: {list}.', { list: Object.entries(e.patch).map(([k, v]) => `${POLICY_FIELDS[k]?.label || k} → ${k === 'twoApprovalCents' ? money(v, currency()) : v}`).join('; ') });
  if (e.kind === 'role_revoke') return t('If a majority votes to remove, the role ends automatically.');
  return null;
};

// One form for both "start a vote" (the committee) and "start a petition" (any member).
function voteForm({ mode, roles, onDone, prefill = {} }) {
  const F = { title: '', description: '', type: prefill.type || 'general', options: 'Yes\nNo', passRule: 'majority', days: 7, dues: 'Standard dues', amount: '', key: 'petitionPct', value: '', target: roles[0] ? `${roles[0].memberId}|${roles[0].role}` : '', ...prefill };
  return view((update) => {
    const typeOptions = Object.entries(TYPE_NAMES).map(([k, v]) => [k, t(v)]);
    const effect = () => {
      if (F.type === 'dues_change') return { kind: 'dues', name: F.dues.trim(), amountCents: dollars(F.amount) };
      if (F.type === 'bylaws_amendment') return { kind: 'policy', patch: { [F.key]: F.key === 'twoApprovalCents' ? dollars(F.value) : Number(F.value) } };
      if (F.type === 'recall') { const [memberId, role] = F.target.split('|'); return { kind: 'role_revoke', memberId, role }; }
      return undefined;
    };
    const submit = async () => {
      if (F.title.trim().length < 3) return toast(t('Please give it a title.'), 'bad');
      const spec = { title: F.title, description: F.description, type: F.type, passRule: F.passRule, options: F.options.split('\n').map((x) => x.trim()).filter(Boolean), effect: effect() };
      if (F.type === 'dues_change' && !(dollars(F.amount) >= 0)) return toast(t('Enter the dues amount.'), 'bad');
      if (F.type === 'bylaws_amendment' && !(Number(F.value) >= 0)) return toast(t('Enter the new value.'), 'bad');
      if (mode === 'petition') { await wcall('POST', '/api/ws/petitions', spec); toast(t('Petition started. You are the first signature.')); return onDone(); }
      const ring = await wcall('GET', '/api/ws/keyring?role=election_committee');
      if (ring.holders.length < 2) return toast(t('You need at least two election committee members with claimed accounts before you can hold a vote.'), 'bad');
      const k = Math.max(2, Math.floor(ring.holders.length / 2) + 1); // a majority of the committee must be together to count
      const vk = await C.newVoteKeys(ring.holders, k);
      await wcall('POST', '/api/ws/votes', { ...spec, closesAt: new Date(Date.now() + F.days * 86400_000).toISOString(), votePublicKey: vk.votePublicKey, committee: vk.committee, thresholdK: k });
      toast(t('The vote is open.'));
      onDone();
    };
    return div({ class: 'card inner stack' },
      h3(mode === 'petition' ? t('Start a petition') : t('Start a vote')),
      mode === 'petition' ? p({ class: 'small muted' }, t('If enough members sign, the election committee must open this vote exactly as you write it.')) : null,
      field(t('What are members deciding?'), textInput({ value: F.title, oninput: (e) => (F.title = e.target.value) })),
      field(t('Explain it (optional)'), textarea({ rows: 3, value: F.description, oninput: (e) => (F.description = e.target.value) })),
      field(t('Kind of decision'), selectBox(typeOptions, F.type, (v) => { F.type = v; update(); })),
      F.type === 'dues_change' ? div({ class: 'row' }, field(t('Name of the dues plan'), textInput({ value: F.dues, oninput: (e) => (F.dues = e.target.value) })), field(t('Amount per month'), textInput({ type: 'number', min: 0, step: '0.01', value: F.amount, oninput: (e) => (F.amount = e.target.value) }))) : null,
      F.type === 'bylaws_amendment' ? div({ class: 'row' }, field(t('Rule to change'), selectBox(Object.entries(POLICY_FIELDS).map(([k, f]) => [k, t(f.label)]), F.key, (v) => { F.key = v; update(); })), field(t('New value'), textInput({ type: 'number', min: 0, value: F.value, oninput: (e) => (F.value = e.target.value) }))) : null,
      F.type === 'recall' ? field(t('Who and which role?'), selectBox(roles.map((r) => [`${r.memberId}|${r.role}`, `${r.name}: ${r.role}`]), F.target, (v) => (F.target = v))) : null,
      !['dues_change', 'bylaws_amendment', 'recall'].includes(F.type) ? field(t('Choices (one per line, the first is "Yes")'), textarea({ rows: 3, value: F.options, oninput: (e) => (F.options = e.target.value) })) : null,
      field(t('It passes with'), selectBox(Object.entries(PASS_NAMES).map(([k, v]) => [k, t(v)]), F.passRule, (v) => (F.passRule = v))),
      mode === 'vote' ? field(t('Voting stays open for (days)'), textInput({ type: 'number', min: 1, max: 60, value: F.days, oninput: (e) => (F.days = Number(e.target.value) || 7) })) : null,
      div({ class: 'row' }, btn(mode === 'petition' ? t('Start the petition') : t('Open the vote'), act(submit), { kind: 'primary' }), btn(t('Cancel'), onDone, { kind: 'secondary' })));
  });
}

export async function VotesTab() {
  setTitle('Votes', true);
  const [{ votes }, { petitions }, { roles }] = await Promise.all([wcall('GET', '/api/ws/votes'), wcall('GET', '/api/ws/petitions'), wcall('GET', '/api/ws/roles')]);
  const S = { form: null, days: {} };
  const status = (v) => (v.status === 'open' ? badge(t('Open'), 'ok') : v.status === 'closed' ? badge(t('Counting'), 'warn') : badge(v.results?.passed ? t('Passed') : t('Did not pass'), v.results?.passed ? 'ok' : ''));
  return wsFrame('votes', view((update) => div(
    h1(t('Votes')),
    p({ class: 'muted' }, t('Every vote is a secret ballot. The committee counts in a browser, and afterward any member can recount.')),
    div({ class: 'row' }, can('vote.create') ? btn(t('Start a vote'), () => { S.form = 'vote'; update(); }, { kind: 'primary' }) : null, can('petition.create') ? btn(t('Start a petition'), () => { S.form = 'petition'; update(); }, { kind: 'secondary' }) : null),
    S.form ? voteForm({ mode: S.form, roles, onDone: () => { S.form = null; render(); } }) : null,
    votes.length ? votes.map((v) => div({ class: 'card' }, div({ class: 'row between' }, h3(a({ href: `/w/votes/${v.id}` }, v.title)), status(v)),
      p({ class: 'small muted' }, `${t(TYPE_NAMES[v.type] || v.type)} · ${v.status === 'open' ? t('closes {d}', { d: fmtDate(v.closesAt) }) : t('closed')} · ${t('{a} of {b} voted', { a: v.turnout.voted, b: v.turnout.eligible })}`),
      v.status === 'open' && v.eligible && !v.hasVoted ? linkBtn(t('Vote now'), `/w/votes/${v.id}`, 'primary small') : null)) : p({ class: 'muted' }, t('No votes yet.')),
    h2(t('Petitions')),
    petitions.length ? petitions.map((q) => div({ class: 'card' }, div({ class: 'row between' }, h3(q.title), badge(q.status === 'open' ? t('Collecting signatures') : q.status === 'qualified' ? t('Qualified: the committee must open it') : t('Opened'), q.status === 'qualified' ? 'warn' : q.status === 'opened' ? 'ok' : '')),
      q.description ? p(q.description) : null, effectText(q.effect) ? p({ class: 'small' }, effectText(q.effect)) : null,
      p({ class: 'small muted' }, t('{a} of {b} signatures needed.', { a: q.signers, b: q.needed }), q.openBy ? ' ' + t('The committee should open it by {d}.', { d: fmtDate(q.openBy) }) : ''),
      q.status !== 'opened' && can('petition.sign') && !q.signedByMe ? btn(t('Sign this petition'), act(async () => { await wcall('POST', `/api/ws/petitions/${q.id}/sign`); render(); }), { kind: 'primary small' }) : q.signedByMe && q.status === 'open' ? p({ class: 'small' }, '✓ ' + t('You signed.')) : null,
      q.status === 'qualified' && can('vote.create') ? div({ class: 'row' }, field(t('Open for (days)'), textInput({ type: 'number', min: 1, max: 60, value: S.days[q.id] || 7, oninput: (e) => (S.days[q.id] = Number(e.target.value) || 7) })),
        btn(t('Open this vote'), act(async () => {
          const ring = await wcall('GET', '/api/ws/keyring?role=election_committee');
          if (ring.holders.length < 2) return toast(t('You need at least two election committee members with claimed accounts before you can hold a vote.'), 'bad');
          const k = Math.max(2, Math.floor(ring.holders.length / 2) + 1), vk = await C.newVoteKeys(ring.holders, k);
          const r = await wcall('POST', '/api/ws/votes', { petitionId: q.id, closesAt: new Date(Date.now() + (S.days[q.id] || 7) * 86400_000).toISOString(), votePublicKey: vk.votePublicKey, committee: vk.committee, thresholdK: k });
          go(`/w/votes/${r.voteId}`);
        }), { kind: 'primary small' })) : null)) : p({ class: 'muted' }, t('No petitions.')))));
}

export async function VoteDetail({ id }) {
  setTitle('Vote', true);
  const v = await wcall('GET', `/api/ws/votes/${id}`);
  const inCommittee = v.committee?.some((c) => c.memberId === WS.memberId);
  const S = { choice: null, receipt: store.get(`receipt.${id}`), check: '', checkResult: null, recount: null };
  let receipts = null;
  if (v.status !== 'open') receipts = (await wcall('GET', `/api/ws/votes/${id}/receipts`)).receiptHashes;
  return wsFrame('votes', view((update) => div(
    p(a({ href: '/w/votes' }, '← ' + t('All votes'))),
    h1(v.title), p({ class: 'muted' }, `${t(TYPE_NAMES[v.type] || v.type)} · ${t(PASS_NAMES[v.passRule])} · ${t('{a} of {b} voted', { a: v.turnout.voted, b: v.turnout.eligible })}`),
    v.description ? p(v.description) : null, effectText(v.effect) ? callout('info', effectText(v.effect)) : null,
    v.status === 'open' ? openBlock(v, S, update) : null,
    v.status === 'closed' ? div({ class: 'card' }, h2(t('Voting is closed')), p(t('The election committee counts the ballots together. Results appear here when they are done.')),
      p({ class: 'small muted' }, t('Committee: {names}. {k} of them must be together to count.', { names: v.committee.map((c) => c.name).join(', '), k: v.thresholdK })),
      inCommittee ? linkBtn(t('Count the ballots'), `/w/votes/${id}/tally`, 'primary') : null) : null,
    v.status === 'tallied' ? resultsBlock(v, S, receipts, update) : null)));

  function openBlock(v, S, update) {
    return div({ class: 'card' },
      v.hasVoted ? div(callout('ok', t('You have voted.')), S.receipt ? receiptBox(S.receipt) : p({ class: 'small muted' }, t('Your receipt code was shown when you voted.'))) :
        v.eligible ? div(h2(t('Cast your secret ballot')),
          div({ class: 'stack' }, v.options.map((o, i) => div({ class: `choice ${S.choice === i ? 'on' : ''}`, role: 'radio', 'aria-checked': S.choice === i, tabindex: 0, onclick: () => { S.choice = i; update(); }, onkeydown: (e) => { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); S.choice = i; update(); } } }, strong(o)))),
          p({ class: 'small muted' }, t('Nobody, including the officers and this website, can tell how you voted. You cannot change your vote afterward.')),
          btn(t('Cast my ballot'), act(async () => {
            if (S.choice == null) return toast(t('Choose an option first.'), 'bad');
            const b = C.castBallot(v.votePublicKey, S.choice);
            await wcall('POST', `/api/ws/votes/${v.id}/ballot`, { ciphertext: b.ciphertext, receiptHash: b.receiptHash });
            store.set(`receipt.${v.id}`, b.receiptCode);
            S.receipt = b.receiptCode;
            render();
          }), { kind: 'primary block', disabled: false })) :
          callout('info', t('Only members can vote. Join the union from the Home tab to take part in the next one.')),
      can('vote.close') ? btn(t('Close voting now'), act(async () => { if (confirm(t('Close voting now? No more ballots can be cast.'))) { await wcall('POST', `/api/ws/votes/${v.id}/close`); render(); } }), { kind: 'secondary small' }) : null);
  }
  function receiptBox(code) {
    return div({ class: 'callout info' }, p(strong(t('Your receipt code'))), div({ class: 'code small' }, code),
      p({ class: 'small' }, t('After the count, use this code to check that your ballot is in the list. It proves you voted, not how.')), btn(t('Copy'), () => copy(code), { kind: 'secondary small' }));
  }
  function resultsBlock(v, S, receipts, update) {
    const r = v.results, total = r.total || 1;
    return div({ class: 'card' }, h2(t('Results')), r.passed ? badge(t('Passed'), 'ok') : badge(t('Did not pass'), ''),
      div({ class: 'bars' }, v.options.map((o, i) => div({ class: 'bar-row' }, span({ class: 'bar-l' }, o), div({ class: 'bar' }, div({ class: `bar-fill ${r.winner === i ? 'win' : ''}`, style: { width: Math.round((r.counts[i] / total) * 100) + '%' } })), span({ class: 'bar-n' }, r.counts[i])))),
      p({ class: 'small muted' }, t('{a} of {b} eligible members voted. {c} ballots counted.', { a: r.voted, b: r.eligible, c: r.total }), r.invalid ? ' ' + t('{n} ballot(s) could not be read and were not counted.', { n: r.invalid }) : ''),
      v.effect && r.passed ? callout('ok', t('This decision has been carried out automatically.')) : null,
      h3(t('Check the count yourself')),
      S.receipt ? p(receipts.includes(C.receiptHash(S.receipt)) ? '✓ ' + t('Your ballot is in the list of counted ballots.') : '✗ ' + t('Your receipt was NOT found in the list. Tell the committee.')) : null,
      div({ class: 'row' }, field(t('Check a receipt code'), textInput({ value: S.check, placeholder: 'ABCD-EFGH-JKMN-PQRS', oninput: (e) => (S.check = e.target.value) })), btn(t('Check'), () => { S.checkResult = receipts.includes(C.receiptHash(S.check)); update(); }, { kind: 'secondary small' })),
      S.checkResult != null ? p(S.checkResult ? '✓ ' + t('That receipt is in the list.') : '✗ ' + t('That receipt is not in the list.')) : null,
      v.keyPublished ? div(btn(t('Recount every ballot in my browser'), act(async () => {
        const pub = await wcall('GET', `/api/ws/votes/${v.id}/ballots`);
        const mine = C.countBallots(pub.votePublicKey, pub.secretKey, pub.ballots, v.options.length);
        S.recount = { counts: mine.counts, same: mine.counts.every((c, i) => c === r.counts[i]), n: pub.ballots.length, receipts: pub.receiptHashes.length };
        update();
      }), { kind: 'primary small' }), S.recount ? callout(S.recount.same ? 'ok' : 'danger', S.recount.same ? t('Your browser recounted {n} ballots and got exactly the published result.', { n: S.recount.n }) : t('Your recount does NOT match the published result. Raise this with the committee.')) : null)
        : p({ class: 'small muted' }, t('The committee counted privately and did not publish the key, so a recount is not possible for this vote.')));
  }
}

// The counting ceremony: k committee members each unlock their key file on one device; the ballot key
// exists only in this browser's memory, only for as long as it takes to count.
export async function TallyPage({ id }) {
  setTitle('Count the ballots', true);
  await C.ready;
  const b = await wcall('GET', `/api/ws/votes/${id}/tally-bundle`);
  const S = { shares: [], who: [], counts: null, sk: null, publish: true };
  const mine = b.committee.find((c) => c.memberId === WS.memberId);
  if (mine) { S.shares.push(C.boxOpen(mine.sealed, WS.keys.boxPublicKey, WS.keys.boxSecretKey)); S.who.push(WS.memberId); }
  return wsFrame('votes', view((update) => {
    if (S.shares.length >= b.thresholdK && !S.sk) {
      C.reconstructVoteKey(S.shares).then((sk) => { S.sk = sk; S.counts = C.countBallots(b.votePublicKey, sk, b.ballots, b.options.length); update(); }).catch(() => toast(t('Those key files could not open the ballots.'), 'bad'));
    }
    const ev = S.counts ? evaluateVote(S.counts.counts, b.passRule) : null;
    return div(h1(t('Count the ballots')), p(t('{a} of {k} committee members have contributed.', { a: S.shares.length, k: b.thresholdK })),
      !S.sk ? div({ class: 'card' }, h2(t('Next committee member')), keyFilePicker({
        prefix: 'mk.', format: 'member-keyfile-v1', cta: t('Contribute'), describe: (f) => t('{union} account (…{id})', { union: f.union || 'Union', id: f.memberId.slice(-4) }),
        exclude: (f) => S.who.includes(f.memberId) || f.workspaceId !== WS.workspaceId || !b.committee.some((c) => c.memberId === f.memberId),
        onUnlock: (file, secrets) => { const m = b.committee.find((c) => c.memberId === file.memberId); S.shares.push(C.boxOpen(m.sealed, secrets.boxPublicKey, secrets.boxSecretKey)); S.who.push(file.memberId); update(); },
      })) : div({ class: 'card' }, h2(t('Counted')),
        div({ class: 'bars' }, b.options.map((o, i) => div({ class: 'bar-row' }, span({ class: 'bar-l' }, o), span({ class: 'bar-n' }, S.counts.counts[i])))),
        S.counts.invalid ? p({ class: 'small' }, t('{n} ballot(s) could not be read.', { n: S.counts.invalid })) : null,
        p(ev.passed ? strong(t('This passes.')) : strong(t('This does not pass.'))),
        label3(t('Publish the ballot key so every member can recount (recommended)'), S.publish, (v) => { S.publish = v; update(); }),
        p({ class: 'small muted' }, t('Ballots are anonymous, so publishing the key shows how many chose what, never who. It lets any member check the count.')),
        btn(t('Publish the results'), act(async () => {
          await wcall('POST', `/api/ws/votes/${id}/results`, { counts: S.counts.counts, ...(S.publish ? { secretKey: S.sk } : {}) });
          S.sk = null; S.shares.forEach((s) => C.wipe(s)); go(`/w/votes/${id}`);
        }), { kind: 'primary block' })));
  }));
}
