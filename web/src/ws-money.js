// Money: every member can see the books, and every member's browser checks that the record is an
// unbroken chain. This device also remembers the newest entry it has seen, so rewriting history later
// shows up as a loud warning the next time anyone opens this page.
import * as C from '../../shared/crypto.js';
import { verifyChain, ledgerFields, checkPinned } from '../../shared/verify.js';
import { store } from './store.js';
import { t } from './i18n.js';
import { WS, wcall, can, has, wsFrame, currency } from './wsbase.js';
import {
  div, span, p, a, ul, li, h1, h2, h3, strong, details, summary, table, thead, tbody, tr, td, th, btn, callout, badge, field, textInput, selectBox, linkBtn,
  setTitle, view, act, toast, money, fmtDate, render,
} from './ui.js';

const dollars = (v) => Math.round(Number(v) * 100);

export async function MoneyTab() {
  setTitle('Money', true);
  const [s, chain] = await Promise.all([wcall('GET', '/api/ws/finance/summary'), wcall('GET', '/api/ws/finance/chain')]);
  const v = verifyChain(chain.entries, ledgerFields);
  const pinKey = `pin.${WS.workspaceId}`, pin = store.get(pinKey);
  const pinned = v.ok ? checkPinned(chain.entries, pin) : { ok: false };
  if (v.ok && pinned.ok && v.head && (!pin || v.head.seq > pin.seq)) store.set(pinKey, v.head);
  const $ = (c) => money(c, currency());
  const F = { rc: { category: 'dues', amount: '', payer: '', memo: '' }, pay: { category: 'office', amount: '', payee: '', memo: '' } };
  const catName = (k) => s.categories.receipts[k] || s.categories.disbursements[k] || k;
  return wsFrame('money', view((update) => div(
    h1(t('Money')),
    !v.ok ? callout('danger', strong(t('The books do not add up.')), ' ', t('Your browser found that the ledger was changed near entry {n}. Do not trust these numbers. Tell your officers and members right away.', { n: v.brokenAt }))
      : !pinned.ok ? callout('danger', strong(t('The history changed.')), ' ', t('On an earlier visit this device saw entries that are now different or missing. Someone may have rewritten the books. Tell your members right away.'))
        : callout('ok', t('Checked in your browser: all {n} ledger entries form an unbroken chain, and nothing this device saw before has changed.', { n: v.count }), v.head ? span({ class: 'small' }, ' ', t('Fingerprint:'), ' ', strong(C.fingerprint(v.head.hash)), ' ', t('(compare with a coworker\'s. If they differ, something is wrong.)')) : null),
    div({ class: 'card' }, div({ class: 'tile big' }, div({ class: 'tile-n' }, $(s.balanceCents)), div({ class: 'tile-l' }, t('in the union\'s account'))),
      p({ class: 'small muted' }, t('Spending of {x} or more needs two different officers to approve. Nobody approves their own request.', { x: $(s.twoApprovalCents) }))),
    div({ class: 'grid2' },
      div({ class: 'card' }, h3(t('Money in')), Object.keys(s.byCategory.receipts).length ? table({ class: 'table' }, tbody(Object.entries(s.byCategory.receipts).map(([k, c]) => tr(td(catName(k)), td({ class: 'num' }, $(c)))))) : p({ class: 'muted' }, t('Nothing yet.'))),
      div({ class: 'card' }, h3(t('Money out')), Object.keys(s.byCategory.disbursements).length ? table({ class: 'table' }, tbody(Object.entries(s.byCategory.disbursements).map(([k, c]) => tr(td(catName(k)), td({ class: 'num' }, $(c)))))) : p({ class: 'muted' }, t('Nothing yet.')))),
    div({ class: 'card' }, h3(t('Dues')), s.dues.length ? p(t('Current dues: {name}, {amount} per month.', { name: s.dues[0].name, amount: $(s.dues[0].amountCents) }), ' ', a({ href: `/w/votes/${s.dues[0].voteId}` }, t('See the vote that set it'))) : p({ class: 'muted' }, t('Dues have not been set. Dues can only be set by a vote of the members.')), linkBtn(t('Propose dues from the Votes tab'), '/w/votes', 'secondary small')),
    s.pending.length ? div({ class: 'card' }, h3(t('Waiting for approval or payment')), s.pending.map((d) => div({ class: 'entry' },
      div({ class: 'row between' }, strong(`${$(d.amountCents)} · ${catName(d.category)}`), badge(d.status === 'approved' ? t('Approved: ready to pay') : t('{a} of {n} approvals', { a: d.approvals, n: d.requiredApprovals }), d.status === 'approved' ? 'ok' : 'warn')),
      p({ class: 'small' }, `${d.payee}${d.memo ? ' · ' + d.memo : ''}`), p({ class: 'small muted' }, t('Requested by {name}', { name: d.requestedBy })),
      div({ class: 'row' },
        d.status === 'pending' && can('disbursement.approve') && !d.mine && !d.approvedByMe ? [btn(t('Approve'), act(async () => { await wcall('POST', `/api/ws/disbursements/${d.id}/approve`, {}); render(); }), { kind: 'primary small' }), btn(t('Reject'), act(async () => { await wcall('POST', `/api/ws/disbursements/${d.id}/approve`, { decision: 'reject' }); render(); }), { kind: 'secondary small' })] : null,
        d.status === 'approved' && can('disbursement.pay') ? btn(t('Mark as paid'), act(async () => { await wcall('POST', `/api/ws/disbursements/${d.id}/pay`); render(); }), { kind: 'primary small' }) : null)))) : null,
    can('ledger.record') ? details({ class: 'card' }, summary(t('Record money received')),
      field(t('What kind?'), selectBox(Object.entries(s.categories.receipts), F.rc.category, (x) => (F.rc.category = x))), field(t('Amount'), textInput({ type: 'number', step: '0.01', min: 0, oninput: (e) => (F.rc.amount = e.target.value) })),
      field(t('From (visible to members)'), textInput({ oninput: (e) => (F.rc.payer = e.target.value) })), field(t('Note (visible to members)'), textInput({ oninput: (e) => (F.rc.memo = e.target.value) })),
      btn(t('Record'), act(async () => { await wcall('POST', '/api/ws/ledger/receipt', { category: F.rc.category, amountCents: dollars(F.rc.amount), payer: F.rc.payer, memo: F.rc.memo }); render(); }), { kind: 'primary small' })) : null,
    can('disbursement.request') ? details({ class: 'card' }, summary(t('Ask to spend money')),
      callout('info', t('Members can see what you write here, except the name of anyone receiving hardship aid.')),
      field(t('What for?'), selectBox(Object.entries(s.categories.disbursements), F.pay.category, (x) => (F.pay.category = x))), field(t('Amount'), textInput({ type: 'number', step: '0.01', min: 0, oninput: (e) => (F.pay.amount = e.target.value) })),
      field(t('Paid to'), textInput({ oninput: (e) => (F.pay.payee = e.target.value) })), field(t('Note'), textInput({ oninput: (e) => (F.pay.memo = e.target.value) })),
      btn(t('Send for approval'), act(async () => { const r = await wcall('POST', '/api/ws/disbursements', { category: F.pay.category, amountCents: dollars(F.pay.amount), payee: F.pay.payee, memo: F.pay.memo }); toast(t('Sent. It needs {n} approval(s) from other officers.', { n: r.requiredApprovals })); render(); }), { kind: 'primary small' })) : null,
    div({ class: 'card' }, h3(t('Every entry')), p({ class: 'small muted' }, t('Entries can never be edited or deleted. A mistake is fixed with a new reversing entry.')),
      div({ class: 'table-wrap' }, table({ class: 'table small' }, thead(tr(th('#'), th(t('Date')), th(t('What')), th(t('Who / note')), th({ class: 'num' }, t('Amount')), th(''))),
        tbody(s.entries.map((e) => tr({ class: e.reversed ? 'struck' : '' }, td(e.seq), td(fmtDate(e.date)), td(catName(e.category), e.reversesSeq ? span({ class: 'small muted' }, ` (${t('reverses #{n}', { n: e.reversesSeq })})`) : null), td(span({ class: 'small' }, [e.payee, e.memo].filter(Boolean).join(' · '))),
          td({ class: 'num' }, (e.kind === 'receipt' ? '+' : '−') + $(e.amountCents)), td(can('ledger.reverse') && !e.reversed && !e.reversesSeq ? btn(t('Reverse'), act(async () => { const reason = prompt(t('Why is this being reversed?')); if (reason) { await wcall('POST', `/api/ws/ledger/${e.id}/reverse`, { reason }); render(); } }), { kind: 'secondary small' }) : e.reversed ? badge(t('Reversed')) : null))))))))));
}
