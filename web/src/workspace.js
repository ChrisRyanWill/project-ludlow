// The workspace: what a union uses once it has gone public. Sign-in is a key file and passphrase,
// never an email link or a password the server could reset.
import * as C from '../../shared/crypto.js';
import { api } from './api.js';
import { store } from './store.js';
import { t } from './i18n.js';
import { packOf } from './packs.js';
import { verifyChain, auditFields, checkPinned, auditRows } from '../../shared/verify.js';
import { plainMd } from './format.js';
import { ASSIGNABLE_ROLES } from '../../shared/permissions.js';
import { POLICY_FIELDS } from '../../shared/constants.js';
import { keyFilePicker, linkTo, label3, loadMeta } from './organize.js';
import { claimsView } from './founding.js';
import { WS, setWS, signIn, wcall, refreshMe, can, has, wsInfo, currency, wsFrame, urgencyBadge } from './wsbase.js';
import {
  div, span, p, a, ul, li, h1, h2, h3, strong, input, textarea, details, summary, table, thead, tbody, tr, td, th, mark,
  btn, callout, badge, field, textInput, selectBox, linkBtn, shell, setTitle, view, fragment, go, act, toast, copy, download, md, money, fmtDate, fmtDateTime, ago, render, scrubFragment,
} from './ui.js';

const wait = (ms = 40) => new Promise((r) => setTimeout(r, ms));
const ROLE_NAMES = { officer: 'Officer', treasurer: 'Treasurer', chief_steward: 'Chief steward', steward: 'Steward', election_committee: 'Election committee' };

// ---------- claim an account ----------
export async function ClaimPage() {
  setTitle('Join your union workspace', true);
  await C.ready;
  const f = fragment(), c = f.get('c'), w = f.get('w');
  const bad = (m) => shell(div({ class: 'wrap' }, callout('danger', m)));
  if (!c || !w) return bad(t('This link is incomplete. Ask for it to be sent again, and copy the whole link.'));
  let info;
  try { info = await api('POST', '/api/ws/claim-info', { body: { workspaceId: w, claimToken: c } }); } catch { return bad(t('This link was already used or is not valid. If you already claimed your account, sign in with your key file.')); }
  scrubFragment(); // the claim token is in memory now; don't leave it in the address bar and the browser's history
  const S = { pass: C.generatePassphrase(), own: false, made: null, saved: false };
  return shell(div({ class: 'wrap' }, view((update) => div(
    h1(t('Welcome to {union}', { union: info.unionName })),
    p({ class: 'lead' }, t('Your union has set up a workspace. Claim your account to vote, get help, and see how the union is run.')),
    callout('info', t('You sign in with a key file and a passphrase that only you have. There is no password reset, so save both.')),
    div({ class: 'card' }, h2(t('1. Choose a passphrase')),
      S.own ? div(field(t('Your passphrase (at least 14 characters)'), input({ type: 'password', autocomplete: 'new-password', oninput: (e) => (S.pass = e.target.value) })), btn(t('Use a generated one instead'), () => { S.own = false; S.pass = C.generatePassphrase(); update(); }, { kind: 'secondary small' }))
        : div(div({ class: 'passphrase', tabindex: 0 }, S.pass), div({ class: 'row' }, btn(t('Copy'), () => copy(S.pass), { kind: 'secondary small' }), btn(t('Another one'), () => { S.pass = C.generatePassphrase(); update(); }, { kind: 'secondary small' }), btn(t('I will choose my own'), () => { S.own = true; S.pass = ''; update(); }, { kind: 'secondary small' })))),
    div({ class: 'card' }, h2(t('2. Save your key file')),
      btn(S.made ? t('Download the key file again') : t('Create my key file'), act(async () => {
        if (!C.passphraseOk(S.pass)) return toast(t('Your passphrase must be at least 14 characters and not a simple pattern (the same letters or words again, or a run like 12345). The generated one is best.'), 'bad');
        if (!S.made) {
          await wait(60);
          const keys = C.newKeypairs();
          const file = C.makeKeyFile({ format: 'member-keyfile-v1', header: { workspaceId: w, memberId: info.memberId, union: info.unionName }, secrets: keys, passphrase: S.pass });
          S.made = { file, keys };
          store.set(`mk.${w}.${info.memberId}`, file);
        }
        download('project-ludlow-account-key.json', JSON.stringify(S.made.file, null, 2), 'application/json');
        update();
      }), { kind: 'primary' }),
      S.made ? label3(t('I saved my key file and my passphrase somewhere safe.'), S.saved, (v) => { S.saved = v; update(); }) : null),
    S.made ? btn(t('Claim my account'), act(async () => {
      if (!S.saved) return toast(t('Please confirm you saved your key file and passphrase.'), 'bad');
      await api('POST', '/api/ws/claim', { body: { workspaceId: w, claimToken: c, boxPublicKey: S.made.keys.boxPublicKey, signPublicKey: S.made.keys.signPublicKey } });
      const token = await signIn(S.made.keys, info.memberId);
      setWS({ token, keys: S.made.keys, memberId: info.memberId, workspaceId: w });
      await refreshMe();
      history.replaceState(null, '', '/w');
      go('/w');
    }), { kind: 'primary block', disabled: !S.saved }) : null))));
}

// ---------- sign in / home ----------
export async function WsEntry() {
  setTitle('Workspace', true);
  await C.ready;
  if (!WS) {
    return shell(div({ class: 'wrap' }, h1(t('Open your union workspace')), p(t('Unlock your account key file to continue.')),
      keyFilePicker({
        prefix: 'mk.', format: 'member-keyfile-v1', describe: (f) => t('{union} account (…{id})', { union: f.union || 'Union', id: f.memberId.slice(-4) }),
        onUnlock: async (file, secrets) => { setWS({ token: await signIn(secrets, file.memberId), keys: secrets, memberId: file.memberId, workspaceId: file.workspaceId }); await refreshMe(); render(); },
      }),
      callout('info', t('New here? Open the account link you were sent to claim your account. Starting a brand new union? Begin with a campaign.'), ' ', a({ href: '/start' }, t('Start a campaign')))));
  }
  await refreshMe();
  return homeTab();
}

async function homeTab() {
  const info = WS.info, w = info.workspace;
  const [ann, votes, pets] = await Promise.all([wcall('GET', '/api/ws/announcements'), wcall('GET', '/api/ws/votes'), wcall('GET', '/api/ws/petitions')]);
  const cases = w.stage === 'recognized' ? (await wcall('GET', '/api/ws/grievances')).grievances : [];
  const health = can('health.read') ? await wcall('GET', '/api/ws/health') : null;
  const comp = can('compliance.read') ? (await wcall('GET', '/api/ws/compliance')).tasks : [];
  const open = votes.votes.filter((v) => v.status === 'open'), forMe = open.filter((v) => v.eligible && !v.hasVoted);
  const soon = comp.filter((x) => !x.doneAt && x.urgency && x.urgency.left <= 30).sort((a, b) => a.urgency.left - b.urgency.left);
  const mine = cases.filter((g) => g.status === 'open' && g.urgency);
  const S = { title: '', body: '', stage: w.stage, note: '' };
  return wsFrame('home', view((update) => div(
    h1(t('Hello, {name}', { name: info.member.name.split(' ')[0] })),
    p({ class: 'muted' }, info.roles.filter((r) => ROLE_NAMES[r]).map((r) => t(ROLE_NAMES[r])).join(', ') || t('Unit employee')),
    !info.roles.includes('member') ? callout('info', t('You are a unit employee. You can get help and see the contract no matter what. To vote and see the union\'s money, join the union.'), ' ', btn(t('Join the union'), act(async () => { await wcall('POST', '/api/ws/me/join'); render(); }), { kind: 'primary small' })) : null,
    div({ class: 'grid2' },
      div({ class: 'card' }, h2(t('What is happening')),
        forMe.length ? forMe.map((v) => div({ class: 'row between' }, span(strong(v.title), ' ', span({ class: 'small muted' }, t('closes {d}', { d: fmtDate(v.closesAt) }))), linkBtn(t('Vote now'), `/w/votes/${v.id}`, 'primary small'))) : p({ class: 'muted' }, open.length ? t('You have voted on everything that is open.') : t('No votes are open right now.')),
        pets.petitions.filter((q) => q.status === 'qualified').map((q) => p(badge(t('Qualified petition'), 'warn'), ' ', a({ href: '/w/votes' }, q.title))),
        soon.map((x) => p(urgencyBadge(x.urgency), ' ', x.title))),
      div({ class: 'card' }, h2(t('Get help')), p(t('Anyone in the unit can raise a workplace problem. It is encrypted so only the people helping you can read it.')),
        div({ class: 'row' }, linkBtn(t('Tell us what happened'), '/w/help', 'primary'), linkBtn(t('Know your rights'), '/rights', 'secondary')),
        mine.map((g) => p(a({ href: `/w/help/${g.id}` }, g.stepName || t('Case')), ' ', urgencyBadge(g.urgency))))),
    health ? div({ class: 'card' }, h2(t('How healthy is the union?')), p({ class: 'small muted' }, t('Numbers only, never names. Groups smaller than 5 are hidden.')),
      div({ class: 'tiles' }, tile(Math.round(health.membershipRate * 100) + '%', t('of the unit are members')), tile(health.openGrievances, t('open cases')), tile(health.overdueSteps, t('overdue steps'), health.overdueSteps ? 'bad' : ''), tile(health.avgTurnout == null ? '—' : Math.round(health.avgTurnout * 100) + '%', t('average vote turnout')), tile(health.votesHeld, t('votes held'))),
      health.shifts.length > 1 ? p({ class: 'small' }, health.shifts.map((s) => s.suppressed ? `${s.shift}: ${t('too few to show')}` : `${s.shift}: ${s.members}/${s.total}`).join('  ·  ')) : null) : null,
    div({ class: 'card' }, h2(t('Announcements')),
      ann.items.length ? ann.items.map((x) => div({ class: 'entry' }, strong(x.title), p({ class: 'pre' }, x.body), p({ class: 'small muted' }, `${x.author}, ${fmtDate(x.at)}`))) : p({ class: 'muted' }, t('Nothing posted yet.')),
      can('announce.write') ? details(summary(t('Post an announcement')), field(t('Title'), textInput({ oninput: (e) => (S.title = e.target.value) })), field(t('Message'), textarea({ rows: 4, oninput: (e) => (S.body = e.target.value) })),
        btn(t('Post'), act(async () => { await wcall('POST', '/api/ws/announcements', { title: S.title, body: S.body }); render(); }), { kind: 'primary small' })) : null),
    can('ws.stage.set') ? div({ class: 'card' }, h3(t('Where is your union in the process?')),
      p({ class: 'small muted' }, t('Recognized means your employer recognized you, or the labor board certified you. Cases and bargaining tools turn on. Add a note (for example, a case number).')),
      div({ class: 'row' }, selectBox([['public_prerecognition', t('Public, not yet recognized')], ['recognized', t('Recognized or certified')]], S.stage, (v) => (S.stage = v)), textInput({ placeholder: t('Note or case number'), value: S.note, oninput: (e) => (S.note = e.target.value) }),
        btn(t('Save'), act(async () => { await wcall('POST', '/api/ws/stage', { stage: S.stage, note: S.note }); render(); }), { kind: 'secondary small' })), w.stageNote ? p({ class: 'small muted' }, w.stageNote) : null) : null)));
}
const tile = (n, label, kind = '') => div({ class: `tile ${kind}` }, div({ class: 'tile-n' }, String(n)), div({ class: 'tile-l' }, label));

// ---------- your union: bylaws, roles, people, records ----------
function bylawsMd(w) {
  const P = w.policy;
  return `> **DRAFT: REQUIRES REVIEW BY A LICENSED LABOR ATTORNEY BEFORE REAL-WORLD USE**

# Rules of ${plainMd(w.unionName)}

These rules are enforced by the software. They can only be changed by a vote of the members.

## 1. Who we represent
We represent every employee in the bargaining unit fairly, whether or not they are members or pay dues. Anyone in the unit can raise a workplace problem and get help.

## 2. Members hold the power
- Members equal to ${P.petitionPct}% of the membership can force a vote on any question with a petition. The election committee must open it within 14 days.
- Members equal to ${P.recallPct}% of the membership can force a vote to remove an officer from a role. If a majority votes to remove them, the role ends automatically.
- These rules change only when the members pass an amendment by vote.

## 3. Votes
All votes are by secret ballot. When the election committee publishes a vote's ballot key, and it always does for a decision that changes dues, rules or roles, any member can recount the ballots and check their receipt.

## 4. Officers
Officers serve terms of ${P.termMonths} months. Election procedures must be reviewed before your first election. TODO(lawyer): add nomination, notice and mail-ballot procedures for officer elections; federal rules for union officer elections are strict.

## 5. Money
- Every receipt and payment goes in a ledger that cannot be edited. Corrections are new entries.
- Spending of ${money(P.twoApprovalCents, currency())} or more needs two different officers to approve. Nobody approves their own request.
- Dues can only be set or changed by a vote of the members.
- Every member can see the books.
`;
}

export const UnionTab = async () => {
  const w = wsInfo();
  const [roles, by, log] = await Promise.all([wcall('GET', '/api/ws/roles'), wcall('GET', '/api/ws/bylaws'), wcall('GET', '/api/ws/me/access-log')]);
  const roster = can('roster.read') ? (await wcall('GET', '/api/ws/roster')).members : null;
  const audit = can('audit.read_all') ? await wcall('GET', '/api/ws/audit') : null;
  const comp = can('compliance.read') ? (await wcall('GET', '/api/ws/compliance')).tasks : null;
  const me = WS.info.member;
  const shown = audit ? audit.entries.slice(0, 100) : []; // entries listed on screen, newest first; more on request
  const S = { role: 'steward', who: roster?.[0]?.id, csv: '', claims: null, phone: me.phone || '', address: me.address || '', job: me.jobTitle || '', shift: me.shift || '' };
  const auditList = audit ? audit.chain : null; // every entry since the first, oldest first: the whole log is checked, not only the page shown
  const chain = audit ? verifyChain(auditList, auditFields, { anchored: true }) : null;
  // Like the ledger, this device remembers the newest audit entry it has seen, so a rewritten log (which a chain check alone cannot notice) is caught on a later visit.
  const auditPinKey = `pin.audit.${WS.workspaceId}`, auditPin = store.get(auditPinKey);
  const auditPinned = chain?.ok ? checkPinned(auditList, auditPin) : { ok: false };
  if (chain?.ok && auditPinned.ok && chain.head && (!auditPin || chain.head.seq > auditPin.seq)) store.set(auditPinKey, chain.head);
  return wsFrame('union', view((update) => div(
    h1(t('Your union')),
    details({ open: true, class: 'card' }, summary(t('Our rules (bylaws)')), md(bylawsMd(w)),
      h3(t('Rule settings')), table({ class: 'table' }, tbody(Object.entries(by.fields).map(([k, f]) => tr(td(t(f.label)), td(strong(k === 'twoApprovalCents' ? money(by.policy[k], currency()) : by.policy[k])))))),
      p({ class: 'small muted' }, t('To change a rule, start a bylaws vote from the Votes tab. If it passes, the rule changes by itself.')),
      by.versions.length > 1 ? details(summary(t('History')), ul(by.versions.map((v) => li(`v${v.version}: ${v.summary} (${fmtDate(v.at)})`)))) : null),
    details({ class: 'card' }, summary(t('Who holds what role')),
      ul(roles.roles.map((r) => li(strong(r.name), ': ', t(ROLE_NAMES[r.role] || r.role), ' ', span({ class: 'small muted' }, t('since {d}', { d: fmtDate(r.since) }))))),
      can('roles.assign') && roster ? div({ class: 'row' }, selectBox(roster.map((m) => [m.id, m.name]), S.who, (v) => (S.who = v)), selectBox(ASSIGNABLE_ROLES.map((r) => [r, t(ROLE_NAMES[r])]), S.role, (v) => (S.role = v)),
        btn(t('Give role'), act(async () => { await wcall('POST', '/api/ws/roles', { memberId: S.who, role: S.role, op: 'add' }); render(); }), { kind: 'primary small' }),
        btn(t('Remove role'), act(async () => { await wcall('POST', '/api/ws/roles', { memberId: S.who, role: S.role, op: 'remove' }); render(); }), { kind: 'secondary small' })) : null),
    roster ? details({ class: 'card' }, summary(t('People ({n})', { n: roster.length })),
      callout('info', t('Every time you view this list, it is recorded and each person can see that you looked.')),
      div({ class: 'table-wrap' }, table({ class: 'table' }, thead(tr(th(t('Name')), th(t('Status')), th(t('Contact')), th(t('Shift')), th(t('Account')))),
        tbody(roster.map((m) => tr(td(m.name), td(m.status === 'member' ? t('Member') : t('Unit employee')), td(span({ class: 'small' }, [m.email, m.phone].filter(Boolean).join(' · '))), td(m.shift || ''), td(m.claimed ? '✓' : t('not claimed'))))))),
      can('roster.add') ? div({ class: 'stack' }, h3(t('Add people')), p({ class: 'small muted' }, t('One person per line: name, email, phone, job title, shift. They get a link to claim their account.')),
        textarea({ rows: 4, placeholder: 'Jo Rivera, jo@example.org, +15555550123, Barista, Days', oninput: (e) => (S.csv = e.target.value) }),
        btn(t('Add and get claim links'), act(async () => {
          const rows = S.csv.split('\n').map((l) => l.split(',').map((x) => x.trim())).filter((r) => r[0]);
          if (!rows.length) return toast(t('Add at least one person.'), 'bad');
          const tokens = rows.map(() => C.newToken());
          await wcall('POST', '/api/ws/members', { members: rows.map((r, i) => ({ legalName: r[0], email: r[1], phone: r[2], jobTitle: r[3], shift: r[4], status: 'unit_employee', claimTokenHash: C.hashToken(tokens[i]) })) });
          S.claims = { links: rows.map((r, i) => ({ name: r[0], link: linkTo('/w/join', { c: tokens[i], w: wsInfo().id }) })) };
          update();
        }), { kind: 'primary small' }), S.claims ? claimsView(S.claims, t('New accounts')) : null) : null) : null,
    details({ class: 'card' }, summary(t('My information')),
      p({ class: 'small muted' }, t('Only you and the officers who need it can see this. Your name and email are set by the union; ask an officer to change them.')),
      field(t('Phone'), textInput({ value: S.phone, oninput: (e) => (S.phone = e.target.value) })), field(t('Home address (for mailed election notices)'), textInput({ value: S.address, oninput: (e) => (S.address = e.target.value) })),
      field(t('Job title'), textInput({ value: S.job, oninput: (e) => (S.job = e.target.value) })), field(t('Shift'), textInput({ value: S.shift, oninput: (e) => (S.shift = e.target.value) })),
      btn(t('Save'), act(async () => { await wcall('POST', '/api/ws/me/profile', { phone: S.phone, address: S.address, jobTitle: S.job, shift: S.shift }); toast(t('Saved.')); }), { kind: 'primary small' }),
      h3(t('Who has looked at my record')), log.entries.length ? ul(log.entries.map((e) => li(`${e.actor || t('Someone')}: ${e.action.replace('member.pii.read', t('viewed your details')).replace('grievance.opened', t('opened your case'))} · ${fmtDateTime(e.at)}`))) : p({ class: 'muted' }, t('Nobody but you.'))),
    comp ? details({ class: 'card' }, summary(t('Legal deadlines and filings')), p({ class: 'small muted' }, t('Suggested dates only. Have your attorney and accountant confirm each one. Project Ludlow never files anything for you.')),
      comp.map((x) => div({ class: 'entry' }, div({ class: 'row between' }, strong(x.title), x.doneAt ? badge(t('Done'), 'ok') : x.urgency ? urgencyBadge(x.urgency) : badge(t('No fixed date'))), p({ class: 'small' }, x.detail), p({ class: 'small muted' }, x.dueOn ? t('Suggested date: {d}', { d: fmtDate(x.dueOn) }) : '', ' ', mark({ class: 'todo' }, x.verify === 'accountant' ? 'TODO(accountant): confirm' : 'TODO(lawyer): confirm')),
        btn(x.doneAt ? t('Mark not done') : t('Mark done'), act(async () => { await wcall('POST', `/api/ws/compliance/${x.key}/toggle`); render(); }), { kind: 'secondary small' })))) : null,
    can('export.all') ? div({ class: 'card' }, h3(t('Your data belongs to the union')), p({ class: 'small muted' }, t('Download everything: members, roles, votes, the whole ledger, rules and the audit log. Private cases stay encrypted, and only the people who hold their keys can read them. The download itself is recorded in the audit log.')),
      btn(t('Export everything (JSON)'), act(async () => { const data = await wcall('GET', '/api/ws/export'); download(`ludlow-export-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(data, null, 2), 'application/json'); toast(t('Exported. This file contains personal information: keep it private.')); }), { kind: 'secondary' })) : null,
    audit ? details({ class: 'card' }, summary(t('Audit log')),
      !chain.ok ? callout('danger', t('The audit log has been tampered with near entry {n}. Do not trust it.', { n: chain.brokenAt }))
        : !auditPinned.ok ? callout('danger', strong(t('The history changed.')), ' ', t('On an earlier visit this device saw audit entries that are now different or missing. Someone may have rewritten the log. Tell your members right away.'))
          : auditPinned.first ? callout('info', t('Checked in your browser: all {n} entries form an unbroken chain from the first. This is the first check on this device, so it cannot yet tell whether entries were rewritten before today. Later visits will.', { n: chain.count }))
            : callout('ok', t('Checked in your browser: all {n} entries form an unbroken chain from the first, and entries this device saw before have not changed.', { n: chain.count })),
      div({ class: 'table-wrap' }, table({ class: 'table small' }, thead(tr(th('#'), th(t('Who')), th(t('What')), th(t('When')))), tbody(auditRows(shown, audit.chain).map((r) => tr(td(r.seq), td(r.actor || '—'), td(r.ok ? r.action : span(r.action, ' ', badge(t('not in the checked log'), 'bad'))), td(ago(r.at)))))),
        shown.length && shown.at(-1).seq > 1 ? btn(t('Show older entries'), act(async () => {
          const more = shown.length < audit.entries.length ? audit.entries.slice(shown.length, shown.length + 100) : (await wcall('GET', `/api/ws/audit?before=${shown.at(-1).seq}`)).entries.slice(0, 100);
          shown.push(...more); update();
        }), { kind: 'secondary small' }) : null)) : null)));
};
