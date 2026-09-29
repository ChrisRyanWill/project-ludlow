// The one bridge from a campaign to a workspace. It runs in the trustees' browser, after they have
// opened the cards, and only after they confirm the union has already gone public: from this point
// names are readable to officers and stored (encrypted at rest) on the server.
import * as C from '../../shared/crypto.js';
import { api } from './api.js';
import { t } from './i18n.js';
import { div, p, h2, h3, strong, span, callout, btn, field, selectBox, textInput, act, copy, download, table, thead, tbody, tr, td, th, input } from './ui.js';
import { linkTo, label3 } from './organize.js';
import { csvCell } from './zip.js';

const ROLE_LABELS = { officer: 'Officer', treasurer: 'Treasurer', chief_steward: 'Chief steward', election_committee: 'Election committee' };
const defaults = (i) => new Set(['officer', 'election_committee', ...(i === 0 ? ['treasurer'] : []), ...(i === 1 ? ['chief_steward'] : [])]);

export function FoundingPanel({ cards, meta, pack, update }) {
  const roster = cards.filter((c) => !c.disavowedAt);
  const guess = (nm) => roster.findIndex((c) => nm && c.payload.legalName.toLowerCase().startsWith(nm.toLowerCase().split(' ')[0]));
  const F = FoundingPanel.state ||= {
    confirmed: false, stage: 'public_prerecognition', fy: '01-01', tz: Intl.DateTimeFormat().resolvedOptions().timeZone || 'America/Denver',
    officers: meta.trusteeNames.map((tn, i) => ({ name: tn.displayName, pick: guess(tn.displayName), roles: defaults(i) })), result: null,
  };
  if (F.result) return claimsView(F.result);

  const create = async () => {
    if (!F.confirmed) return;
    const picked = F.officers.filter((o) => o.pick >= 0);
    if (!picked.length || !picked.some((o) => o.roles.has('officer'))) return alert(t('Choose at least one officer from the roster.'));
    if (new Set(picked.map((o) => o.pick)).size !== picked.length) return alert(t('Each officer must be a different person.'));
    const tokens = roster.map(() => C.newToken());
    const rolesFor = (i) => { const o = picked.find((x) => x.pick === i); return o ? [...o.roles] : []; };
    const members = roster.map((c, i) => ({
      legalName: c.payload.legalName, email: c.payload.personalEmail, phone: c.payload.phone, jobTitle: c.payload.jobTitle, shift: c.payload.shiftOrDepartment,
      preferredLanguage: c.payload.preferredLanguage, status: 'member', founding: true, claimTokenHash: C.hashToken(tokens[i]), roles: rolesFor(i),
    }));
    const res = await api('POST', '/api/ws', { body: { confirmedPublic: true, stage: F.stage, unionName: meta.unionName, employerName: meta.employerName, unitDescription: meta.unitDescription, jurisdiction: pack.id, timezone: F.tz, fiscalYearStart: F.fy, members } });
    F.result = { workspaceId: res.workspaceId, links: roster.map((c, i) => ({ name: c.payload.legalName, link: linkTo('/w/join', { c: tokens[i], w: res.workspaceId }) })) };
    update();
  };
  return div({ class: 'card founding' },
    h2(t('Start your union workspace')),
    p(t('A union that has gone public needs a real membership list to hold votes, collect dues and represent people by name. The workspace does that.')),
    callout('danger', strong(t('Read this before you continue.')), ' ', t('Creating a workspace copies the names, emails and phone numbers of {n} signers to the server, where officers can see them. They are encrypted at rest, but they are no longer secret. Only do this once your union has already gone public: you have sent a demand letter or filed a petition.', { n: roster.length })),
    label3(t('We have already gone public.'), F.confirmed, (v) => { F.confirmed = v; update(); }),
    F.confirmed ? div({ class: 'stack' },
      field(t('Where is your union right now?'), selectBox([['public_prerecognition', t('Public, not yet recognized')], ['recognized', t('Recognized or certified')]], F.stage, (v) => { F.stage = v; })),
      p({ class: 'small muted' }, t('Grievance handling and bargaining tools only turn on once you are recognized. You can change this later with a note.')),
      h3(t('Interim officers')),
      p({ class: 'small muted' }, t('Until your first election, your trustees can hold these roles. Choose who each trustee is on the roster. You can change roles later. Committee votes need at least two people on the election committee.')),
      F.officers.map((o) => div({ class: 'card inner' }, strong(o.name),
        field(t('This trustee is'), selectBox([['-1', t('(not on the roster)')], ...roster.map((c, i) => [String(i), c.payload.legalName])], String(o.pick), (v) => { o.pick = Number(v); })),
        div({ class: 'row' }, Object.entries(ROLE_LABELS).map(([r, l]) => label3(t(l), o.roles.has(r), (v) => (v ? o.roles.add(r) : o.roles.delete(r))))))),
      div({ class: 'row' }, field(t('Fiscal year starts (MM-DD)'), textInput({ value: F.fy, oninput: (e) => (F.fy = e.target.value) })), field(t('Time zone'), textInput({ value: F.tz, oninput: (e) => (F.tz = e.target.value) }))),
      btn(t('Create the workspace'), act(create), { kind: 'primary block' })) : null);
}

export function claimsView(R, heading = t('Your workspace is ready')) {
  const msg = (l) => t('Hi {name}, our union workspace is ready. Claim your account with this link, on your own phone: ', { name: l.name.split(' ')[0] }) + l.link;
  return div({ class: 'card founding' },
    h2(heading),
    callout('warn', strong(t('Each link below is a key to one person\'s account.')), ' ', t('Send each one privately to that person only. It works once. Then destroy the campaign so the old, anonymous data is deleted.')),
    div({ class: 'row' },
      btn(t('Download all links (CSV)'), () => download('claim-links.csv', ['name,link', ...R.links.map((l) => `${csvCell(l.name)},${csvCell(l.link)}`)].join('\r\n'), 'text/csv')),
      btn(t('Copy all messages'), () => copy(R.links.map(msg).join('\n\n')), { kind: 'secondary' })),
    div({ class: 'table-wrap' }, table({ class: 'table' }, thead(tr(th(t('Person')), th(''))),
      tbody(R.links.map((l) => tr(td(l.name), td(btn(t('Copy message'), () => copy(msg(l)), { kind: 'secondary small' }))))))),
    p(t('Once you have handed out the links and at least one officer has claimed their account, go back to your trustee dashboard and destroy the campaign.')));
}
