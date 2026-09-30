// Workplace concerns and grievances. What a worker writes is encrypted on their device to the people
// who will help them; the server only runs the deadlines. Help is never gated by dues.
import * as C from '../../shared/crypto.js';
import { ApiError } from './api.js';
import { t } from './i18n.js';
import { GRIEVANCE_DECISIONS, ARTICLE_REF } from '../../shared/constants.js';
import { WS, wcall, can, has, wsInfo, wsFrame, pack, urgencyBadge } from './wsbase.js';
import {
  div, span, p, a, ul, li, h1, h2, h3, strong, input, textarea, details, summary, btn, callout, badge, field, textInput, selectBox,
  setTitle, view, act, toast, fmtDate, md, readAloud, render, mark, go,
} from './ui.js';

const DECISIONS = { pursue: 'We will pursue this', resolved_informally: 'It was resolved informally', not_pursued: 'We will not pursue this' };
const OUTCOMES = { advance: 'Move to the next step', resolved: 'Mark this step resolved', denied: 'Denied: move to the next step' };
const myBoxPub = () => WS.info.member.boxPublicKey;

export async function HelpTab() {
  setTitle('Get help', true);
  const w = wsInfo(), pk = pack(), rec = w.stage === 'recognized';
  const [{ grievances }, proc] = await Promise.all([rec ? wcall('GET', '/api/ws/grievances') : { grievances: [] }, wcall('GET', '/api/ws/procedure')]);
  const F = { what: '', when: new Date().toISOString().slice(0, 10), who: '', article: '', desired: '' };
  const P = { steps: proc.steps.map((s) => `${s.name} | ${s.days} | ${s.dayType}`).join('\n'), holidays: proc.holidays.join('\n') };
  return wsFrame('help', view((update) => div(
    h1(t('Get help')),
    p({ class: 'lead' }, t('If something at work is not right, tell us. Anyone in the unit can do this, member or not, and it never depends on dues.')),
    pk.weingarten ? details({ class: 'card' }, summary(t('In a meeting with a manager? Know your Weingarten rights')), md(pk.weingarten), readAloud(pk.weingarten.replace(/[>#*`]/g, ''))) : null,
    rec ? div({ class: 'card' }, h2(t('Tell us what happened')),
      callout('info', t('This is locked so that only you, the chief stewards and any steward your case is shared with can read it. Other officers cannot. The keys it is locked to come from this website, so for now you are trusting the website to hand out the right ones.')),
      field(t('What happened?'), textarea({ rows: 4, oninput: (e) => (F.what = e.target.value) })), field(t('When?'), input({ type: 'date', value: F.when, oninput: (e) => (F.when = e.target.value) })),
      field(t('Who was involved?'), textInput({ oninput: (e) => (F.who = e.target.value) })), field(t('Contract article, number only (if you know it). This one is not encrypted.'), textInput({ oninput: (e) => (F.article = e.target.value) })),
      field(t('What would fix it?'), textInput({ oninput: (e) => (F.desired = e.target.value) })),
      btn(t('Send it, encrypted'), act(async () => {
        if (F.what.trim().length < 5) return toast(t('Please describe what happened.'), 'bad');
        if (F.article.trim() && !ARTICLE_REF.test(F.article.trim())) return toast(t('Put only the article number there, such as "Art. 12". Everything else belongs in the description, which is encrypted.'), 'bad');
        const ring = await wcall('GET', '/api/ws/keyring?role=chief_steward');
        if (!ring.holders.length) throw new ApiError(409, 'no_chief_steward');
        const id = C.uuid(), key = C.randomBytes(32);
        const box = C.sealJson(key, { what: F.what, when: F.when, who: F.who, desired: F.desired, filedAt: new Date().toISOString() }, 'grievance|' + id);
        const sealedKeys = { [WS.memberId]: C.boxSeal(myBoxPub(), key) };
        for (const h of ring.holders) sealedKeys[h.memberId] = C.boxSeal(h.boxPublicKey, key);
        C.wipe(key);
        await wcall('POST', '/api/ws/grievances', { id, ...box, articleRef: F.article.trim() || undefined, sealedKeys });
        toast(t('Sent. A steward will be assigned.'));
        go(`/w/help/${id}`);
      }), { kind: 'primary' })) : callout('info', t('Formal cases turn on once your union is recognized. Until then, talk to a steward or officer in person.')),
    grievances.length ? div({ class: 'card' }, h2(rec && has('chief_steward') ? t('All cases') : t('Your cases')),
      grievances.map((g) => div({ class: 'entry' }, div({ class: 'row between' }, a({ href: `/w/help/${g.id}` }, strong(g.stepName || t('Case')), ' ', span({ class: 'small muted' }, `${t('filed {d}', { d: fmtDate(g.filedOn) })}${g.articleRef ? ` · ${g.articleRef}` : ''}`)),
        g.status === 'closed' ? badge(t('Closed'), 'ok') : urgencyBadge(g.urgency) || badge(t('Open'))),
        g.assignedTo ? p({ class: 'small muted' }, t('Steward: {name}', { name: g.assignedTo.name })) : p({ class: 'small muted' }, t('Waiting for a steward.')), g.workerNotified && g.mine ? p({ class: 'small' }, '● ' + t('There is an update on your case.')) : null))) : null,
    can('procedure.write') ? details({ class: 'card' }, summary(t('Grievance steps and deadlines (officers)')),
      p({ class: 'small muted' }, t('One step per line: name | days | business or calendar. These deadlines come from your contract. Deadlines are counted for you and stewards get reminders.'), ' ', mark({ class: 'todo' }, 'TODO(lawyer): match this to your contract')),
      textarea({ rows: 5, value: P.steps, oninput: (e) => (P.steps = e.target.value) }), field(t('Holidays (one date per line, YYYY-MM-DD)'), textarea({ rows: 3, value: P.holidays, oninput: (e) => (P.holidays = e.target.value) })),
      btn(t('Save steps'), act(async () => {
        const steps = P.steps.split('\n').map((l) => l.split('|').map((x) => x.trim())).filter((r) => r[0]).map((r) => ({ name: r[0], days: Number(r[1]), dayType: r[2] === 'calendar' ? 'calendar' : 'business' }));
        await wcall('PUT', '/api/ws/procedure', { steps, holidays: P.holidays.split('\n').map((x) => x.trim()).filter(Boolean) });
        toast(t('Saved.'));
      }), { kind: 'primary small' })) : null)));
}

export async function CaseDetail({ id }) {
  setTitle('Case', true);
  const g = await wcall('GET', `/api/ws/grievances/${id}`);
  let key = null, content = null, reason = null;
  if (g.sealedKey) { try { key = C.boxOpen(g.sealedKey, myBoxPub(), WS.keys.boxSecretKey); content = C.openJson(key, g.content, 'grievance|' + id); } catch { key = null; } }
  const open = (box, aad) => { try { return key ? C.openJson(key, box, aad) : null; } catch { return null; } };
  if (g.reason) reason = open(g.reason, 'reason|' + id);
  const notes = g.notes.map((n) => ({ ...n, data: open(n, 'note|' + id) }));
  const chief = has('chief_steward');
  const ring = chief && g.status === 'open' ? [...(await wcall('GET', '/api/ws/keyring?role=steward')).holders, ...(await wcall('GET', '/api/ws/keyring?role=chief_steward')).holders].filter((x, i, arr) => arr.findIndex((y) => y.memberId === x.memberId) === i) : [];
  const S = { note: '', outcome: 'advance', decision: 'pursue', reason: '', steward: ring[0]?.memberId };
  return wsFrame('help', view((update) => div(
    p(a({ href: '/w/help' }, '← ' + t('All cases'))),
    div({ class: 'row between' }, h1(g.stepName || t('Case')), g.status === 'closed' ? badge(t('Closed'), 'ok') : urgencyBadge(g.urgency)),
    p({ class: 'muted' }, `${t('Filed {d}', { d: fmtDate(g.filedOn) })}${g.articleRef ? ' · ' + g.articleRef : ''} · ${g.assignedTo ? t('Steward: {name}', { name: g.assignedTo.name }) : t('No steward yet')}`),
    content ? div({ class: 'card' }, h2(t('What happened')), p({ class: 'pre' }, content.what), content.when ? p({ class: 'small' }, t('When: {x}', { x: content.when })) : null, content.who ? p({ class: 'small' }, t('Who: {x}', { x: content.who })) : null, content.desired ? p({ class: 'small' }, t('What would fix it: {x}', { x: content.desired })) : null)
      : callout('warn', t('You do not hold the key to read this case. Ask the worker, or a steward who is on the case, to share it with you.')),
    key && g.missingKeys?.length ? div({ class: 'card' }, h3(t('Not everyone who should can read this case')),
      p({ class: 'small muted' }, t('These chief stewards were appointed after the case was filed, so they cannot read or work it until someone who holds the key shares it with them. Sharing seals the key to them alone.')),
      g.missingKeys.map((m) => div({ class: 'row' }, span(m.name),
        btn(t('Share this case with {name}', { name: m.name }), act(async () => { await wcall('POST', `/api/ws/grievances/${id}/share`, { memberId: m.memberId, sealedKey: C.boxSeal(m.boxPublicKey, key) }); render(); }), { kind: 'secondary small' })))) : null,
    div({ class: 'card' }, h2(t('Steps and deadlines')), ul({ class: 'timeline' }, g.steps.map((s) => li({ class: s.completedOn ? 'done' : s.n === g.currentStep && g.status === 'open' ? 'now' : '' },
      strong(s.name), ' ', span({ class: 'small muted' }, `${s.days} ${s.dayType === 'business' ? t('business days') : t('calendar days')}`),
      s.completedOn ? span({ class: 'small' }, ` · ${t('done {d}', { d: fmtDate(s.completedOn) })}: ${s.outcome}`) : s.dueOn ? span({ class: 'small' }, ` · ${t('due {d}', { d: fmtDate(s.dueOn) })} `) : null, !s.completedOn ? urgencyBadge(s.urgency) : null)))),
    g.decision ? div({ class: 'card' }, h2(t('Decision')), p(strong(t(DECISIONS[g.decision]))), reason ? p({ class: 'pre' }, reason.reason) : null, p({ class: 'small muted' }, g.workerNotified ? t('The worker has been told.') : t('The worker has not been told yet.'))) : null,
    notes.length ? div({ class: 'card' }, h2(t('Notes')), notes.map((n) => div({ class: 'entry' }, p({ class: 'pre' }, n.data?.note ?? t('(cannot read)')), p({ class: 'small muted' }, `${n.author}, ${fmtDate(n.at)}`)))) : null,
    chief && g.status === 'open' && ring.length && key ? div({ class: 'card' }, h3(t('Assign a steward')), p({ class: 'small muted' }, t('The case key is also sealed to the steward you assign, so they can read it too.')),
      div({ class: 'row' }, selectBox(ring.map((s) => [s.memberId, s.name]), S.steward, (v) => (S.steward = v)),
        btn(t('Assign'), act(async () => { const s = ring.find((x) => x.memberId === S.steward); await wcall('POST', `/api/ws/grievances/${id}/assign`, { stewardId: s.memberId, sealedKey: C.boxSeal(s.boxPublicKey, key) }); render(); }), { kind: 'primary small' }))) : null,
    g.canWork && g.status === 'open' && key ? div({ class: 'card stack' }, h3(t('Work on this case')),
      field(t('Add a note (encrypted)'), textarea({ rows: 3, oninput: (e) => (S.note = e.target.value) })),
      btn(t('Save note'), act(async () => { if (!S.note.trim()) return; await wcall('POST', `/api/ws/grievances/${id}/notes`, C.sealJson(key, { note: S.note }, 'note|' + id)); render(); }), { kind: 'secondary small' }),
      g.steps.some((s) => s.n === g.currentStep && !s.completedOn) ? div({ class: 'row' }, selectBox(Object.entries(OUTCOMES).map(([k, v]) => [k, t(v)]), S.outcome, (v) => (S.outcome = v)), btn(t('Complete this step'), act(async () => { await wcall('POST', `/api/ws/grievances/${id}/steps/complete`, { outcome: S.outcome }); render(); }), { kind: 'primary small' })) : null,
      h3(t('Decision and closing')), p({ class: 'small muted' }, t('Every case must end with a decision, a reason, and telling the worker. That protects the worker and the union.')),
      selectBox(Object.entries(DECISIONS).map(([k, v]) => [k, t(v)]), S.decision, (v) => (S.decision = v)), field(t('Reason (the worker will read this)'), textarea({ rows: 3, oninput: (e) => (S.reason = e.target.value) })),
      div({ class: 'row' },
        btn(t('Record decision'), act(async () => { if (S.reason.trim().length < 3) return toast(t('Please give a reason.'), 'bad'); const b = C.sealJson(key, { reason: S.reason }, 'reason|' + id); await wcall('POST', `/api/ws/grievances/${id}/decision`, { decision: S.decision, reasonCiphertext: b.ciphertext, reasonNonce: b.nonce }); render(); }), { kind: 'secondary small' }),
        btn(t('Tell the worker'), act(async () => { await wcall('POST', `/api/ws/grievances/${id}/notify-worker`); render(); }), { kind: 'secondary small', disabled: !g.decision }),
        btn(t('Close the case'), act(async () => {
          try { await wcall('POST', `/api/ws/grievances/${id}/close`); render(); } catch (e) {
            if (e.code === 'cannot_close') return toast(t('Before closing: {list}.', { list: (e.extra?.missing || []).map((m) => ({ decision: t('record a decision'), reason: t('give a reason'), worker_notification: t('tell the worker') }[m] || m)).join(', ') }), 'bad');
            throw e;
          }
        }), { kind: 'primary small' }))) : null)));
}
