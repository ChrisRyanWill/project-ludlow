// Workspace API: the tools a union uses once it has gone public. Different privacy model from the
// campaign system (named members, roles, encryption at rest, audit log) and no table is shared with it.
// Every route below is registered through W(), which authenticates, checks the permission matrix in
// shared/permissions.js, and (for recognized-only modules) checks the workspace stage.
import { randomUUID, randomInt } from 'node:crypto';
import { fail } from './http.js';
import { hashToken, newToken, verifyAuth, verifyTally, publicFromSecret, countBallots, chainHash, sha256Text, GENESIS, b64, randomBytes } from '../shared/crypto.js';
import { takeChallenge, bearer } from './auth.js';
import { PERMS, can, ASSIGNABLE_ROLES } from '../shared/permissions.js';
import {
  STAGES, VOTE_TYPES, PASS_RULES, GRIEVANCE_DECISIONS, SMALL_GROUP, RECEIPT_CATEGORIES, DISBURSEMENT_CATEGORIES,
  REDACTED_CATEGORIES, DEFAULT_PROCEDURE, DEFAULT_POLICY, POLICY_FIELDS, evaluateVote, complianceTasks,
  ARTICLE_REF,
} from '../shared/constants.js';
import { dueDate, todayIn, urgency, addCalendar } from '../shared/deadlines.js';

const B64 = /^[A-Za-z0-9_-]+$/;
const isB64 = (s, min, max) => typeof s === 'string' && s.length >= min && s.length <= max && B64.test(s);
const isTok = (s) => isB64(s, 43, 43);
const isUuid = (s) => typeof s === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);
const isStr = (s, max) => typeof s === 'string' && s.trim().length > 0 && s.length <= max;
const int = (v, min, max) => Number.isInteger(v) && v >= min && v <= max;
const need = (cond, code = 'bad_request') => { if (!cond) fail(400, code); };
const now = () => new Date().toISOString();
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const validTz = (tz) => { try { new Intl.DateTimeFormat('en', { timeZone: tz }); return typeof tz === 'string'; } catch { return false; } };
const optStr = (v, max) => (v == null || v === '' ? null : typeof v === 'string' && v.length <= max ? v.trim() : fail(400, 'bad_request'));
const constraint = (e) => { if (String(e?.code).startsWith('SQLITE_CONSTRAINT')) fail(409, 'conflict'); throw e; };

export function workspaceRoutes({ router, db, cfg, kms }) {
  // ---------- field encryption (envelope, at rest) ----------
  const enc = (dk, aad, v) => kms.enc(dk, v, aad);
  const dec = (dk, aad, v) => kms.dec(dk, v, aad);
  const person = (dk, m, full = true) => ({
    id: m.id, name: dec(dk, 'member.legal_name', m.legal_name_enc),
    ...(full ? { email: dec(dk, 'member.email', m.email_enc), phone: dec(dk, 'member.phone', m.phone_enc), address: dec(dk, 'member.address', m.address_enc), jobTitle: dec(dk, 'member.job_title', m.job_title_enc) } : {}),
    shift: m.shift, location: m.location, language: m.preferred_language, status: m.membership_status,
    founding: !!m.founding, claimed: !!m.claimed_at, joinedAt: m.joined_at,
  });
  const nameOf = (dk, id) => { const m = id && db.prepare('SELECT legal_name_enc FROM ws_members WHERE id=?').get(id); return m ? dec(dk, 'member.legal_name', m.legal_name_enc) : null; };

  // ---------- tamper-evident audit log ----------
  function audit(wsId, actorId, action, resType = null, resId = null) {
    const last = db.prepare('SELECT seq, hash FROM ws_audit WHERE workspace_id=? ORDER BY seq DESC LIMIT 1').get(wsId);
    const seq = (last?.seq || 0) + 1, at = now();
    const hash = chainHash(last?.hash || GENESIS, { seq, actor: actorId, action, type: resType, id: resId, at });
    db.prepare('INSERT INTO ws_audit (workspace_id,seq,actor_member_id,action,resource_type,resource_id,created_at,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?,?)')
      .run(wsId, seq, actorId, action, resType, resId, at, last?.hash || GENESIS, hash);
  }

  // ---------- members ----------
  function cleanMember(m) {
    if (!m || typeof m !== 'object') fail(400, 'bad_request');
    const legalName = optStr(m.legalName, 120);
    need(legalName && isTok(m.claimTokenHash));
    const roles = Array.isArray(m.roles) ? [...new Set(m.roles)] : []; // a role listed twice would violate the primary key and come back as a 500
    need(roles.every((r) => ASSIGNABLE_ROLES.includes(r)));
    return {
      legalName, email: optStr(m.email, 254), phone: optStr(m.phone, 32), address: optStr(m.address, 300), jobTitle: optStr(m.jobTitle, 120),
      shift: optStr(m.shift, 60), location: optStr(m.location, 60), preferredLanguage: optStr(m.preferredLanguage, 30),
      status: m.status === 'member' ? 'member' : 'unit_employee', founding: !!m.founding, claimTokenHash: m.claimTokenHash, roles,
    };
  }
  function insertMember(wsId, dk, m, actorId) {
    const id = randomUUID(), t = now();
    db.prepare(`INSERT INTO ws_members (id,workspace_id,legal_name_enc,email_enc,phone_enc,address_enc,job_title_enc,shift,location,preferred_language,membership_status,founding,joined_at,claim_token_hash,created_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, wsId, enc(dk, 'member.legal_name', m.legalName), enc(dk, 'member.email', m.email), enc(dk, 'member.phone', m.phone),
      enc(dk, 'member.address', m.address), enc(dk, 'member.job_title', m.jobTitle), m.shift, m.location, m.preferredLanguage, m.status, m.founding ? 1 : 0,
      m.status === 'member' ? t : null, m.claimTokenHash, t);
    for (const r of m.roles) db.prepare('INSERT INTO ws_roles (member_id,role,assigned_by,assigned_at) VALUES (?,?,?,?)').run(id, r, actorId, t);
    return id;
  }

  // ---------- public routes: founding, claiming an account, signing in ----------
  // The founding flow is the only bridge from a campaign. It runs in the trustees' browser; the server
  // just refuses to proceed unless the trustees have confirmed the union has already gone public.
  router.add('POST', '/api/ws', { strict: true, maxBody: 10_000_000 }, ({ body: b }) => {
    if (b.confirmedPublic !== true) fail(400, 'confirmation_required');
    need(STAGES.includes(b.stage) && isStr(b.unionName, 200) && isStr(b.employerName, 200));
    need(Array.isArray(b.members) && b.members.length >= 1 && b.members.length <= 3000);
    const jurisdiction = /^[a-z0-9-]{2,30}$/.test(b.jurisdiction || '') ? b.jurisdiction : 'us-nlra';
    const timezone = validTz(b.timezone) ? b.timezone : 'America/Denver';
    const validMonthDay = (s) => { const m = /^(\d{2})-(\d{2})$/.exec(s || ''); return !!m && Number(m[1]) >= 1 && Number(m[1]) <= 12 && Number(m[2]) >= 1 && Number(m[2]) <= [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][Number(m[1]) - 1]; };
    const fy = validMonthDay(b.fiscalYearStart) ? b.fiscalYearStart : '01-01';
    const members = b.members.map(cleanMember);
    if (!members.some((m) => m.roles.includes('officer'))) fail(400, 'officer_required');
    const wsId = randomUUID(), { dk, wrapped } = kms.newDataKey(), t = now();
    const memberIds = db.transaction(() => {
      db.prepare(`INSERT INTO ws_workspaces (id,stage,stage_note,union_name,employer_name,unit_description,jurisdiction,timezone,fiscal_year_start,policy_json,procedure_json,data_key_wrapped,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(wsId, b.stage, optStr(b.stageNote, 300), b.unionName.trim(), b.employerName.trim(), optStr(b.unitDescription, 500), jurisdiction, timezone, fy,
        JSON.stringify(DEFAULT_POLICY), JSON.stringify(DEFAULT_PROCEDURE), wrapped, t);
      const ids = members.map((m) => insertMember(wsId, dk, m, null));
      db.prepare('INSERT INTO ws_bylaws_versions (id,workspace_id,version,summary,policy_json,created_at) VALUES (?,?,?,?,?,?)')
        .run(randomUUID(), wsId, 1, 'Democratic defaults adopted at founding', JSON.stringify(DEFAULT_POLICY), t);
      audit(wsId, null, 'workspace.created', 'workspace', wsId);
      return ids;
    })();
    return { workspaceId: wsId, memberIds };
  });

  router.add('GET', '/api/ws/public/:id', {}, ({ params }) => {
    const w = db.prepare('SELECT union_name u, employer_name e FROM ws_workspaces WHERE id=?').get(params.id);
    if (!w) fail(404, 'not_found');
    return { unionName: w.u, employerName: w.e };
  });

  // Lets a new member see which account a claim link belongs to BEFORE spending it, so they can save their
  // key file first (the key file is bound to the account id).
  router.add('POST', '/api/ws/claim-info', { strict: true }, ({ body: b }) => {
    need(isUuid(b.workspaceId) && isTok(b.claimToken));
    const m = db.prepare(`SELECT m.id, w.union_name u, w.employer_name e FROM ws_members m JOIN ws_workspaces w ON w.id=m.workspace_id
      WHERE m.workspace_id=? AND m.claim_token_hash=? AND m.claimed_at IS NULL`).get(b.workspaceId, hashToken(b.claimToken));
    if (!m) fail(404, 'not_found');
    return { memberId: m.id, unionName: m.u, employerName: m.e };
  });

  router.add('POST', '/api/ws/claim', { strict: true }, ({ body: b }) => {
    need(isUuid(b.workspaceId) && isTok(b.claimToken) && isB64(b.boxPublicKey, 43, 43) && isB64(b.signPublicKey, 43, 43));
    const m = db.prepare('SELECT id FROM ws_members WHERE workspace_id=? AND claim_token_hash=? AND claimed_at IS NULL').get(b.workspaceId, hashToken(b.claimToken));
    if (!m) fail(401, 'unauthorized');
    db.prepare('UPDATE ws_members SET box_public_key=?, sign_public_key=?, claimed_at=?, claim_token_hash=NULL WHERE id=?').run(b.boxPublicKey, b.signPublicKey, now(), m.id);
    audit(b.workspaceId, m.id, 'account.claimed', 'member', m.id);
    return { memberId: m.id };
  });

  router.add('POST', '/api/ws/auth/login', { strict: true }, ({ body: b }) => {
    need(isUuid(b.memberId) && isStr(b.challengeId, 64) && isStr(b.signature, 200));
    const nonce = takeChallenge(b.challengeId);
    if (!nonce) fail(401, 'bad_challenge');
    const m = db.prepare('SELECT id, sign_public_key k FROM ws_members WHERE id=? AND sign_public_key IS NOT NULL').get(b.memberId);
    if (!m || !verifyAuth(m.k, b.signature, { nonce, route: 'POST /api/ws/auth/login', scope: m.id })) fail(401, 'bad_signature');
    const token = newToken(), t = now();
    db.prepare('DELETE FROM ws_sessions WHERE created_at < ?').run(new Date(Date.now() - cfg.sessionMaxDays * 86400_000).toISOString());
    db.prepare('INSERT INTO ws_sessions (token_hash,member_id,created_at,last_seen_at) VALUES (?,?,?,?)').run(hashToken(token), m.id, t, t);
    return { token };
  });

  // ---------- authenticated routes ----------
  function authenticate(ctx) {
    const tok = bearer(ctx.headers);
    const s = tok && db.prepare('SELECT * FROM ws_sessions WHERE token_hash=?').get(hashToken(tok));
    if (!s) fail(401, 'unauthorized');
    const t = Date.now();
    if (t - Date.parse(s.last_seen_at) > cfg.sessionIdleHours * 3600_000 || t - Date.parse(s.created_at) > cfg.sessionMaxDays * 86400_000) {
      db.prepare('DELETE FROM ws_sessions WHERE token_hash=?').run(s.token_hash);
      fail(401, 'session_expired');
    }
    if (t - Date.parse(s.last_seen_at) > 60_000) db.prepare('UPDATE ws_sessions SET last_seen_at=? WHERE token_hash=?').run(now(), s.token_hash);
    const m = db.prepare('SELECT * FROM ws_members WHERE id=?').get(s.member_id);
    const ws = db.prepare('SELECT * FROM ws_workspaces WHERE id=?').get(m.workspace_id);
    const roles = new Set(['unit_employee']);
    if (m.membership_status === 'member') roles.add('member');
    for (const r of db.prepare('SELECT role FROM ws_roles WHERE member_id=? AND removed_at IS NULL').all(m.id)) roles.add(r.role);
    return { m, ws, id: m.id, wsId: ws.id, dk: kms.dataKey(ws.id, ws.data_key_wrapped), roles, tokenHash: s.token_hash, today: todayIn(ws.timezone) };
  }
  function W(method, pattern, action, handler, opts = {}) {
    if (!PERMS[action]) throw new Error('unknown permission: ' + action);
    router.add(method, pattern, { ...opts, action, ws: true }, async (ctx) => {
      const me = authenticate(ctx);
      if (!can(me.roles, action)) fail(403, 'forbidden');
      if (opts.stage === 'recognized' && me.ws.stage !== 'recognized') fail(409, 'stage_required', { stage: 'recognized' });
      return handler({ ...ctx, me });
    });
  }
  const policyOf = (me) => ({ ...DEFAULT_POLICY, ...JSON.parse(me.ws.policy_json) });
  const holders = (wsId, role, claimedOnly = false) => db.prepare(
    `SELECT m.* FROM ws_roles r JOIN ws_members m ON m.id=r.member_id WHERE m.workspace_id=? AND r.role=? AND r.removed_at IS NULL ${claimedOnly ? 'AND m.box_public_key IS NOT NULL' : ''}`).all(wsId, role);

  W('POST', '/api/ws/auth/logout', 'ws.read', ({ me }) => { db.prepare('DELETE FROM ws_sessions WHERE token_hash=?').run(me.tokenHash); return { ok: true }; });

  W('GET', '/api/ws/me', 'ws.read', ({ me }) => {
    const ws = me.ws;
    return {
      member: { ...person(me.dk, me.m), boxPublicKey: me.m.box_public_key },
      roles: [...me.roles], permissions: Object.keys(PERMS).filter((a) => can(me.roles, a)),
      workspace: {
        id: ws.id, unionName: ws.union_name, employerName: ws.employer_name, unitDescription: ws.unit_description, stage: ws.stage, stageNote: ws.stage_note,
        jurisdiction: ws.jurisdiction, timezone: ws.timezone, fiscalYearStart: ws.fiscal_year_start, policy: policyOf(me), createdAt: ws.created_at,
        onlineOfficerElections: cfg.onlineOfficerElections,
      },
      today: me.today,
    };
  });

  W('POST', '/api/ws/me/join', 'me.write', ({ me }) => {
    if (me.m.membership_status === 'unit_employee') {
      db.prepare("UPDATE ws_members SET membership_status='member', joined_at=? WHERE id=?").run(now(), me.id);
      audit(me.wsId, me.id, 'member.joined', 'member', me.id);
    }
    return { status: 'member' };
  });
  W('POST', '/api/ws/me/profile', 'me.write', ({ me, body: b }) => {
    // A field the form does not send keeps its value; only what is sent changes (saving used to erase the location and language).
    const cur = db.prepare('SELECT shift, location, preferred_language pl FROM ws_members WHERE id=?').get(me.id);
    const keep = (sent, old, max) => (sent === undefined ? old : optStr(sent, max));
    db.prepare('UPDATE ws_members SET phone_enc=?, address_enc=?, job_title_enc=?, shift=?, location=?, preferred_language=? WHERE id=?').run(
      enc(me.dk, 'member.phone', optStr(b.phone, 32)), enc(me.dk, 'member.address', optStr(b.address, 300)), enc(me.dk, 'member.job_title', optStr(b.jobTitle, 120)),
      keep(b.shift, cur.shift, 60), keep(b.location, cur.location, 60), keep(b.preferredLanguage, cur.pl, 30), me.id);
    return { saved: true };
  });
  // Members can always see who looked at their record.
  W('GET', '/api/ws/me/access-log', 'ws.read', ({ me }) => {
    const rows = db.prepare("SELECT actor_member_id a, action, created_at t FROM ws_audit WHERE workspace_id=? AND resource_type='member' AND resource_id=? AND actor_member_id IS NOT ? ORDER BY seq DESC LIMIT 200").all(me.wsId, me.id, me.id);
    return { entries: rows.map((r) => ({ at: r.t, action: r.action, actor: nameOf(me.dk, r.a) })) };
  });

  // ---------- roles, roster ----------
  W('GET', '/api/ws/roles', 'roles.read', ({ me }) => {
    const rows = db.prepare(`SELECT r.member_id id, r.role, r.assigned_at t FROM ws_roles r JOIN ws_members m ON m.id=r.member_id
      WHERE m.workspace_id=? AND r.removed_at IS NULL ORDER BY r.role, r.assigned_at`).all(me.wsId);
    return { roles: rows.map((r) => ({ memberId: r.id, name: nameOf(me.dk, r.id), role: r.role, since: r.t })) };
  });
  W('POST', '/api/ws/roles', 'roles.assign', ({ me, body: b }) => {
    need(isUuid(b.memberId) && ASSIGNABLE_ROLES.includes(b.role) && ['add', 'remove'].includes(b.op));
    const target = db.prepare('SELECT id, membership_status s FROM ws_members WHERE id=? AND workspace_id=?').get(b.memberId, me.wsId);
    if (!target) fail(404, 'not_found');
    if (b.op === 'add') {
      // Nobody hands themselves power, and only someone who has joined the union can hold a role. Without these two rules one officer could
      // add people who then approve each other's spending. A role the members took away by a vote comes back only by a vote.
      if (b.memberId === me.id) fail(403, 'no_self_assign');
      if (target.s !== 'member') fail(409, 'not_a_member');
      if (db.prepare('SELECT 1 FROM ws_roles WHERE member_id=? AND role=? AND removed_at IS NOT NULL AND removed_by_vote_id IS NOT NULL').get(b.memberId, b.role)) fail(409, 'removed_by_vote');
    }
    db.transaction(() => {
      if (b.op === 'add') {
        db.prepare(`INSERT INTO ws_roles (member_id,role,assigned_by,assigned_at) VALUES (?,?,?,?)
          ON CONFLICT(member_id,role) DO UPDATE SET removed_at=NULL, assigned_by=excluded.assigned_by, assigned_at=excluded.assigned_at`).run(b.memberId, b.role, me.id, now());
      } else {
        if (b.role === 'officer' && holders(me.wsId, 'officer').length <= 1) fail(409, 'last_officer');
        db.prepare('UPDATE ws_roles SET removed_at=? WHERE member_id=? AND role=? AND removed_at IS NULL').run(now(), b.memberId, b.role);
      }
      audit(me.wsId, me.id, `role.${b.op}:${b.role}`, 'member', b.memberId);
    })();
    return { ok: true };
  });

  W('GET', '/api/ws/roster', 'roster.read', ({ me }) => {
    const rows = db.prepare('SELECT * FROM ws_members WHERE workspace_id=?').all(me.wsId);
    db.transaction(() => { for (const m of rows) if (m.id !== me.id) audit(me.wsId, me.id, 'member.pii.read', 'member', m.id); })(); // every look at someone's data is logged
    return { members: rows.map((m) => person(me.dk, m)).sort((a, b) => a.name.localeCompare(b.name)) };
  });
  W('POST', '/api/ws/members', 'roster.add', ({ me, body: b }) => {
    need(Array.isArray(b.members) && b.members.length >= 1 && b.members.length <= 3000);
    // Adding people after founding only creates unit employees. Each joins the union themselves, and roles are assigned one at a time (and audited).
    // Taking `status` and `roles` from the request let a single officer create voting members and officers in one call.
    const members = b.members.map(cleanMember).map((m) => ({ ...m, status: 'unit_employee', roles: [], founding: false }));
    const ids = db.transaction(() => {
      const out = members.map((m) => insertMember(me.wsId, me.dk, m, me.id));
      audit(me.wsId, me.id, `roster.add:${out.length}`, 'workspace', me.wsId);
      return out;
    })();
    return { memberIds: ids };
  }, { maxBody: 10_000_000 });

  W('GET', '/api/ws/keyring', 'keyring.read', ({ me, query }) => {
    need(['chief_steward', 'steward', 'election_committee', 'officer'].includes(query.role));
    return { holders: holders(me.wsId, query.role, true).map((m) => ({ memberId: m.id, name: dec(me.dk, 'member.legal_name', m.legal_name_enc), boxPublicKey: m.box_public_key })) };
  });

  W('POST', '/api/ws/stage', 'ws.stage.set', ({ me, body: b }) => {
    need(STAGES.includes(b.stage));
    db.prepare('UPDATE ws_workspaces SET stage=?, stage_note=? WHERE id=?').run(b.stage, optStr(b.note, 300), me.wsId);
    audit(me.wsId, me.id, `stage.set:${b.stage}`, 'workspace', me.wsId);
    return { stage: b.stage };
  });

  // ---------- announcements ----------
  W('GET', '/api/ws/announcements', 'announce.read', ({ me }) => ({
    items: db.prepare('SELECT id, title, body, author_member_id a, created_at t FROM ws_announcements WHERE workspace_id=? ORDER BY created_at DESC LIMIT 50').all(me.wsId)
      .map((r) => ({ id: r.id, title: r.title, body: r.body, author: nameOf(me.dk, r.a), at: r.t })),
  }));
  W('POST', '/api/ws/announcements', 'announce.write', ({ me, body: b }) => {
    need(isStr(b.title, 160) && isStr(b.body, 4000));
    db.prepare('INSERT INTO ws_announcements (id,workspace_id,author_member_id,title,body,created_at) VALUES (?,?,?,?,?,?)').run(randomUUID(), me.wsId, me.id, b.title.trim(), b.body.trim(), now());
    return { posted: true };
  });

  // ---------- bylaws as data ----------
  W('GET', '/api/ws/bylaws', 'ws.read', ({ me }) => ({
    policy: policyOf(me), fields: POLICY_FIELDS,
    versions: db.prepare('SELECT version, summary, policy_json p, ratified_by_vote_id v, created_at t FROM ws_bylaws_versions WHERE workspace_id=? ORDER BY version DESC').all(me.wsId)
      .map((r) => ({ version: r.version, summary: r.summary, policy: JSON.parse(r.p), voteId: r.v, at: r.t })),
  }));

  // ---------- votes ----------
  // A vote can carry an "effect" that the server applies itself when the vote passes: nobody has to
  // remember to implement the members' decision, and nobody can quietly skip it.
  const EFFECT_TYPES = ['dues_change', 'bylaws_amendment', 'recall', 'officer_election'];
  function validateEffect(me, type, e, options) {
    const memberOk = (id) => isUuid(id) && db.prepare('SELECT 1 FROM ws_members WHERE id=? AND workspace_id=?').get(id, me.wsId);
    if (type === 'dues_change') { need(e?.kind === 'dues' && isStr(e.name, 80) && int(e.amountCents, 0, 100_000_000)); return { kind: 'dues', name: e.name.trim(), amountCents: e.amountCents }; }
    if (type === 'bylaws_amendment') {
      const keys = Object.keys(e?.patch || {});
      need(e?.kind === 'policy' && keys.length >= 1 && keys.every((k) => POLICY_FIELDS[k] && int(e.patch[k], POLICY_FIELDS[k].min, POLICY_FIELDS[k].max)));
      return { kind: 'policy', patch: e.patch };
    }
    if (type === 'recall') { need(e?.kind === 'role_revoke' && memberOk(e.memberId) && ASSIGNABLE_ROLES.includes(e.role)); return { kind: 'role_revoke', memberId: e.memberId, role: e.role }; }
    if (type === 'officer_election') {
      need(e?.kind === 'role_grant' && ASSIGNABLE_ROLES.includes(e.role) && Array.isArray(e.memberIds) && e.memberIds.length === options.length && e.memberIds.every(memberOk));
      return { kind: 'role_grant', role: e.role, memberIds: e.memberIds };
    }
    need(e == null); return null;
  }
  function normalizeSpec(me, s) {
    need(isStr(s.title, 160) && VOTE_TYPES.includes(s.type));
    if (s.type === 'officer_election' && !cfg.onlineOfficerElections) fail(403, 'feature_disabled'); // online officer elections stay off until an attorney approves (V2 rule 13)
    let options = Array.isArray(s.options) ? s.options.map((o) => String(o).trim()) : [];
    // A vote that carries out its own decision must mean the same thing whoever wrote it: option 0 is the action, and the rule looks at option 0.
    // Otherwise a creator could list "Keep dues as they are" first, or pick "plurality" so a unique "No" winner counts as "passed".
    if (s.type === 'recall') options = ['Remove from office', 'Keep in office'];
    if (s.type === 'dues_change' || s.type === 'bylaws_amendment') options = ['Yes', 'No'];
    need(options.length >= 2 && options.length <= 12 && options.every((o) => o && o.length <= 120));
    const passRule = s.type === 'officer_election' ? 'plurality'
      : EFFECT_TYPES.includes(s.type) ? (['majority', 'two_thirds'].includes(s.passRule) ? s.passRule : 'majority')
        : PASS_RULES.includes(s.passRule) ? s.passRule : 'majority';
    return { title: s.title.trim(), description: optStr(s.description, 2000), type: s.type, options, passRule, effect: validateEffect(me, s.type, s.effect, options) };
  }
  const refreshVotes = (wsId) => db.prepare("UPDATE ws_votes SET status='closed', closed_at=? WHERE workspace_id=? AND status='open' AND closes_at < ?").run(now(), wsId, now());
  function getVote(me, id) {
    refreshVotes(me.wsId);
    const v = db.prepare('SELECT * FROM ws_votes WHERE id=? AND workspace_id=?').get(id, me.wsId);
    if (!v) fail(404, 'not_found');
    return v;
  }
  function voteView(me, v, detail) {
    const p = db.prepare('SELECT has_voted h FROM ws_vote_participation WHERE vote_id=? AND member_id=?').get(v.id, me.id);
    const t = db.prepare('SELECT COUNT(*) e, COALESCE(SUM(has_voted),0) v FROM ws_vote_participation WHERE vote_id=?').get(v.id);
    const out = {
      id: v.id, title: v.title, description: v.description, type: v.type, options: JSON.parse(v.options_json), passRule: v.pass_rule, status: v.status,
      closesAt: v.closes_at, createdAt: v.created_at, closedAt: v.closed_at, eligible: !!p, hasVoted: !!p?.h, turnout: { eligible: t.e, voted: t.v },
      effect: v.effect_json ? JSON.parse(v.effect_json) : null, results: v.results_json ? JSON.parse(v.results_json) : null, keyPublished: !!v.revealed_secret_key, petitionId: v.petition_id,
    };
    if (detail) {
      const committee = JSON.parse(v.committee_json);
      out.thresholdK = v.threshold_k;
      out.committee = committee.map((c) => ({ memberId: c.memberId, name: nameOf(me.dk, c.memberId) }));
      if (v.status === 'open') out.votePublicKey = v.vote_public_key;
    }
    return out;
  }
  W('GET', '/api/ws/votes', 'vote.read', ({ me }) => {
    refreshVotes(me.wsId);
    return { votes: db.prepare('SELECT * FROM ws_votes WHERE workspace_id=? ORDER BY created_at DESC').all(me.wsId).map((v) => voteView(me, v, false)) };
  });
  W('GET', '/api/ws/votes/:id', 'vote.read', ({ me, params }) => voteView(me, getVote(me, params.id), true));

  W('POST', '/api/ws/votes', 'vote.create', ({ me, body: b }) => {
    let spec;
    let petition = null;
    if (b.petitionId) { // a qualified petition is opened exactly as the members wrote it
      petition = db.prepare('SELECT * FROM ws_petitions WHERE id=? AND workspace_id=?').get(b.petitionId, me.wsId);
      if (!petition || petition.status !== 'qualified') fail(409, 'petition_not_qualified');
      spec = { title: petition.title, description: petition.description, type: petition.vote_type, options: JSON.parse(petition.options_json), passRule: petition.pass_rule, effect: petition.effect_json ? JSON.parse(petition.effect_json) : null };
      spec = normalizeSpec(me, spec);
    } else spec = normalizeSpec(me, b);
    const closesMs = Date.parse(b.closesAt);
    // Members need real time to see a vote and take part. Without a minimum, whoever opens it could give it a few seconds and let it close unseen
    // (the recall of an officer is the obvious target). Five minutes of slack absorbs clock differences with the person's device.
    const minMs = cfg.minVoteHours > 0 ? cfg.minVoteHours * 3600_000 - 300_000 : 1000;
    need(closesMs >= Date.now() + minMs && closesMs < Date.now() + 400 * 86400_000);
    need(isB64(b.votePublicKey, 43, 43) && Array.isArray(b.committee) && b.committee.length >= 2 && b.committee.length <= 9 && int(b.thresholdK, 2, b.committee.length));
    const ok = new Set(holders(me.wsId, 'election_committee', true).map((m) => m.id));
    need(b.committee.every((c) => ok.has(c?.memberId) && isB64(c.sealed, 60, 300)) && new Set(b.committee.map((c) => c.memberId)).size === b.committee.length);
    if (spec.type === 'officer_election' && spec.effect.memberIds.some((id) => b.committee.some((c) => c.memberId === id))) fail(409, 'committee_conflict'); // candidates cannot run their own election
    // ...and nobody can run their own recall: not by opening it, and not by sitting on the committee that counts it
    if (spec.type === 'recall' && (spec.effect.memberId === me.id || b.committee.some((c) => c.memberId === spec.effect.memberId))) fail(409, 'committee_conflict');
    const id = randomUUID();
    db.transaction(() => {
      db.prepare(`INSERT INTO ws_votes (id,workspace_id,title,description,type,options_json,pass_rule,effect_json,petition_id,closes_at,created_by,created_at,vote_public_key,threshold_k,committee_json)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, me.wsId, spec.title, spec.description, spec.type, JSON.stringify(spec.options), spec.passRule, spec.effect ? JSON.stringify(spec.effect) : null,
        petition?.id || null, new Date(closesMs).toISOString(), me.id, now(), b.votePublicKey, b.thresholdK, JSON.stringify(b.committee.map((c) => ({ memberId: c.memberId, sealed: c.sealed }))));
      const n = db.prepare("INSERT INTO ws_vote_participation (vote_id,member_id,has_voted) SELECT ?, id, 0 FROM ws_members WHERE workspace_id=? AND membership_status='member'").run(id, me.wsId).changes;
      if (n === 0) fail(409, 'no_eligible_voters');
      if (petition) db.prepare("UPDATE ws_petitions SET status='opened', vote_id=? WHERE id=?").run(id, petition.id);
      audit(me.wsId, me.id, 'vote.created', 'vote', id);
    })();
    return { voteId: id };
  });

  // Rewrites one vote's ballots and receipts in a random order. SQLite places each new row below the previous one inside its page, so without this the
  // order they sit on disk IS the order people voted in, and a copy of the database (a backup, a subpoena) could line ballots up with the times members
  // were seen. secure_delete is on, so the old layout is zeroed rather than left behind. Cheap at a union's size: it moves one vote's rows, once per cast.
  function scrambleVote(voteId) {
    const shuffled = (rows) => { for (let i = rows.length - 1; i > 0; i--) { const j = randomInt(i + 1); [rows[i], rows[j]] = [rows[j], rows[i]]; } return rows; };
    const ballots = shuffled(db.prepare('SELECT id, choice_ciphertext c FROM ws_ballots WHERE vote_id=?').all(voteId));
    const receipts = shuffled(db.prepare('SELECT receipt_hash h FROM ws_vote_receipts WHERE vote_id=?').all(voteId));
    db.prepare('DELETE FROM ws_ballots WHERE vote_id=?').run(voteId);
    db.prepare('DELETE FROM ws_vote_receipts WHERE vote_id=?').run(voteId);
    const addBallot = db.prepare('INSERT INTO ws_ballots (id,vote_id,choice_ciphertext) VALUES (?,?,?)');
    for (const b of ballots) addBallot.run(b.id, voteId, b.c);
    const addReceipt = db.prepare('INSERT INTO ws_vote_receipts (vote_id,receipt_hash) VALUES (?,?)');
    for (const r of receipts) addReceipt.run(voteId, r.h);
  }

  // Casting a ballot: one transaction that (1) marks the voter as having voted and (2) stores an
  // encrypted ballot with NO reference to the voter and NO timestamp. Nothing here is logged with an identity.
  W('POST', '/api/ws/votes/:id/ballot', 'vote.cast', ({ me, params, body: b }) => {
    need(isB64(b.ciphertext, 107, 107) && isTok(b.receiptHash)); // sealed box of 32 bytes: fixed length
    const v = getVote(me, params.id);
    if (v.status !== 'open') fail(409, 'vote_closed');
    try {
      db.transaction(() => {
        const r = db.prepare('UPDATE ws_vote_participation SET has_voted=1 WHERE vote_id=? AND member_id=? AND has_voted=0').run(v.id, me.id);
        if (r.changes !== 1) {
          fail(db.prepare('SELECT 1 FROM ws_vote_participation WHERE vote_id=? AND member_id=?').get(v.id, me.id) ? 409 : 403, db.prepare('SELECT 1 FROM ws_vote_participation WHERE vote_id=? AND member_id=?').get(v.id, me.id) ? 'already_voted' : 'not_eligible');
        }
        db.prepare('INSERT INTO ws_ballots (id,vote_id,choice_ciphertext) VALUES (?,?,?)').run(randomUUID(), v.id, b.ciphertext);
        db.prepare('INSERT INTO ws_vote_receipts (vote_id,receipt_hash) VALUES (?,?)').run(v.id, b.receiptHash);
        scrambleVote(v.id); // so the rows on disk do not spell out who voted first
      })();
    } catch (e) { if (e?.status) throw e; constraint(e); }
    return { cast: true };
  });

  W('POST', '/api/ws/votes/:id/close', 'vote.close', ({ me, params }) => {
    const v = getVote(me, params.id);
    if (v.status === 'open') {
      // A vote ends at its closing time, or once every eligible member has voted. Nobody can end it early: that would let whoever holds this
      // permission shut a vote (for instance their own recall) before members have seen it.
      const t = db.prepare('SELECT COUNT(*) e, COALESCE(SUM(has_voted),0) v FROM ws_vote_participation WHERE vote_id=?').get(v.id);
      if (t.v < t.e) fail(409, 'vote_still_open');
      db.prepare("UPDATE ws_votes SET status='closed', closed_at=? WHERE id=?").run(now(), v.id);
      audit(me.wsId, me.id, 'vote.closed', 'vote', v.id);
    }
    return { status: 'closed' };
  });

  W('GET', '/api/ws/votes/:id/tally-bundle', 'vote.tally', ({ me, params }) => {
    const v = getVote(me, params.id);
    if (v.status === 'open') fail(409, 'vote_open');
    if (!JSON.parse(v.committee_json).some((c) => c.memberId === me.id)) fail(403, 'forbidden');
    return {
      votePublicKey: v.vote_public_key, options: JSON.parse(v.options_json), passRule: v.pass_rule, thresholdK: v.threshold_k, committee: JSON.parse(v.committee_json), status: v.status,
      hasEffect: !!v.effect_json, // such a decision must be counted in the open: the ballot key has to be published so anyone can recount
      ballots: db.prepare('SELECT choice_ciphertext c FROM ws_ballots WHERE vote_id=? ORDER BY id').all(v.id).map((r) => r.c),
    };
  });

  function applyEffect(me, v, res) {
    if (!v.effect_json) return null;
    const e = JSON.parse(v.effect_json), t = now();
    if (e.kind === 'dues' && res.passed) {
      db.prepare('INSERT INTO ws_dues_plans (id,workspace_id,name,amount_cents,approved_by_vote_id,created_at) VALUES (?,?,?,?,?,?)').run(randomUUID(), me.wsId, e.name, e.amountCents, v.id, t);
      audit(me.wsId, me.id, 'dues.changed', 'vote', v.id);
      return 'dues';
    }
    if (e.kind === 'policy' && res.passed) {
      const next = { ...policyOf(me), ...e.patch };
      db.prepare('UPDATE ws_workspaces SET policy_json=? WHERE id=?').run(JSON.stringify(next), me.wsId);
      const ver = db.prepare('SELECT COALESCE(MAX(version),0)+1 n FROM ws_bylaws_versions WHERE workspace_id=?').get(me.wsId).n;
      db.prepare('INSERT INTO ws_bylaws_versions (id,workspace_id,version,summary,policy_json,ratified_by_vote_id,created_at) VALUES (?,?,?,?,?,?,?)').run(randomUUID(), me.wsId, ver, v.title, JSON.stringify(next), v.id, t);
      audit(me.wsId, me.id, 'bylaws.amended', 'vote', v.id);
      return 'policy';
    }
    if (e.kind === 'role_revoke' && res.passed) {
      db.prepare('UPDATE ws_roles SET removed_at=?, removed_by_vote_id=? WHERE member_id=? AND role=? AND removed_at IS NULL').run(t, v.id, e.memberId, e.role); // remembered, so an officer cannot quietly give the role back
      audit(me.wsId, me.id, `recall.applied:${e.role}`, 'member', e.memberId);
      return 'role_revoke';
    }
    if (e.kind === 'role_grant' && res.winner != null) {
      db.prepare(`INSERT INTO ws_roles (member_id,role,assigned_by,assigned_at) VALUES (?,?,?,?)
        ON CONFLICT(member_id,role) DO UPDATE SET removed_at=NULL, removed_by_vote_id=NULL, assigned_at=excluded.assigned_at`).run(e.memberIds[res.winner], e.role, me.id, t);
      audit(me.wsId, me.id, `election.applied:${e.role}`, 'member', e.memberIds[res.winner]);
      return 'role_grant';
    }
    return null;
  }

  W('POST', '/api/ws/votes/:id/results', 'vote.tally', ({ me, params, body: b }) => {
    const v = getVote(me, params.id);
    if (v.status === 'open') fail(409, 'vote_open');
    if (v.status === 'tallied') fail(409, 'already_tallied');
    if (!JSON.parse(v.committee_json).some((c) => c.memberId === me.id)) fail(403, 'forbidden');
    const options = JSON.parse(v.options_json);
    const ballots = db.prepare('SELECT choice_ciphertext c FROM ws_ballots WHERE vote_id=? ORDER BY id').all(v.id).map((r) => r.c);
    // Every ballot came from a member who voted, and each has a receipt. A different number means something was added or removed outside the
    // normal path, so nothing is counted until that is explained.
    const t = db.prepare('SELECT COUNT(*) e, COALESCE(SUM(has_voted),0) v FROM ws_vote_participation WHERE vote_id=?').get(v.id);
    const receiptCount = db.prepare('SELECT COUNT(*) c FROM ws_vote_receipts WHERE vote_id=?').get(v.id).c;
    if (ballots.length !== t.v || receiptCount !== t.v) fail(409, 'ballot_count_mismatch', { ballots: ballots.length, receipts: receiptCount, voted: t.v });
    let counts, invalid, attested = 0;
    if (b.secretKey != null) { // the committee chose to publish the key: the server re-counts and refuses a wrong tally
      need(isB64(b.secretKey, 43, 43));
      if (publicFromSecret(b.secretKey) !== v.vote_public_key) fail(400, 'wrong_key');
      ({ counts, invalid } = countBallots(v.vote_public_key, b.secretKey, ballots, options.length));
      if (Array.isArray(b.counts) && b.counts.some((c, i) => c !== counts[i])) fail(400, 'count_mismatch');
    } else {
      // Without the key the server cannot recount, so the result is only as good as the people who vouch for it.
      // A decision that changes who holds a role, the dues or the rules is never accepted this way: everyone must be able to recount it.
      if (v.effect_json) fail(409, 'key_required');
      need(Array.isArray(b.counts) && b.counts.length === options.length && b.counts.every((c) => int(c, 0, 1_000_000)));
      counts = b.counts;
      const sum = counts.reduce((a, c) => a + c, 0);
      if (sum > ballots.length) fail(400, 'count_mismatch');
      invalid = ballots.length - sum;
      // ...and k different committee members must each have signed exactly these counts (one member alone cannot make up a result).
      const committee = JSON.parse(v.committee_json), signers = new Set();
      for (const a of Array.isArray(b.attestations) ? b.attestations.slice(0, 20) : []) {
        if (!isUuid(a?.memberId) || !isB64(a.signature, 86, 86) || !committee.some((c) => c.memberId === a.memberId)) continue;
        const m = db.prepare('SELECT sign_public_key k FROM ws_members WHERE id=? AND workspace_id=?').get(a.memberId, me.wsId);
        if (m?.k && verifyTally(m.k, a.signature, v.id, counts)) signers.add(a.memberId);
      }
      if (signers.size < v.threshold_k) fail(403, 'not_enough_committee', { have: signers.size, need: v.threshold_k });
      attested = signers.size;
    }
    const ev = evaluateVote(counts, v.pass_rule);
    const results = { counts, invalid, total: ev.total, passed: ev.passed, winner: ev.winner, eligible: t.e, voted: t.v, tallyAt: now(), verifiable: b.secretKey != null, ...(attested ? { attestedBy: attested } : {}) };
    let effect = null;
    db.transaction(() => {
      db.prepare("UPDATE ws_votes SET status='tallied', results_json=?, revealed_secret_key=? WHERE id=?").run(JSON.stringify(results), b.secretKey ?? null, v.id);
      audit(me.wsId, me.id, 'vote.tallied', 'vote', v.id);
      effect = applyEffect(me, v, results);
    })();
    return { results, effectApplied: effect };
  });

  // After the key is published, anyone can re-count: ballots are anonymous and the key opens only ballots.
  W('GET', '/api/ws/votes/:id/ballots', 'vote.read', ({ me, params }) => {
    const v = getVote(me, params.id);
    if (!v.revealed_secret_key) fail(409, 'key_not_published');
    return {
      votePublicKey: v.vote_public_key, secretKey: v.revealed_secret_key, options: JSON.parse(v.options_json),
      ballots: db.prepare('SELECT choice_ciphertext c FROM ws_ballots WHERE vote_id=? ORDER BY id').all(v.id).map((r) => r.c),
      receiptHashes: db.prepare('SELECT receipt_hash h FROM ws_vote_receipts WHERE vote_id=? ORDER BY receipt_hash').all(v.id).map((r) => r.h),
    };
  });
  W('GET', '/api/ws/votes/:id/receipts', 'vote.read', ({ me, params }) => {
    const v = getVote(me, params.id);
    if (v.status === 'open') fail(409, 'vote_open');
    return { receiptHashes: db.prepare('SELECT receipt_hash h FROM ws_vote_receipts WHERE vote_id=? ORDER BY receipt_hash').all(v.id).map((r) => r.h) };
  });

  // ---------- petitions: members can force a vote or a recall ----------
  const petitionView = (me, p) => {
    const signers = db.prepare('SELECT COUNT(*) c FROM ws_petition_signers WHERE petition_id=?').get(p.id).c;
    return {
      id: p.id, title: p.title, description: p.description, voteType: p.vote_type, options: JSON.parse(p.options_json), passRule: p.pass_rule, effect: p.effect_json ? JSON.parse(p.effect_json) : null,
      status: p.status, needed: p.needed, signers, signedByMe: !!db.prepare('SELECT 1 FROM ws_petition_signers WHERE petition_id=? AND member_id=?').get(p.id, me.id),
      createdAt: p.created_at, qualifiedAt: p.qualified_at, openBy: p.qualified_at ? addCalendar(p.qualified_at.slice(0, 10), 14) : null, voteId: p.vote_id,
    };
  };
  W('GET', '/api/ws/petitions', 'vote.read', ({ me }) => ({ petitions: db.prepare('SELECT * FROM ws_petitions WHERE workspace_id=? ORDER BY created_at DESC').all(me.wsId).map((p) => petitionView(me, p)) }));
  W('POST', '/api/ws/petitions', 'petition.create', ({ me, body: b }) => {
    const spec = normalizeSpec(me, b);
    const eligible = db.prepare("SELECT COUNT(*) c FROM ws_members WHERE workspace_id=? AND membership_status='member'").get(me.wsId).c;
    const pct = spec.type === 'recall' ? policyOf(me).recallPct : policyOf(me).petitionPct;
    const needed = Math.max(2, Math.ceil((eligible * pct) / 100));
    const id = randomUUID();
    db.transaction(() => {
      db.prepare('INSERT INTO ws_petitions (id,workspace_id,title,description,vote_type,options_json,pass_rule,effect_json,created_by,needed,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
        .run(id, me.wsId, spec.title, spec.description, spec.type, JSON.stringify(spec.options), spec.passRule, spec.effect ? JSON.stringify(spec.effect) : null, me.id, needed, now());
      db.prepare('INSERT INTO ws_petition_signers (petition_id,member_id) VALUES (?,?)').run(id, me.id);
      audit(me.wsId, me.id, 'petition.created', 'petition', id);
    })();
    return { petitionId: id, needed };
  });
  W('POST', '/api/ws/petitions/:id/sign', 'petition.sign', ({ me, params }) => {
    const p = db.prepare('SELECT * FROM ws_petitions WHERE id=? AND workspace_id=?').get(params.id, me.wsId);
    if (!p) fail(404, 'not_found');
    if (p.status === 'opened') fail(409, 'already_opened');
    db.transaction(() => {
      db.prepare('INSERT OR IGNORE INTO ws_petition_signers (petition_id,member_id) VALUES (?,?)').run(p.id, me.id);
      const n = db.prepare('SELECT COUNT(*) c FROM ws_petition_signers WHERE petition_id=?').get(p.id).c;
      if (p.status === 'open' && n >= p.needed) { db.prepare("UPDATE ws_petitions SET status='qualified', qualified_at=? WHERE id=?").run(now(), p.id); audit(me.wsId, me.id, 'petition.qualified', 'petition', p.id); }
    })();
    return petitionView(me, db.prepare('SELECT * FROM ws_petitions WHERE id=?').get(p.id));
  });

  // ---------- grievances: content is end-to-end encrypted; the server only runs the workflow ----------
  const procOf = (me) => JSON.parse(me.ws.procedure_json);
  W('GET', '/api/ws/procedure', 'procedure.read', ({ me }) => procOf(me));
  W('PUT', '/api/ws/procedure', 'procedure.write', ({ me, body: b }) => {
    need(Array.isArray(b.steps) && b.steps.length >= 1 && b.steps.length <= 8 && b.steps.every((s) => isStr(s.name, 80) && int(s.days, 1, 365) && ['calendar', 'business'].includes(s.dayType)));
    const holidays = Array.isArray(b.holidays) ? b.holidays : [];
    need(holidays.length <= 80 && holidays.every((d) => DATE.test(d)));
    db.prepare('UPDATE ws_workspaces SET procedure_json=? WHERE id=?').run(JSON.stringify({ steps: b.steps.map((s) => ({ name: s.name.trim(), days: s.days, dayType: s.dayType })), holidays }), me.wsId);
    audit(me.wsId, me.id, 'procedure.changed', 'workspace', me.wsId);
    return { saved: true };
  });

  function grievanceFor(me, id, mode) {
    const g = db.prepare('SELECT * FROM ws_grievances WHERE id=? AND workspace_id=?').get(id, me.wsId);
    const chief = me.roles.has('chief_steward');
    // Reading is for the chief stewards, the assigned steward and the worker. WORKING a case (steps, decisions, closing, assigning) also takes
    // the case key: the sealed key is what proves the worker's case was entrusted to you. A role alone (a chief steward granted yesterday) is not
    // enough, or one officer could give themselves the role and take over, reassign or close a case they can't even read.
    const keyed = !!g && !!JSON.parse(g.sealed_keys)[me.id];
    const allowed = g && (mode === 'read' ? (chief || g.assigned_to === me.id || g.submitted_by === me.id) : (chief || g.assigned_to === me.id) && keyed);
    if (!allowed) fail(404, 'not_found'); // never reveal whether a case exists to someone who cannot see it
    return g;
  }
  function grievanceMeta(me, g) {
    const step = db.prepare('SELECT * FROM ws_grievance_steps WHERE grievance_id=? AND step_number=?').get(g.id, g.current_step);
    return {
      id: g.id, status: g.status, articleRef: g.article_ref, filedOn: g.filed_on, currentStep: g.current_step, stepName: step?.name || null,
      dueOn: step && !step.completed_on ? step.due_on : null, urgency: step?.due_on && !step.completed_on ? urgency(step.due_on, me.today) : null,
      decision: g.decision, workerNotified: !!g.worker_notified_at, mine: g.submitted_by === me.id,
      assignedTo: g.assigned_to ? { id: g.assigned_to, name: nameOf(me.dk, g.assigned_to) } : null,
    };
  }
  // The contract article is kept in the clear so the case list can show it, so it may only be a short reference like "Art. 12" (the words of the
  // concern are what is encrypted). A longer entry is refused instead of quietly storing, say, a supervisor's name in plaintext.
  const articleRef = (v) => (v == null || v === '' ? null : typeof v === 'string' && ARTICLE_REF.test(v.trim()) ? v.trim() : fail(400, 'bad_article'));
  W('POST', '/api/ws/grievances', 'grievance.submit', ({ me, body: b }) => {
    need(isUuid(b.id) && isB64(b.ciphertext, 16, 60000) && isB64(b.nonce, 32, 32) && b.sealedKeys && typeof b.sealedKeys === 'object');
    const chiefs = holders(me.wsId, 'chief_steward', true);
    if (chiefs.length === 0) fail(409, 'no_chief_steward'); // nobody could read it: refuse instead of losing the worker's words
    const need2 = new Set([me.id, ...chiefs.map((c) => c.id)]);
    const keys = Object.entries(b.sealedKeys);
    need(keys.length <= 40 && keys.every(([k, v]) => isUuid(k) && isB64(v, 60, 300)) && [...need2].every((id) => b.sealedKeys[id]));
    const proc = procOf(me), today = me.today;
    try {
      db.transaction(() => {
        db.prepare(`INSERT INTO ws_grievances (id,workspace_id,submitted_by,article_ref,content_ciphertext,content_nonce,sealed_keys,filed_on,created_at) VALUES (?,?,?,?,?,?,?,?,?)`)
          .run(b.id, me.wsId, me.id, articleRef(b.articleRef), b.ciphertext, b.nonce, JSON.stringify(b.sealedKeys), today, now());
        proc.steps.forEach((s, i) => db.prepare('INSERT INTO ws_grievance_steps (grievance_id,step_number,name,days,day_type,started_on,due_on) VALUES (?,?,?,?,?,?,?)')
          .run(b.id, i + 1, s.name, s.days, s.dayType, i === 0 ? today : null, i === 0 ? dueDate(today, s, proc.holidays) : null));
        audit(me.wsId, me.id, 'grievance.filed', 'grievance', b.id);
      })();
    } catch (e) { constraint(e); }
    return { grievanceId: b.id };
  }, { stage: 'recognized', maxBody: 200_000 });

  W('GET', '/api/ws/grievances', 'grievance.list', ({ me }) => {
    const chief = me.roles.has('chief_steward');
    const rows = chief
      ? db.prepare('SELECT * FROM ws_grievances WHERE workspace_id=? ORDER BY created_at DESC').all(me.wsId)
      : db.prepare('SELECT * FROM ws_grievances WHERE workspace_id=? AND (submitted_by=? OR assigned_to=?) ORDER BY created_at DESC').all(me.wsId, me.id, me.id);
    return { grievances: rows.map((g) => grievanceMeta(me, g)) };
  });

  W('GET', '/api/ws/grievances/:id', 'grievance.list', ({ me, params }) => {
    const g = grievanceFor(me, params.id, 'read');
    if (g.submitted_by !== me.id) audit(me.wsId, me.id, 'grievance.opened', 'member', g.submitted_by); // the worker can see who opened their case
    return {
      ...grievanceMeta(me, g),
      content: { ciphertext: g.content_ciphertext, nonce: g.content_nonce }, sealedKey: JSON.parse(g.sealed_keys)[me.id] || null,
      reason: g.reason_ciphertext ? { ciphertext: g.reason_ciphertext, nonce: g.reason_nonce } : null,
      canWork: me.roles.has('chief_steward') || (g.assigned_to === me.id && me.roles.has('steward')),
      steps: db.prepare('SELECT step_number n, name, days, day_type dayType, started_on startedOn, due_on dueOn, completed_on completedOn, outcome FROM ws_grievance_steps WHERE grievance_id=? ORDER BY step_number').all(g.id)
        .map((s) => ({ ...s, urgency: s.dueOn && !s.completedOn ? urgency(s.dueOn, me.today) : null })),
      notes: db.prepare('SELECT id, author_member_id a, ciphertext, nonce, created_at t FROM ws_grievance_notes WHERE grievance_id=? ORDER BY created_at').all(g.id)
        .map((n) => ({ id: n.id, author: nameOf(me.dk, n.a), ciphertext: n.ciphertext, nonce: n.nonce, at: n.t })),
    };
  });

  W('POST', '/api/ws/grievances/:id/assign', 'grievance.assign', ({ me, params, body: b }) => {
    const g = grievanceFor(me, params.id, 'work');
    need(isUuid(b.stewardId) && isB64(b.sealedKey, 60, 300));
    if (g.status === 'closed') fail(409, 'closed');
    const steward = db.prepare(`SELECT m.id FROM ws_members m JOIN ws_roles r ON r.member_id=m.id WHERE m.id=? AND m.workspace_id=? AND r.role IN ('steward','chief_steward') AND r.removed_at IS NULL AND m.box_public_key IS NOT NULL`).get(b.stewardId, me.wsId);
    if (!steward) fail(404, 'steward_not_found');
    const keys = JSON.parse(g.sealed_keys);
    if (!keys[b.stewardId]) keys[b.stewardId] = b.sealedKey; // the case key is re-sealed to the assigned steward. Nobody's existing key is ever replaced: a junk key would lock them out
    db.prepare('UPDATE ws_grievances SET assigned_to=?, sealed_keys=? WHERE id=?').run(b.stewardId, JSON.stringify(keys), g.id);
    audit(me.wsId, me.id, 'grievance.assigned', 'grievance', g.id);
    return { assigned: true };
  });

  W('POST', '/api/ws/grievances/:id/notes', 'grievance.work', ({ me, params, body: b }) => {
    const g = grievanceFor(me, params.id, 'work');
    need(isB64(b.ciphertext, 16, 30000) && isB64(b.nonce, 32, 32));
    db.prepare('INSERT INTO ws_grievance_notes (id,grievance_id,author_member_id,ciphertext,nonce,created_at) VALUES (?,?,?,?,?,?)').run(randomUUID(), g.id, me.id, b.ciphertext, b.nonce, now());
    return { saved: true };
  });

  W('POST', '/api/ws/grievances/:id/steps/complete', 'grievance.work', ({ me, params, body: b }) => {
    const g = grievanceFor(me, params.id, 'work');
    if (g.status === 'closed') fail(409, 'closed');
    need(['advance', 'resolved', 'denied'].includes(b.outcome));
    const step = db.prepare('SELECT * FROM ws_grievance_steps WHERE grievance_id=? AND step_number=?').get(g.id, g.current_step);
    if (!step || step.completed_on) fail(409, 'no_active_step');
    const holidays = procOf(me).holidays;
    db.transaction(() => {
      db.prepare('UPDATE ws_grievance_steps SET completed_on=?, outcome=? WHERE grievance_id=? AND step_number=?').run(me.today, b.outcome, g.id, step.step_number);
      const next = db.prepare('SELECT * FROM ws_grievance_steps WHERE grievance_id=? AND step_number=?').get(g.id, step.step_number + 1);
      if (next && b.outcome !== 'resolved') { // the next step's clock starts today
        db.prepare('UPDATE ws_grievance_steps SET started_on=?, due_on=? WHERE grievance_id=? AND step_number=?').run(me.today, dueDate(me.today, { days: next.days, dayType: next.day_type }, holidays), g.id, next.step_number);
      }
      db.prepare('UPDATE ws_grievances SET current_step=? WHERE id=?').run(step.step_number + 1, g.id);
      audit(me.wsId, me.id, `grievance.step:${b.outcome}`, 'grievance', g.id);
    })();
    return { ok: true };
  });

  // Fair representation: every case ends with a recorded decision and reason, and the worker is told.
  W('POST', '/api/ws/grievances/:id/decision', 'grievance.work', ({ me, params, body: b }) => {
    const g = grievanceFor(me, params.id, 'work');
    if (g.status === 'closed') fail(409, 'closed');
    need(GRIEVANCE_DECISIONS.includes(b.decision) && isB64(b.reasonCiphertext, 16, 30000) && isB64(b.reasonNonce, 32, 32));
    db.prepare('UPDATE ws_grievances SET decision=?, reason_ciphertext=?, reason_nonce=?, worker_notified_at=NULL WHERE id=?').run(b.decision, b.reasonCiphertext, b.reasonNonce, g.id);
    audit(me.wsId, me.id, `grievance.decision:${b.decision}`, 'grievance', g.id);
    return { ok: true };
  });
  W('POST', '/api/ws/grievances/:id/notify-worker', 'grievance.work', ({ me, params }) => {
    const g = grievanceFor(me, params.id, 'work');
    if (!g.decision) fail(409, 'no_decision');
    db.prepare('UPDATE ws_grievances SET worker_notified_at=? WHERE id=?').run(now(), g.id);
    audit(me.wsId, me.id, 'grievance.worker_notified', 'grievance', g.id);
    return { ok: true };
  });
  W('POST', '/api/ws/grievances/:id/close', 'grievance.work', ({ me, params }) => {
    const g = grievanceFor(me, params.id, 'work');
    if (g.status === 'closed') fail(409, 'closed');
    const missing = [];
    if (!g.decision) missing.push('decision');
    if (!g.reason_ciphertext) missing.push('reason');
    if (!g.worker_notified_at) missing.push('worker_notification');
    if (missing.length) fail(409, 'cannot_close', { missing });
    db.prepare("UPDATE ws_grievances SET status='closed', closed_at=? WHERE id=?").run(now(), g.id);
    audit(me.wsId, me.id, 'grievance.closed', 'grievance', g.id);
    return { closed: true };
  });

  // ---------- money: hash-chained ledger ----------
  const LEDGER_PRIVATE = ['ledger.payee', 'ledger.memo'];
  function addLedger(me, { kind, amountCents, category, payee, memo, disbursementId = null, reversesId = null, reversesSeq = null }) {
    const last = db.prepare('SELECT seq, hash FROM ws_ledger WHERE workspace_id=? ORDER BY seq DESC LIMIT 1').get(me.wsId);
    const seq = (last?.seq || 0) + 1, at = now(), date = me.today;
    const salt = b64(randomBytes(16));
    const commit = sha256Text(`${salt}|${payee || ''}|${memo || ''}`); // members verify the chain without seeing the private text
    const hash = chainHash(last?.hash || GENESIS, { seq, date, kind, cents: amountCents, cat: category, rev: reversesSeq, at, commit });
    const id = randomUUID();
    db.prepare(`INSERT INTO ws_ledger (id,workspace_id,seq,entry_date,kind,amount_cents,category,payee_enc,memo_enc,commit_hash,disbursement_id,reverses_id,created_by,created_at,prev_hash,hash)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, me.wsId, seq, date, kind, amountCents, category, enc(me.dk, LEDGER_PRIVATE[0], payee), enc(me.dk, LEDGER_PRIVATE[1], JSON.stringify({ memo: memo || '', salt })),
      commit, disbursementId, reversesId, me.id, at, last?.hash || GENESIS, hash);
    return { id, seq, hash };
  }
  const money = (b) => { need(int(b.amountCents, 1, 100_000_000_000)); return b.amountCents; };

  W('GET', '/api/ws/finance/summary', 'finance.read', ({ me }) => {
    const rows = db.prepare('SELECT * FROM ws_ledger WHERE workspace_id=? ORDER BY seq').all(me.wsId);
    const byId = new Map(rows.map((r) => [r.id, r]));
    const reversedIds = new Set(rows.filter((r) => r.reverses_id).map((r) => r.reverses_id));
    let balance = 0;
    const byCategory = { receipts: {}, disbursements: {} }, byMonth = {};
    for (const r of rows) {
      balance += r.kind === 'receipt' ? r.amount_cents : -r.amount_cents;
      const orig = r.reverses_id ? byId.get(r.reverses_id) : null;
      const kind = orig ? orig.kind : r.kind, amt = orig ? -r.amount_cents : r.amount_cents; // a reversal cancels its original
      const bucket = kind === 'receipt' ? byCategory.receipts : byCategory.disbursements;
      bucket[r.category] = (bucket[r.category] || 0) + amt;
      const mo = (byMonth[r.entry_date.slice(0, 7)] ||= { receipts: 0, disbursements: 0 });
      mo[kind === 'receipt' ? 'receipts' : 'disbursements'] += amt;
    }
    const seqOf = new Map(rows.map((r) => [r.id, r.seq]));
    const view = (r) => {
      const redact = REDACTED_CATEGORIES.includes(r.category);
      const priv = r.memo_enc ? JSON.parse(dec(me.dk, LEDGER_PRIVATE[1], r.memo_enc)) : {};
      return { id: r.id, seq: r.seq, date: r.entry_date, kind: r.kind, amountCents: r.amount_cents, category: r.category, payee: redact ? 'Member' : dec(me.dk, LEDGER_PRIVATE[0], r.payee_enc), memo: redact ? '' : priv.memo || '',
        reversesSeq: r.reverses_id ? seqOf.get(r.reverses_id) : null, reversed: reversedIds.has(r.id), createdBy: nameOf(me.dk, r.created_by), hash: r.hash };
    };
    const pending = db.prepare("SELECT * FROM ws_disbursements WHERE workspace_id=? AND status IN ('pending','approved') ORDER BY created_at").all(me.wsId).map((d) => {
      const redact = REDACTED_CATEGORIES.includes(d.category);
      const approvals = db.prepare("SELECT approver_id a FROM ws_disbursement_approvals WHERE disbursement_id=? AND decision='approve'").all(d.id);
      return { id: d.id, amountCents: d.amount_cents, category: d.category, payee: redact ? 'Member' : dec(me.dk, 'disb.payee', d.payee_enc), memo: redact ? '' : dec(me.dk, 'disb.memo', d.memo_enc), status: d.status,
        requiredApprovals: d.required_approvals, approvals: approvals.length, approvedByMe: approvals.some((a) => a.a === me.id), mine: d.requested_by === me.id, requestedBy: nameOf(me.dk, d.requested_by), createdAt: d.created_at };
    });
    const dues = db.prepare('SELECT name, amount_cents a, approved_by_vote_id v, created_at t FROM ws_dues_plans WHERE workspace_id=? ORDER BY created_at DESC').all(me.wsId);
    const head = rows.at(-1);
    return {
      balanceCents: balance, byCategory, byMonth, entries: rows.map(view).reverse().slice(0, 300), pending, head: head ? { seq: head.seq, hash: head.hash } : null,
      dues: dues.map((d) => ({ name: d.name, amountCents: d.a, voteId: d.v, at: d.t })), twoApprovalCents: policyOf(me).twoApprovalCents,
      categories: { receipts: RECEIPT_CATEGORIES, disbursements: DISBURSEMENT_CATEGORIES },
    };
  });
  // Public fields plus each entry's hash. Any member's browser can re-derive every hash and spot tampering.
  W('GET', '/api/ws/finance/chain', 'finance.read', ({ me }) => {
    const rows = db.prepare('SELECT * FROM ws_ledger WHERE workspace_id=? ORDER BY seq').all(me.wsId);
    const seqOf = new Map(rows.map((r) => [r.id, r.seq]));
    return { genesis: GENESIS, entries: rows.map((r) => ({ seq: r.seq, date: r.entry_date, kind: r.kind, cents: r.amount_cents, cat: r.category, rev: r.reverses_id ? seqOf.get(r.reverses_id) : null, at: r.created_at, commit: r.commit_hash, prevHash: r.prev_hash, hash: r.hash })) };
  });
  W('POST', '/api/ws/ledger/receipt', 'ledger.record', ({ me, body: b }) => {
    need(Object.hasOwn(RECEIPT_CATEGORIES, b.category)); // own keys only: "constructor" is a property of every object
    const r = addLedger(me, { kind: 'receipt', amountCents: money(b), category: b.category, payee: optStr(b.payer, 120), memo: optStr(b.memo, 300) });
    audit(me.wsId, me.id, 'ledger.receipt', 'ledger', r.id);
    return r;
  });
  W('POST', '/api/ws/ledger/:id/reverse', 'ledger.reverse', ({ me, params, body: b }) => {
    const e = db.prepare('SELECT * FROM ws_ledger WHERE id=? AND workspace_id=?').get(params.id, me.wsId);
    if (!e) fail(404, 'not_found');
    if (e.reverses_id) fail(409, 'is_reversal');
    need(isStr(b.reason, 300));
    let r;
    try {
      r = addLedger(me, { kind: e.kind === 'receipt' ? 'disbursement' : 'receipt', amountCents: e.amount_cents, category: e.category, payee: '', memo: 'Reversal: ' + b.reason.trim(), reversesId: e.id, reversesSeq: e.seq });
    } catch (err) { constraint(err); }
    audit(me.wsId, me.id, 'ledger.reversal', 'ledger', e.id);
    return r;
  });

  const disbursementNeeds = (me, cents) => (cents >= policyOf(me).twoApprovalCents ? 2 : 1);
  W('POST', '/api/ws/disbursements', 'disbursement.request', ({ me, body: b }) => {
    need(Object.hasOwn(DISBURSEMENT_CATEGORIES, b.category) && isStr(b.payee, 120));
    const cents = money(b), id = randomUUID();
    db.prepare('INSERT INTO ws_disbursements (id,workspace_id,requested_by,amount_cents,category,payee_enc,memo_enc,required_approvals,created_at) VALUES (?,?,?,?,?,?,?,?,?)')
      .run(id, me.wsId, me.id, cents, b.category, enc(me.dk, 'disb.payee', b.payee.trim()), enc(me.dk, 'disb.memo', optStr(b.memo, 300)), disbursementNeeds(me, cents), now());
    audit(me.wsId, me.id, 'disbursement.requested', 'disbursement', id);
    return { id, requiredApprovals: disbursementNeeds(me, cents) };
  });
  W('POST', '/api/ws/disbursements/:id/approve', 'disbursement.approve', ({ me, params, body: b }) => {
    const d = db.prepare('SELECT * FROM ws_disbursements WHERE id=? AND workspace_id=?').get(params.id, me.wsId);
    if (!d) fail(404, 'not_found');
    if (d.requested_by === me.id) fail(403, 'own_request'); // nobody approves their own request
    if (d.status !== 'pending') fail(409, 'not_pending');
    const decision = b.decision === 'reject' ? 'reject' : 'approve';
    try {
      db.transaction(() => {
        db.prepare('INSERT INTO ws_disbursement_approvals (disbursement_id,approver_id,decision,created_at) VALUES (?,?,?,?)').run(d.id, me.id, decision, now());
        if (decision === 'reject') db.prepare("UPDATE ws_disbursements SET status='rejected' WHERE id=?").run(d.id);
        else if (db.prepare("SELECT COUNT(*) c FROM ws_disbursement_approvals WHERE disbursement_id=? AND decision='approve'").get(d.id).c >= d.required_approvals) db.prepare("UPDATE ws_disbursements SET status='approved' WHERE id=?").run(d.id);
        audit(me.wsId, me.id, `disbursement.${decision}`, 'disbursement', d.id);
      })();
    } catch (e) { constraint(e); } // a second approval from the same person is a conflict, not a second approver
    return { status: db.prepare('SELECT status FROM ws_disbursements WHERE id=?').get(d.id).status };
  });
  W('POST', '/api/ws/disbursements/:id/pay', 'disbursement.pay', ({ me, params }) => {
    const d = db.prepare('SELECT * FROM ws_disbursements WHERE id=? AND workspace_id=?').get(params.id, me.wsId);
    if (!d) fail(404, 'not_found');
    if (d.status !== 'approved') fail(409, 'not_approved');
    let r;
    db.transaction(() => {
      r = addLedger(me, { kind: 'disbursement', amountCents: d.amount_cents, category: d.category, payee: dec(me.dk, 'disb.payee', d.payee_enc), memo: dec(me.dk, 'disb.memo', d.memo_enc), disbursementId: d.id });
      db.prepare("UPDATE ws_disbursements SET status='paid', paid_ledger_id=? WHERE id=?").run(r.id, d.id);
      audit(me.wsId, me.id, 'disbursement.paid', 'disbursement', d.id);
    })();
    return r;
  });

  // ---------- transparency ----------
  W('GET', '/api/ws/audit', 'audit.read_all', ({ me }) => {
    const rows = db.prepare('SELECT * FROM ws_audit WHERE workspace_id=? ORDER BY seq').all(me.wsId);
    const names = new Map();
    const nm = (id) => (id ? (names.has(id) ? names.get(id) : (names.set(id, nameOf(me.dk, id)), names.get(id))) : null);
    return {
      genesis: GENESIS,
      entries: rows.map((r) => ({ seq: r.seq, actorId: r.actor_member_id, actor: nm(r.actor_member_id), action: r.action, type: r.resource_type, id: r.resource_id, at: r.created_at, prevHash: r.prev_hash, hash: r.hash })).reverse().slice(0, 500),
      head: rows.at(-1) ? { seq: rows.at(-1).seq, hash: rows.at(-1).hash } : null,
    };
  });

  // The union owns its data: a complete export, always available to officers, and itself audit-logged.
  // End-to-end records (grievance content, notes, reasons) are exported as ciphertext: only their holders can read them.
  W('GET', '/api/ws/export', 'export.all', ({ me }) => {
    const all = (sql, ...a) => db.prepare(sql).all(...a);
    const memberRows = all('SELECT * FROM ws_members WHERE workspace_id=?', me.wsId);
    // Every look at someone's data is logged where they can see it, and an export is a look at everyone's.
    db.transaction(() => {
      audit(me.wsId, me.id, 'export.all', 'workspace', me.wsId);
      for (const m of memberRows) if (m.id !== me.id) audit(me.wsId, me.id, 'member.pii.read', 'member', m.id);
    })();
    const w = me.ws;
    const seqOf = new Map(all('SELECT id, seq FROM ws_ledger WHERE workspace_id=?', me.wsId).map((r) => [r.id, r.seq]));
    return {
      format: 'ludlow-export-v1', exportedAt: now(),
      workspace: { id: w.id, unionName: w.union_name, employerName: w.employer_name, unitDescription: w.unit_description, stage: w.stage, stageNote: w.stage_note, jurisdiction: w.jurisdiction, timezone: w.timezone, fiscalYearStart: w.fiscal_year_start, policy: policyOf(me), procedure: procOf(me), createdAt: w.created_at },
      members: memberRows.map((m) => person(me.dk, m)),
      roles: all('SELECT member_id memberId, role, assigned_at assignedAt, removed_at removedAt FROM ws_roles WHERE member_id IN (SELECT id FROM ws_members WHERE workspace_id=?)', me.wsId),
      bylawsVersions: all('SELECT version, summary, policy_json p, ratified_by_vote_id voteId, created_at at FROM ws_bylaws_versions WHERE workspace_id=? ORDER BY version', me.wsId).map((r) => ({ ...r, policy: JSON.parse(r.p), p: undefined })),
      announcements: all('SELECT title, body, created_at at FROM ws_announcements WHERE workspace_id=? ORDER BY created_at', me.wsId),
      votes: all('SELECT * FROM ws_votes WHERE workspace_id=? ORDER BY created_at', me.wsId).map((v) => ({
        id: v.id, title: v.title, description: v.description, type: v.type, options: JSON.parse(v.options_json), passRule: v.pass_rule, status: v.status, closesAt: v.closes_at,
        effect: v.effect_json ? JSON.parse(v.effect_json) : null, results: v.results_json ? JSON.parse(v.results_json) : null, revealedSecretKey: v.revealed_secret_key,
        // Ballots and receipts leave only once the vote is counted. While it is open, reading them as they arrive would isolate each ballot with its receipt.
        ...(v.status === 'tallied' ? { ballots: all('SELECT choice_ciphertext c FROM ws_ballots WHERE vote_id=?', v.id).map((r) => r.c), receiptHashes: all('SELECT receipt_hash h FROM ws_vote_receipts WHERE vote_id=?', v.id).map((r) => r.h) } : { ballots: [], receiptHashes: [] }),
      })),
      petitions: all('SELECT * FROM ws_petitions WHERE workspace_id=?', me.wsId).map((p) => ({ id: p.id, title: p.title, description: p.description, voteType: p.vote_type, status: p.status, needed: p.needed, signers: all('SELECT COUNT(*) c FROM ws_petition_signers WHERE petition_id=?', p.id)[0].c })),
      grievances: all('SELECT * FROM ws_grievances WHERE workspace_id=?', me.wsId).map((g) => ({
        id: g.id, status: g.status, filedOn: g.filed_on, closedAt: g.closed_at, articleRef: g.article_ref, decision: g.decision, workerNotifiedAt: g.worker_notified_at,
        steps: all('SELECT step_number n, name, days, day_type dayType, started_on startedOn, due_on dueOn, completed_on completedOn, outcome FROM ws_grievance_steps WHERE grievance_id=? ORDER BY step_number', g.id),
        encrypted: { content: { ciphertext: g.content_ciphertext, nonce: g.content_nonce }, reason: g.reason_ciphertext ? { ciphertext: g.reason_ciphertext, nonce: g.reason_nonce } : null, sealedKeys: JSON.parse(g.sealed_keys),
          notes: all('SELECT ciphertext, nonce, created_at at FROM ws_grievance_notes WHERE grievance_id=? ORDER BY created_at', g.id) },
      })),
      ledger: all('SELECT * FROM ws_ledger WHERE workspace_id=? ORDER BY seq', me.wsId).map((r) => {
        const priv = r.memo_enc ? JSON.parse(dec(me.dk, LEDGER_PRIVATE[1], r.memo_enc)) : {};
        return { seq: r.seq, date: r.entry_date, kind: r.kind, amountCents: r.amount_cents, category: r.category, payee: dec(me.dk, LEDGER_PRIVATE[0], r.payee_enc), memo: priv.memo || '', salt: priv.salt, reversesSeq: r.reverses_id ? seqOf.get(r.reverses_id) : null, at: r.created_at, prevHash: r.prev_hash, hash: r.hash, commit: r.commit_hash };
      }),
      dues: all('SELECT name, amount_cents amountCents, approved_by_vote_id voteId, created_at at FROM ws_dues_plans WHERE workspace_id=? ORDER BY created_at', me.wsId),
      audit: all('SELECT seq, actor_member_id actorId, action, resource_type type, resource_id id, created_at at, prev_hash prevHash, hash FROM ws_audit WHERE workspace_id=? ORDER BY seq', me.wsId),
    };
  });

  W('GET', '/api/ws/health', 'health.read', ({ me }) => {
    const q = (sql, ...a) => db.prepare(sql).get(...a);
    const total = q('SELECT COUNT(*) c FROM ws_members WHERE workspace_id=?', me.wsId).c;
    const members = q("SELECT COUNT(*) c FROM ws_members WHERE workspace_id=? AND membership_status='member'", me.wsId).c;
    const shifts = db.prepare("SELECT COALESCE(shift,'(none)') s, COUNT(*) t, SUM(membership_status='member') m FROM ws_members WHERE workspace_id=? GROUP BY s").all(me.wsId)
      .map((r) => (r.t < SMALL_GROUP ? { shift: r.s, suppressed: true } : { shift: r.s, total: r.t, members: r.m })); // small groups are hidden so nobody can be picked out
    const open = q("SELECT COUNT(*) c FROM ws_grievances WHERE workspace_id=? AND status='open'", me.wsId).c;
    const overdue = q(`SELECT COUNT(*) c FROM ws_grievance_steps s JOIN ws_grievances g ON g.id=s.grievance_id WHERE g.workspace_id=? AND g.status='open' AND g.current_step=s.step_number AND s.completed_on IS NULL AND s.due_on < ?`, me.wsId, me.today).c;
    const avg = q("SELECT AVG(julianday(closed_at)-julianday(created_at)) d FROM ws_grievances WHERE workspace_id=? AND status='closed'", me.wsId).d;
    const tallied = db.prepare("SELECT results_json r FROM ws_votes WHERE workspace_id=? AND status='tallied'").all(me.wsId).map((r) => JSON.parse(r.r));
    const turnout = tallied.length ? tallied.reduce((a, r) => a + (r.eligible ? r.voted / r.eligible : 0), 0) / tallied.length : null;
    return { unitSize: total, members, membershipRate: total ? members / total : 0, shifts, openGrievances: open, overdueSteps: overdue, avgResolutionDays: avg == null ? null : Math.round(avg * 10) / 10, votesHeld: tallied.length, avgTurnout: turnout };
  });

  const addMonths = (iso, n) => { const d = new Date(iso); d.setUTCMonth(d.getUTCMonth() + n); return d.toISOString().slice(0, 10); };
  W('GET', '/api/ws/compliance', 'compliance.read', ({ me }) => {
    const receipts = db.prepare("SELECT COALESCE(SUM(amount_cents),0) c FROM ws_ledger WHERE workspace_id=? AND kind='receipt' AND reverses_id IS NULL").get(me.wsId).c;
    const tasks = complianceTasks({ createdOn: me.ws.created_at.slice(0, 10), fiscalYearStart: me.ws.fiscal_year_start, today: me.today, receiptsCents: receipts });
    const first = db.prepare("SELECT MIN(r.assigned_at) a FROM ws_roles r JOIN ws_members m ON m.id=r.member_id WHERE m.workspace_id=? AND r.role='officer' AND r.removed_at IS NULL").get(me.wsId).a;
    if (first) {
      const end = addMonths(first, policyOf(me).termMonths);
      tasks.push({ key: 'terms', title: `Officer terms end ${end}: begin election preparation`, dueOn: addCalendar(end, -120), owner: 'officer', verify: 'lawyer', detail: 'Reminders come 120 and 60 days before terms end. Term length comes from your bylaws.' });
    }
    const done = new Map(db.prepare('SELECT task_key k, done_at d FROM ws_compliance WHERE workspace_id=?').all(me.wsId).map((r) => [r.k, r.d]));
    return { tasks: tasks.map((t) => ({ ...t, doneAt: done.get(t.key) || null, urgency: t.dueOn ? urgency(t.dueOn, me.today) : null })) };
  });
  W('POST', '/api/ws/compliance/:key/toggle', 'compliance.write', ({ me, params }) => {
    need(/^[a-z0-9_]{1,30}$/.test(params.key));
    const cur = db.prepare('SELECT done_at d FROM ws_compliance WHERE workspace_id=? AND task_key=?').get(me.wsId, params.key);
    db.prepare('INSERT INTO ws_compliance (workspace_id,task_key,done_at) VALUES (?,?,?) ON CONFLICT(workspace_id,task_key) DO UPDATE SET done_at=excluded.done_at').run(me.wsId, params.key, cur?.d ? null : now());
    return { done: !cur?.d };
  });
}
