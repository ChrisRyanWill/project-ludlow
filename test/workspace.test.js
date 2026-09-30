import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as C from '../shared/crypto.js';
import * as D from '../shared/deadlines.js';
import { verifyChain, ledgerFields, auditFields, checkPinned, checkCommitments } from '../shared/verify.js';
import { can, ROLES } from '../shared/permissions.js';
import { startApp, makeWorkspace, login } from './helpers.js';
import { physicalOrder } from './sqlite-pages.js';

const person = (name, i, extra = {}) => ({ name, email: `${name.split(' ')[0].toLowerCase()}+leak@example.com`, phone: `+155501990${i}0`, address: `${i} Leakcheck Lane`, jobTitle: 'Leakcheck Barista', status: 'member', shift: i < 6 ? 'Day' : 'Night', ...extra });
const PEOPLE = [
  person('Ofelia Qqqofficer', 0, { roles: ['officer', 'treasurer', 'chief_steward'] }),
  person('Enzo Qqqelect', 1, { roles: ['officer', 'election_committee'] }),
  person('Elena Qqqelect', 2, { roles: ['officer', 'election_committee'] }),
  person('Ezra Qqqelect', 3, { roles: ['election_committee'] }),
  person('Mona Qqqmember', 4),
  person('Marco Qqqmember', 5),
  person('Una Qqqunit', 6, { status: 'unit_employee' }), // a unit employee who has not joined the union
  person('Sam Qqqsteward', 7, { roles: ['steward'] }),
];
const NEEDLES = [...PEOPLE.flatMap((p) => [p.name, p.email, p.phone, p.address]), 'Leakcheck Barista', 'Zyxwvut grievance narrative', 'Zyxwvut reason', 'Zyxwvut Payee', 'Zyxwvut memo'];
const V = [0, 1, 2, 3, 4, 5, 7]; // indexes of the union's members (Una has not joined)

async function openVote(ws, idx, spec, k = 2) {
  const ring = await ws.as(idx, 'GET', '/api/ws/keyring?role=election_committee');
  const vk = await C.newVoteKeys(ring.json.holders, k);
  const r = await ws.as(idx, 'POST', '/api/ws/votes', { closesAt: new Date(Date.now() + 3600_000).toISOString(), votePublicKey: vk.votePublicKey, committee: vk.committee, thresholdK: k, ...spec });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  return (await ws.as(idx, 'GET', `/api/ws/votes/${r.json.voteId}`)).json;
}
async function cast(ws, idx, vote, option) {
  const b = C.castBallot(vote.votePublicKey, option);
  return { r: await ws.as(idx, 'POST', `/api/ws/votes/${vote.id}/ballot`, { ciphertext: b.ciphertext, receiptHash: b.receiptHash }), receipt: b.receiptCode };
}
// A vote ends at its closing time (or when everyone has voted). Tests move the closing time into the past instead of waiting for it.
const endVote = (ws, voteId) => ws.h.app.db.prepare('UPDATE ws_votes SET closes_at=? WHERE id=?').run(new Date(Date.now() - 1000).toISOString(), voteId);
async function tally(ws, closer, vote, committeeIdx, { publish = true } = {}) {
  endVote(ws, vote.id);
  const shares = []; let bundle;
  for (const i of committeeIdx) {
    bundle = (await ws.as(i, 'GET', `/api/ws/votes/${vote.id}/tally-bundle`)).json;
    const mine = bundle.committee.find((c) => c.memberId === ws.members[i].id);
    shares.push(C.boxOpen(mine.sealed, ws.members[i].keys.boxPublicKey, ws.members[i].keys.boxSecretKey));
  }
  const sk = await C.reconstructVoteKey(shares);
  const { counts } = C.countBallots(bundle.votePublicKey, sk, bundle.ballots, bundle.options.length);
  return ws.as(committeeIdx[0], 'POST', `/api/ws/votes/${vote.id}/results`, publish ? { counts, secretKey: sk } : { counts });
}
async function runVote(ws, spec, yes, no, committeeIdx = [1, 3]) {
  const vote = await openVote(ws, 0, spec);
  const receipts = [];
  for (const i of yes) receipts.push((await cast(ws, i, vote, 0)).receipt);
  for (const i of no) receipts.push((await cast(ws, i, vote, 1)).receipt);
  const res = await tally(ws, 1, vote, committeeIdx);
  return { vote, res, receipts };
}

describe('workspace: founding, accounts, audit', () => {
  let h, ws;
  before(async () => { h = await startApp(); ws = await makeWorkspace(h, PEOPLE); });
  after(() => h.stop());

  it('refuses to found a workspace unless the union has confirmed it already went public', async () => {
    const body = { stage: 'recognized', unionName: 'U', employerName: 'E', members: [{ legalName: 'A B', roles: ['officer'], claimTokenHash: C.hashToken(C.newToken()) }] };
    assert.equal((await h.call('POST', '/api/ws', { body })).json.error, 'confirmation_required');
    assert.equal((await h.call('POST', '/api/ws', { body: { ...body, confirmedPublic: 'yes' } })).json.error, 'confirmation_required');
    assert.equal((await h.call('POST', '/api/ws', { body: { ...body, confirmedPublic: true, members: [{ ...body.members[0], roles: [] }] } })).json.error, 'officer_required');
    assert.equal((await h.call('POST', '/api/ws', { body: { ...body, confirmedPublic: true } })).status, 200);
  });

  it('claim tokens are single-use, and sign-in needs a fresh signature', async () => {
    const tok = C.newToken();
    const r = await h.call('POST', '/api/ws', { body: { confirmedPublic: true, stage: 'recognized', unionName: 'U', employerName: 'E', members: [{ legalName: 'C D', roles: ['officer'], claimTokenHash: C.hashToken(tok) }] } });
    const keys = C.newKeypairs();
    const claim = { workspaceId: r.json.workspaceId, claimToken: tok, boxPublicKey: keys.boxPublicKey, signPublicKey: keys.signPublicKey };
    const c1 = await h.call('POST', '/api/ws/claim', { body: claim });
    assert.equal(c1.status, 200);
    assert.equal((await h.call('POST', '/api/ws/claim', { body: claim })).status, 401);
    const { json: ch } = await h.call('POST', '/api/auth/challenge');
    const signature = C.signAuth(keys.signSecretKey, { nonce: ch.nonce, route: 'POST /api/ws/auth/login', scope: c1.json.memberId });
    const body = { memberId: c1.json.memberId, challengeId: ch.challengeId, signature };
    assert.equal((await h.call('POST', '/api/ws/auth/login', { body })).status, 200);
    assert.equal((await h.call('POST', '/api/ws/auth/login', { body })).status, 401); // replay
    assert.equal((await h.call('GET', '/api/ws/me')).status, 401);
    assert.equal((await h.call('GET', '/api/ws/me', { auth: 'Bearer ' + C.newToken() })).status, 401);
  });

  it('sessions expire when idle', async () => {
    const m = await login(h, { ...ws.members[4] });
    assert.equal((await h.call('GET', '/api/ws/me', { auth: m.auth })).status, 200);
    h.app.db.prepare('UPDATE ws_sessions SET last_seen_at=? WHERE token_hash=?').run(new Date(Date.now() - 13 * 3600_000).toISOString(), C.hashToken(m.token));
    assert.equal((await h.call('GET', '/api/ws/me', { auth: m.auth })).json.error, 'session_expired');
  });

  it('personal data is readable to permitted roles and every read is logged where the member can see it', async () => {
    const roster = await ws.as(0, 'GET', '/api/ws/roster');
    assert.equal(roster.json.members.length, 8);
    const una = roster.json.members.find((m) => m.name.startsWith('Una'));
    assert.deepEqual([una.email, una.phone, una.address, una.jobTitle], ['una+leak@example.com', '+15550199060', '6 Leakcheck Lane', 'Leakcheck Barista']);
    assert.equal((await ws.as(4, 'GET', '/api/ws/roster')).status, 403);
    const log = await ws.as(6, 'GET', '/api/ws/me/access-log');
    assert.ok(log.json.entries.some((e) => e.action === 'member.pii.read' && e.actor.startsWith('Ofelia')));
    assert.equal((await ws.as(4, 'GET', '/api/ws/me/access-log')).json.entries.length, 1);
    const own = await ws.as(0, 'GET', '/api/ws/me/access-log'); // your own reads are not "someone else" looking
    assert.equal(own.json.entries.length, 0);
  });

  it('roles: assigned by officers, visible to everyone, and the last officer cannot be removed', async () => {
    assert.equal((await ws.as(4, 'POST', '/api/ws/roles', { memberId: ws.members[4].id, role: 'officer', op: 'add' })).status, 403);
    assert.equal((await ws.as(0, 'POST', '/api/ws/roles', { memberId: ws.members[4].id, role: 'steward', op: 'add' })).status, 200);
    const list = await ws.as(6, 'GET', '/api/ws/roles');
    assert.ok(list.json.roles.some((r) => r.role === 'steward' && r.name.startsWith('Mona')));
    assert.equal((await ws.as(0, 'POST', '/api/ws/roles', { memberId: ws.members[4].id, role: 'steward', op: 'remove' })).status, 200);
    for (const i of [1, 2]) await ws.as(0, 'POST', '/api/ws/roles', { memberId: ws.members[i].id, role: 'officer', op: 'remove' });
    assert.equal((await ws.as(0, 'POST', '/api/ws/roles', { memberId: ws.members[0].id, role: 'officer', op: 'remove' })).json.error, 'last_officer');
    for (const i of [1, 2]) await ws.as(0, 'POST', '/api/ws/roles', { memberId: ws.members[i].id, role: 'officer', op: 'add' });
  });

  it('the union owns its data: officers can export everything, and the export itself is audited', async () => {
    const before = h.logs.length;
    const ex = await ws.as(0, 'GET', '/api/ws/export');
    assert.equal(ex.status, 200);
    assert.equal(ex.json.format, 'ludlow-export-v1');
    assert.equal(ex.json.members.length, 8);
    assert.ok(ex.json.members.some((m) => m.email === 'una+leak@example.com')); // readable to the union that owns it
    assert.ok(ex.json.audit.length >= 8);
    assert.equal((await ws.as(4, 'GET', '/api/ws/export')).status, 403);
    const log = (await ws.as(0, 'GET', '/api/ws/audit')).json.entries;
    assert.ok(log.some((e) => e.action === 'export.all' && e.actor.startsWith('Ofelia')));
    assert.ok(h.logs.slice(before).every((l) => !l.includes('una+leak'))); // and never in server logs
  });

  it('announcements and joining the union', async () => {
    assert.equal((await ws.as(4, 'POST', '/api/ws/announcements', { title: 't', body: 'b' })).status, 403);
    assert.equal((await ws.as(0, 'POST', '/api/ws/announcements', { title: 'First meeting', body: 'Thursday at noon.' })).status, 200);
    assert.equal((await ws.as(6, 'GET', '/api/ws/announcements')).json.items[0].title, 'First meeting');
    assert.equal((await ws.as(6, 'GET', '/api/ws/me')).json.roles.includes('member'), false);
    await ws.as(6, 'POST', '/api/ws/me/join');
    assert.ok((await ws.as(6, 'GET', '/api/ws/me')).json.roles.includes('member'));
    h.app.db.prepare("UPDATE ws_members SET membership_status='unit_employee', joined_at=NULL WHERE id=?").run(ws.members[6].id); // back to a non-member for later tests
  });

  it('plaintext-leak test: names, emails, phones, addresses and job titles are ciphertext on disk, and no token is logged', () => {
    assert.deepEqual(h.leaks([...NEEDLES, ...ws.members.map((m) => m.token)]), []);
    const row = h.app.db.prepare('SELECT legal_name_enc, email_enc FROM ws_members LIMIT 1').get();
    assert.match(row.legal_name_enc, /^v2\./);
  });
});

describe('workspace: the permission matrix', () => {
  let h, mx;
  const ROLE_PEOPLE = [
    ['super', { roles: ['officer', 'treasurer', 'chief_steward', 'steward', 'election_committee'] }],
    ['unit_employee', { status: 'unit_employee' }], ['member', {}],
    ['steward', { roles: ['steward'] }], ['chief_steward', { roles: ['chief_steward'] }], ['officer', { roles: ['officer'] }],
    ['treasurer', { roles: ['treasurer'] }], ['election_committee', { roles: ['election_committee'] }],
  ];
  before(async () => { h = await startApp(); mx = await makeWorkspace(h, ROLE_PEOPLE.map(([n, e], i) => person('Matrix ' + n.replace('_', ''), i, e))); });
  after(() => h.stop());

  it('every workspace route × every role matches shared/permissions.js, and anonymous callers get 401', async () => {
    const routes = h.app.router.routes.filter((r) => r.opts.ws);
    assert.ok(routes.length >= 45, 'found ' + routes.length + ' workspace routes');
    const skip = new Set(['/api/ws/auth/logout', '/api/ws/me/join', '/api/ws/me/profile']); // always allowed; they change the caller
    let checked = 0;
    for (const r of routes) {
      const url = r.pattern.replace(/:(\w+)/g, (_, k) => (k === 'key' ? 'lm1' : crypto.randomUUID()));
      assert.equal((await h.call(r.method, url)).status, 401, 'anonymous: ' + r.method + ' ' + r.pattern);
      if (skip.has(r.pattern)) continue;
      for (let i = 1; i < ROLE_PEOPLE.length; i++) {
        const [name, extra] = ROLE_PEOPLE[i];
        const roles = new Set(['unit_employee', ...(extra.status === 'unit_employee' ? [] : ['member']), ...(extra.roles || [])]);
        const res = await mx.as(i, r.method, url, ['GET', 'HEAD'].includes(r.method) ? undefined : {});
        const allowed = can(roles, r.opts.action);
        assert.equal(res.status === 403, !allowed, `${name} ${r.method} ${r.pattern} (${r.opts.action}) -> ${res.status} ${JSON.stringify(res.json)}`);
        checked++;
      }
    }
    assert.ok(checked > 250, 'checked ' + checked);
  });
});

describe('workspace: secret ballots and self-executing votes', () => {
  let h, ws;
  before(async () => { h = await startApp(); ws = await makeWorkspace(h, PEOPLE); });
  after(() => h.stop());

  it('a vote is opened by the committee; only members vote; nobody votes twice, even in a race', async () => {
    const vote = await openVote(ws, 0, { title: 'Test question', type: 'general', options: ['Yes', 'No'], passRule: 'majority' });
    assert.equal(vote.turnout.eligible, 7);
    assert.equal((await cast(ws, 6, vote, 0)).r.status, 403); // Una has not joined
    assert.equal((await cast(ws, 4, vote, 0)).r.status, 200);
    assert.equal((await cast(ws, 4, vote, 1)).r.json.error, 'already_voted');
    const b = C.castBallot(vote.votePublicKey, 1);
    const race = await Promise.all(Array.from({ length: 8 }, () => ws.as(5, 'POST', `/api/ws/votes/${vote.id}/ballot`, { ciphertext: b.ciphertext, receiptHash: b.receiptHash })));
    assert.deepEqual(race.map((r) => r.status).sort(), [200, 409, 409, 409, 409, 409, 409, 409]);
    assert.equal(h.app.db.prepare('SELECT COUNT(*) c FROM ws_ballots WHERE vote_id=?').get(vote.id).c, 2);
    assert.equal((await ws.as(5, 'POST', `/api/ws/votes/${vote.id}/close`)).status, 403); // members cannot close votes
    assert.equal((await ws.as(0, 'GET', `/api/ws/votes/${vote.id}/tally-bundle`)).status, 403); // and officers cannot open the ballot box
    assert.equal((await ws.as(1, 'GET', `/api/ws/votes/${vote.id}/tally-bundle`)).json.error, 'vote_open');
  });

  it('ballots cannot be linked to voters: no column, no key, no timestamp, nothing in the logs', async () => {
    const cols = (t) => h.app.db.prepare(`SELECT name FROM pragma_table_info('${t}')`).all().map((c) => c.name);
    assert.deepEqual(cols('ws_ballots'), ['id', 'vote_id', 'choice_ciphertext']);
    assert.deepEqual(cols('ws_vote_receipts'), ['vote_id', 'receipt_hash']);
    assert.deepEqual(cols('ws_vote_participation'), ['vote_id', 'member_id', 'has_voted']);
    for (const t of ['ws_ballots', 'ws_vote_receipts']) assert.deepEqual(h.app.db.prepare(`SELECT "table" t FROM pragma_foreign_key_list('${t}')`).all().map((r) => r.t), ['ws_votes']);
    const sql = h.app.db.prepare("SELECT sql FROM sqlite_master WHERE name='ws_ballots'").get().sql;
    assert.match(sql, /WITHOUT ROWID/); // sorted by a random id, so the logical order says nothing. (The physical order on disk still would, which is why every cast rewrites the vote's rows in random order; see "the order people voted in is not left on disk".)
    const ballotLogs = h.logs.filter((l) => l.includes('/ballot'));
    assert.ok(ballotLogs.length >= 8);
    for (const l of ballotLogs) for (const m of ws.members) assert.ok(!l.includes(m.id) && !l.includes(m.token));
  });

  it('the committee tallies in the browser, the server re-checks it, and every member can recount', async () => {
    const { vote, res, receipts } = await runVote(ws, { title: 'Set dues', type: 'dues_change', options: ['Yes', 'No'], passRule: 'two_thirds', effect: { kind: 'dues', name: 'Standard dues', amountCents: 3500 } }, [0, 1, 2, 3, 4], [5, 7]);
    assert.equal(res.status, 200, JSON.stringify(res.json));
    assert.deepEqual(res.json.results.counts, [5, 2]);
    assert.equal(res.json.results.passed, true); // 5 of 7 is at least two thirds
    assert.equal(res.json.effectApplied, 'dues'); // the decision executes itself
    const fin = await ws.as(4, 'GET', '/api/ws/finance/summary');
    assert.deepEqual([fin.json.dues[0].name, fin.json.dues[0].amountCents, fin.json.dues[0].voteId], ['Standard dues', 3500, vote.id]);
    // anyone can recount from the published key and check their receipt is in the list
    const pub = (await ws.as(5, 'GET', `/api/ws/votes/${vote.id}/ballots`)).json;
    assert.deepEqual(C.countBallots(pub.votePublicKey, pub.secretKey, pub.ballots, 2).counts, [5, 2]);
    assert.equal(pub.ballots.length, pub.receiptHashes.length);
    for (const code of receipts) assert.ok(pub.receiptHashes.includes(C.receiptHash(code)));
    assert.ok(!pub.receiptHashes.includes(C.receiptHash('AAAA-BBBB-CCCC-DDDD')));
    assert.equal((await ws.as(1, 'POST', `/api/ws/votes/${vote.id}/results`, { counts: [1, 1] })).json.error, 'already_tallied');
  });

  it('a lying tally is rejected, one committee member alone cannot tally, and a failed vote changes nothing', async () => {
    const vote = await openVote(ws, 0, { title: 'Second dues', type: 'dues_change', options: ['Yes', 'No'], effect: { kind: 'dues', name: 'Higher dues', amountCents: 9900 } });
    for (const i of [0, 1, 2]) await cast(ws, i, vote, 1);
    for (const i of [3, 4]) await cast(ws, i, vote, 0);
    endVote(ws, vote.id);
    const bundle = (await ws.as(1, 'GET', `/api/ws/votes/${vote.id}/tally-bundle`)).json;
    const share = (i) => C.boxOpen(bundle.committee.find((c) => c.memberId === ws.members[i].id).sealed, ws.members[i].keys.boxPublicKey, ws.members[i].keys.boxSecretKey);
    await assert.rejects(C.reconstructVoteKey([share(1)])); // 1 of 3 cannot rebuild the key
    const sk = await C.reconstructVoteKey([share(1), share(2)]);
    assert.equal((await ws.as(1, 'POST', `/api/ws/votes/${vote.id}/results`, { counts: [5, 0], secretKey: sk })).json.error, 'count_mismatch');
    assert.equal((await ws.as(1, 'POST', `/api/ws/votes/${vote.id}/results`, { counts: [2, 3], secretKey: C.newToken() })).json.error, 'wrong_key');
    assert.equal((await ws.as(5, 'POST', `/api/ws/votes/${vote.id}/results`, { counts: [2, 3] })).status, 403); // not on the committee
    const ok = await ws.as(1, 'POST', `/api/ws/votes/${vote.id}/results`, { counts: [2, 3], secretKey: sk });
    assert.equal(ok.json.results.passed, false);
    assert.equal(ok.json.effectApplied, null);
    assert.equal((await ws.as(4, 'GET', '/api/ws/finance/summary')).json.dues.length, 1); // still only the ratified plan
  });

  it('a passed bylaws amendment rewrites the policy and keeps a version history', async () => {
    const { vote, res } = await runVote(ws, { title: 'Lower the petition threshold', type: 'bylaws_amendment', options: ['Yes', 'No'], effect: { kind: 'policy', patch: { petitionPct: 5, termMonths: 12 } } }, [0, 1, 2, 3, 4], [5]);
    assert.equal(res.json.effectApplied, 'policy');
    const by = (await ws.as(4, 'GET', '/api/ws/bylaws')).json;
    assert.deepEqual([by.policy.petitionPct, by.policy.termMonths, by.versions.length, by.versions[0].voteId], [5, 12, 2, vote.id]);
    assert.equal((await ws.as(0, 'POST', '/api/ws/votes', { title: 'x', type: 'bylaws_amendment', options: ['Yes', 'No'], effect: { kind: 'policy', patch: { petitionPct: 999 } } })).status, 400); // out-of-range policy is refused
  });

  it('online officer elections are off unless enabled; a passed recall removes the role', async () => {
    assert.equal((await ws.as(0, 'POST', '/api/ws/votes', { title: 'Elect', type: 'officer_election', options: ['A', 'B'] })).json.error, 'feature_disabled');
    const { res } = await runVote(ws, { title: 'Recall Sam', type: 'recall', effect: { kind: 'role_revoke', memberId: ws.members[7].id, role: 'steward' } }, [0, 1, 2, 3], [4, 5]);
    assert.equal(res.json.effectApplied, 'role_revoke');
    assert.ok(!(await ws.as(7, 'GET', '/api/ws/me')).json.roles.includes('steward'));
    // a role the members took away by a vote does not come back through the officers' role screen
    assert.equal((await ws.as(0, 'POST', '/api/ws/roles', { memberId: ws.members[7].id, role: 'steward', op: 'add' })).json.error, 'removed_by_vote');
    h.app.db.prepare("UPDATE ws_roles SET removed_at=NULL, removed_by_vote_id=NULL WHERE member_id=? AND role='steward'").run(ws.members[7].id); // restore Sam for the tests that follow
  });

  it('members can force a vote: a petition qualifies at the threshold and opens exactly as written', async () => {
    const mk = await ws.as(4, 'POST', '/api/ws/petitions', { title: 'Vote on Saturday shifts', description: 'Should Saturday shifts be optional?', type: 'general', options: ['Yes', 'No'], passRule: 'majority' });
    assert.equal(mk.status, 200, JSON.stringify(mk.json));
    assert.equal(mk.json.needed, 2); // 5% of 7 members, minimum 2
    assert.equal((await ws.as(6, 'POST', '/api/ws/petitions', { title: 't', type: 'general', options: ['Yes', 'No'] })).status, 403); // must be a member
    assert.equal((await ws.as(0, 'POST', '/api/ws/votes', { petitionId: mk.json.petitionId, closesAt: new Date(Date.now() + 3600_000).toISOString() })).status, 409); // not qualified yet
    const s = await ws.as(4, 'POST', `/api/ws/petitions/${mk.json.petitionId}/sign`); // signing twice is still one signature
    assert.equal(s.json.signers, 1);
    const q = await ws.as(5, 'POST', `/api/ws/petitions/${mk.json.petitionId}/sign`);
    assert.deepEqual([q.json.status, q.json.signers], ['qualified', 2]);
    assert.ok(q.json.openBy);
    const vote = await openVote(ws, 1, { petitionId: mk.json.petitionId, title: 'A different title the committee would prefer', type: 'general', options: ['Maybe', 'Never'] });
    assert.deepEqual([vote.title, vote.options], ['Vote on Saturday shifts', ['Yes', 'No']]); // the committee cannot reword it
    assert.equal((await ws.as(4, 'GET', '/api/ws/petitions')).json.petitions[0].status, 'opened');
  });
});

describe('workspace: one person cannot make up a result, or take power alone', () => {
  let h, ws;
  before(async () => { h = await startApp(); ws = await makeWorkspace(h, PEOPLE); });
  after(() => h.stop());
  const post = (idx, vote, body) => ws.as(idx, 'POST', `/api/ws/votes/${vote.id}/results`, body);
  const attest = (vote, counts, idxs) => idxs.map((i) => ({ memberId: ws.members[i].id, signature: C.signTally(ws.members[i].keys.signSecretKey, vote.id, counts) }));

  it('a result nobody can recount needs k committee signatures over the same counts; one member cannot make one up', async () => {
    const vote = await openVote(ws, 0, { title: 'Authorize a strike?', type: 'strike_authorization', options: ['Yes', 'No'], passRule: 'majority' });
    for (const i of [0, 1, 2, 4]) await cast(ws, i, vote, 0);
    await cast(ws, 5, vote, 1);
    endVote(ws, vote.id);
    const short = (r) => { assert.equal(r.status, 403); assert.equal(r.json.error, 'not_enough_committee'); };
    short(await post(1, vote, { counts: [5, 0] })); // one committee member posting whatever they like
    short(await post(1, vote, { counts: [5, 0], attestations: attest(vote, [5, 0], [1]) })); // ...even signing it themselves
    short(await post(1, vote, { counts: [4, 1], attestations: [...attest(vote, [4, 1], [1]), ...attest(vote, [5, 0], [3])] })); // a second signature over different counts is worth nothing
    short(await post(1, vote, { counts: [4, 1], attestations: [...attest(vote, [4, 1], [1]), ...attest(vote, [4, 1], [5])] })); // Marco is not on the committee
    short(await post(1, vote, { counts: [4, 1], attestations: [...attest(vote, [4, 1], [1]), ...attest(vote, [4, 1], [1])] })); // signing twice is still one member
    const other = await openVote(ws, 0, { title: 'Another question', type: 'general', options: ['Yes', 'No'] });
    short(await post(1, vote, { counts: [4, 1], attestations: [...attest(vote, [4, 1], [1]), { memberId: ws.members[3].id, signature: attest(other, [4, 1], [3])[0].signature }] })); // a signature for another vote
    assert.equal(h.app.db.prepare('SELECT status FROM ws_votes WHERE id=?').get(vote.id).status, 'closed'); // none of that recorded anything
    const ok = await post(1, vote, { counts: [4, 1], attestations: attest(vote, [4, 1], [1, 3]) }); // two different committee members who each signed these counts
    assert.equal(ok.status, 200, JSON.stringify(ok.json));
    assert.deepEqual([ok.json.results.counts, ok.json.results.passed, ok.json.results.verifiable, ok.json.results.attestedBy], [[4, 1], true, false, 2]);
  });

  it('a decision that changes dues, rules or roles is always counted in the open: the ballot key is required', async () => {
    const vote = await openVote(ws, 0, { title: 'Raise dues', type: 'dues_change', options: ['Yes', 'No'], effect: { kind: 'dues', name: 'Made-up dues', amountCents: 50_000 } });
    for (const i of [0, 1]) await cast(ws, i, vote, 1); // both vote No
    endVote(ws, vote.id);
    const forged = await post(1, vote, { counts: [2, 0], attestations: attest(vote, [2, 0], [1, 2, 3]) }); // even every committee member's signature is not enough
    assert.equal(forged.status, 409);
    assert.equal(forged.json.error, 'key_required');
    assert.equal((await ws.as(4, 'GET', '/api/ws/finance/summary')).json.dues.length, 0);
  });

  it('refuses to count when the ballots and receipts do not match who voted', async () => {
    const vote = await openVote(ws, 0, { title: 'Stuffed box', type: 'general', options: ['Yes', 'No'] });
    await cast(ws, 4, vote, 1);
    const extra = C.castBallot(vote.votePublicKey, 0); // someone with database access adds a ballot nobody cast
    h.app.db.prepare('INSERT INTO ws_ballots (id,vote_id,choice_ciphertext) VALUES (?,?,?)').run(crypto.randomUUID(), vote.id, extra.ciphertext);
    const res = await tally(ws, 1, vote, [1, 3]);
    assert.equal(res.status, 409);
    assert.deepEqual([res.json.error, res.json.ballots, res.json.voted], ['ballot_count_mismatch', 2, 1]);
  });

  it('"No" can never win as "passed": a decision with an effect has fixed options and a real rule', async () => {
    // a recall asked with "plurality": any unique winner counted as passed, so "Keep in office" removed the role
    const recall = await openVote(ws, 0, { title: 'Recall Sam', type: 'recall', passRule: 'plurality', effect: { kind: 'role_revoke', memberId: ws.members[7].id, role: 'steward' } });
    assert.equal(recall.passRule, 'majority');
    for (const i of [0, 1, 2, 3]) await cast(ws, i, recall, 1); // keep
    for (const i of [4, 5]) await cast(ws, i, recall, 0); // remove
    const res = await tally(ws, 1, recall, [1, 3]);
    assert.deepEqual([res.json.results.passed, res.json.effectApplied], [false, null]);
    assert.ok((await ws.as(7, 'GET', '/api/ws/me')).json.roles.includes('steward'));
    // dues cannot be worded so that "Yes" means "keep things as they are"
    const dues = await openVote(ws, 0, { title: 'Dues', type: 'dues_change', options: ['Keep dues as they are', 'Raise to $500'], passRule: 'plurality', effect: { kind: 'dues', name: 'Five hundred', amountCents: 50_000 } });
    assert.deepEqual([dues.options, dues.passRule], [['Yes', 'No'], 'majority']);
  });

  it('nobody can run their own recall, and a recalled role is not handed back', async () => {
    const ring = (await ws.as(0, 'GET', '/api/ws/keyring?role=election_committee')).json.holders;
    const spec = (holders) => C.newVoteKeys(holders, 2).then((vk) => ({ title: 'Recall Enzo', type: 'recall', effect: { kind: 'role_revoke', memberId: ws.members[1].id, role: 'officer' },
      closesAt: new Date(Date.now() + 3600_000).toISOString(), votePublicKey: vk.votePublicKey, committee: vk.committee, thresholdK: 2 }));
    assert.equal((await ws.as(0, 'POST', '/api/ws/votes', await spec(ring))).json.error, 'committee_conflict'); // the target is on the committee that would count it
    const clean = await spec(ring.filter((x) => x.memberId !== ws.members[1].id));
    assert.equal((await ws.as(1, 'POST', '/api/ws/votes', clean)).json.error, 'committee_conflict'); // ...or opens it himself
    assert.equal((await ws.as(0, 'POST', '/api/ws/votes', clean)).status, 200); // someone else can
  });

  it('adding people to the roster cannot create voting members or officers, and nobody grants themselves a role', async () => {
    const r = await ws.as(0, 'POST', '/api/ws/members', { members: [{ legalName: 'Fake Officer', claimTokenHash: C.hashToken(C.newToken()), status: 'member', roles: ['officer', 'treasurer'] }] });
    assert.equal(r.status, 200, JSON.stringify(r.json));
    assert.equal(h.app.db.prepare('SELECT membership_status s FROM ws_members WHERE id=?').get(r.json.memberIds[0]).s, 'unit_employee'); // status comes from the server, not the request
    assert.equal(h.app.db.prepare('SELECT COUNT(*) c FROM ws_roles WHERE member_id=?').get(r.json.memberIds[0]).c, 0);
    assert.equal((await ws.as(0, 'POST', '/api/ws/roles', { memberId: r.json.memberIds[0], role: 'officer', op: 'add' })).json.error, 'not_a_member'); // and someone who has not joined cannot hold a role
    assert.equal((await ws.as(0, 'POST', '/api/ws/roles', { memberId: ws.members[0].id, role: 'election_committee', op: 'add' })).json.error, 'no_self_assign');
  });

  it('a founding roster that lists a role twice is accepted, not a server error', async () => {
    const t = await makeWorkspace(h, [person('Dup Officer', 0, { roles: ['officer', 'officer', 'treasurer'] }), person('Worker Two', 1)]);
    assert.equal(t.members.length, 2);
  });

  it('the export does not reveal ballots while a vote is open, and it shows in every member\'s access log', async () => {
    const vote = await openVote(ws, 0, { title: 'Still open', type: 'general', options: ['Yes', 'No'] });
    await cast(ws, 4, vote, 0);
    const seen = async () => (await ws.as(4, 'GET', '/api/ws/me/access-log')).json.entries.filter((e) => e.action === 'member.pii.read').length;
    const before = await seen();
    const open = (await ws.as(0, 'GET', '/api/ws/export')).json.votes.find((v) => v.id === vote.id);
    assert.deepEqual([open.ballots, open.receiptHashes], [[], []]); // reading them as they arrive would isolate each ballot with its receipt
    assert.equal(await seen(), before + 1); // Mona can see that an officer exported her details
    await tally(ws, 1, vote, [1, 3]);
    const done = (await ws.as(0, 'GET', '/api/ws/export')).json.votes.find((v) => v.id === vote.id);
    assert.equal(done.ballots.length, 1); // after the count they are part of the record
  });
});

describe('workspace: an encrypted field belongs to its row', () => {
  let h, ws;
  before(async () => { h = await startApp(); ws = await makeWorkspace(h, [person('Ofelia Qqqofficer', 0, { roles: ['officer'] }), person('Mona Qqqmember', 4), person('Marco Qqqmember', 5)]); });
  after(() => h.stop());
  const row = (i) => h.app.db.prepare('SELECT email_enc e, legal_name_enc n FROM ws_members WHERE id=?').get(ws.members[i].id);

  it('swapping two members\' encrypted email or name in the database does not show one person\'s data as another\'s', async () => {
    const [mona, marco] = [row(1), row(2)];
    assert.match(mona.e, /^v2\./); // new values are bound to their row
    const put = h.app.db.prepare('UPDATE ws_members SET email_enc=?, legal_name_enc=? WHERE id=?');
    put.run(marco.e, marco.n, ws.members[1].id); put.run(mona.e, mona.n, ws.members[2].id); // someone with the database swaps them
    const list = (await ws.as(0, 'GET', '/api/ws/roster')).json.members;
    assert.ok(!list.some((m) => m.email === 'marco+leak@example.com' && m.id === ws.members[1].id), 'Marco\'s email shown as Mona\'s');
    assert.ok(!list.some((m) => m.name === 'Mona Qqqmember' && m.id === ws.members[2].id), 'Mona\'s name shown as Marco\'s');
    assert.equal(list.find((m) => m.id === ws.members[1].id).email, '[unreadable]'); // the damage shows instead
    put.run(mona.e, mona.n, ws.members[1].id); put.run(marco.e, marco.n, ws.members[2].id);
  });

  it('values written before this change (bound to their column only) still read', async () => {
    const dk = h.app.kms.dataKey(ws.wsId, h.app.db.prepare('SELECT data_key_wrapped w FROM ws_workspaces WHERE id=?').get(ws.wsId).w);
    const box = C.aeadSeal(dk, C.utf8('old+leak@example.com'), 'member.email'); // how values were written before: bound to the column only
    const old = 'v1.' + box.nonce + '.' + box.ciphertext;
    assert.match(old, /^v1\./);
    h.app.db.prepare('UPDATE ws_members SET email_enc=? WHERE id=?').run(old, ws.members[1].id);
    assert.equal((await ws.as(0, 'GET', '/api/ws/roster')).json.members.find((m) => m.id === ws.members[1].id).email, 'old+leak@example.com');
  });
});

describe('workspace: members can check who was paid, not only how much (#41)', () => {
  let h, ws;
  before(async () => { h = await startApp(); ws = await makeWorkspace(h, [person('Tess Qqqtreasurer', 0, { roles: ['treasurer', 'officer'] }), person('Mona Qqqmember', 4)]); });
  after(() => h.stop());

  it('each visible payee and memo matches the commitment inside the hash chain, and a changed payee is caught', async () => {
    assert.equal((await ws.as(0, 'POST', '/api/ws/ledger/receipt', { category: 'dues', amountCents: 1500, payer: 'Zyxwvut Payee', memo: 'Zyxwvut memo' })).status, 200);
    assert.equal((await ws.as(0, 'POST', '/api/ws/ledger/receipt', { category: 'donations', amountCents: 900, payer: 'A Friend' })).status, 200);
    const read = async () => [(await ws.as(1, 'GET', '/api/ws/finance/summary')).json.entries, (await ws.as(1, 'GET', '/api/ws/finance/chain')).json.entries];
    const [entries, chain] = await read();
    assert.ok(entries.every((e) => typeof e.salt === 'string')); // a member gets what they need to check it
    assert.deepEqual(checkCommitments(entries, chain), { ok: true, checked: 2, brokenAt: null });
    // someone with the database and the master key re-encrypts a different payee into entry 1: amounts and hashes are untouched
    const row = h.app.db.prepare('SELECT id, workspace_id w FROM ws_ledger WHERE seq=1 AND workspace_id=?').get(ws.wsId);
    const dk = h.app.kms.dataKey(row.w, h.app.db.prepare('SELECT data_key_wrapped k FROM ws_workspaces WHERE id=?').get(row.w).k);
    h.app.db.exec('DROP TRIGGER IF EXISTS ws_ledger_no_update'); // what a person editing the file directly can do
    h.app.db.prepare('UPDATE ws_ledger SET payee_enc=? WHERE id=?').run(h.app.kms.enc(dk, 'Somebody Else', 'ledger.payee', row.id), row.id);
    const [e2, c2] = await read();
    assert.equal(e2.find((e) => e.seq === 1).payee, 'Somebody Else');
    assert.deepEqual(checkCommitments(e2, c2), { ok: false, checked: 2, brokenAt: 1 });
    assert.equal(verifyChain(c2, ledgerFields).ok, true); // the chain alone would not have noticed
  });
});

describe('workspace: the whole audit log is checked, not only the newest page (#41)', () => {
  let h, ws;
  before(async () => { h = await startApp(); ws = await makeWorkspace(h, PEOPLE); });
  after(() => h.stop());

  it('an officer gets every entry\'s hash to check from the very first, and can page back through the entries', async () => {
    for (let i = 0; i < 80; i++) await ws.as(0, 'GET', '/api/ws/roster'); // each view writes one entry per person: 560 entries
    const a = (await ws.as(0, 'GET', '/api/ws/audit')).json;
    const total = h.app.db.prepare('SELECT COUNT(*) c FROM ws_audit WHERE workspace_id=?').get(ws.wsId).c;
    assert.ok(total > 500);
    assert.equal(a.entries.length, 500); // the page shown
    assert.equal(a.chain.length, total); // what is checked: everything
    assert.equal(verifyChain(a.chain, auditFields, { anchored: true }).ok, true);
    const older = (await ws.as(0, 'GET', `/api/ws/audit?before=${a.entries.at(-1).seq}`)).json.entries;
    assert.equal(older.length, total - 500);
    assert.equal(older[0].seq, a.entries.at(-1).seq - 1);
    // a rewritten early entry, out of sight of the first page, is caught
    h.app.db.exec('DROP TRIGGER IF EXISTS ws_audit_no_update');
    h.app.db.prepare("UPDATE ws_audit SET action='member.pii.read.x' WHERE workspace_id=? AND seq=2").run(ws.wsId);
    assert.equal(verifyChain((await ws.as(0, 'GET', '/api/ws/audit')).json.chain, auditFields, { anchored: true }).ok, false);
  });
});

describe('workspace: a recall cannot be blocked or dodged by the person it targets', () => {
  let h;
  before(async () => { h = await startApp(); });
  after(() => h.stop());
  const team = (names) => makeWorkspace(h, names.map(([n, roles], i) => person(n, i, roles ? { roles } : {})));
  const recallSpec = (ws, target, role = 'officer') => ({ title: 'Recall', type: 'recall', effect: { kind: 'role_revoke', memberId: ws.members[target].id, role } });

  it('taking the committee\'s role away after the vote closes does not stop the count', async () => {
    const ws = await team([['Solo Qqqofficer', ['officer']], ['Eve Qqqelect', ['election_committee']], ['Eli Qqqelect', ['election_committee']], ['Moe Qqqmember']]);
    const vote = await openVote(ws, 1, recallSpec(ws, 0));
    for (const i of [1, 2, 3]) await cast(ws, i, vote, 0); // remove
    endVote(ws, vote.id);
    for (const i of [1, 2]) await ws.as(0, 'POST', '/api/ws/roles', { memberId: ws.members[i].id, role: 'election_committee', op: 'remove' });
    const res = await tally(ws, 1, vote, [1, 2]); // the people who hold the shares still count it
    assert.equal(res.status, 200, JSON.stringify(res.json));
    assert.deepEqual([res.json.results.passed, res.json.effectApplied], [true, 'role_revoke']);
    assert.ok(!(await ws.as(0, 'GET', '/api/ws/me')).json.roles.includes('officer'));
    assert.equal((await ws.as(3, 'GET', `/api/ws/votes/${vote.id}/tally-bundle`)).status, 403); // being on the vote's committee is what counts, not the role
  });

  it('stepping down just before the count does not let the role be handed back afterwards', async () => {
    const ws = await team([['Tara Qqqofficer', ['officer']], ['Alan Qqqofficer', ['officer']], ['Eve Qqqelect', ['election_committee']], ['Eli Qqqelect', ['election_committee']], ['Moe Qqqmember'], ['Max Qqqmember']]);
    const vote = await openVote(ws, 2, recallSpec(ws, 0));
    for (const i of [2, 3, 4, 5]) await cast(ws, i, vote, 0);
    endVote(ws, vote.id);
    assert.equal((await ws.as(0, 'POST', '/api/ws/roles', { memberId: ws.members[0].id, role: 'officer', op: 'remove' })).status, 200);
    const res = await tally(ws, 2, vote, [2, 3]);
    assert.deepEqual([res.json.results.passed, res.json.effectApplied], [true, 'role_revoke']);
    const back = await ws.as(1, 'POST', '/api/ws/roles', { memberId: ws.members[0].id, role: 'officer', op: 'add' });
    assert.equal(back.json.error, 'removed_by_vote');
  });

  it('a ratification or strike vote cannot be worded or ruled so that "No" passes', async () => {
    const ws = await team([['Olga Qqqofficer', ['officer']], ['Eve Qqqelect', ['election_committee']], ['Eli Qqqelect', ['election_committee']], ['Moe Qqqmember']]);
    for (const type of ['ratification', 'strike_authorization']) {
      const v = await openVote(ws, 0, { title: 'Question', type, options: ['Reject the contract', 'Accept it', 'Undecided'], passRule: 'plurality' });
      assert.deepEqual([v.options, v.passRule], [['Yes', 'No'], 'majority'], type);
      assert.equal((await openVote(ws, 0, { title: 'Question', type, passRule: 'two_thirds' })).passRule, 'two_thirds');
    }
  });
});

describe('workspace: the order people voted in is not left on disk', () => {
  let h, ws;
  const kendall = (a, b) => { // rank correlation of the same items in two orders: 1 identical, -1 reversed, about 0 unrelated
    const pos = new Map(b.map((x, i) => [x, i])); let c = 0, d = 0;
    for (let i = 0; i < a.length; i++) for (let j = i + 1; j < a.length; j++) (pos.get(a[i]) < pos.get(a[j]) ? c++ : d++);
    return (c - d) / (c + d);
  };
  const BIG = Array.from({ length: 20 }, (_, i) => person(`Voter${i} Qqqperson`, i, i === 0 ? { roles: ['officer', 'election_committee'] } : i < 3 ? { roles: ['election_committee'] } : {}));
  before(async () => { h = await startApp(); ws = await makeWorkspace(h, BIG); });
  after(() => h.stop());

  it('a copy of the database does not show which ballot or receipt came first', async () => {
    const vote = await openVote(ws, 0, { title: 'Order test', type: 'general', options: ['Yes', 'No'] });
    const order = BIG.map((_, i) => i).sort(() => C.randomBytes(1)[0] - 128); // people vote in an arbitrary order
    const cts = [], rhs = [], who = [];
    for (const i of order) {
      const b = C.castBallot(vote.votePublicKey, i % 2);
      assert.equal((await ws.as(i, 'POST', `/api/ws/votes/${vote.id}/ballot`, { ciphertext: b.ciphertext, receiptHash: b.receiptHash })).status, 200);
      cts.push(b.ciphertext); rhs.push(b.receiptHash); who.push(ws.members[i].id);
    }
    // what someone holding a copy of the file can read: the rows in the order they sit on disk (inside a page the newest cell sits lowest)
    const ballots = physicalOrder(h, 'ws_ballots', (v) => v[1] === vote.id).flat().map((v) => v[2]);
    const receipts = physicalOrder(h, 'ws_vote_receipts', (v) => v[0] === vote.id).flat().map((v) => v[1]);
    const voted = physicalOrder(h, 'ws_vote_participation', (v) => v[0] === vote.id && v[2] === 1).flat().map((v) => v[1]);
    assert.deepEqual([ballots.length, receipts.length, voted.length], [20, 20, 20]);
    const mirror = (a) => [...a].reverse();
    for (const [name, onDisk, cast] of [['ballots', ballots, cts], ['receipts', receipts, rhs], ['who has voted', voted, who]]) {
      assert.notDeepEqual(onDisk, cast, `${name} sit in cast order`);
      assert.notDeepEqual(onDisk, mirror(cast), `${name} sit in reverse cast order`);
      // ...and not nearly in order either: Kendall's tau between the two orders. Random layouts of 20 give |tau| around 0.16 (a bound of 0.7 is over
      // four standard deviations, so this does not fail by chance); a layout close to cast order, with a row or two moved, scores about 0.9.
      // (Today the rewrite reads rows back by their random primary key, so re-inserting them already scatters them; the shuffle is a second layer.)
      assert.ok(Math.abs(kendall(onDisk, cast)) < 0.7, `${name} are laid out close to cast order (tau ${kendall(onDisk, cast).toFixed(2)})`);
    }
    // scrambling only moves rows: everything is still there, and the count still works
    assert.deepEqual([...ballots].sort(), [...cts].sort());
    assert.deepEqual([...receipts].sort(), [...rhs].sort());
  });
});

describe('workspace: a vote cannot be opened so briefly that nobody sees it, or ended early', () => {
  let h, ws;
  before(async () => { h = await startApp({ minVoteHours: 24 }); ws = await makeWorkspace(h, PEOPLE); });
  after(() => h.stop());

  it('refuses a voting window shorter than the minimum, and refuses to end a vote before everyone has voted', async () => {
    const ring = (await ws.as(0, 'GET', '/api/ws/keyring?role=election_committee')).json.holders;
    const vk = await C.newVoteKeys(ring, 2);
    const base = { title: 'Short window', type: 'general', options: ['Yes', 'No'], votePublicKey: vk.votePublicKey, committee: vk.committee, thresholdK: 2 };
    for (const ms of [2_000, 3600_000, 23 * 3600_000]) assert.equal((await ws.as(0, 'POST', '/api/ws/votes', { ...base, closesAt: new Date(Date.now() + ms).toISOString() })).status, 400, String(ms));
    const ok = await ws.as(0, 'POST', '/api/ws/votes', { ...base, closesAt: new Date(Date.now() + 24 * 3600_000).toISOString() });
    assert.equal(ok.status, 200, JSON.stringify(ok.json));
    const vote = (await ws.as(0, 'GET', `/api/ws/votes/${ok.json.voteId}`)).json;
    assert.equal((await ws.as(0, 'POST', `/api/ws/votes/${vote.id}/close`)).json.error, 'vote_still_open'); // nobody can end it while members are still to vote
    for (const i of V.slice(0, 6)) await cast(ws, i, vote, 0);
    assert.equal((await ws.as(0, 'POST', `/api/ws/votes/${vote.id}/close`)).json.error, 'vote_still_open'); // 6 of 7
    await cast(ws, V[6], vote, 0);
    assert.equal((await ws.as(0, 'POST', `/api/ws/votes/${vote.id}/close`)).json.status, 'closed'); // everyone has voted
  });
});

describe('workspace: smaller fixes from the review', () => {
  let h, ws;
  const TEAM = [person('Ofelia Qqqofficer', 0, { roles: ['officer', 'treasurer', 'chief_steward'] }), person('Mona Qqqmember', 1, { location: 'Warehouse B', preferredLanguage: 'Español' }), person('Una Qqqunit', 2, { status: 'unit_employee' })];
  before(async () => { h = await startApp(); ws = await makeWorkspace(h, TEAM); });
  after(() => h.stop());

  it('a category must be one we defined, not a property every object has', async () => {
    for (const category of ['constructor', '__proto__', 'toString', 'hasOwnProperty']) {
      assert.equal((await ws.as(0, 'POST', '/api/ws/ledger/receipt', { amountCents: 100, category })).status, 400, category);
      assert.equal((await ws.as(0, 'POST', '/api/ws/disbursements', { amountCents: 100, category, payee: 'Somebody' })).status, 400, category);
    }
    assert.equal((await ws.as(0, 'POST', '/api/ws/ledger/receipt', { amountCents: 100, category: 'dues' })).status, 200);
  });

  it('saving your profile keeps the fields the form does not send', async () => {
    const row = () => h.app.db.prepare('SELECT shift, location, preferred_language pl FROM ws_members WHERE id=?').get(ws.members[1].id);
    const before = row();
    assert.deepEqual(before, { shift: 'Day', location: 'Warehouse B', pl: 'Español' });
    assert.equal((await ws.as(1, 'POST', '/api/ws/me/profile', { phone: '+15550100', address: '1 Main St', jobTitle: 'Barista', shift: 'Day' })).status, 200); // what the form sends
    assert.deepEqual(row(), before); // location and language survived
    assert.equal((await ws.as(1, 'POST', '/api/ws/me/profile', { phone: '', address: '', jobTitle: '', shift: 'Night', location: null })).status, 200);
    assert.deepEqual(row(), { shift: 'Night', location: null, pl: 'Español' }); // what is sent changes; null clears; the rest stays
  });

  it('a contract article is a short reference; a narrative is refused instead of being stored in the clear', async () => {
    const file = (articleRef) => {
      const id = crypto.randomUUID(), k = C.randomBytes(32);
      return { id, ...C.sealJson(k, { what: 'Zyxwvut concern' }, 'grievance|' + id), ...(articleRef === undefined ? {} : { articleRef }),
        sealedKeys: { [ws.members[2].id]: C.boxSeal(ws.members[2].keys.boxPublicKey, k), [ws.members[0].id]: C.boxSeal(ws.members[0].keys.boxPublicKey, k) } };
    };
    for (const bad of ['supervisor J. Doe told me to sign off on it', 'Art. 12; call him', '<script>', 'x'.repeat(21), 'Art. 5\n(b)', 'Art. 5 [b]', 'a@b.c']) assert.equal((await ws.as(2, 'POST', '/api/ws/grievances', file(bad))).json.error, 'bad_article', bad);
    for (const good of ['Art. 12', 'Article 3.2', '§ 4', 'Art. 5(b)', '12/3', 'Art. 7, 9', 'Art. IV', undefined, '']) assert.equal((await ws.as(2, 'POST', '/api/ws/grievances', file(good))).status, 200, String(good));
    assert.equal(h.app.db.prepare("SELECT COUNT(*) c FROM ws_grievances WHERE article_ref LIKE '%supervisor%'").get().c, 0);
  });

  it('a fiscal year cannot start on a day that does not exist', async () => {
    const start = async (v) => { const w = await makeWorkspace(h, [TEAM[0]], { fiscalYearStart: v }); return h.app.db.prepare('SELECT fiscal_year_start f FROM ws_workspaces WHERE id=?').get(w.wsId).f; };
    assert.equal(await start('07-01'), '07-01');
    assert.equal(await start('02-29'), '02-29'); // a leap day is a real day
    for (const bad of ['02-31', '04-31', '13-01', '00-10', '06-00', '1-1', 'nonsense']) assert.equal(await start(bad), '01-01', bad);
  });
});

describe('workspace: officer elections (when the feature flag is on)', () => {
  let h, ws;
  before(async () => { h = await startApp({ onlineOfficerElections: true }); ws = await makeWorkspace(h, PEOPLE); });
  after(() => h.stop());

  it('candidates cannot sit on the committee that runs their election; the winner receives the role', async () => {
    const ring = (await ws.as(0, 'GET', '/api/ws/keyring?role=election_committee')).json.holders;
    const vk = await C.newVoteKeys(ring, 2);
    const base = { title: 'Elect a steward', type: 'officer_election', options: ['Enzo', 'Marco'], closesAt: new Date(Date.now() + 3600_000).toISOString(), votePublicKey: vk.votePublicKey, committee: vk.committee, thresholdK: 2 };
    const conflict = await ws.as(0, 'POST', '/api/ws/votes', { ...base, effect: { kind: 'role_grant', role: 'steward', memberIds: [ws.members[1].id, ws.members[5].id] } });
    assert.equal(conflict.json.error, 'committee_conflict'); // Enzo is on the committee
    const { res } = await runVote(ws, { title: 'Elect a steward', type: 'officer_election', options: ['Mona', 'Marco'], effect: { kind: 'role_grant', role: 'steward', memberIds: [ws.members[4].id, ws.members[5].id] } }, [0, 1, 4], [5]);
    assert.equal(res.status, 200);
    assert.equal(res.json.results.winner, 0);
    assert.equal(res.json.effectApplied, 'role_grant');
    assert.ok((await ws.as(4, 'GET', '/api/ws/me')).json.roles.includes('steward'));
  });

  it('the name on the ballot is the person who gets the role: labels come from the candidates, never from free text', async () => {
    const ring = (await ws.as(0, 'GET', '/api/ws/keyring?role=election_committee')).json.holders.filter((x) => x.memberId !== ws.members[5].id);
    const open = async (options, memberIds) => {
      const vk = await C.newVoteKeys(ring, 2);
      return ws.as(0, 'POST', '/api/ws/votes', { title: 'Elect a treasurer', type: 'officer_election', options, closesAt: new Date(Date.now() + 3600_000).toISOString(), votePublicKey: vk.votePublicKey, committee: vk.committee, thresholdK: 2, effect: { kind: 'role_grant', role: 'treasurer', memberIds } });
    };
    // labels that say one thing while the ids say another
    const r = await open(['Mona', 'Marco'], [ws.members[5].id, ws.members[4].id]);
    assert.equal(r.status, 200, JSON.stringify(r.json));
    const v = (await ws.as(0, 'GET', `/api/ws/votes/${r.json.voteId}`)).json;
    assert.deepEqual(v.options, ['Marco Qqqmember', 'Mona Qqqmember']); // each option is its candidate's own name, in the same order as the ids
    assert.deepEqual(JSON.parse(h.app.db.prepare('SELECT options_json o FROM ws_votes WHERE id=?').get(r.json.voteId).o), ['Candidate 1', 'Candidate 2']); // names stay encrypted at rest
    assert.equal((await open(['A', 'B'], [ws.members[4].id, ws.members[4].id])).status, 400); // the same person twice
    assert.equal((await open(['A', 'B'], [ws.members[4].id, ws.members[6].id])).json.error, 'not_a_member'); // Una has not joined the union
  });
});

describe('workspace: an account claimed after a vote opens does not vote in it (#43)', () => {
  let h, ws;
  before(async () => { h = await startApp(); ws = await makeWorkspace(h, PEOPLE); });
  after(() => h.stop());

  it('whoever holds an unclaimed claim link cannot use it to vote in a vote that is already open', async () => {
    // a member account that has not been claimed yet (as founding members' accounts are until they open their link)
    const tok = C.newToken();
    const id = (await ws.as(0, 'POST', '/api/ws/members', { members: [{ legalName: 'Unclaimed Qqqmember', claimTokenHash: C.hashToken(tok) }] })).json.memberIds[0];
    h.app.db.prepare("UPDATE ws_members SET membership_status='member' WHERE id=?").run(id);
    const vote = await openVote(ws, 0, { title: 'Open question', type: 'general', options: ['Yes', 'No'] });
    assert.equal(h.app.db.prepare('SELECT COUNT(*) c FROM ws_vote_participation WHERE vote_id=? AND member_id=?').get(vote.id, id).c, 0); // not eligible, and not counted
    const keys = C.newKeypairs();
    assert.equal((await h.call('POST', '/api/ws/claim', { body: { workspaceId: ws.wsId, claimToken: tok, boxPublicKey: keys.boxPublicKey, signPublicKey: keys.signPublicKey } })).status, 200);
    const m = await login(h, { id, keys });
    const b = C.castBallot(vote.votePublicKey, 0);
    assert.equal((await h.call('POST', `/api/ws/votes/${vote.id}/ballot`, { auth: m.auth, body: { ciphertext: b.ciphertext, receiptHash: b.receiptHash } })).status, 403);
    const next = await openVote(ws, 0, { title: 'Next question', type: 'general', options: ['Yes', 'No'] }); // claimed now: eligible for the next vote
    assert.equal((await h.call('POST', `/api/ws/votes/${next.id}/ballot`, { auth: m.auth, body: { ...C.castBallot(next.votePublicKey, 0), receiptCode: undefined } })).status, 200);
  });
});

describe('workspace: money you can audit', () => {
  let h, ws;
  before(async () => { h = await startApp(); ws = await makeWorkspace(h, PEOPLE); });
  after(() => h.stop());

  it('receipts, spending with approvals, and the rule that nobody approves their own request', async () => {
    const rc = await ws.as(0, 'POST', '/api/ws/ledger/receipt', { amountCents: 100_000, category: 'dues', payer: 'Zyxwvut Payer', memo: 'Zyxwvut memo: September dues' });
    assert.equal(rc.status, 200, JSON.stringify(rc.json));
    assert.equal((await ws.as(1, 'POST', '/api/ws/ledger/receipt', { amountCents: 5, category: 'dues' })).status, 403); // officers do not hold the books
    const small = (await ws.as(0, 'POST', '/api/ws/disbursements', { amountCents: 3000, category: 'office', payee: 'Zyxwvut Payee Copy Shop', memo: 'Flyers' })).json;
    assert.equal(small.requiredApprovals, 1);
    assert.equal((await ws.as(0, 'POST', `/api/ws/disbursements/${small.id}/approve`, {})).json.error, 'own_request');
    assert.equal((await ws.as(4, 'POST', `/api/ws/disbursements/${small.id}/approve`, {})).status, 403);
    assert.equal((await ws.as(0, 'POST', `/api/ws/disbursements/${small.id}/pay`)).json.error, 'not_approved');
    assert.equal((await ws.as(1, 'POST', `/api/ws/disbursements/${small.id}/approve`, {})).json.status, 'approved');
    assert.equal((await ws.as(0, 'POST', `/api/ws/disbursements/${small.id}/pay`)).status, 200);
    const big = (await ws.as(0, 'POST', '/api/ws/disbursements', { amountCents: 60_000, category: 'professional', payee: 'Zyxwvut Payee Law Office', memo: 'Retainer' })).json;
    assert.equal(big.requiredApprovals, 2); // over the threshold: two different officers
    assert.equal((await ws.as(1, 'POST', `/api/ws/disbursements/${big.id}/approve`, {})).json.status, 'pending');
    assert.equal((await ws.as(1, 'POST', `/api/ws/disbursements/${big.id}/approve`, {})).status, 409); // the same officer twice is not two officers
    assert.equal((await ws.as(2, 'POST', `/api/ws/disbursements/${big.id}/approve`, {})).json.status, 'approved');
    assert.equal((await ws.as(0, 'POST', `/api/ws/disbursements/${big.id}/pay`)).status, 200);
    const rej = (await ws.as(0, 'POST', '/api/ws/disbursements', { amountCents: 100, category: 'office', payee: 'X' })).json;
    assert.equal((await ws.as(2, 'POST', `/api/ws/disbursements/${rej.id}/approve`, { decision: 'reject' })).json.status, 'rejected');
    const aid = (await ws.as(0, 'POST', '/api/ws/disbursements', { amountCents: 2500, category: 'member_benefits', payee: 'Zyxwvut Payee Hardship', memo: 'Rent help' })).json;
    await ws.as(1, 'POST', `/api/ws/disbursements/${aid.id}/approve`, {});
    await ws.as(0, 'POST', `/api/ws/disbursements/${aid.id}/pay`);
    const sum = (await ws.as(4, 'GET', '/api/ws/finance/summary')).json;
    assert.equal(sum.balanceCents, 100_000 - 3000 - 60_000 - 2500);
    assert.equal(sum.entries.find((e) => e.category === 'member_benefits').payee, 'Member'); // aid recipients stay private
    assert.ok(sum.entries.some((e) => e.payee === 'Zyxwvut Payee Copy Shop'));
  });

  it('the ledger cannot be edited, even directly in the database; mistakes are fixed with reversing entries', async () => {
    assert.throws(() => h.app.db.prepare('UPDATE ws_ledger SET amount_cents=1').run(), /immutable/);
    assert.throws(() => h.app.db.prepare('DELETE FROM ws_ledger').run(), /immutable/);
    assert.throws(() => h.app.db.prepare('UPDATE ws_audit SET action=?').run('x'), /append-only/);
    // INSERT OR REPLACE deletes the row it replaces; without recursive triggers it did so without tripping the guards above
    assert.throws(() => h.app.db.prepare('INSERT OR REPLACE INTO ws_ledger SELECT * FROM ws_ledger WHERE seq=1').run(), /immutable/);
    assert.throws(() => h.app.db.prepare('INSERT OR REPLACE INTO ws_audit SELECT * FROM ws_audit WHERE seq=1').run(), /append-only/);
    const rows = (await ws.as(4, 'GET', '/api/ws/finance/summary')).json.entries;
    const receipt = rows.find((e) => e.kind === 'receipt');
    const rev = await ws.as(0, 'POST', `/api/ws/ledger/${h.app.db.prepare('SELECT id FROM ws_ledger WHERE seq=?').get(receipt.seq).id}/reverse`, { reason: 'Entered twice' });
    assert.equal(rev.status, 200, JSON.stringify(rev.json));
    const id = h.app.db.prepare('SELECT id FROM ws_ledger WHERE seq=?').get(receipt.seq).id;
    assert.equal((await ws.as(0, 'POST', `/api/ws/ledger/${id}/reverse`, { reason: 'again' })).status, 409); // already reversed
    assert.equal((await ws.as(0, 'POST', `/api/ws/ledger/${h.app.db.prepare('SELECT id FROM ws_ledger WHERE seq=?').get(rev.json.seq).id}/reverse`, { reason: 'undo undo' })).json.error, 'is_reversal');
    const sum = (await ws.as(4, 'GET', '/api/ws/finance/summary')).json;
    assert.equal(sum.balanceCents, -3000 - 60_000 - 2500); // the receipt is cancelled out, not erased
    assert.equal(sum.byCategory.receipts.dues, 0);
    assert.ok(sum.entries.find((e) => e.seq === receipt.seq).reversed);
  });

  it('every member can verify the whole ledger is an unbroken chain, and rewritten history is caught', async () => {
    const chain = (await ws.as(4, 'GET', '/api/ws/finance/chain')).json;
    assert.ok(chain.entries.length >= 5);
    const ok = verifyChain(chain.entries, ledgerFields);
    assert.equal(ok.ok, true);
    const pin = ok.head;
    // a corrupt database: someone edits an amount and recomputes nothing
    const edited = structuredClone(chain.entries); edited[2].cents += 1;
    assert.deepEqual(verifyChain(edited, ledgerFields), { ok: false, brokenAt: edited[2].seq, why: 'hash' });
    // cleverer: recompute the edited entry's own hash, but then the next link breaks
    const forged = structuredClone(chain.entries); forged[2].cents += 1;
    forged[2].hash = C.chainHash(forged[2].prevHash, ledgerFields(forged[2]));
    assert.equal(verifyChain(forged, ledgerFields).why, 'link');
    // cleverest: rewrite the whole tail consistently. The head this device pinned earlier gives it away.
    const rewritten = structuredClone(chain.entries); rewritten[2].cents += 1;
    for (let i = 2; i < rewritten.length; i++) { if (i > 2) rewritten[i].prevHash = rewritten[i - 1].hash; rewritten[i].hash = C.chainHash(rewritten[i].prevHash, ledgerFields(rewritten[i])); }
    assert.equal(verifyChain(rewritten, ledgerFields).ok, true);
    assert.deepEqual(checkPinned(rewritten, pin), { ok: false, why: 'changed' });
    assert.deepEqual(checkPinned(chain.entries, pin), { ok: true });
    assert.equal(checkPinned(chain.entries.slice(0, 2), pin).why, 'missing');
    const audit = (await ws.as(0, 'GET', '/api/ws/audit')).json;
    assert.equal(verifyChain([...audit.entries].reverse(), auditFields, { anchored: audit.entries.length < 500 }).ok, true);
  });

  it('plaintext-leak test: payees, memos and people are encrypted at rest', () => {
    assert.deepEqual(h.leaks([...NEEDLES, 'Zyxwvut Payee Copy Shop', 'Zyxwvut Payee Law Office', 'Zyxwvut Payee Hardship', 'Flyers', 'Retainer', 'Rent help', 'Entered twice']), []);
  });
});

describe('workspace: grievances (end-to-end encrypted, never gated by dues)', () => {
  let h, ws, id, key;
  const CHIEF = 0, STEW = 7, WORKER = 6, OTHER = 4;
  const sealTo = (i, k) => C.boxSeal(ws.members[i].keys.boxPublicKey, k);
  const openKey = (i, sealed) => C.boxOpen(sealed, ws.members[i].keys.boxPublicKey, ws.members[i].keys.boxSecretKey);
  const today = async () => (await ws.as(CHIEF, 'GET', '/api/ws/me')).json.today;
  before(async () => { h = await startApp(); ws = await makeWorkspace(h, PEOPLE); });
  after(() => h.stop());

  it('is unavailable before recognition, and refuses to accept a concern nobody could read', async () => {
    const t = await makeWorkspace(h, [person('Only Officer', 0, { roles: ['officer'] }), person('Worker One', 1)], { stage: 'public_prerecognition' });
    const gid = crypto.randomUUID(), k = C.randomBytes(32);
    const body = { id: gid, ...C.sealJson(k, { what: 'x' }, 'grievance|' + gid), sealedKeys: { [t.members[1].id]: C.boxSeal(t.members[1].keys.boxPublicKey, k) } };
    assert.equal((await t.as(1, 'POST', '/api/ws/grievances', body)).json.error, 'stage_required');
    assert.equal((await t.as(0, 'POST', '/api/ws/stage', { stage: 'recognized', note: 'NLRB certification' })).status, 200);
    assert.equal((await t.as(1, 'POST', '/api/ws/grievances', body)).json.error, 'no_chief_steward');
  });

  it('a non-member files a concern; only the chief steward and the worker can read it', async () => {
    id = crypto.randomUUID(); key = C.randomBytes(32);
    const box = C.sealJson(key, { what: 'Zyxwvut grievance narrative: my hours were cut after I signed', who: 'Shift manager', desired: 'Restore my hours' }, 'grievance|' + id);
    const keys = { [ws.members[WORKER].id]: sealTo(WORKER, key), [ws.members[CHIEF].id]: sealTo(CHIEF, key) };
    assert.equal((await ws.as(WORKER, 'POST', '/api/ws/grievances', { id, ...box, sealedKeys: { [ws.members[WORKER].id]: keys[ws.members[WORKER].id] } })).status, 400); // the chief steward's key is required
    const r = await ws.as(WORKER, 'POST', '/api/ws/grievances', { id, ...box, articleRef: 'Art. 12', sealedKeys: keys });
    assert.equal(r.status, 200, JSON.stringify(r.json));
    const g = (await ws.as(WORKER, 'GET', `/api/ws/grievances/${id}`)).json;
    assert.deepEqual([g.mine, g.canWork, g.steps.length], [true, false, 3]);
    assert.equal(g.dueOn, D.dueDate(g.filedOn, { days: 5, dayType: 'business' }, [])); // step 1: 5 business days
    assert.equal(C.openJson(openKey(WORKER, g.sealedKey), g.content, 'grievance|' + id).desired, 'Restore my hours');
    const c = (await ws.as(CHIEF, 'GET', `/api/ws/grievances/${id}`)).json;
    assert.match(C.openJson(openKey(CHIEF, c.sealedKey), c.content, 'grievance|' + id).what, /hours were cut/);
    for (const i of [STEW, OTHER, 1]) assert.equal((await ws.as(i, 'GET', `/api/ws/grievances/${id}`)).status, 404); // nobody else can even tell it exists
    assert.equal((await ws.as(STEW, 'GET', '/api/ws/grievances')).json.grievances.length, 0);
    assert.equal((await ws.as(CHIEF, 'GET', '/api/ws/grievances')).json.grievances.length, 1);
    const log = (await ws.as(WORKER, 'GET', '/api/ws/me/access-log')).json.entries;
    assert.ok(log.some((e) => e.action === 'grievance.opened' && e.actor.startsWith('Ofelia'))); // the worker can see who opened their case
  });

  it('the chief steward assigns a steward by re-sealing the case key to them', async () => {
    const ring = (await ws.as(CHIEF, 'GET', '/api/ws/keyring?role=steward')).json.holders;
    const sam = ring.find((x) => x.memberId === ws.members[STEW].id);
    assert.equal((await ws.as(STEW, 'POST', `/api/ws/grievances/${id}/assign`, { stewardId: sam.memberId, sealedKey: C.boxSeal(sam.boxPublicKey, key) })).status, 403); // stewards cannot assign
    assert.equal((await ws.as(CHIEF, 'POST', `/api/ws/grievances/${id}/assign`, { stewardId: ws.members[OTHER].id, sealedKey: C.boxSeal(sam.boxPublicKey, key) })).json.error, 'steward_not_found');
    const g0 = (await ws.as(CHIEF, 'GET', `/api/ws/grievances/${id}`)).json;
    const resealed = C.boxSeal(sam.boxPublicKey, openKey(CHIEF, g0.sealedKey)); // only someone holding the key can hand it on
    assert.equal((await ws.as(CHIEF, 'POST', `/api/ws/grievances/${id}/assign`, { stewardId: sam.memberId, sealedKey: resealed })).status, 200);
    const g = (await ws.as(STEW, 'GET', `/api/ws/grievances/${id}`)).json;
    assert.equal(g.canWork, true);
    assert.equal(C.openJson(openKey(STEW, g.sealedKey), g.content, 'grievance|' + id).who, 'Shift manager');
    const note = C.sealJson(key, { note: 'Zyxwvut note: met with the manager' }, 'note|' + id);
    assert.equal((await ws.as(OTHER, 'POST', `/api/ws/grievances/${id}/notes`, note)).status, 403);
    assert.equal((await ws.as(STEW, 'POST', `/api/ws/grievances/${id}/notes`, note)).status, 200);
    const seen = (await ws.as(WORKER, 'GET', `/api/ws/grievances/${id}`)).json.notes[0];
    assert.match(C.openJson(key, seen, 'note|' + id).note, /met with the manager/);
  });

  it('a chief steward with no key for a case cannot work it, and assigning never replaces anyone\'s key', async () => {
    // Ezra becomes a chief steward AFTER the case was filed, so no key for it was ever sealed to him
    assert.equal((await ws.as(CHIEF, 'POST', '/api/ws/roles', { memberId: ws.members[3].id, role: 'chief_steward', op: 'add' })).status, 200);
    const before = h.app.db.prepare('SELECT sealed_keys k, assigned_to a, decision d, status s FROM ws_grievances WHERE id=?').get(id);
    assert.equal((await ws.as(3, 'GET', '/api/ws/grievances')).json.grievances.length, 1); // he can see that cases exist...
    const junk = C.boxSeal(ws.members[3].keys.boxPublicKey, C.randomBytes(32));
    for (const [route, body] of [['assign', { stewardId: ws.members[3].id, sealedKey: junk }], ['decision', { decision: 'not_pursued', reasonCiphertext: 'x'.repeat(30), reasonNonce: 'y'.repeat(32) }],
      ['notify-worker', {}], ['close', {}], ['steps/complete', { outcome: 'denied' }], ['notes', { ciphertext: 'x'.repeat(30), nonce: 'y'.repeat(32) }]]) {
      const r = await ws.as(3, 'POST', `/api/ws/grievances/${id}/${route}`, body); // ...but cannot act on one he was never entrusted with, and is told why
      assert.deepEqual([r.status, r.json.error], [409, 'no_case_key'], route);
    }
    assert.deepEqual(h.app.db.prepare('SELECT sealed_keys k, assigned_to a, decision d, status s FROM ws_grievances WHERE id=?').get(id), before); // nothing changed
    // a key holder cannot overwrite another person's key either (a junk key would lock the real steward out)
    const samKey = JSON.parse(before.k)[ws.members[STEW].id];
    assert.ok(samKey);
    assert.equal((await ws.as(CHIEF, 'POST', `/api/ws/grievances/${id}/assign`, { stewardId: ws.members[STEW].id, sealedKey: C.boxSeal(ws.members[STEW].keys.boxPublicKey, C.randomBytes(32)) })).status, 200);
    assert.equal(JSON.parse(h.app.db.prepare('SELECT sealed_keys k FROM ws_grievances WHERE id=?').get(id).k)[ws.members[STEW].id], samKey);
    assert.equal((await ws.as(CHIEF, 'POST', '/api/ws/roles', { memberId: ws.members[3].id, role: 'chief_steward', op: 'remove' })).status, 200);
  });

  it('when a new chief steward takes over, whoever holds the case key can hand it on, so no case is left stranded', async () => {
    const EZRA = 3;
    assert.equal((await ws.as(CHIEF, 'POST', '/api/ws/roles', { memberId: ws.members[EZRA].id, role: 'chief_steward', op: 'add' })).status, 200);
    const mine = (await ws.as(WORKER, 'GET', `/api/ws/grievances/${id}`)).json;
    assert.deepEqual(mine.missingKeys, [{ memberId: ws.members[EZRA].id, name: 'Ezra Qqqelect', boxPublicKey: ws.members[EZRA].keys.boxPublicKey }]); // the worker is shown who cannot read it yet
    const his = (await ws.as(EZRA, 'GET', `/api/ws/grievances/${id}`)).json;
    assert.deepEqual([his.canWork, his.sealedKey], [false, null]); // not offered work he cannot do
    const share = (i, memberId, sealedKey) => ws.as(i, 'POST', `/api/ws/grievances/${id}/share`, { memberId, sealedKey });
    const toEzra = C.boxSeal(ws.members[EZRA].keys.boxPublicKey, key);
    assert.equal((await share(OTHER, ws.members[EZRA].id, toEzra)).status, 404); // someone with no part in the case
    assert.equal((await share(EZRA, ws.members[EZRA].id, toEzra)).json.error, 'no_case_key'); // nobody hands a case to themselves
    assert.equal((await share(WORKER, ws.members[OTHER].id, C.boxSeal(ws.members[OTHER].keys.boxPublicKey, key))).json.error, 'steward_not_found'); // only to a steward
    assert.equal((await share(CHIEF, ws.members[EZRA].id, toEzra)).status, 200); // the outgoing chief (or the worker) hands it on
    const g = (await ws.as(EZRA, 'GET', `/api/ws/grievances/${id}`)).json;
    assert.equal(g.canWork, true);
    assert.match(C.openJson(openKey(EZRA, g.sealedKey), g.content, 'grievance|' + id).what, /hours were cut/);
    assert.deepEqual((await ws.as(WORKER, 'GET', `/api/ws/grievances/${id}`)).json.missingKeys, []);
    assert.equal((await share(WORKER, ws.members[EZRA].id, C.boxSeal(ws.members[EZRA].keys.boxPublicKey, C.randomBytes(32)))).status, 200); // a second hand-over...
    assert.equal(JSON.parse(h.app.db.prepare('SELECT sealed_keys k FROM ws_grievances WHERE id=?').get(id).k)[ws.members[EZRA].id], toEzra); // ...never replaces a key
    assert.ok((await ws.as(WORKER, 'GET', '/api/ws/me/access-log')).json.entries.some((e) => e.action === 'grievance.shared')); // and the worker sees it happened
    assert.equal((await ws.as(CHIEF, 'POST', '/api/ws/roles', { memberId: ws.members[EZRA].id, role: 'chief_steward', op: 'remove' })).status, 200);
  });

  it('steps start their own clocks, and overdue steps show up for the union', async () => {
    const t0 = await today();
    assert.equal((await ws.as(WORKER, 'POST', `/api/ws/grievances/${id}/steps/complete`, { outcome: 'advance' })).status, 403);
    assert.equal((await ws.as(STEW, 'POST', `/api/ws/grievances/${id}/steps/complete`, { outcome: 'advance' })).status, 200);
    const g = (await ws.as(STEW, 'GET', `/api/ws/grievances/${id}`)).json;
    assert.deepEqual([g.currentStep, g.steps[0].outcome], [2, 'advance']);
    assert.equal(g.steps[1].dueOn, D.dueDate(t0, { days: 10, dayType: 'business' }, [])); // step 2's clock started today
    h.app.db.prepare('UPDATE ws_grievance_steps SET due_on=? WHERE grievance_id=? AND step_number=2').run('2020-01-01', id);
    assert.equal((await ws.as(CHIEF, 'GET', '/api/ws/grievances')).json.grievances[0].urgency.level, 'overdue');
    assert.equal((await ws.as(CHIEF, 'GET', '/api/ws/health')).json.overdueSteps, 1);
  });

  it('a case cannot close without a recorded decision, a reason and telling the worker', async () => {
    const closeIt = () => ws.as(STEW, 'POST', `/api/ws/grievances/${id}/close`);
    assert.deepEqual((await closeIt()).json, { error: 'cannot_close', missing: ['decision', 'reason', 'worker_notification'] });
    assert.equal((await ws.as(STEW, 'POST', `/api/ws/grievances/${id}/decision`, { decision: 'pursue' })).status, 400); // a decision needs a reason
    assert.equal((await ws.as(STEW, 'POST', `/api/ws/grievances/${id}/decision`, { decision: 'whatever', ...C.sealJson(key, { r: 'x' }, 'reason|' + id), reasonCiphertext: 'AAAAAAAAAAAAAAAAAAAA', reasonNonce: 'A'.repeat(32) })).status, 400);
    const reason = C.sealJson(key, { reason: 'Zyxwvut reason: the contract clearly covers this' }, 'reason|' + id);
    assert.equal((await ws.as(STEW, 'POST', `/api/ws/grievances/${id}/decision`, { decision: 'pursue', reasonCiphertext: reason.ciphertext, reasonNonce: reason.nonce })).status, 200);
    assert.deepEqual((await closeIt()).json.missing, ['worker_notification']);
    assert.equal((await ws.as(STEW, 'POST', `/api/ws/grievances/${id}/notify-worker`)).status, 200);
    assert.equal((await closeIt()).status, 200);
    assert.equal((await ws.as(STEW, 'POST', `/api/ws/grievances/${id}/steps/complete`, { outcome: 'advance' })).json.error, 'closed');
    const g = (await ws.as(WORKER, 'GET', `/api/ws/grievances/${id}`)).json; // the worker reads the decision and the reason
    assert.deepEqual([g.decision, g.workerNotified, g.status], ['pursue', true, 'closed']);
    assert.match(C.openJson(key, { nonce: g.reason.nonce, ciphertext: g.reason.ciphertext }, 'reason|' + id).reason, /contract clearly covers/);
  });

  it('the union configures its own grievance procedure, including holidays', async () => {
    assert.equal((await ws.as(OTHER, 'PUT', '/api/ws/procedure', { steps: [{ name: 'S', days: 3, dayType: 'calendar' }] })).status, 403);
    assert.equal((await ws.as(0, 'PUT', '/api/ws/procedure', { steps: [{ name: 'S', days: 0, dayType: 'calendar' }] })).status, 400);
    const t0 = await today();
    const hol = D.addCalendar(t0, 3);
    assert.equal((await ws.as(0, 'PUT', '/api/ws/procedure', { steps: [{ name: 'Only step', days: 3, dayType: 'business' }], holidays: [hol] })).status, 200);
    const gid = crypto.randomUUID(), k = C.randomBytes(32);
    const r = await ws.as(OTHER, 'POST', '/api/ws/grievances', { id: gid, ...C.sealJson(k, { what: 'Zyxwvut second concern' }, 'grievance|' + gid), sealedKeys: { [ws.members[OTHER].id]: sealTo(OTHER, k), [ws.members[CHIEF].id]: C.boxSeal(ws.members[CHIEF].keys.boxPublicKey, k) } });
    assert.equal(r.status, 200);
    const g = (await ws.as(OTHER, 'GET', `/api/ws/grievances/${gid}`)).json;
    assert.equal(g.steps.length, 1);
    assert.equal(g.steps[0].dueOn, D.dueDate(t0, { days: 3, dayType: 'business' }, [hol]));
  });

  it('union health shows aggregates only and hides small groups', async () => {
    const hl = (await ws.as(0, 'GET', '/api/ws/health')).json;
    assert.deepEqual([hl.unitSize, hl.members], [8, 7]);
    assert.deepEqual(hl.shifts.find((x) => x.shift === 'Night'), { shift: 'Night', suppressed: true }); // 2 people: hidden
    // ...and Day too: otherwise 8 people in all, minus the 6 on Day, gives Night's size away
    assert.deepEqual(hl.shifts.find((x) => x.shift === 'Day'), { shift: 'Day', suppressed: true });
    // with three shifts, one small one hidden, the next smallest is hidden with it and the largest still shows
    const t = await makeWorkspace(h, [...Array.from({ length: 7 }, (_, i) => person(`Day${i} Qqq`, i, { shift: 'Day', ...(i === 0 ? { roles: ['officer'] } : {}) })),
      ...Array.from({ length: 5 }, (_, i) => person(`Eve${i} Qqq`, i, { shift: 'Evening' })), ...Array.from({ length: 2 }, (_, i) => person(`Night${i} Qqq`, i, { shift: 'Night' }))]);
    const three = (await t.as(0, 'GET', '/api/ws/health')).json.shifts;
    assert.deepEqual(three.filter((x) => x.suppressed).map((x) => x.shift).sort(), ['Evening', 'Night']);
    assert.deepEqual(three.find((x) => x.shift === 'Day'), { shift: 'Day', total: 7, members: 7 });
    assert.equal((await ws.as(4, 'GET', '/api/ws/health')).status, 403);
    const cal = (await ws.as(0, 'GET', '/api/ws/compliance')).json.tasks;
    assert.ok(cal.find((t) => t.key === 'lm1').dueOn);
    assert.equal((await ws.as(0, 'POST', '/api/ws/compliance/lm1/toggle')).json.done, true);
  });

  it('plaintext-leak test: grievance content, decisions and notes never reach the server in any readable form', async () => {
    const tokens = ws.members.map((m) => m.token);
    const ex = JSON.stringify((await ws.as(CHIEF, 'GET', '/api/ws/export')).json);
    assert.ok(!ex.includes('my hours were cut') && !ex.includes('contract clearly covers')); // E2E content is exported as ciphertext only
    assert.deepEqual(h.leaks([...NEEDLES, 'my hours were cut', 'Restore my hours', 'Shift manager', 'met with the manager', 'contract clearly covers', 'second concern', ...tokens, C.b64(key)]), []);
  });
});
