import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as C from '../shared/crypto.js';
import { startApp, makeCampaign, makeInvite, signCard, confirm, trusteeAuth, enrollTrustee } from './helpers.js';

const NAMES = { a: 'Zyxwvut Qqqname', b: 'Bertrand Leakcheck', c: 'Cordelia Leakcheck', d: 'Dominic Leakcheck' };
const person = (k, n) => ({ name: NAMES[k], email: `leaktest+${k}@example.com`, phone: `+1555019999${n}` });
const LEAK_STRINGS = [...Object.values(NAMES), 'leaktest+a@example.com', 'leaktest+b@example.com', '+15550199991', 'Leakcheck Industries LLC', 'Leakcheck Workers United', 'I authorize the union'];

describe('campaign: zero-knowledge authorization cards', () => {
  let h, camp, A, B, C2, D, gInvite, secrets = [];
  const t = (i) => camp.trustees[i - 1];
  const tAuth = (i, route) => trusteeAuth(h, t(i).keys, i, route, camp.id);
  before(async () => {
    h = await startApp();
    camp = await makeCampaign(h, { meta: { unionName: 'Leakcheck Workers United', employerName: 'Leakcheck Industries LLC', estimatedUnitSize: 10 } });
  });
  after(() => h.stop());

  it('goes live as soon as the founder has a key, completes when everyone has joined, and hides the metadata from strangers', async () => {
    const me = await h.call('GET', `/api/campaigns/${camp.id}/meta`, { auth: await tAuth(1, 'GET /api/campaigns/:id/meta') });
    assert.equal(me.status, 200);
    assert.equal(me.json.status, 'active');
    assert.equal(me.json.k, 2);
    assert.equal(me.json.trustees.length, 3);
    assert.deepEqual(C.decryptMeta(camp.campaignKey, { nonce: me.json.metaNonce, ciphertext: me.json.metaCiphertext }, camp.id).unionName, 'Leakcheck Workers United');
    assert.equal((await h.call('GET', `/api/campaigns/${camp.id}/meta`)).status, 401);
    assert.equal((await h.call('GET', `/api/campaigns/${camp.id}/meta`, { auth: 'Bearer ' + C.newToken() })).status, 401);
    // a second campaign stays a draft until its trustees enroll
    const id = crypto.randomUUID(), box = C.encryptMeta(C.newCampaignKey(), { x: 1 }, id), tok = [C.newToken(), C.newToken()];
    await h.call('POST', '/api/campaigns', { body: { id, k: 2, n: 2, metaCiphertext: box.ciphertext, metaNonce: box.nonce, templateVersion: 'card-v1', enrollTokenHashes: tok.map(C.hashToken) } });
    const k = C.newKeypairs();
    const e = await h.call('POST', '/api/trustees/enroll', { body: { campaignId: id, enrollToken: tok[0], boxPublicKey: k.boxPublicKey, signPublicKey: k.signPublicKey } });
    assert.deepEqual([e.json.enrolledCount, e.json.status, e.json.committeeComplete], [1, 'active', false]); // the founder alone is enough to start collecting cards
    const k2 = C.newKeypairs(); // a second trustee is a second person with their own keys
    const e2 = await h.call('POST', '/api/trustees/enroll', { body: { campaignId: id, enrollToken: tok[1], boxPublicKey: k2.boxPublicKey, signPublicKey: k2.signPublicKey } });
    assert.deepEqual([e2.json.enrolledCount, e2.json.committeeComplete], [2, true]);
    assert.equal((await h.call('POST', '/api/trustees/enroll', { body: { campaignId: id, enrollToken: tok[0], boxPublicKey: k.boxPublicKey, signPublicKey: k.signPublicKey } })).status, 401); // token is single-use
  });

  it('trustee challenge-response: valid passes; replay, wrong key and wrong route fail', async () => {
    const route = 'GET /api/campaigns/:id/progress';
    const auth = await tAuth(1, route);
    assert.equal((await h.call('GET', `/api/campaigns/${camp.id}/progress`, { auth })).status, 200);
    assert.equal((await h.call('GET', `/api/campaigns/${camp.id}/progress`, { auth })).status, 401); // replay
    const wrong = await trusteeAuth(h, C.newKeypairs(), 1, route, camp.id);
    assert.equal((await h.call('GET', `/api/campaigns/${camp.id}/progress`, { auth: wrong })).status, 401);
    const other = await tAuth(1, 'POST /api/campaigns/:id/freeze'); // signed for a different action
    assert.equal((await h.call('GET', `/api/campaigns/${camp.id}/progress`, { auth: other })).status, 401);
  });

  it('a direct invite signs a card that counts at once, and cannot be reused', async () => {
    const inv = await makeInvite(h, camp, { kind: 'direct' });
    assert.equal((await h.call('POST', '/api/invites/resolve', { body: { token: inv.token } })).json.kind, 'direct');
    A = await signCard(h, camp, inv.token, person('a', 1));
    assert.equal(A.res.status, 200);
    assert.equal(A.res.json.status, 'vouched');
    assert.equal((await h.call('POST', '/api/invites/resolve', { body: { token: inv.token } })).status, 404);
    const again = await signCard(h, camp, inv.token, person('b', 2));
    assert.equal(again.res.status, 404);
    secrets.push(inv.token);
  });

  it('sends the Confirmation Transmission with every field GC 15-08 requires, and stores none of it', async () => {
    const r = await confirm(h, camp, A);
    assert.equal(r.status, 200);
    // the development outbox holds that email: served to a browser on this machine only, not to one a proxy passes on
    assert.equal((await fetch(h.base + '/dev/outbox')).status, 200);
    assert.equal((await fetch(h.base + '/dev/outbox', { headers: { 'x-forwarded-for': '203.0.113.9' } })).status, 404);
    const mail = h.app.mail.outbox.at(-1);
    for (const s of [NAMES.a, 'leaktest+a@example.com', '+15550199991', 'Leakcheck Industries LLC', 'Leakcheck Workers United', 'I authorize the union to represent me.', 'UTC', '/d#t=' + A.disavowToken]) assert.ok(mail.text.includes(s), 'email lacks: ' + s);
    assert.match(mail.subject, /Confirmation/);
    assert.match(mail.text, /\d{4}-\d{2}-\d{2}T/); // the date signed, from the server clock
    assert.equal((await confirm(h, camp, A)).status, 409); // only once
    const row = h.app.db.prepare('SELECT confirmation_sent_at s, confirmation_message_id m FROM cards WHERE id=?').get(A.cardId);
    assert.ok(row.s && row.m.startsWith('dev-'));
    const bad = await h.call('POST', `/api/cards/${A.cardId}/confirm`, { auth: A.auth, body: { to: 'x@example.com', legalName: 'n', phone: '1', employerName: 'e', unionName: 'u', cardText: 't', disavowToken: C.newToken() } });
    assert.ok([400, 409].includes(bad.status)); // a link that does not match the stored hash is refused
  });

  it('a group link creates pending cards that only the link\'s creator can vouch, with a 5-try lockout', async () => {
    const g = await makeInvite(h, camp, { kind: 'group', by: A });
    gInvite = g; secrets.push(g.token);
    B = await signCard(h, camp, g.token, person('b', 2), { group: true });
    C2 = await signCard(h, camp, g.token, person('c', 3), { group: true });
    D = await signCard(h, camp, g.token, person('d', 4), { group: true });
    assert.equal(B.res.json.status, 'pending');
    // pending members see nothing and cannot invite
    assert.equal((await h.call('GET', `/api/campaigns/${camp.id}/progress`, { auth: B.auth })).status, 403);
    assert.equal((await h.call('POST', '/api/invites', { auth: B.auth, body: { campaignId: camp.id, tokenHash: C.hashToken(C.newToken()), kind: 'direct' } })).status, 403);
    assert.equal((await h.call('GET', '/api/cards/me', { auth: B.auth })).json.status, 'pending');
    // another pending signer cannot vouch
    assert.equal((await h.call('POST', `/api/cards/${B.cardId}/vouch`, { auth: C2.auth, body: { code: B.vouch } })).status, 403);
    // creator sees the queue, ids and times only
    const q = await h.call('GET', `/api/campaigns/${camp.id}/pending-vouches`, { auth: A.auth });
    assert.equal(q.json.pending.length, 3);
    assert.deepEqual(Object.keys(q.json.pending[0]).sort(), ['attemptsLeft', 'cardId', 'createdAt']);
    // wrong codes: five failures lock the card, even for the right code afterwards
    for (let i = 0; i < 5; i++) assert.equal((await h.call('POST', `/api/cards/${B.cardId}/vouch`, { auth: A.auth, body: { code: 'WRONG-CODE' } })).status, 403);
    assert.equal((await h.call('POST', `/api/cards/${B.cardId}/vouch`, { auth: A.auth, body: { code: B.vouch } })).status, 423);
    // right code works on the others, case-insensitively
    assert.equal((await h.call('POST', `/api/cards/${C2.cardId}/vouch`, { auth: A.auth, body: { code: C2.vouch.toLowerCase() } })).status, 200);
    // a trustee may also vouch (with the code)
    assert.equal((await h.call('POST', `/api/cards/${D.cardId}/vouch`, { auth: await tAuth(2, 'POST /api/cards/:id/vouch'), body: { code: D.vouch } })).status, 200);
    assert.equal((await h.call('POST', `/api/cards/${D.cardId}/vouch`, { auth: await tAuth(2, 'POST /api/cards/:id/vouch'), body: { code: D.vouch } })).status, 409); // already vouched
  });

  it('progress shows counts and momentum to vouched members and trustees only', async () => {
    const p = await h.call('GET', `/api/campaigns/${camp.id}/progress`, { auth: A.auth });
    assert.equal(p.json.vouched, 3);
    assert.equal(p.json.pending, 1);
    assert.ok(p.json.history.length >= 1);
    const tp = await h.call('GET', `/api/campaigns/${camp.id}/progress`, { auth: await tAuth(3, 'GET /api/campaigns/:id/progress') });
    assert.equal(tp.json.destroyApprovals, 0);
  });

  it('invites expire, can be revoked, and group links respect max uses', async () => {
    const i1 = await makeInvite(h, camp, { kind: 'direct' });
    h.app.db.prepare('UPDATE invites SET expires_at=? WHERE token_hash=?').run(new Date(Date.now() - 1000).toISOString(), C.hashToken(i1.token));
    assert.equal((await signCard(h, camp, i1.token)).res.status, 404);
    const i2 = await makeInvite(h, camp, { kind: 'direct', by: A });
    assert.equal((await h.call('POST', '/api/invites/revoke', { auth: C2.auth, body: { inviteId: i2.inviteId } })).status, 403); // only the creator
    assert.equal((await h.call('POST', '/api/invites/revoke', { auth: A.auth, body: { inviteId: i2.inviteId } })).status, 200);
    assert.equal((await signCard(h, camp, i2.token)).res.status, 404);
    const token = C.newToken();
    await h.call('POST', '/api/invites', { auth: A.auth, body: { campaignId: camp.id, tokenHash: C.hashToken(token), kind: 'group', maxUses: 2 } });
    assert.equal((await signCard(h, camp, token, {}, { group: true })).res.status, 200);
    assert.equal((await signCard(h, camp, token, {}, { group: true })).res.status, 200);
    assert.equal((await signCard(h, camp, token, {}, { group: true })).res.status, 404);
  });

  it('a worker\'s private locker and a shared report: the server holds only ciphertext', async () => {
    const id = crypto.randomUUID();
    const entry = C.sealJson(A.lockerKey, { kind: 'interrogation', what: 'Supervisor asked if I signed', date: '2026-09-20' }, 'locker|' + id);
    assert.equal((await h.call('POST', '/api/locker', { auth: A.auth, body: { id, ...entry } })).status, 200);
    const list = await h.call('GET', '/api/locker', { auth: A.auth });
    assert.equal(list.json.entries.length, 1);
    assert.equal(C.openJson(A.lockerKey, list.json.entries[0], 'locker|' + id).what, 'Supervisor asked if I signed');
    assert.equal((await h.call('GET', '/api/locker', { auth: C2.auth })).json.entries.length, 0); // nobody else's
    // share with the committee: sealed to every trustee, and not linked to the card
    const rid = crypto.randomUUID();
    const rep = C.sealForTrustees({ kind: 'interrogation', what: 'Supervisor asked if I signed' }, camp.trustees.map((x) => ({ index: x.index, boxPublicKey: x.keys.boxPublicKey })), rid);
    assert.equal((await h.call('POST', '/api/reports', { auth: A.auth, body: { id: rid, ...rep } })).status, 200);
    const reports = await h.call('GET', `/api/campaigns/${camp.id}/reports`, { auth: await tAuth(3, 'GET /api/campaigns/:id/reports') });
    assert.equal(C.openReport(reports.json.reports[0], 3, t(3).keys.boxPublicKey, t(3).keys.boxSecretKey).what, 'Supervisor asked if I signed');
    assert.equal((await h.call('GET', `/api/campaigns/${camp.id}/reports`, { auth: A.auth })).status, 401);
    assert.deepEqual(h.app.db.prepare("SELECT name FROM pragma_table_info('reports')").all().map((r) => r.name).filter((n) => /card|member/.test(n)), []);
  });

  it('unlock: two trustees decrypt every vouched card; one trustee cannot', async () => {
    const bundle = await h.call('GET', `/api/campaigns/${camp.id}/export-bundle`, { auth: await tAuth(1, 'GET /api/campaigns/:id/export-bundle') });
    assert.equal(bundle.status, 200);
    const share = (c, tr) => C.openShare(c.sealedShares.find((s) => s.trusteeIndex === tr.index).sealed, tr.keys.boxPublicKey, tr.keys.boxSecretKey);
    const ctx = (c) => ({ campaignId: camp.id, templateVersion: c.templateVersion, ciphertext: c.ciphertext, nonce: c.nonce });
    const names = [];
    for (const c of bundle.json.cards) names.push((await C.decryptCard(ctx(c), [share(c, t(1)), share(c, t(3))])).legalName);
    assert.ok(names.includes(NAMES.a) && names.includes(NAMES.c) && names.includes(NAMES.d));
    assert.ok(!names.includes(NAMES.b), 'the locked, unvouched card must not be exported');
    await assert.rejects(C.decryptCard(ctx(bundle.json.cards[0]), [share(bundle.json.cards[0], t(2))]));
    assert.equal((await h.call('GET', `/api/campaigns/${camp.id}/export-bundle`, { auth: A.auth })).status, 401); // members cannot export
  });

  it('disavow flags the card; withdraw hard-deletes it and revokes its links', async () => {
    assert.equal((await h.call('POST', '/api/cards/disavow', { body: { cardId: D.cardId, token: C.newToken() } })).status, 403);
    assert.equal((await h.call('POST', '/api/cards/disavow', { body: { cardId: D.cardId, token: D.disavowToken } })).status, 200);
    let p = await h.call('GET', `/api/campaigns/${camp.id}/progress`, { auth: A.auth });
    assert.equal(p.json.vouched, 2); // A and C2 count; D disavowed
    // C2 makes a link, then withdraws: the card is gone for good and so is the link
    const c2link = await makeInvite(h, camp, { kind: 'direct', by: C2 });
    assert.equal((await h.call('DELETE', '/api/cards/me', { auth: C2.auth })).status, 200);
    assert.equal((await h.call('GET', '/api/cards/me', { auth: C2.auth })).status, 401);
    assert.equal((await signCard(h, camp, c2link.token)).res.status, 404);
    p = await h.call('GET', `/api/campaigns/${camp.id}/progress`, { auth: A.auth });
    assert.equal(p.json.vouched, 1);
    assert.equal(h.app.db.prepare('SELECT COUNT(*) c FROM cards WHERE id=?').get(C2.cardId).c, 0);
  });

  it('freeze stops new signatures; destroy needs k trustees and removes everything', async () => {
    const freeze = async (frozen) => h.call('POST', `/api/campaigns/${camp.id}/freeze`, { auth: await tAuth(2, 'POST /api/campaigns/:id/freeze'), body: { frozen } });
    assert.equal((await freeze(true)).json.status, 'frozen');
    const inv = C.newToken();
    assert.equal((await h.call('POST', '/api/invites', { auth: A.auth, body: { campaignId: camp.id, tokenHash: C.hashToken(inv), kind: 'direct' } })).status, 409);
    assert.equal((await freeze(false)).json.status, 'active');
    const destroy = async (i) => h.call('POST', `/api/campaigns/${camp.id}/destroy-approve`, { auth: await tAuth(i, 'POST /api/campaigns/:id/destroy-approve') });
    assert.deepEqual((await destroy(1)).json, { approvals: 1, needed: 2, destroyed: false });
    assert.equal((await destroy(1)).json.approvals, 1); // the same trustee twice is still one
    assert.equal((await destroy(3)).json.destroyed, true);
    assert.equal(h.app.db.prepare('SELECT COUNT(*) c FROM cards').get().c, 0);
    assert.equal(h.app.db.prepare('SELECT COUNT(*) c FROM locker_entries').get().c, 0);
    assert.equal((await h.call('GET', `/api/campaigns/${camp.id}/progress`, { auth: A.auth })).status, 401);
  });
});

describe('campaign: safety properties', () => {
  let h;
  before(async () => { h = await startApp(); });
  after(() => h.stop());

  it('plaintext-leak test: no name, email, phone, employer, union or token reaches the database or the logs', async () => {
    const camp = await makeCampaign(h, { meta: { unionName: 'Leakcheck Workers United', employerName: 'Leakcheck Industries LLC' } });
    const inv = await makeInvite(h, camp, { kind: 'direct' });
    const card = await signCard(h, camp, inv.token, person('a', 1));
    await confirm(h, camp, card);
    const g = await makeInvite(h, camp, { kind: 'group', by: card });
    const pending = await signCard(h, camp, g.token, person('b', 2), { group: true });
    await h.call('POST', `/api/cards/${pending.cardId}/vouch`, { auth: card.auth, body: { code: pending.vouch } });
    await h.call('POST', '/api/cards/disavow', { body: { cardId: pending.cardId, token: pending.disavowToken } });
    await h.call('POST', '/api/cards/disavow', { body: { cardId: pending.cardId, token: 'x' } }); // errors must not echo input either
    const id = crypto.randomUUID();
    await h.call('POST', '/api/locker', { auth: card.auth, body: { id, ...C.sealJson(card.lockerKey, { what: 'Zyxwvut Qqqname was threatened' }, 'locker|' + id) } });
    await h.call('DELETE', '/api/cards/me', { auth: pending.auth }); // a withdrawn card leaves no trace on disk
    const tokens = [inv.token, g.token, card.authToken, card.secret, card.disavowToken, pending.authToken, C.b64(card.lockerKey), camp.campaignKey, ...camp.enrollTokens];
    assert.deepEqual(h.leaks([...LEAK_STRINGS, ...tokens]), []);
    assert.ok(h.logs.length > 10);
    for (const line of h.logs) {
      const o = JSON.parse(line);
      assert.ok(Object.keys(o).every((k) => ['t', 'm', 'r', 's', 'ms', 'err', 'msg'].includes(k)), 'unexpected log field: ' + line);
      assert.ok(!/[0-9a-f]{8}-[0-9a-f]{4}-4/.test(line), 'raw id in log: ' + line);
    }
    assert.ok(h.logs.some((l) => l.includes('/api/cards/:id/confirm'))); // route patterns, never raw paths
  });

  it('sends the required security headers on the app and on the API', async () => {
    for (const url of ['/', '/api/campaigns/x/meta']) {
      const r = await h.call('GET', url);
      const hd = r.headers;
      assert.match(hd.get('content-security-policy'), /default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'/);
      assert.match(hd.get('content-security-policy'), /frame-ancestors 'none'; base-uri 'none'; form-action 'self'/);
      assert.equal(hd.get('referrer-policy'), 'no-referrer');
      assert.match(hd.get('strict-transport-security'), /max-age=63072000; includeSubDomains; preload/);
      assert.equal(hd.get('x-content-type-options'), 'nosniff');
      assert.match(hd.get('permissions-policy'), /camera=\(\)/);
      assert.equal(hd.get('cross-origin-opener-policy'), 'same-origin');
      assert.ok(!hd.get('set-cookie'));
    }
  });

  it('errors are generic, bodies are size-limited and malformed input is refused', async () => {
    const r = await h.call('POST', '/api/cards', { body: { cardId: 'not-a-uuid', ciphertext: 'Zyxwvut Qqqname' } });
    assert.deepEqual(r.json, { error: 'bad_request' });
    const big = await fetch(h.base + '/api/campaigns', { method: 'POST', body: JSON.stringify({ x: 'a'.repeat(1_100_000) }) }).catch(() => null);
    assert.ok(big === null || big.status === 413); // refused outright, or the connection dropped mid-upload
    const bad = await fetch(h.base + '/api/campaigns', { method: 'POST', body: '{nope' });
    assert.equal(bad.status, 400);
    assert.equal((await h.call('GET', '/api/nope')).status, 404);
  });

  it('inactive campaigns are hard-deleted by the expiry sweep', async () => {
    const camp = await makeCampaign(h);
    h.app.db.prepare('UPDATE campaigns SET last_activity_at=? WHERE id=?').run(new Date(Date.now() - 181 * 86400_000).toISOString(), camp.id);
    h.app.sweep();
    assert.equal(h.app.db.prepare('SELECT COUNT(*) c FROM campaigns WHERE id=?').get(camp.id).c, 0);
  });
});

describe('campaign: one person can start alone and add the committee later', () => {
  let h, camp, A, B, aliceCard;
  before(async () => { h = await startApp(); camp = await makeCampaign(h, { n: 3, k: 2, enroll: 1 }); });
  after(() => h.stop());
  const tAuth = (i, route) => trusteeAuth(h, camp.trustees.find((t) => t.index === i).keys, i, route, camp.id);

  it('is live as soon as the founder has a key, and early cards are sealed to the founder alone', async () => {
    const meta = await h.call('GET', `/api/campaigns/${camp.id}/meta`, { auth: await tAuth(1, 'GET /api/campaigns/:id/meta') });
    assert.equal(meta.json.status, 'active');
    assert.deepEqual(meta.json.trustees.map((t) => t.enrolled), [true, false, false]);
    const inv = await makeInvite(h, camp, { kind: 'direct' });
    A = await signCard(h, camp, inv.token, { name: 'Alice Anderson', email: 'a@example.org', phone: '+15550100001' });
    assert.equal(A.res.status, 200, JSON.stringify(A.res.json));
    const row = h.app.db.prepare('SELECT seal_mode m, sealed_shares s FROM cards WHERE id=?').get(A.cardId);
    assert.equal(row.m, 'solo');
    assert.deepEqual(JSON.parse(row.s).map((x) => x.trusteeIndex), [1]);
    // a card sealed to a committee that does not exist yet, or to anyone but the founder, is refused
    const fake = [1, 2, 3].map((i) => ({ index: i, boxPublicKey: C.newKeypairs().boxPublicKey }));
    const shamir = await C.encryptCard({ campaignId: camp.id, templateVersion: 'card-v1', payload: { x: 1 }, trustees: fake, k: 2 });
    const inv2 = await makeInvite(h, camp, { kind: 'direct' });
    const post = (enc) => h.call('POST', '/api/cards', { body: { cardId: crypto.randomUUID(), inviteToken: inv2.token, ...enc, memberTokenHash: C.hashToken(C.newToken()), disavowTokenHash: C.hashToken(C.newToken()) } });
    assert.equal((await post(shamir)).json.error, 'committee_changed');
    assert.equal((await post(C.encryptCardSolo({ campaignId: camp.id, templateVersion: 'card-v1', payload: { x: 1 }, founder: { index: 2, boxPublicKey: fake[1].boxPublicKey } }))).json.error, 'bad_shares');
  });

  it('group links and in-person vouching work exactly the same', async () => {
    const g = await makeInvite(h, camp, { kind: 'group', by: A });
    B = await signCard(h, camp, g.token, { name: 'Bob Baker', email: 'b@example.org', phone: '+15550100002' }, { group: true });
    assert.equal(B.res.json.status, 'pending');
    assert.equal((await h.call('POST', `/api/cards/${B.cardId}/vouch`, { auth: await tAuth(1, 'POST /api/cards/:id/vouch'), body: { code: B.vouch } })).status, 200);
  });

  it('the founder can open early cards alone; no other trustee has a key to them', async () => {
    const bundle = (await h.call('GET', `/api/campaigns/${camp.id}/export-bundle`, { auth: await tAuth(1, 'GET /api/campaigns/:id/export-bundle') })).json.cards;
    assert.ok(bundle.every((c) => c.sealMode === 'solo' && c.sealedShares.length === 1));
    const f = camp.trustees[0].keys;
    const names = bundle.map((c) => C.decryptSoloCard({ campaignId: camp.id, templateVersion: c.templateVersion, ciphertext: c.ciphertext, nonce: c.nonce }, C.openShare(c.sealedShares[0].sealed, f.boxPublicKey, f.boxSecretKey)).legalName);
    assert.deepEqual(names.sort(), ['Alice Anderson', 'Bob Baker']);
    const stranger = C.newKeypairs();
    assert.throws(() => C.openShare(bundle[0].sealedShares[0].sealed, stranger.boxPublicKey, stranger.boxSecretKey));
  });

  it('until the founder has signed the roster, reports go to the founder alone', async () => {
    const id = crypto.randomUUID();
    const mk = (ts) => C.sealForTrustees({ what: 'x' }, ts.map((t) => ({ index: t.index, boxPublicKey: t.keys?.boxPublicKey || C.newKeypairs().boxPublicKey })), id);
    assert.equal((await h.call('POST', '/api/reports', { auth: A.auth, body: { id, ...mk([{ index: 1, keys: camp.trustees[0].keys }, { index: 2 }, { index: 3 }]) } })).json.error, 'committee_changed');
    assert.equal((await h.call('POST', '/api/reports', { auth: A.auth, body: { id, ...mk([{ index: 1, keys: camp.trustees[0].keys }]) } })).status, 200);
  });

  it('the founder can change the plan and make a fresh invitation for a seat, which revokes the old link', async () => {
    const change = async (n, k) => h.call('POST', `/api/campaigns/${camp.id}/committee`, { auth: await tAuth(1, 'POST /api/campaigns/:id/committee'), body: { n, k } });
    assert.equal((await change(4, 3)).json.n, 4);
    assert.equal(h.app.db.prepare('SELECT COUNT(*) c FROM trustees WHERE campaign_id=?').get(camp.id).c, 4);
    assert.equal((await change(4, 5)).status, 400); // k cannot exceed n
    assert.equal((await change(1, 1)).status, 400); // a committee needs at least two people
    assert.equal((await change(3, 2)).json.n, 3); // back down: the empty seat is removed
    const fresh = C.newToken();
    assert.equal((await h.call('POST', `/api/campaigns/${camp.id}/trustees/reset`, { auth: await tAuth(1, 'POST /api/campaigns/:id/trustees/reset'), body: { index: 2, tokenHash: C.hashToken(fresh) } })).status, 200);
    assert.equal((await enrollTrustee(h, camp, 2, camp.enrollTokens[1])).r.status, 401); // the old link is dead
    assert.equal((await enrollTrustee(h, camp, 2, fresh)).r.status, 200);
    assert.equal((await h.call('POST', `/api/campaigns/${camp.id}/trustees/reset`, { auth: await tAuth(1, 'POST /api/campaigns/:id/trustees/reset'), body: { index: 2, tokenHash: C.hashToken(C.newToken()) } })).json.error, 'slot_taken'); // a taken seat cannot be reset
    assert.equal((await h.call('POST', `/api/campaigns/${camp.id}/committee`, { auth: await tAuth(2, 'POST /api/campaigns/:id/committee'), body: { n: 3, k: 2 } })).json.error, 'founder_only');
  });

  it('only the founder hands out seats: a trustee cannot re-issue an empty seat to take it (which would let one person hold k shares)', async () => {
    const before = h.app.db.prepare('SELECT enrollment_token_hash h FROM trustees WHERE campaign_id=? AND trustee_index=3').get(camp.id).h;
    const rogue = await h.call('POST', `/api/campaigns/${camp.id}/trustees/reset`, { auth: await tAuth(2, 'POST /api/campaigns/:id/trustees/reset'), body: { index: 3, tokenHash: C.hashToken(C.newToken()) } });
    assert.equal(rogue.status, 403);
    assert.equal(rogue.json.error, 'founder_only');
    // nothing changed: the link the founder gave the real third trustee is still the only one that works
    assert.equal(h.app.db.prepare('SELECT enrollment_token_hash h FROM trustees WHERE campaign_id=? AND trustee_index=3').get(camp.id).h, before);
    // and without any trustee credentials at all it is refused too
    assert.equal((await h.call('POST', `/api/campaigns/${camp.id}/trustees/reset`, { body: { index: 3, tokenHash: C.hashToken(C.newToken()) } })).status, 401);
  });

  it('the same keys cannot fill two seats, and a refused attempt leaves the seat open for the real person', async () => {
    const c2 = await makeCampaign(h, { n: 3, k: 2, enroll: 1 });
    const founderKeys = c2.trustees[0].keys;
    const reuse = await h.call('POST', '/api/trustees/enroll', { body: { campaignId: c2.id, enrollToken: c2.enrollTokens[1], boxPublicKey: founderKeys.boxPublicKey, signPublicKey: founderKeys.signPublicKey } });
    assert.equal(reuse.status, 409);
    assert.equal(reuse.json.error, 'key_reused');
    // reusing just one of the two keys is refused as well
    const half = C.newKeypairs();
    const halfReuse = await h.call('POST', '/api/trustees/enroll', { body: { campaignId: c2.id, enrollToken: c2.enrollTokens[1], boxPublicKey: half.boxPublicKey, signPublicKey: founderKeys.signPublicKey } });
    assert.equal(halfReuse.json.error, 'key_reused');
    // the seat is still open, and the real second trustee, with their own keys, can take it with the same link
    assert.equal((await enrollTrustee(h, c2, 2)).r.status, 200);
  });

  it('when everyone has joined but the founder has not signed the roster, cards are still sealed to the founder alone', async () => {
    const before = await h.call('GET', `/api/campaigns/${camp.id}/progress`, { auth: await tAuth(1, 'GET /api/campaigns/:id/progress') });
    assert.equal(before.json.solo, 2);
    const rosterOf = (ts) => ({ campaignId: camp.id, k: 2, n: 3, seats: [1, 2, 3].map((i) => ({ index: i, boxPublicKey: ts.find((t) => t.index === i)?.keys.boxPublicKey || C.newKeypairs().boxPublicKey })) });
    const early = rosterOf(camp.trustees);
    assert.equal((await h.call('POST', `/api/campaigns/${camp.id}/roster`, { auth: await tAuth(1, 'POST /api/campaigns/:id/roster'), body: { roster: early, signature: C.signRoster(camp.trustees[0].keys.signSecretKey, early) } })).json.error, 'committee_incomplete'); // someone has not joined
    const j = await enrollTrustee(h, camp, 3);
    assert.equal(j.r.json.committeeComplete, true);
    assert.equal((await h.call('POST', `/api/campaigns/${camp.id}/committee`, { auth: await tAuth(1, 'POST /api/campaigns/:id/committee'), body: { n: 3, k: 2 } })).json.error, 'committee_complete');
    // every trustee has joined, but nobody vouched for their keys: a browser cannot tell them from a server's inventions, so it still seals to the founder alone
    const inv = await makeInvite(h, camp, { kind: 'direct' });
    const still = await signCard(h, camp, inv.token, { name: 'Cara Cruz', email: 'c@example.org', phone: '+15550100003' });
    assert.equal(still.res.status, 200, JSON.stringify(still.res.json));
    assert.equal(h.app.db.prepare('SELECT seal_mode m FROM cards WHERE id=?').get(still.cardId).m, 'solo');
    // ...and a k-of-n card is refused until the founder has signed
    const shamir = await C.encryptCard({ campaignId: camp.id, templateVersion: 'card-v1', payload: { x: 1 }, trustees: camp.trustees.map((t) => ({ index: t.index, boxPublicKey: t.keys.boxPublicKey })), k: 2 });
    const inv2 = await makeInvite(h, camp, { kind: 'direct' });
    assert.equal((await h.call('POST', '/api/cards', { body: { cardId: crypto.randomUUID(), inviteToken: inv2.token, ...shamir, memberTokenHash: C.hashToken(C.newToken()), disavowTokenHash: C.hashToken(C.newToken()) } })).json.error, 'committee_changed');
    // the early cards cannot be re-locked yet either: the founder signs first, so that the set of solo cards stops growing
    const rb = await h.call('GET', `/api/campaigns/${camp.id}/reshare-bundle`, { auth: await tAuth(1, 'GET /api/campaigns/:id/reshare-bundle') });
    assert.equal(rb.json.cards.length, 3);
    assert.equal((await h.call('POST', `/api/campaigns/${camp.id}/reshare`, { auth: await tAuth(1, 'POST /api/campaigns/:id/reshare'), body: { cards: [{ cardId: rb.json.cards[0].id, sealedShares: [] }] } })).json.error, 'roster_not_confirmed');
  });

  it('the founder signs the roster: only the founder, only the committee the server holds, only with a valid signature', async () => {
    const F = camp.trustees[0].keys;
    const good = { campaignId: camp.id, k: 2, n: 3, seats: [...camp.trustees].sort((a, b) => a.index - b.index).map((t) => ({ index: t.index, boxPublicKey: t.keys.boxPublicKey })) };
    const sig = C.signRoster(F.signSecretKey, good);
    const post = async (i, body) => h.call('POST', `/api/campaigns/${camp.id}/roster`, { auth: await tAuth(i, 'POST /api/campaigns/:id/roster'), body });
    const stored = () => h.app.db.prepare('SELECT roster_json j FROM campaigns WHERE id=?').get(camp.id).j;
    assert.equal((await post(2, { roster: good, signature: sig })).json.error, 'founder_only'); // a trustee cannot confirm a committee (or sign for the founder)
    assert.equal((await h.call('POST', `/api/campaigns/${camp.id}/roster`, { body: { roster: good, signature: sig } })).status, 401);
    const swapped = { ...good, seats: good.seats.map((s) => (s.index === 2 ? { ...s, boxPublicKey: C.newKeypairs().boxPublicKey } : s)) };
    assert.equal((await post(1, { roster: swapped, signature: C.signRoster(F.signSecretKey, swapped) })).json.error, 'roster_mismatch'); // names a key the server does not hold for that seat
    assert.equal((await post(1, { roster: { ...good, k: 3 }, signature: C.signRoster(F.signSecretKey, { ...good, k: 3 }) })).json.error, 'roster_mismatch'); // a different threshold
    assert.equal((await post(1, { roster: { ...good, campaignId: crypto.randomUUID() }, signature: sig })).json.error, 'roster_mismatch'); // another campaign
    assert.equal((await post(1, { roster: good, signature: C.signRoster(camp.trustees[1].keys.signSecretKey, good) })).json.error, 'bad_signature'); // not the founder's signature
    assert.equal((await post(1, { roster: good, signature: 'not a signature' })).json.error, 'bad_signature');
    assert.equal((await post(1, { roster: 'x', signature: sig })).status, 400);
    assert.equal((await post(1, { roster: good })).status, 400);
    assert.equal(stored(), null); // none of that stored anything
    assert.equal((await post(1, { roster: good, signature: sig })).json.confirmed, true);
    assert.deepEqual((await post(1, { roster: good, signature: sig })).json, { confirmed: true, already: true }); // a retry is fine
    // the server now serves the founder's signing key and the roster, which anyone can verify without trusting it
    const meta = (await h.call('GET', `/api/campaigns/${camp.id}/meta`, { auth: await tAuth(2, 'GET /api/campaigns/:id/meta') })).json;
    assert.equal(meta.trustees[0].signPublicKey, F.signPublicKey);
    assert.deepEqual(meta.roster, { roster: good, signature: sig });
    assert.ok(C.verifyRoster(meta.trustees[0].signPublicKey, meta.roster.signature, meta.roster.roster));
    camp.confirmed = true;
  });

  it('once the roster is signed, new cards are k-of-n, and the founder locks the early ones to the committee', async () => {
    const inv = await makeInvite(h, camp, { kind: 'direct' });
    const late = await signCard(h, camp, inv.token, { name: 'Dee Diaz', email: 'd@example.org', phone: '+15550100004' });
    assert.equal(late.res.status, 200, JSON.stringify(late.res.json));
    assert.equal(h.app.db.prepare('SELECT seal_mode m FROM cards WHERE id=?').get(late.cardId).m, 'shamir');
    const solo = C.encryptCardSolo({ campaignId: camp.id, templateVersion: 'card-v1', payload: { x: 1 }, founder: { index: 1, boxPublicKey: camp.trustees[0].keys.boxPublicKey } });
    const inv2 = await makeInvite(h, camp, { kind: 'direct' });
    assert.equal((await h.call('POST', '/api/cards', { body: { cardId: crypto.randomUUID(), inviteToken: inv2.token, ...solo, memberTokenHash: C.hashToken(C.newToken()), disavowTokenHash: C.hashToken(C.newToken()) } })).json.error, 'committee_changed');

    const rb = await h.call('GET', `/api/campaigns/${camp.id}/reshare-bundle`, { auth: await tAuth(1, 'GET /api/campaigns/:id/reshare-bundle') });
    assert.equal(rb.json.cards.length, 3);
    assert.ok(rb.json.cards.every((c) => Object.keys(c).sort().join() === 'id,sealedShares')); // no ciphertext: reshaping cannot be used to read cards
    assert.equal((await h.call('GET', `/api/campaigns/${camp.id}/reshare-bundle`, { auth: await tAuth(2, 'GET /api/campaigns/:id/reshare-bundle') })).json.error, 'founder_only');
    const trustees = camp.trustees.map((t) => ({ index: t.index, boxPublicKey: t.keys.boxPublicKey }));
    const cards = [];
    for (const c of rb.json.cards) cards.push({ cardId: c.id, sealedShares: await C.reshareCard(c.sealedShares[0].sealed, camp.trustees[0].keys, trustees, 2) });
    const reshare = async (i, body) => h.call('POST', `/api/campaigns/${camp.id}/reshare`, { auth: await tAuth(i, 'POST /api/campaigns/:id/reshare'), body });
    assert.equal((await reshare(2, { cards })).json.error, 'founder_only'); // a rogue trustee could only destroy cards
    assert.equal((await reshare(1, { cards: [{ cardId: cards[0].cardId, sealedShares: cards[0].sealedShares.slice(0, 2) }] })).json.error, 'bad_shares');
    for (const junk of [null, 'x', {}, 7]) assert.equal((await reshare(1, { cards: [{ cardId: cards[0].cardId, sealedShares: junk }] })).status, 400, String(junk)); // malformed input is a 400, never a crash
    assert.deepEqual((await reshare(1, { cards })).json, { converted: 3, remaining: 0 });
    assert.equal((await reshare(1, { cards: [cards[0]] })).json.error, 'not_solo');

    // now trustees 2 and 3 can open the early cards WITHOUT the founder, and the founder alone cannot
    const bundle = (await h.call('GET', `/api/campaigns/${camp.id}/export-bundle`, { auth: await tAuth(2, 'GET /api/campaigns/:id/export-bundle') })).json.cards;
    assert.equal(bundle.length, 4);
    assert.ok(bundle.every((c) => c.sealMode === 'shamir' && c.sealedShares.length === 3));
    const sh = (c, i) => { const t = camp.trustees.find((x) => x.index === i).keys; return C.openShare(c.sealedShares.find((s) => s.trusteeIndex === i).sealed, t.boxPublicKey, t.boxSecretKey); };
    const ctx = (c) => ({ campaignId: camp.id, templateVersion: c.templateVersion, ciphertext: c.ciphertext, nonce: c.nonce });
    const opened = [];
    for (const c of bundle) opened.push((await C.decryptCard(ctx(c), [sh(c, 2), sh(c, 3)])).legalName);
    assert.deepEqual(opened.sort(), ['Alice Anderson', 'Bob Baker', 'Cara Cruz', 'Dee Diaz']);
    await assert.rejects(C.decryptCard(ctx(bundle[0]), [sh(bundle[0], 1)]));
  });

  it('reports go to the founder alone until the roster is signed, and to every trustee after', async () => {
    const id = () => crypto.randomUUID();
    const mk = (idxs, rid) => C.sealForTrustees({ what: 'x' }, idxs.map((i) => ({ index: i, boxPublicKey: camp.trustees.find((t) => t.index === i).keys.boxPublicKey })), rid);
    const send = (idxs) => { const rid = id(); return h.call('POST', '/api/reports', { auth: A.auth, body: { id: rid, ...mk(idxs, rid) } }); };
    assert.equal((await send([1, 2, 3])).status, 200); // signed: every trustee
    assert.equal((await send([1])).json.error, 'committee_changed'); // the founder alone is no longer the whole committee
    assert.equal((await send([1, 2])).json.error, 'committee_changed');
  });
});

describe('campaign: the release number is enforced, not advisory', () => {
  let h, camp;
  before(async () => { h = await startApp(); camp = await makeCampaign(h, { n: 3, k: 2, releaseMin: 3 }); });
  after(() => h.stop());
  const tAuth = (i, route) => trusteeAuth(h, camp.trustees[i - 1].keys, i, route, camp.id);
  const bundle = async (i) => h.call('GET', `/api/campaigns/${camp.id}/export-bundle`, { auth: await tAuth(i, 'GET /api/campaigns/:id/export-bundle') });
  const setMin = async (i, value) => h.call('POST', `/api/campaigns/${camp.id}/release-min`, { auth: await tAuth(i, 'POST /api/campaigns/:id/release-min'), body: { value } });
  let cards = [];

  it('refuses to hand over any sealed card until enough people have signed AND been counted (vouched for)', async () => {
    for (const n of ['Ann One', 'Ben Two']) { const inv = await makeInvite(h, camp); cards.push(await signCard(h, camp, inv.token, { name: n })); }
    const g = await makeInvite(h, camp, { kind: 'group', by: cards[0] });
    const pending = await signCard(h, camp, g.token, { name: 'Pending Person' }, { group: true }); // an unconfirmed card does not count
    for (const i of [1, 2, 3]) { const r = await bundle(i); assert.equal(r.status, 403); assert.deepEqual([r.json.error, r.json.have, r.json.need], ['threshold_not_met', 2, 3]); } // all three trustees, k or more: nothing to decrypt
    const inv = await makeInvite(h, camp);
    cards.push(await signCard(h, camp, inv.token, { name: 'Cy Three' }));
    const ok = await bundle(1);
    assert.equal(ok.status, 200);
    assert.equal(ok.json.cards.length, 3);
    // a signer disavowing (or a card being withdrawn) closes the gate again
    await h.call('POST', '/api/cards/disavow', { body: { cardId: cards[2].cardId, token: cards[2].disavowToken } });
    assert.equal((await bundle(2)).json.have, 2);
    await h.call('DELETE', '/api/cards/me', { auth: pending.auth });
  });

  it('everyone who can see the campaign can see the number', async () => {
    const meta = await h.call('GET', `/api/campaigns/${camp.id}/meta`, { auth: cards[0].auth });
    assert.equal(meta.json.releaseMin, 3);
    const p = await h.call('GET', `/api/campaigns/${camp.id}/progress`, { auth: cards[0].auth });
    assert.deepEqual([p.json.releaseMin, p.json.vouched], [3, 2]);
  });

  it('raising the number is free; lowering it takes k trustees agreeing on the same value', async () => {
    assert.deepEqual((await setMin(1, 4)).json, { releaseMin: 4, applied: true });
    const one = await setMin(1, 2);
    assert.deepEqual([one.json.applied, one.json.approvals, one.json.needed, one.json.releaseMin], [false, 1, 2, 4]); // one trustee cannot weaken it
    assert.equal((await setMin(2, 3)).json.applied, false); // a different value does not add up
    assert.equal((await bundle(1)).json.need, 4);
    const two = await setMin(2, 2); // trustee 2 changes their mind to agree with trustee 1
    assert.deepEqual([two.json.applied, two.json.releaseMin], [true, 2]);
    assert.equal(h.app.db.prepare('SELECT COUNT(*) c FROM release_approvals').get().c, 0); // approvals are cleared once applied
    for (const bad of [0, -1, 1.5, '3', null, 1_000_000]) assert.equal((await setMin(1, bad)).status, 400);
    assert.equal((await h.call('POST', `/api/campaigns/${camp.id}/release-min`, { body: { value: 1 } })).status, 401); // members cannot change it
  });

  it('refuses an invalid number when the campaign is created', async () => {
    const id = crypto.randomUUID(), box = C.encryptMeta(C.newCampaignKey(), { x: 1 }, id);
    const body = (releaseMin) => ({ id, k: 2, n: 2, releaseMin, metaCiphertext: box.ciphertext, metaNonce: box.nonce, templateVersion: 'card-v1', enrollTokenHashes: [C.hashToken(C.newToken()), C.hashToken(C.newToken())] });
    for (const bad of [0, 2.5, 'many']) assert.equal((await h.call('POST', '/api/campaigns', { body: body(bad) })).status, 400);
    assert.equal((await h.call('POST', '/api/campaigns', { body: body(51) })).status, 200);
  });
});


describe('campaign: the confirmation email cannot be used to send mail to arbitrary people', () => {
  let h, camp;
  before(async () => { h = await startApp({ rateLimitDisabled: false, confirmationsPerCampaignPerDay: 5 }); camp = await makeCampaign(h, { n: 3, k: 2 }); });
  after(() => h.stop());
  const signer = async (email) => { const inv = await makeInvite(h, camp); return signCard(h, camp, inv.token, { name: 'Pat Signer', email }); };

  it('one address gets at most three a day, however many cards name it', async () => {
    const results = [];
    for (let i = 0; i < 4; i++) results.push(await confirm(h, camp, await signer('victim@example.net')));
    assert.deepEqual(results.map((r) => r.status), [200, 200, 200, 429]);
    assert.equal(results[3].json.error, 'too_many_for_this_address');
    assert.equal((await confirm(h, camp, await signer('other@example.net'))).status, 200); // other addresses are unaffected
  });

  it('one campaign can only make so much mail go out in a day', async () => {
    // 4 already went out above; the limit for this test app is 5
    assert.equal((await confirm(h, camp, await signer('another@example.net'))).status, 200);
    const capped = await confirm(h, camp, await signer('yet-another@example.net'));
    assert.equal(capped.status, 429);
    assert.equal(capped.json.error, 'confirmations_capped');
  });

  it('withdrawing cards does not reset the campaign\'s daily count', async () => {
    const h2 = await startApp({ rateLimitDisabled: false, confirmationsPerCampaignPerDay: 3 });
    try {
      const c2 = await makeCampaign(h2, { n: 3, k: 2 });
      const statuses = [];
      for (let i = 0; i < 5; i++) {
        const inv = await makeInvite(h2, c2);
        const card = await signCard(h2, c2, inv.token, { name: 'Pat Signer', email: `loop${i}@example.net` });
        statuses.push((await confirm(h2, c2, card)).status);
        await h2.call('DELETE', '/api/cards/me', { auth: card.auth }); // the card is gone, but the email went out
      }
      assert.deepEqual(statuses, [200, 200, 200, 429, 429]);
    } finally { await h2.stop(); }
  });

  it('spelling an address differently does not reach it more often', async () => {
    const h4 = await startApp({ rateLimitDisabled: false });
    try {
      const c4 = await makeCampaign(h4, { n: 3, k: 2 });
      const send = async (email) => (await confirm(h4, c4, await signCard(h4, c4, (await makeInvite(h4, c4)).token, { name: 'Pat Signer', email }))).json.error || 'sent';
      const results = [];
      for (const v of ['Target+a@Example.net', 'target+b@example.net', 'TARGET@example.net', 'target+c@example.net']) results.push(await send(v));
      assert.deepEqual(results, ['sent', 'sent', 'sent', 'too_many_for_this_address']);
      const gmail = [];
      for (const v of ['g.m.a.i.l.user@gmail.com', 'gmailuser@googlemail.com', 'GmailUser+x@gmail.com', 'gmail.user@gmail.com']) gmail.push(await send(v));
      assert.deepEqual(gmail, ['sent', 'sent', 'sent', 'too_many_for_this_address']);
      assert.equal(await send('gmail.user@example.org'), 'sent'); // dots matter everywhere else
    } finally { await h4.stop(); }
  });

  it('two confirmations sent at the same moment send one email', async () => {
    const h3 = await startApp();
    try {
      const c3 = await makeCampaign(h3, { n: 3, k: 2 });
      const inv = await makeInvite(h3, c3);
      const card = await signCard(h3, c3, inv.token, { name: 'Pat Signer', email: 'race@example.net' });
      const send = h3.app.mail.send; h3.app.mail.send = async (m) => { await new Promise((r) => setTimeout(r, 50)); return send(m); }; // a real provider takes a moment
      const before = h3.app.mail.outbox.length;
      const both = await Promise.all([confirm(h3, c3, card), confirm(h3, c3, card)]);
      assert.deepEqual(both.map((r) => r.status).sort(), [200, 409]);
      assert.equal(h3.app.mail.outbox.length - before, 1);
    } finally { await h3.stop(); }
  });
});

describe('campaign: a signed trustee request cannot be altered on the way', () => {
  let h, camp;
  before(async () => { h = await startApp(); camp = await makeCampaign(h, { n: 3, k: 2, releaseMin: 5 }); });
  after(() => h.stop());

  it('the signature covers the body, so changing it is refused', async () => {
    const route = 'POST /api/campaigns/:id/release-min', t1 = camp.trustees.find((t) => t.index === 1);
    const signedFor = async (text) => {
      const { json } = await h.call('POST', '/api/auth/challenge');
      return `Sig ${json.challengeId}.1.${C.signAuth(t1.keys.signSecretKey, { nonce: json.nonce, route, scope: camp.id, bodyHash: C.bodyHash(text) })}`;
    };
    const altered = await h.call('POST', `/api/campaigns/${camp.id}/release-min`, { auth: await signedFor('{"value":6}'), body: { value: 99999 } });
    assert.deepEqual([altered.status, altered.json.error], [401, 'bad_signature']);
    const legacy = await h.call('POST', '/api/auth/challenge'); // a signature that covers no body at all is not accepted either
    const noBody = `Sig ${legacy.json.challengeId}.1.${C.signAuth(t1.keys.signSecretKey, { nonce: legacy.json.nonce, route, scope: camp.id })}`;
    assert.equal((await h.call('POST', `/api/campaigns/${camp.id}/release-min`, { auth: noBody, body: { value: 6 } })).status, 401);
    assert.equal((await h.call('POST', `/api/campaigns/${camp.id}/release-min`, { auth: await signedFor('{"value":6}'), body: { value: 6 } })).status, 200);
  });
});

describe('campaign: trustees can see where the release count comes from (#38)', () => {
  let h, camp;
  before(async () => { h = await startApp(); camp = await makeCampaign(h, { n: 3, k: 2, releaseMin: 50 }); });
  after(() => h.stop());

  it('the count is broken down by who made the invitation, without naming any signer', async () => {
    const byTrustee = async (i, kind = 'direct') => {
      const token = C.newToken();
      const r = await h.call('POST', '/api/invites', { auth: await trusteeAuth(h, camp.trustees.find((t) => t.index === i).keys, i, 'POST /api/invites', camp.id), body: { campaignId: camp.id, tokenHash: C.hashToken(token), kind } });
      assert.equal(r.status, 200); return token;
    };
    const A = await signCard(h, camp, await byTrustee(1));
    await signCard(h, camp, await byTrustee(1));
    const B = await signCard(h, camp, await byTrustee(2));
    for (let i = 0; i < 3; i++) await signCard(h, camp, (await makeInvite(h, camp, { by: A })).token); // one member brings in three
    await signCard(h, camp, (await makeInvite(h, camp, { by: B })).token);
    const g = await signCard(h, camp, await byTrustee(3, 'group'), {}, { group: true });
    await signCard(h, camp, await byTrustee(3, 'group'), {}, { group: true }); // not confirmed in person: not counted
    assert.equal((await h.call('POST', `/api/cards/${g.cardId}/vouch`, { auth: await trusteeAuth(h, camp.trustees[0].keys, 1, 'POST /api/cards/:id/vouch', camp.id), body: { code: g.vouch } })).status, 200);
    const p = (await h.call('GET', `/api/campaigns/${camp.id}/progress`, { auth: await trusteeAuth(h, camp.trustees[0].keys, 1, 'GET /api/campaigns/:id/progress', camp.id) })).json;
    assert.equal(p.vouched, 8);
    assert.deepEqual(p.provenance, { byTrustee: { 1: 2, 2: 1 }, byMembers: 4, membersInviting: 2, mostFromOneMember: 3, confirmedInPerson: 1, other: 0 });
    // members see the count, not the breakdown
    assert.equal((await h.call('GET', `/api/campaigns/${camp.id}/progress`, { auth: `Bearer ${A.authToken}` })).json.provenance, undefined);
  });
});
