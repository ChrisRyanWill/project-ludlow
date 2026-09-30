// Test harness: boots the real server in-process on a temp database and plays the role of the
// browser using the SAME shared/crypto.js the web app uses.
import { mkdtempSync, rmSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { createApp } from '../server/index.js';
import { setLogSink } from '../server/log.js';
import * as C from '../shared/crypto.js';

export async function startApp(over = {}) {
  await C.ready;
  const dir = mkdtempSync(path.join(tmpdir(), 'ludlow-'));
  const logs = [];
  setLogSink((l) => logs.push(l));
  const app = await createApp({ dbPath: path.join(dir, 'test.db'), masterKey: C.b64(C.randomBytes(32)), rateLimitDisabled: true, emailProvider: 'dev', minVoteHours: 0, ...over }); // minVoteHours 0: tests open votes that close in an hour, not a day
  const port = await app.listen(0, '127.0.0.1');
  const base = `http://127.0.0.1:${port}`;
  async function call(method, url, { body, auth } = {}) {
    const raw = body ? JSON.stringify(body) : undefined;
    if (auth?.signFor) auth = auth.signFor(raw);
    const r = await fetch(base + url, { method, headers: { 'content-type': 'application/json', ...(auth ? { authorization: auth } : {}) }, body: raw });
    let json = null;
    try { json = await r.json(); } catch { /* not json */ }
    return { status: r.status, json, headers: r.headers };
  }
  // Every byte the database has ever written to disk, for plaintext-leak checks.
  const diskBytes = () => Buffer.concat(readdirSync(dir).map((f) => readFileSync(path.join(dir, f))));
  const leaks = (needles) => {
    const disk = diskBytes();
    const log = logs.join('\n');
    const found = [];
    for (const n of needles) for (const v of new Set([n, n.toLowerCase(), n.toUpperCase()])) {
      if (disk.includes(Buffer.from(v))) found.push('db:' + n);
      if (log.includes(v)) found.push('log:' + n);
    }
    return found;
  };
  return { app, base, call, logs, dir, leaks, stop: async () => { await app.close(); rmSync(dir, { recursive: true, force: true }); setLogSink((l) => process.stdout.write(l + '\n')); } };
}

// Trustee signatures cover the exact body, which is only known when the request is sent, so this returns a signer that call() applies.
export async function trusteeAuth(h, keys, index, route, campaignId) {
  const { json } = await h.call('POST', '/api/auth/challenge');
  return { signFor: (raw) => `Sig ${json.challengeId}.${index}.${C.signAuth(keys.signSecretKey, { nonce: json.nonce, route, scope: campaignId, bodyHash: C.bodyHash(raw) })}` };
}

export async function makeCampaign(h, { n = 3, k = 2, meta = {}, releaseMin = 1, enroll = n, confirm = true } = {}) {
  const id = randomUUID(), campaignKey = C.newCampaignKey();
  const enrollTokens = Array.from({ length: n }, () => C.newToken());
  const fullMeta = { unionName: 'Test Workers United', employerName: 'Acme Corp', estimatedUnitSize: 10, unitDescription: 'All staff', trusteeNames: [], ...meta };
  const box = C.encryptMeta(campaignKey, fullMeta, id);
  const r = await h.call('POST', '/api/campaigns', { body: { id, k, n, releaseMin, metaCiphertext: box.ciphertext, metaNonce: box.nonce, templateVersion: 'card-v1', enrollTokenHashes: enrollTokens.map(C.hashToken) } });
  if (r.status !== 200) throw new Error('create campaign failed: ' + JSON.stringify(r.json));
  const trustees = [];
  for (let i = 0; i < enroll; i++) { // enroll < n leaves the committee incomplete: a founder-first campaign
    const keys = C.newKeypairs();
    const e = await h.call('POST', '/api/trustees/enroll', { body: { campaignId: id, enrollToken: enrollTokens[i], boxPublicKey: keys.boxPublicKey, signPublicKey: keys.signPublicKey } });
    if (e.status !== 200) throw new Error('enroll failed: ' + JSON.stringify(e.json));
    trustees.push({ index: i + 1, keys });
  }
  const camp = { id, k, n, campaignKey, trustees, enrollTokens, meta: fullMeta, confirmed: false };
  if (enroll === n && confirm) await confirmRoster(h, camp); // a committee that is complete from the start is signed by its founder straight away
  return camp;
}

// The founder signs the roster of the whole committee (docs/PROTOCOL.md 1a). Until then cards are sealed to the founder alone, however many trustees have joined.
export async function confirmRoster(h, camp) {
  const ts = [...camp.trustees].sort((a, b) => a.index - b.index);
  const roster = { campaignId: camp.id, k: camp.k, n: camp.n, seats: ts.map((t) => ({ index: t.index, boxPublicKey: t.keys.boxPublicKey })) };
  const signature = C.signRoster(ts[0].keys.signSecretKey, roster);
  const r = await h.call('POST', `/api/campaigns/${camp.id}/roster`, { auth: await trusteeAuth(h, ts[0].keys, 1, 'POST /api/campaigns/:id/roster', camp.id), body: { roster, signature } });
  if (r.status === 200) camp.confirmed = true;
  return { r, roster, signature };
}

export async function enrollTrustee(h, camp, index, token = camp.enrollTokens[index - 1]) {
  const keys = C.newKeypairs();
  const r = await h.call('POST', '/api/trustees/enroll', { body: { campaignId: camp.id, enrollToken: token, boxPublicKey: keys.boxPublicKey, signPublicKey: keys.signPublicKey } });
  if (r.status === 200) camp.trustees.push({ index, keys });
  return { r, keys };
}

export async function makeInvite(h, camp, { kind = 'direct', by } = {}) {
  const token = C.newToken();
  const auth = by ? `Bearer ${by.authToken}` : await trusteeAuth(h, camp.trustees[0].keys, 1, 'POST /api/invites', camp.id);
  const r = await h.call('POST', '/api/invites', { auth, body: { campaignId: camp.id, tokenHash: C.hashToken(token), kind } });
  if (r.status !== 200) throw new Error('invite failed: ' + JSON.stringify(r.json));
  return { token, ...r.json };
}

export async function signCard(h, camp, inviteToken, who = {}, { group = false } = {}) {
  const cardId = randomUUID(), secret = C.newToken();
  const { authToken, lockerKey } = C.deriveMember(secret);
  const disavowToken = C.newToken();
  const payload = {
    legalName: who.name || 'Pat Signer', personalEmail: who.email || 'pat@example.org', phone: who.phone || '+15555550100', employerName: camp.meta.employerName,
    unionName: camp.meta.unionName, cardText: 'I authorize the union to represent me.', cardTextSha256: 'x', typedSignature: who.name || 'Pat Signer', consentChecked: true, clientSignedAt: new Date().toISOString(), ...who.extra,
  };
  const enc = !camp.confirmed
    ? C.encryptCardSolo({ campaignId: camp.id, templateVersion: 'card-v1', payload, founder: { index: 1, boxPublicKey: camp.trustees[0].keys.boxPublicKey } })
    : await C.encryptCard({ campaignId: camp.id, templateVersion: 'card-v1', payload, trustees: camp.trustees.map((t) => ({ index: t.index, boxPublicKey: t.keys.boxPublicKey })), k: camp.k });
  const vouch = group ? C.vouchCode() : null;
  const res = await h.call('POST', '/api/cards', { body: { cardId, inviteToken, ...enc, memberTokenHash: C.hashToken(authToken), disavowTokenHash: C.hashToken(disavowToken), vouchCodeHash: group ? C.vouchHash(cardId, vouch) : undefined } });
  return { cardId, secret, authToken, lockerKey, disavowToken, vouch, res, payload, auth: `Bearer ${authToken}` };
}

export async function confirm(h, camp, card) {
  const p = card.payload;
  return h.call('POST', `/api/cards/${card.cardId}/confirm`, { auth: card.auth, body: { to: p.personalEmail, legalName: p.legalName, phone: p.phone, employerName: p.employerName, unionName: p.unionName, cardText: p.cardText, disavowToken: card.disavowToken } });
}

// ---- workspace ----
export async function login(h, m) {
  const { json } = await h.call('POST', '/api/auth/challenge');
  const signature = C.signAuth(m.keys.signSecretKey, { nonce: json.nonce, route: 'POST /api/ws/auth/login', scope: m.id });
  const r = await h.call('POST', '/api/ws/auth/login', { body: { memberId: m.id, challengeId: json.challengeId, signature } });
  if (r.status !== 200) throw new Error('login failed: ' + JSON.stringify(r.json));
  m.token = r.json.token; m.auth = 'Bearer ' + r.json.token;
  return m;
}

export async function makeWorkspace(h, people, { stage = 'recognized', fiscalYearStart } = {}) {
  const claims = people.map(() => C.newToken());
  const r = await h.call('POST', '/api/ws', { body: { confirmedPublic: true, stage, ...(fiscalYearStart ? { fiscalYearStart } : {}), unionName: 'Leakcheck Workers United', employerName: 'Leakcheck Industries LLC', jurisdiction: 'us-nlra', members: people.map((p, i) => ({ ...p, legalName: p.name, claimTokenHash: C.hashToken(claims[i]), status: p.status ?? 'member' })) } });
  if (r.status !== 200) throw new Error('create workspace failed: ' + JSON.stringify(r.json));
  const wsId = r.json.workspaceId;
  const members = [];
  for (let i = 0; i < people.length; i++) {
    const keys = C.newKeypairs();
    const c = await h.call('POST', '/api/ws/claim', { body: { workspaceId: wsId, claimToken: claims[i], boxPublicKey: keys.boxPublicKey, signPublicKey: keys.signPublicKey } });
    if (c.status !== 200) throw new Error('claim failed: ' + JSON.stringify(c.json));
    members.push(await login(h, { id: c.json.memberId, keys, ...people[i] }));
  }
  const as = (i, method, url, body) => h.call(method, url, { body, auth: members[i].auth });
  return { wsId, members, as, h };
}
