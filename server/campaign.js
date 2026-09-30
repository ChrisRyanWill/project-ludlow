// Campaign API: zero-knowledge authorization cards. The server stores ciphertext, hashes of bearer
// tokens, public keys and counts. It never receives a key that opens a card or the campaign metadata.
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { fail, fromThisMachine } from './http.js';
import { hashToken, vouchHash, verifyAuth, verifyRoster, canonicalJson, bodyHash } from '../shared/crypto.js';
import { issueChallenge, takeChallenge, bearer, sigHeader } from './auth.js';
import { confirmationEmail } from './mail.js';
import { makeLimiter } from './rate.js';

const B64 = /^[A-Za-z0-9_-]+$/;
const isB64 = (s, min, max) => typeof s === 'string' && s.length >= min && s.length <= max && B64.test(s);
const isTok = (s) => isB64(s, 43, 43); // 32 bytes, base64url
const isUuid = (s) => typeof s === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);
const isStr = (s, max) => typeof s === 'string' && s.length > 0 && s.length <= max;
const EMAIL = /^[^\s@<>,;"]{1,64}@[^\s@<>,;"[\]]{1,190}\.[^\s@<>,;"[\].]{2,}$/; // no address literals ([1.2.3.4]) and no trailing dot
const TEMPLATE = /^card-v\d+(-[a-z]{2,3})?$/;
const now = () => new Date().toISOString();
const equal = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const constraint = (e) => { if (String(e?.code).startsWith('SQLITE_CONSTRAINT')) fail(409, 'conflict'); throw e; };

export function sweepInactive(db, days) {
  const cutoff = new Date(Date.now() - days * 86400_000).toISOString();
  return db.prepare('DELETE FROM campaigns WHERE last_activity_at < ?').run(cutoff).changes;
}

// The mailbox an address reaches, for counting only: case, a "+tag" and (for Gmail) dots do not make it a different inbox.
export function mailboxKey(address) {
  const [local, domain0] = String(address).trim().toLowerCase().split(/@(?=[^@]*$)/);
  const domain = (domain0 || '').replace(/\.+$/, ''); // 'gmail.com.' is the same place as 'gmail.com'
  let user = (local || '').split('+')[0];
  const d = domain === 'googlemail.com' ? 'gmail.com' : domain;
  if (d === 'gmail.com') user = user.replace(/\./g, '');
  return user + '@' + d;
}

export function campaignRoutes({ router, db, cfg, mail }) {
  const R = (method, pattern, opts, handler) => router.add(method, pattern, opts, handler);
  // One address gets at most three confirmations a day. Counted in memory only, under a salt that rotates daily: nothing about the address is stored.
  const perRecipient = makeLimiter({ disabled: cfg.rateLimitDisabled, windowMs: 86_400_000, max: 3 });
  // What one campaign has made go out today, also in memory: counting rows in the database would forget every card that was withdrawn since.
  // A slot is reserved only when every other check has passed, and given back if the email could not be sent.
  const sentToday = new Map(); // campaignId -> { n, reset }
  const campaignSlot = (id, delta) => {
    const t = Date.now();
    if (sentToday.size > 10_000) for (const [k, v] of sentToday) if (v.reset < t) sentToday.delete(k);
    let e = sentToday.get(id);
    if (!e || e.reset < t) { e = { n: 0, reset: t + 86_400_000 }; sentToday.set(id, e); }
    if (delta > 0 && e.n >= cfg.confirmationsPerCampaignPerDay) return false;
    e.n = Math.max(0, e.n + delta);
    return true;
  };
  const sending = new Set(); // cards whose confirmation is on its way, so a second request at the same moment cannot send it twice
  const touch = (id) => db.prepare('UPDATE campaigns SET last_activity_at=? WHERE id=?').run(now(), id);

  // A trustee proves who they are by signing a fresh challenge; returns the trustee's index.
  function authTrustee(ctx, route, campaignId) {
    const a = sigHeader(ctx.headers);
    if (!a) fail(401, 'unauthorized');
    const nonce = takeChallenge(a.challengeId);
    if (!nonce) fail(401, 'bad_challenge');
    const t = db.prepare('SELECT sign_public_key k FROM trustees WHERE campaign_id=? AND trustee_index=? AND sign_public_key IS NOT NULL').get(campaignId, Number(a.index));
    if (!t || !verifyAuth(t.k, a.sig, { nonce, route, scope: campaignId, bodyHash: bodyHash(ctx.rawBody) })) fail(401, 'bad_signature'); // the body is signed too
    return Number(a.index);
  }
  function cardByToken(ctx) {
    const tok = bearer(ctx.headers);
    const c = tok && db.prepare('SELECT * FROM cards WHERE member_token_hash=?').get(hashToken(tok));
    if (!c) fail(401, 'unauthorized');
    return c;
  }
  // Returns which trustee seat an enrollment token belongs to (null for every other kind of credential).
  function authorizeMeta(ctx, id) {
    const tok = bearer(ctx.headers);
    if (!tok) { authTrustee(ctx, 'GET /api/campaigns/:id/meta', id); return { enrollIndex: null }; }
    const h = hashToken(tok);
    const enr = db.prepare('SELECT trustee_index i FROM trustees WHERE enrollment_token_hash=? AND campaign_id=?').get(h, id);
    const ok = enr
      || db.prepare('SELECT 1 FROM invites WHERE token_hash=? AND campaign_id=? AND revoked_at IS NULL AND expires_at>? AND use_count<max_uses').get(h, id, now())
      || db.prepare('SELECT 1 FROM cards WHERE member_token_hash=? AND campaign_id=?').get(h, id);
    if (!ok) fail(401, 'unauthorized');
    return { enrollIndex: enr?.i ?? null };
  }

  R('POST', '/api/auth/challenge', {}, () => issueChallenge());

  // ---- create + enroll ----
  R('POST', '/api/campaigns', { strict: true }, ({ body: b }) => {
    const { id, k, n, metaCiphertext, metaNonce, templateVersion, enrollTokenHashes } = b;
    const releaseMin = b.releaseMin === undefined ? 1 : b.releaseMin;
    if (!Number.isInteger(releaseMin) || releaseMin < 1 || releaseMin > 100_000) fail(400, 'bad_request');
    if (!isUuid(id) || !Number.isInteger(n) || n < 2 || n > 7 || !Number.isInteger(k) || k < 2 || k > n) fail(400, 'bad_request');
    if (!isB64(metaCiphertext, 16, 20000) || !isB64(metaNonce, 32, 32) || !TEMPLATE.test(templateVersion)) fail(400, 'bad_request');
    if (!Array.isArray(enrollTokenHashes) || enrollTokenHashes.length !== n || !enrollTokenHashes.every(isTok)) fail(400, 'bad_request');
    const t = now();
    try {
      db.transaction(() => {
        db.prepare('INSERT INTO campaigns (id,status,threshold_k,trustee_count_n,meta_ciphertext,meta_nonce,card_template_version,release_min,created_at,last_activity_at) VALUES (?,?,?,?,?,?,?,?,?,?)')
          .run(id, 'draft', k, n, metaCiphertext, metaNonce, templateVersion, releaseMin, t, t);
        const ins = db.prepare('INSERT INTO trustees (id,campaign_id,trustee_index,enrollment_token_hash) VALUES (?,?,?,?)');
        enrollTokenHashes.forEach((h, i) => ins.run(randomUUID(), id, i + 1, h));
      })();
    } catch (e) { constraint(e); }
    return { campaignId: id };
  });

  R('GET', '/api/campaigns/:id/meta', {}, (ctx) => {
    const id = ctx.params.id;
    const who = authorizeMeta(ctx, id); // authenticate first so unknown ids and bad tokens look identical
    const c = db.prepare('SELECT * FROM campaigns WHERE id=?').get(id);
    if (!c) fail(404, 'not_found');
    const trustees = db.prepare('SELECT trustee_index i, box_public_key pk, sign_public_key sk, enrolled_at e FROM trustees WHERE campaign_id=? ORDER BY trustee_index').all(id);
    const idleDays = Math.floor((Date.now() - Date.parse(c.last_activity_at)) / 86400_000);
    return {
      id, status: c.status, k: c.threshold_k, n: c.trustee_count_n, metaCiphertext: c.meta_ciphertext, metaNonce: c.meta_nonce,
      templateVersion: c.card_template_version, releaseMin: c.release_min, createdAt: c.created_at,
      // Browsers do not take these on trust: they check the founder's keys against the invitation link and the roster against the founder's signature (shared/roster.js).
      trustees: trustees.map((t) => ({ index: t.i, enrolled: !!t.e, boxPublicKey: t.pk, signPublicKey: t.sk })),
      roster: c.roster_json ? { roster: JSON.parse(c.roster_json), signature: c.roster_sig } : null,
      inactivityDaysLeft: Math.max(0, cfg.inactivityDays - idleDays), inactivityWarn: idleDays >= cfg.inactivityDays - 30,
      ...(who.enrollIndex ? { yourTrusteeIndex: who.enrollIndex } : {}),
    };
  });

  R('POST', '/api/trustees/enroll', { strict: true }, ({ body: b }) => {
    if (!isUuid(b.campaignId) || !isTok(b.enrollToken) || !isB64(b.boxPublicKey, 43, 43) || !isB64(b.signPublicKey, 43, 43)) fail(400, 'bad_request');
    return db.transaction(() => {
      const t = db.prepare('SELECT id, trustee_index i FROM trustees WHERE campaign_id=? AND enrollment_token_hash=?').get(b.campaignId, hashToken(b.enrollToken));
      if (!t) fail(401, 'unauthorized');
      // The same keys can never fill two seats. This is only a cheap guard (someone can still make a second key file), which is why the
      // founder also confirms each seat's key words with the person before locking cards to the committee.
      if (db.prepare('SELECT 1 FROM trustees WHERE campaign_id=? AND enrolled_at IS NOT NULL AND (box_public_key=? OR sign_public_key=?)').get(b.campaignId, b.boxPublicKey, b.signPublicKey)) fail(409, 'key_reused');
      db.prepare('UPDATE trustees SET box_public_key=?, sign_public_key=?, enrolled_at=?, enrollment_token_hash=NULL WHERE id=?').run(b.boxPublicKey, b.signPublicKey, now(), t.id);
      // The founder's key is enough to start collecting cards; the rest of the committee can join later.
      if (db.prepare('SELECT 1 FROM trustees WHERE campaign_id=? AND trustee_index=1 AND enrolled_at IS NOT NULL').get(b.campaignId)) {
        db.prepare("UPDATE campaigns SET status='active' WHERE id=? AND status='draft'").run(b.campaignId);
      }
      touch(b.campaignId);
      const c = db.prepare('SELECT trustee_count_n n, status FROM campaigns WHERE id=?').get(b.campaignId);
      const enrolled = db.prepare('SELECT COUNT(*) c FROM trustees WHERE campaign_id=? AND enrolled_at IS NOT NULL').get(b.campaignId).c;
      return { trusteeIndex: t.i, enrolledCount: enrolled, status: c.status, committeeComplete: enrolled === c.n };
    })();
  });

  // ---- invites ----
  R('POST', '/api/invites', {}, (ctx) => {
    const b = ctx.body;
    if (!isUuid(b.campaignId) || !isTok(b.tokenHash) || !['direct', 'group'].includes(b.kind)) fail(400, 'bad_request');
    let cardId = null, trusteeIndex = null;
    const tok = bearer(ctx.headers);
    if (tok) {
      const card = db.prepare('SELECT id, status, disavowed_at d FROM cards WHERE member_token_hash=? AND campaign_id=?').get(hashToken(tok), b.campaignId);
      if (!card) fail(401, 'unauthorized');
      if (card.status !== 'vouched' || card.d) fail(403, 'not_vouched');
      cardId = card.id;
    } else trusteeIndex = authTrustee(ctx, 'POST /api/invites', b.campaignId);
    const c = db.prepare('SELECT status FROM campaigns WHERE id=?').get(b.campaignId);
    if (!c) fail(404, 'not_found');
    if (c.status !== 'active') fail(409, 'campaign_not_active');
    const direct = b.kind === 'direct';
    const maxUses = direct ? 1 : Math.min(Math.max(parseInt(b.maxUses, 10) || 50, 1), 200);
    const expiresAt = new Date(Date.now() + (direct ? cfg.directTtlDays * 86400_000 : cfg.groupTtlHours * 3600_000)).toISOString();
    const id = randomUUID();
    try {
      db.prepare('INSERT INTO invites (id,campaign_id,token_hash,kind,created_by_card_id,created_by_trustee_index,max_uses,expires_at) VALUES (?,?,?,?,?,?,?,?)')
        .run(id, b.campaignId, b.tokenHash, b.kind, cardId, trusteeIndex, maxUses, expiresAt);
    } catch (e) { constraint(e); }
    touch(b.campaignId);
    return { inviteId: id, expiresAt, maxUses };
  });

  R('POST', '/api/invites/revoke', {}, (ctx) => {
    const inv = db.prepare('SELECT * FROM invites WHERE id=?').get(String(ctx.body.inviteId || ''));
    const tok = bearer(ctx.headers);
    if (tok) {
      const me = db.prepare('SELECT id FROM cards WHERE member_token_hash=?').get(hashToken(tok));
      if (!me || !inv || inv.created_by_card_id !== me.id) fail(403, 'forbidden');
    } else {
      const cid = String(ctx.body.campaignId || '');
      authTrustee(ctx, 'POST /api/invites/revoke', cid);
      if (!inv || inv.campaign_id !== cid) fail(404, 'not_found');
    }
    db.prepare('UPDATE invites SET revoked_at=? WHERE id=? AND revoked_at IS NULL').run(now(), inv.id);
    return { revoked: true };
  });

  R('POST', '/api/invites/resolve', { strict: true }, ({ body }) => {
    if (!isTok(body.token)) fail(404, 'invalid_invite');
    const inv = db.prepare(`SELECT i.campaign_id, i.kind FROM invites i JOIN campaigns c ON c.id=i.campaign_id
      WHERE i.token_hash=? AND i.revoked_at IS NULL AND i.expires_at>? AND i.use_count<i.max_uses AND c.status='active'`).get(hashToken(body.token), now());
    if (!inv) fail(404, 'invalid_invite');
    return { campaignId: inv.campaign_id, kind: inv.kind };
  });

  // ---- cards ----
  R('POST', '/api/cards', { strict: true, maxBody: 200_000 }, ({ body: b }) => {
    if (!isUuid(b.cardId) || !isTok(b.inviteToken) || !isB64(b.ciphertext, 16, 30000) || !isB64(b.nonce, 32, 32)
      || !isTok(b.memberTokenHash) || !isTok(b.disavowTokenHash) || !TEMPLATE.test(b.templateVersion) || !Array.isArray(b.sealedShares)) fail(400, 'bad_request');
    return db.transaction(() => {
      const inv = db.prepare(`SELECT i.*, c.status cstatus, c.trustee_count_n n, c.card_template_version tv, c.roster_json rj
        FROM invites i JOIN campaigns c ON c.id=i.campaign_id WHERE i.token_hash=?`).get(hashToken(b.inviteToken));
      if (!inv || inv.revoked_at || inv.expires_at <= now() || inv.use_count >= inv.max_uses) fail(404, 'invalid_invite');
      if (inv.cstatus !== 'active') fail(409, 'campaign_not_active');
      if (b.templateVersion !== inv.tv && !b.templateVersion.startsWith(inv.tv + '-')) fail(400, 'bad_template');
      // A card is sealed to the founder alone ('solo') until the founder has signed the roster of the whole committee, and split k-of-n after that.
      // (Every trustee having joined is not enough: a browser can only trust keys the founder vouched for.) If that changed while the signer was typing,
      // they get 409 and their browser seals it again.
      const enrolled = db.prepare('SELECT trustee_index i FROM trustees WHERE campaign_id=? AND enrolled_at IS NOT NULL').all(inv.campaign_id).map((r) => r.i);
      const solo = b.sealMode === 'solo';
      if (solo === !!inv.rj) fail(409, 'committee_changed');
      const idx = b.sealedShares.map((s) => s?.trusteeIndex);
      if (solo) {
        if (b.sealedShares.length !== 1 || idx[0] !== 1 || !enrolled.includes(1) || !isB64(b.sealedShares[0].sealed, 60, 300)) fail(400, 'bad_shares');
      } else if (b.sealedShares.length !== inv.n || !b.sealedShares.every((s) => Number.isInteger(s?.trusteeIndex) && isB64(s.sealed, 60, 300))
        || new Set(idx).size !== inv.n || idx.some((i) => i < 1 || i > inv.n)) fail(400, 'bad_shares');
      const group = inv.kind === 'group';
      if (group && !isTok(b.vouchCodeHash)) fail(400, 'bad_request');
      const createdAt = now(), status = group ? 'pending' : 'vouched';
      try {
        db.prepare(`INSERT INTO cards (id,campaign_id,invite_id,ciphertext,nonce,sealed_shares,template_version,seal_mode,status,vouch_code_hash,member_token_hash,disavow_token_hash,created_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(b.cardId, inv.campaign_id, inv.id, b.ciphertext, b.nonce, JSON.stringify(b.sealedShares.map((s) => ({ trusteeIndex: s.trusteeIndex, sealed: s.sealed }))),
          b.templateVersion, solo ? 'solo' : 'shamir', status, group ? b.vouchCodeHash : null, b.memberTokenHash, b.disavowTokenHash, createdAt);
      } catch (e) { constraint(e); }
      db.prepare('UPDATE invites SET use_count=use_count+1 WHERE id=?').run(inv.id);
      touch(inv.campaign_id);
      return { cardId: b.cardId, status, createdAt };
    })();
  });

  R('GET', '/api/cards/me', {}, (ctx) => {
    const c = cardByToken(ctx);
    return { cardId: c.id, campaignId: c.campaign_id, status: c.status, createdAt: c.created_at, confirmationSentAt: c.confirmation_sent_at, disavowedAt: c.disavowed_at };
  });

  // The Confirmation Transmission. The signer's details arrive in this request body, are put in an
  // email, and are discarded. Only the send time and the provider's message id are stored (rule 2).
  R('POST', '/api/cards/:id/confirm', { strict: true }, async (ctx) => {
    const card = cardByToken(ctx);
    if (card.id !== ctx.params.id) fail(403, 'forbidden');
    if (card.confirmation_sent_at) fail(409, 'already_sent');
    const b = ctx.body;
    if (!isStr(b.to, 254) || !EMAIL.test(b.to) || !isStr(b.legalName, 120) || !isStr(b.phone, 32) || !isStr(b.employerName, 200)
      || !isStr(b.unionName, 200) || !isStr(b.cardText, 4000) || !isTok(b.disavowToken) || !equal(hashToken(b.disavowToken), card.disavow_token_hash)) fail(400, 'bad_request');
    // Anyone can start a campaign and sign a card, so this route must not become a way to send mail from this server to arbitrary people:
    // limit what one address can receive, and how much one campaign can make go out in a day.
    if (sending.has(card.id)) fail(409, 'already_sent');
    const since = new Date(Date.now() - 86400_000).toISOString();
    if (db.prepare('SELECT COUNT(*) c FROM cards WHERE campaign_id=? AND confirmation_sent_at > ?').get(card.campaign_id, since).c >= cfg.confirmationsPerCampaignPerDay) fail(429, 'confirmations_capped');
    const today = sentToday.get(card.campaign_id);
    if (today && today.reset > Date.now() && today.n >= cfg.confirmationsPerCampaignPerDay) fail(429, 'confirmations_capped');
    if (!perRecipient(mailboxKey(b.to))) fail(429, 'too_many_for_this_address');
    if (!campaignSlot(card.campaign_id, 1)) fail(429, 'confirmations_capped');
    const email = confirmationEmail({ appName: cfg.appName, baseUrl: cfg.baseUrl, card: b, signedAt: card.created_at, cardId: card.id, disavowToken: b.disavowToken, templateVersion: card.template_version });
    let sent;
    sending.add(card.id);
    try {
      try { sent = await mail.send({ to: b.to, subject: email.subject, text: email.text, replyTo: cfg.replyTo }); } catch { campaignSlot(card.campaign_id, -1); fail(502, 'email_failed'); }
      db.prepare('UPDATE cards SET confirmation_sent_at=?, confirmation_message_id=? WHERE id=?').run(now(), String(sent.messageId).slice(0, 100), card.id);
    } finally { sending.delete(card.id); }
    return { sent: true };
  });

  R('POST', '/api/cards/:id/vouch', { strict: true }, (ctx) => {
    const card = db.prepare('SELECT * FROM cards WHERE id=?').get(ctx.params.id);
    const tok = bearer(ctx.headers);
    if (tok) {
      const me = db.prepare('SELECT id FROM cards WHERE member_token_hash=?').get(hashToken(tok));
      const inv = card && db.prepare('SELECT created_by_card_id c FROM invites WHERE id=?').get(card.invite_id);
      if (!me || !inv || inv.c !== me.id) fail(403, 'forbidden'); // only the person who made the link can vouch
    } else {
      if (!card) fail(404, 'not_found');
      authTrustee(ctx, 'POST /api/cards/:id/vouch', card.campaign_id);
    }
    if (card.status !== 'pending') fail(409, 'not_pending');
    if (card.vouch_attempts >= 5) fail(423, 'locked');
    if (!isStr(ctx.body.code, 40) || !equal(vouchHash(card.id, ctx.body.code), card.vouch_code_hash)) {
      db.prepare('UPDATE cards SET vouch_attempts=vouch_attempts+1 WHERE id=?').run(card.id);
      fail(403, 'wrong_code', { attemptsLeft: Math.max(0, 4 - card.vouch_attempts) });
    }
    db.prepare("UPDATE cards SET status='vouched', vouch_code_hash=NULL WHERE id=?").run(card.id);
    touch(card.campaign_id);
    return { vouched: true };
  });

  R('GET', '/api/campaigns/:id/pending-vouches', {}, (ctx) => {
    const id = ctx.params.id;
    const tok = bearer(ctx.headers);
    let rows;
    if (tok) {
      const me = db.prepare('SELECT id, status FROM cards WHERE member_token_hash=? AND campaign_id=?').get(hashToken(tok), id);
      if (!me) fail(401, 'unauthorized');
      if (me.status !== 'vouched') fail(403, 'not_vouched');
      rows = db.prepare(`SELECT c.id, c.created_at, c.vouch_attempts FROM cards c JOIN invites i ON i.id=c.invite_id
        WHERE c.campaign_id=? AND c.status='pending' AND i.created_by_card_id=? ORDER BY c.created_at`).all(id, me.id);
    } else {
      authTrustee(ctx, 'GET /api/campaigns/:id/pending-vouches', id);
      rows = db.prepare("SELECT id, created_at, vouch_attempts FROM cards WHERE campaign_id=? AND status='pending' ORDER BY created_at").all(id);
    }
    return { pending: rows.map((r) => ({ cardId: r.id, createdAt: r.created_at, attemptsLeft: 5 - r.vouch_attempts })) };
  });

  R('DELETE', '/api/cards/me', {}, (ctx) => {
    const card = cardByToken(ctx);
    db.transaction(() => {
      db.prepare('UPDATE invites SET revoked_at=? WHERE created_by_card_id=? AND revoked_at IS NULL').run(now(), card.id);
      db.prepare('DELETE FROM cards WHERE id=?').run(card.id); // hard delete; secure_delete zeroes the pages; the private locker cascades away
    })();
    return { deleted: true };
  });

  R('POST', '/api/cards/disavow', { strict: true }, ({ body: b }) => {
    if (!isUuid(b.cardId) || !isTok(b.token)) fail(400, 'bad_request');
    const card = db.prepare('SELECT id, disavow_token_hash h, disavowed_at d FROM cards WHERE id=?').get(b.cardId);
    if (!card || !equal(hashToken(b.token), card.h)) fail(403, 'forbidden');
    if (!card.d) db.prepare('UPDATE cards SET disavowed_at=? WHERE id=?').run(now(), card.id);
    return { disavowed: true };
  });

  // ---- progress ----
  R('GET', '/api/campaigns/:id/progress', {}, (ctx) => {
    const id = ctx.params.id;
    let trustee = false, trusteeIndex = null;
    const tok = bearer(ctx.headers);
    if (tok) {
      const card = db.prepare('SELECT status FROM cards WHERE member_token_hash=? AND campaign_id=?').get(hashToken(tok), id);
      if (!card) fail(401, 'unauthorized');
      if (card.status !== 'vouched') fail(403, 'not_vouched'); // pending members see nothing (rule: least information)
    } else { trusteeIndex = authTrustee(ctx, 'GET /api/campaigns/:id/progress', id); trustee = true; }
    const c = db.prepare('SELECT status, release_min FROM campaigns WHERE id=?').get(id);
    if (!c) fail(404, 'not_found');
    const count = (sql) => db.prepare(sql).get(id).c;
    const out = {
      status: c.status, releaseMin: c.release_min,
      vouched: count("SELECT COUNT(*) c FROM cards WHERE campaign_id=? AND status='vouched' AND disavowed_at IS NULL"),
      pending: count("SELECT COUNT(*) c FROM cards WHERE campaign_id=? AND status='pending'"),
      history: db.prepare("SELECT substr(created_at,1,10) d, COUNT(*) c FROM cards WHERE campaign_id=? AND status='vouched' AND disavowed_at IS NULL GROUP BY d ORDER BY d").all(id).map((r) => ({ day: r.d, count: r.c })),
    };
    if (trustee) {
      // Where the count comes from (#38). Anyone who can make direct invitations adds cards that count at once, so the release number is only as
      // good as the people behind it; this lets the trustees see if one person accounts for much of it. Counts only: no signer is named.
      const rows = db.prepare(`SELECT i.kind k, i.created_by_trustee_index t, i.created_by_card_id m, COUNT(*) c FROM cards c JOIN invites i ON i.id=c.invite_id
        WHERE c.campaign_id=? AND c.status='vouched' AND c.disavowed_at IS NULL GROUP BY i.kind, i.created_by_trustee_index, i.created_by_card_id`).all(id);
      const pv = { byTrustee: {}, byMembers: 0, membersInviting: 0, mostFromOneMember: 0, confirmedInPerson: 0, other: 0 };
      for (const r of rows) {
        if (r.k === 'group') pv.confirmedInPerson += r.c;
        else if (r.t != null) pv.byTrustee[r.t] = (pv.byTrustee[r.t] || 0) + r.c;
        else if (r.m != null) { pv.byMembers += r.c; pv.membersInviting++; pv.mostFromOneMember = Math.max(pv.mostFromOneMember, r.c); }
        else pv.other += r.c; // the member who invited them has since withdrawn
      }
      out.provenance = pv;
      out.destroyApprovals = count('SELECT COUNT(*) c FROM destroy_approvals WHERE campaign_id=?');
      out.reports = count('SELECT COUNT(*) c FROM reports WHERE campaign_id=?');
      const votes = db.prepare('SELECT trustee_index i, value v FROM release_approvals WHERE campaign_id=?').all(id);
      out.releaseVotes = votes.reduce((m, r) => ({ ...m, [r.v]: (m[r.v] || 0) + 1 }), {}); // value -> approvals so far
      out.myReleaseVote = votes.find((r) => r.i === trusteeIndex)?.v ?? null;
      out.solo = count("SELECT COUNT(*) c FROM cards WHERE campaign_id=? AND seal_mode='solo'"); // cards only the founder can open until the committee is locked in
    }
    return out;
  });

  // ---- private locker: a worker's own encrypted record of employer conduct ----
  R('GET', '/api/locker', {}, (ctx) => {
    const card = cardByToken(ctx);
    return { entries: db.prepare('SELECT id, ciphertext, nonce, created_at createdAt FROM locker_entries WHERE card_id=? ORDER BY created_at').all(card.id) };
  });
  R('POST', '/api/locker', { maxBody: 100_000 }, (ctx) => {
    const card = cardByToken(ctx);
    const b = ctx.body;
    if (!isUuid(b.id) || !isB64(b.ciphertext, 16, 30000) || !isB64(b.nonce, 32, 32)) fail(400, 'bad_request');
    if (db.prepare('SELECT COUNT(*) c FROM locker_entries WHERE card_id=?').get(card.id).c >= 300) fail(409, 'locker_full');
    try { db.prepare('INSERT INTO locker_entries (id,campaign_id,card_id,ciphertext,nonce,created_at) VALUES (?,?,?,?,?,?)').run(b.id, card.campaign_id, card.id, b.ciphertext, b.nonce, now()); } catch (e) { constraint(e); }
    return { saved: true };
  });
  R('DELETE', '/api/locker/:id', {}, (ctx) => {
    const card = cardByToken(ctx);
    db.prepare('DELETE FROM locker_entries WHERE id=? AND card_id=?').run(ctx.params.id, card.id);
    return { deleted: true };
  });

  // ---- reports a worker chose to share with the committee (sealed to every trustee, unlinked to the card) ----
  R('POST', '/api/reports', { strict: true, maxBody: 200_000 }, (ctx) => {
    const card = cardByToken(ctx);
    const b = ctx.body;
    // A browser can only seal to keys it can authenticate: the founder's (from the invitation link), and the whole committee once the founder has signed the roster.
    const cmp = db.prepare('SELECT trustee_count_n n, roster_json rj FROM campaigns WHERE id=?').get(card.campaign_id);
    const joined = cmp.rj ? Array.from({ length: cmp.n }, (_, i) => i + 1) : [1];
    if (!isUuid(b.id) || !isB64(b.ciphertext, 16, 30000) || !isB64(b.nonce, 32, 32) || !Array.isArray(b.sealedKeys) || b.sealedKeys.length !== joined.length
      || !b.sealedKeys.every((s) => Number.isInteger(s?.trusteeIndex) && joined.includes(s.trusteeIndex) && isB64(s.sealed, 60, 300)) || new Set(b.sealedKeys.map((s) => s.trusteeIndex)).size !== joined.length) fail(409, 'committee_changed');
    try {
      db.prepare('INSERT INTO reports (id,campaign_id,ciphertext,nonce,sealed_keys,created_at) VALUES (?,?,?,?,?,?)')
        .run(b.id, card.campaign_id, b.ciphertext, b.nonce, JSON.stringify(b.sealedKeys.map((s) => ({ trusteeIndex: s.trusteeIndex, sealed: s.sealed }))), now());
    } catch (e) { constraint(e); }
    touch(card.campaign_id);
    return { shared: true };
  });
  R('GET', '/api/campaigns/:id/reports', {}, (ctx) => {
    authTrustee(ctx, 'GET /api/campaigns/:id/reports', ctx.params.id);
    const rows = db.prepare('SELECT id, ciphertext, nonce, sealed_keys, created_at FROM reports WHERE campaign_id=? ORDER BY created_at').all(ctx.params.id);
    return { reports: rows.map((r) => ({ id: r.id, ciphertext: r.ciphertext, nonce: r.nonce, sealedKeys: JSON.parse(r.sealed_keys), createdAt: r.created_at })) };
  });
  R('POST', '/api/campaigns/:id/reports/delete', {}, (ctx) => {
    authTrustee(ctx, 'POST /api/campaigns/:id/reports/delete', ctx.params.id);
    db.prepare('DELETE FROM reports WHERE id=? AND campaign_id=?').run(String(ctx.body.reportId || ''), ctx.params.id);
    return { deleted: true };
  });

  // ---- trustee-only ----
  R('GET', '/api/campaigns/:id/export-bundle', {}, (ctx) => {
    const id = ctx.params.id;
    authTrustee(ctx, 'GET /api/campaigns/:id/export-bundle', id);
    // Trustees hold keys, but the sealed cards live only here. Until enough people have signed and been confirmed,
    // this refuses, so even k trustees acting together have nothing to decrypt. (An operator with direct database
    // access could bypass it; the trustees themselves cannot, unless they also run the server.)
    const gate = db.prepare("SELECT release_min need, (SELECT COUNT(*) FROM cards WHERE campaign_id=campaigns.id AND status='vouched' AND disavowed_at IS NULL) have FROM campaigns WHERE id=?").get(id);
    if (!gate) fail(404, 'not_found');
    if (gate.have < gate.need) fail(403, 'threshold_not_met', { have: gate.have, need: gate.need });
    const rows = db.prepare(`SELECT id, ciphertext, nonce, sealed_shares, template_version, seal_mode, created_at, confirmation_sent_at, confirmation_message_id, disavowed_at
      FROM cards WHERE campaign_id=? AND status='vouched' ORDER BY created_at`).all(id);
    return {
      cards: rows.map((c) => ({
        id: c.id, ciphertext: c.ciphertext, nonce: c.nonce, sealedShares: JSON.parse(c.sealed_shares), templateVersion: c.template_version, sealMode: c.seal_mode,
        createdAt: c.created_at, confirmationSentAt: c.confirmation_sent_at, confirmationMessageId: c.confirmation_message_id, disavowedAt: c.disavowed_at,
      })),
    };
  });

  // ---- the committee: the founder can plan it later, hand out invitations any time, and lock cards to it ----
  const enrolledCount = (id) => db.prepare('SELECT COUNT(*) c FROM trustees WHERE campaign_id=? AND enrolled_at IS NOT NULL').get(id).c;

  // Change the planned committee (size and threshold). Only the founder, and only until everyone has joined.
  R('POST', '/api/campaigns/:id/committee', {}, (ctx) => {
    const id = ctx.params.id;
    if (authTrustee(ctx, 'POST /api/campaigns/:id/committee', id) !== 1) fail(403, 'founder_only');
    const { n, k } = ctx.body;
    if (!Number.isInteger(n) || n < 2 || n > 7 || !Number.isInteger(k) || k < 2 || k > n) fail(400, 'bad_request');
    return db.transaction(() => {
      const c = db.prepare('SELECT trustee_count_n n FROM campaigns WHERE id=?').get(id);
      if (!c) fail(404, 'not_found');
      const joined = enrolledCount(id);
      if (joined === c.n) fail(409, 'committee_complete'); // once everyone has joined the plan is fixed
      if (n < joined) fail(409, 'slot_enrolled');
      if (n < c.n && db.prepare('SELECT 1 FROM trustees WHERE campaign_id=? AND trustee_index>? AND enrolled_at IS NOT NULL').get(id, n)) fail(409, 'slot_enrolled');
      db.prepare('DELETE FROM trustees WHERE campaign_id=? AND trustee_index>?').run(id, n);
      for (let i = c.n + 1; i <= n; i++) db.prepare('INSERT INTO trustees (id,campaign_id,trustee_index) VALUES (?,?,?)').run(randomUUID(), id, i); // no invitation yet; the founder creates one when ready
      db.prepare('UPDATE campaigns SET trustee_count_n=?, threshold_k=? WHERE id=?').run(n, k, id);
      touch(id);
      return { n, k, enrolled: joined, complete: joined === n };
    })();
  });

  // A fresh invitation for a trustee seat that has not been taken (also revokes any earlier, possibly leaked, link).
  R('POST', '/api/campaigns/:id/trustees/reset', { strict: true }, (ctx) => {
    const id = ctx.params.id;
    // Seats are the founder's to hand out. If any trustee could re-issue an empty seat, one person could take enough seats to hold k shares
    // alone (and approve lowering the release number k times), which would defeat both the k-of-n rule and the release lock.
    if (authTrustee(ctx, 'POST /api/campaigns/:id/trustees/reset', id) !== 1) fail(403, 'founder_only');
    const { index, tokenHash } = ctx.body;
    if (!Number.isInteger(index) || !isTok(tokenHash)) fail(400, 'bad_request');
    const r = db.prepare('UPDATE trustees SET enrollment_token_hash=? WHERE campaign_id=? AND trustee_index=? AND enrolled_at IS NULL').run(tokenHash, id, index);
    if (r.changes !== 1) fail(409, 'slot_taken');
    return { ok: true };
  });

  // The founder signs the committee once every trustee has joined and they have checked each one's key words with them (docs/PROTOCOL.md 1a).
  // The server stores it and flips new cards to k-of-n, but it cannot forge one: browsers verify the founder's signature themselves. Checking it here too
  // only keeps a mistaken or corrupted roster out.
  R('POST', '/api/campaigns/:id/roster', { strict: true }, (ctx) => {
    const id = ctx.params.id;
    if (authTrustee(ctx, 'POST /api/campaigns/:id/roster', id) !== 1) fail(403, 'founder_only');
    const signature = ctx.body.signature;
    if (!ctx.body.roster || typeof signature !== 'string' || signature.length > 200) fail(400, 'bad_request');
    return db.transaction(() => {
      const c = db.prepare('SELECT trustee_count_n n, threshold_k k, roster_json rj FROM campaigns WHERE id=?').get(id);
      if (!c) fail(404, 'not_found');
      const ts = db.prepare('SELECT trustee_index i, box_public_key pk, sign_public_key sk, enrolled_at e FROM trustees WHERE campaign_id=? ORDER BY trustee_index').all(id);
      if (ts.length !== c.n || ts.some((t) => !t.e)) fail(409, 'committee_incomplete');
      const held = { campaignId: id, k: c.k, n: c.n, seats: ts.map((t) => ({ index: t.i, boxPublicKey: t.pk })) };
      const sent = ctx.body.roster;
      if (canonicalJson({ campaignId: sent.campaignId, k: sent.k, n: sent.n, seats: Array.isArray(sent.seats) ? sent.seats.map((s) => ({ index: s?.index, boxPublicKey: s?.boxPublicKey })) : null }) !== canonicalJson(held)) fail(400, 'roster_mismatch');
      if (!verifyRoster(ts[0].sk, signature, held)) fail(400, 'bad_signature');
      if (c.rj) { // already signed: the same roster again is fine (a retry), a different one is not
        if (c.rj === JSON.stringify(held)) return { confirmed: true, already: true };
        fail(409, 'roster_exists');
      }
      db.prepare('UPDATE campaigns SET roster_json=?, roster_sig=? WHERE id=?').run(JSON.stringify(held), signature, id);
      touch(id);
      return { confirmed: true };
    })();
  });

  // Cards still sealed to the founder alone, so the founder can re-lock them to the whole committee.
  R('GET', '/api/campaigns/:id/reshare-bundle', {}, (ctx) => {
    const id = ctx.params.id;
    if (authTrustee(ctx, 'GET /api/campaigns/:id/reshare-bundle', id) !== 1) fail(403, 'founder_only');
    const rows = db.prepare("SELECT id, sealed_shares FROM cards WHERE campaign_id=? AND seal_mode='solo' ORDER BY created_at").all(id);
    return { cards: rows.map((r) => ({ id: r.id, sealedShares: JSON.parse(r.sealed_shares) })) };
  });
  R('POST', '/api/campaigns/:id/reshare', { maxBody: 4_000_000 }, (ctx) => {
    const id = ctx.params.id;
    if (authTrustee(ctx, 'POST /api/campaigns/:id/reshare', id) !== 1) fail(403, 'founder_only'); // only the founder holds these cards' keys; anyone else could only destroy them
    const cards = ctx.body.cards;
    if (!Array.isArray(cards) || cards.length < 1 || cards.length > 500) fail(400, 'bad_request');
    return db.transaction(() => {
      const c = db.prepare('SELECT trustee_count_n n, roster_json rj FROM campaigns WHERE id=?').get(id);
      if (!c) fail(404, 'not_found');
      if (!c.rj) fail(409, 'roster_not_confirmed'); // the founder signs the roster first; that is what makes new cards k-of-n, so the set of solo cards stops growing
      for (const item of cards) {
        const idx = Array.isArray(item?.sealedShares) ? item.sealedShares.map((s) => s?.trusteeIndex) : [];
        if (!isUuid(item?.cardId) || !Array.isArray(item.sealedShares) || item.sealedShares.length !== c.n || !item.sealedShares.every((s) => Number.isInteger(s?.trusteeIndex) && isB64(s.sealed, 60, 300))
          || new Set(idx).size !== c.n || idx.some((i) => i < 1 || i > c.n)) fail(400, 'bad_shares');
        const r = db.prepare("UPDATE cards SET sealed_shares=?, seal_mode='shamir' WHERE id=? AND campaign_id=? AND seal_mode='solo'")
          .run(JSON.stringify(item.sealedShares.map((s) => ({ trusteeIndex: s.trusteeIndex, sealed: s.sealed }))), item.cardId, id);
        if (r.changes !== 1) fail(409, 'not_solo');
      }
      touch(id);
      return { converted: cards.length, remaining: db.prepare("SELECT COUNT(*) c FROM cards WHERE campaign_id=? AND seal_mode='solo'").get(id).c };
    })();
  });

  R('POST', '/api/campaigns/:id/release-min', {}, (ctx) => {
    const id = ctx.params.id;
    const index = authTrustee(ctx, 'POST /api/campaigns/:id/release-min', id);
    const value = ctx.body.value;
    if (!Number.isInteger(value) || value < 1 || value > 100_000) fail(400, 'bad_request');
    return db.transaction(() => {
      const c = db.prepare('SELECT release_min r, threshold_k k FROM campaigns WHERE id=?').get(id);
      if (!c) fail(404, 'not_found');
      if (value >= c.r) { // raising the guard is always safe, so any one trustee may do it
        db.prepare('UPDATE campaigns SET release_min=? WHERE id=?').run(value, id);
        db.prepare('DELETE FROM release_approvals WHERE campaign_id=?').run(id);
        touch(id);
        return { releaseMin: value, applied: true };
      }
      // Lowering it weakens the guard: it takes k trustees approving the same lower value.
      db.prepare('INSERT INTO release_approvals (campaign_id,trustee_index,value,approved_at) VALUES (?,?,?,?) ON CONFLICT(campaign_id,trustee_index) DO UPDATE SET value=excluded.value, approved_at=excluded.approved_at')
        .run(id, index, value, now());
      const approvals = db.prepare('SELECT COUNT(*) c FROM release_approvals WHERE campaign_id=? AND value=?').get(id, value).c;
      if (approvals >= c.k) {
        db.prepare('UPDATE campaigns SET release_min=? WHERE id=?').run(value, id);
        db.prepare('DELETE FROM release_approvals WHERE campaign_id=?').run(id);
        touch(id);
        return { releaseMin: value, applied: true };
      }
      return { releaseMin: c.r, applied: false, approvals, needed: c.k };
    })();
  });

  R('POST', '/api/campaigns/:id/freeze', {}, (ctx) => {
    const id = ctx.params.id;
    authTrustee(ctx, 'POST /api/campaigns/:id/freeze', id);
    const c = db.prepare('SELECT status FROM campaigns WHERE id=?').get(id);
    if (!c || c.status === 'draft') fail(409, 'not_active');
    const status = ctx.body.frozen === false ? 'active' : 'frozen';
    db.prepare('UPDATE campaigns SET status=? WHERE id=?').run(status, id);
    touch(id);
    return { status };
  });

  R('POST', '/api/campaigns/:id/destroy-approve', {}, (ctx) => {
    const id = ctx.params.id;
    const index = authTrustee(ctx, 'POST /api/campaigns/:id/destroy-approve', id);
    return db.transaction(() => {
      const c = db.prepare('SELECT threshold_k k FROM campaigns WHERE id=?').get(id);
      if (!c) fail(404, 'not_found');
      db.prepare('INSERT OR IGNORE INTO destroy_approvals (campaign_id,trustee_index,approved_at) VALUES (?,?,?)').run(id, index, now());
      const approvals = db.prepare('SELECT COUNT(*) c FROM destroy_approvals WHERE campaign_id=?').get(id).c;
      if (approvals >= c.k) { db.prepare('DELETE FROM campaigns WHERE id=?').run(id); return { approvals, needed: c.k, destroyed: true }; }
      return { approvals, needed: c.k, destroyed: false };
    })();
  });

  // Development only: an in-memory outbox so you can read the Confirmation Transmission without email.
  // Only to a browser on this machine: on a server others can reach, the messages hold signers' names and addresses.
  if (mail.outbox && !cfg.production) R('GET', '/dev/outbox', {}, ({ req }) => { if (!fromThisMachine(req)) fail(404, 'not_found'); return { messages: mail.outbox }; });
}
