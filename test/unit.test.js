import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as C from '../shared/crypto.js';
import { WORDS } from '../shared/words.js';
import * as D from '../shared/deadlines.js';
import { can, PERMS, ROLES } from '../shared/permissions.js';
import { evaluateVote, complianceTasks } from '../shared/constants.js';
import { makeLimiter } from '../server/rate.js';
import { clientIp } from '../server/http.js';
import { loadMasterKey } from '../server/kms.js';
import { loadConfig } from '../server/config.js';
import { openDb } from '../server/db.js';
import Database from 'better-sqlite3';
import { mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { zip, crc32, csvCell, toCsv } from '../web/src/zip.js';
import { verifyChain, auditFields, checkPinned } from '../shared/verify.js';
import { authenticate, rosterToSign, checkMySeat, checkEnrollment, RosterError } from '../shared/roster.js';

await C.ready;
const flip = (s) => s.slice(0, -2) + (s.at(-2) === 'A' ? 'B' : 'A') + s.at(-1);
const trustees = (n) => Array.from({ length: n }, (_, i) => ({ index: i + 1, keys: C.newKeypairs() }));
const pubs = (ts) => ts.map((t) => ({ index: t.index, boxPublicKey: t.keys.boxPublicKey }));

test('word list is large and has no duplicates', () => {
  assert.ok(WORDS.length >= 200, 'have ' + WORDS.length);
  assert.equal(new Set(WORDS).size, WORDS.length);
});

test('card: exactly k trustees open it; fewer, wrong keys and tampering all fail', async () => {
  const ts = trustees(5);
  const payload = { legalName: 'Zyxwvut Qqqname', phone: '+15550199999' };
  const enc = await C.encryptCard({ campaignId: 'c1', templateVersion: 'card-v1', payload, trustees: pubs(ts), k: 3 });
  const share = (t) => C.openShare(enc.sealedShares.find((s) => s.trusteeIndex === t.index).sealed, t.keys.boxPublicKey, t.keys.boxSecretKey);
  const ctx = { campaignId: 'c1', templateVersion: 'card-v1', ciphertext: enc.ciphertext, nonce: enc.nonce };
  assert.deepEqual(await C.decryptCard(ctx, [share(ts[0]), share(ts[2]), share(ts[4])]), payload);
  await assert.rejects(C.decryptCard(ctx, [share(ts[0]), share(ts[2])]), /unlock_failed/); // k-1
  await assert.rejects(C.decryptCard(ctx, [share(ts[0])]), /unlock_failed/);
  assert.throws(() => C.openShare(enc.sealedShares[0].sealed, ts[1].keys.boxPublicKey, ts[1].keys.boxSecretKey)); // someone else's key
  const three = [share(ts[0]), share(ts[1]), share(ts[2])];
  await assert.rejects(C.decryptCard({ ...ctx, ciphertext: flip(ctx.ciphertext) }, three));
  await assert.rejects(C.decryptCard({ ...ctx, nonce: flip(ctx.nonce) }, three));
  await assert.rejects(C.decryptCard({ ...ctx, campaignId: 'other' }, three)); // bound to its campaign
  await assert.rejects(C.decryptCard({ ...ctx, templateVersion: 'card-v2' }, three)); // and to the exact template
});

test('key file: round trip, wrong passphrase, and header tampering', () => {
  const secrets = { boxSecretKey: 'a', signSecretKey: 'b', campaignKey: 'c' };
  const file = C.makeKeyFile({ format: 'trustee-keyfile-v1', header: { campaignId: 'c1', trusteeIndex: 2 }, secrets, passphrase: 'correct horse battery staple', fast: true });
  assert.deepEqual(C.openKeyFile(file, 'correct horse battery staple'), secrets);
  assert.throws(() => C.openKeyFile(file, 'wrong passphrase entirely'), /wrong_passphrase/);
  assert.throws(() => C.openKeyFile({ ...file, trusteeIndex: 1 }, 'correct horse battery staple'), /wrong_passphrase/); // cannot be moved to another trustee
  assert.throws(() => C.openKeyFile({ ...file, kdf: { ...file.kdf, memlimit: 2 ** 40 } }, 'x'), /bad_keyfile/); // refuses absurd KDF costs
  const pass = 'correct horse battery staple';
  assert.throws(() => C.openKeyFile({ ...file, format: 'member-keyfile-v1' }, pass), /wrong_passphrase/); // format is bound in
  assert.throws(() => C.openKeyFile({ ...file, nonce: flip(file.nonce) }, pass), /wrong_passphrase/);
  assert.throws(() => C.openKeyFile({ ...file, ciphertext: flip(file.ciphertext) }, pass), /wrong_passphrase/);
  assert.throws(() => C.openKeyFile({ ...file, kdf: { ...file.kdf, salt: flip(file.kdf.salt) } }, pass), /wrong_passphrase/);
  const cheap = C.makeKeyFile({ format: 'trustee-keyfile-v1', header: { campaignId: 'c1', trusteeIndex: 2 }, secrets, passphrase: pass, fast: true });
  assert.throws(() => C.openKeyFile({ ...file, kdf: { ...file.kdf, opslimit: cheap.kdf.opslimit + 1 } }, pass), /wrong_passphrase/); // the cost is part of the key
  assert.throws(() => C.openKeyFile({ ...file, kdf: { ...file.kdf, opslimit: 2 ** 40 } }, 'x'), /bad_keyfile/);
  assert.throws(() => C.openKeyFile({ ...file, kdf: { ...file.kdf, alg: 'argon2i13' } }, pass), /bad_keyfile/);
  for (const broken of [null, {}, { ...file, kdf: undefined }, { ...file, format: '' }]) assert.throws(() => C.openKeyFile(broken, pass), /bad_keyfile/);
  assert.ok(C.passphraseOk(C.generatePassphrase()));
  assert.ok(!C.passphraseOk('short'));
});

test('metadata, signatures and member key derivation', () => {
  const key = C.newCampaignKey();
  const box = C.encryptMeta(key, { unionName: 'X' }, 'cid');
  assert.deepEqual(C.decryptMeta(key, box, 'cid'), { unionName: 'X' });
  assert.throws(() => C.decryptMeta(C.newCampaignKey(), box, 'cid'));
  assert.throws(() => C.decryptMeta(key, box, 'other-campaign'));
  const k = C.newKeypairs(), parts = { nonce: 'n1', route: 'POST /a', scope: 's1' };
  const sig = C.signAuth(k.signSecretKey, parts);
  assert.ok(C.verifyAuth(k.signPublicKey, sig, parts));
  assert.ok(!C.verifyAuth(k.signPublicKey, sig, { ...parts, route: 'POST /b' }));
  assert.ok(!C.verifyAuth(C.newKeypairs().signPublicKey, sig, parts));
  const s = C.newToken(), a = C.deriveMember(s), b = C.deriveMember(s);
  assert.equal(a.authToken, b.authToken);
  assert.notEqual(a.authToken, C.b64(a.lockerKey)); // the server sees one, never the other
  assert.equal(C.hashToken(a.authToken).length, 43);
});

test('reports shared with the committee: any one trustee can read, outsiders cannot', () => {
  const ts = trustees(3);
  const r = { id: 'r1', ...C.sealForTrustees({ what: 'boss asked who signed' }, pubs(ts), 'r1') };
  for (const t of ts) assert.deepEqual(C.openReport(r, t.index, t.keys.boxPublicKey, t.keys.boxSecretKey), { what: 'boss asked who signed' });
  const outsider = C.newKeypairs();
  assert.throws(() => C.openReport(r, 1, outsider.boxPublicKey, outsider.boxSecretKey));
  assert.throws(() => C.openReport({ ...r, id: 'r2' }, 1, ts[0].keys.boxPublicKey, ts[0].keys.boxSecretKey)); // bound to its id: cannot be replayed as another report
  assert.throws(() => C.openReport(r, 4, ts[0].keys.boxPublicKey, ts[0].keys.boxSecretKey), /not_for_you/);
});

test('secret ballots: sealed to a key nobody holds whole; k committee members recount', async () => {
  const committee = trustees(3);
  const vk = await C.newVoteKeys(committee.map((t) => ({ memberId: 'm' + t.index, boxPublicKey: t.keys.boxPublicKey })), 2);
  const mine = (t) => C.boxOpen(vk.committee[t.index - 1].sealed, t.keys.boxPublicKey, t.keys.boxSecretKey);
  const cast = [0, 0, 1, 2, 0].map((o) => C.castBallot(vk.votePublicKey, o));
  assert.equal(new Set(cast.map((c) => c.ciphertext)).size, 5); // identical choices look different
  assert.ok(cast.every((c) => c.ciphertext.length === 107)); // fixed length: length leaks nothing
  const sk = await C.reconstructVoteKey([mine(committee[0]), mine(committee[2])]);
  assert.equal(C.publicFromSecret(sk), vk.votePublicKey);
  assert.deepEqual(C.countBallots(vk.votePublicKey, sk, cast.map((c) => c.ciphertext), 3), { counts: [3, 1, 1], invalid: 0 });
  await assert.rejects(C.reconstructVoteKey([mine(committee[0])])); // one member alone cannot
  // A made-up share still combines (Shamir cannot tell), but into a key that does not match the vote's public key.
  const wrong = await C.reconstructVoteKey([mine(committee[0]), mine(committee[1]), new Uint8Array(33).fill(7)]);
  assert.notEqual(C.publicFromSecret(wrong), vk.votePublicKey);
  const bent = mine(committee[1]); bent[0] ^= 1; // one flipped bit in a real share
  assert.notEqual(C.publicFromSecret(await C.reconstructVoteKey([mine(committee[0]), bent])), vk.votePublicKey);
  await assert.rejects(C.reconstructVoteKey([mine(committee[0]), mine(committee[0])]), /bad_shares/); // the same share twice is not two
  const junk = C.countBallots(vk.votePublicKey, sk, ['A'.repeat(107)], 3);
  assert.equal(junk.invalid, 1);
  // Out-of-range choices (a tampered client) are counted as invalid, never folded into an option.
  const odd = [3, 255, -1].map((o) => C.castBallot(vk.votePublicKey, o).ciphertext);
  assert.deepEqual(C.countBallots(vk.votePublicKey, sk, odd, 3), { counts: [0, 0, 0], invalid: 3 });
  // Sealed to another key: invalid, not counted.
  const other = C.newKeypairs();
  assert.deepEqual(C.countBallots(vk.votePublicKey, sk, [C.castBallot(other.boxPublicKey, 0).ciphertext], 3), { counts: [0, 0, 0], invalid: 1 });
  // countBallots counts what it is given: de-duplication is the server's job (one ballot per receipt), so a copy counts twice here.
  assert.deepEqual(C.countBallots(vk.votePublicKey, sk, [cast[3].ciphertext, cast[3].ciphertext], 3).counts, [0, 0, 2]);
  assert.equal(C.receiptHash(cast[0].receiptCode), cast[0].receiptHash);
  assert.equal(C.receiptHash(cast[0].receiptCode.toLowerCase()), cast[0].receiptHash);
});

test('hash chain is deterministic and any edit changes every later hash', () => {
  const e = [{ seq: 1, cents: 100 }, { seq: 2, cents: 250 }, { seq: 3, cents: 75 }];
  const run = (rows) => rows.reduce((acc, r) => { acc.push(C.chainHash(acc.at(-1) || C.GENESIS, r)); return acc; }, []);
  const a = run(e), b = run(e);
  assert.deepEqual(a, b);
  const t = run([e[0], { seq: 2, cents: 251 }, e[2]]);
  assert.equal(t[0], a[0]);
  assert.notEqual(t[1], a[1]);
  assert.notEqual(t[2], a[2]);
  assert.equal(C.canonicalJson({ b: 1, a: [2, { d: 1, c: 2 }] }), '{"a":[2,{"c":2,"d":1}],"b":1}');
  assert.equal(C.canonicalJson({ a: undefined, b: null, c: [] , d: {} }), '{"b":null,"c":[],"d":{}}'); // undefined keys dropped, null kept
  assert.equal(C.canonicalJson({ 'é': 1, z: 2, Z: 3, 10: 4, 9: 5 }), C.canonicalJson({ 9: 5, 10: 4, Z: 3, z: 2, 'é': 1 })); // insertion order never matters
  assert.equal(C.canonicalJson('a"b\u2028'), JSON.stringify('a"b\u2028'));
  assert.notEqual(C.canonicalJson({ a: '1' }), C.canonicalJson({ a: 1 })); // types are kept apart
  assert.notEqual(C.canonicalJson(['a,b']), C.canonicalJson(['a', 'b']));
  assert.equal(C.vouchHash('id', ' maple  river '), C.vouchHash('id', 'MAPLE-RIVER'));
});

test('deadline engine: business days, holidays, weekends, year ends, time zones', () => {
  assert.equal(D.addBusinessDays('2026-10-02', 1), '2026-10-05'); // Friday -> Monday
  assert.equal(D.addBusinessDays('2026-09-30', 5), '2026-10-07');
  assert.equal(D.addBusinessDays('2026-10-09', 1, ['2026-10-12']), '2026-10-13'); // Monday holiday skipped
  assert.equal(D.dueDate('2026-09-25', { days: 1, dayType: 'calendar' }), '2026-09-28'); // lands on Saturday, rolls to Monday
  assert.equal(D.dueDate('2026-12-30', { days: 5, dayType: 'calendar' }), '2027-01-04'); // crosses the year
  assert.equal(D.dueDate('2028-02-28', { days: 2, dayType: 'calendar' }), '2028-03-01'); // leap year
  assert.equal(D.dueDate('2026-09-28', { days: 0, dayType: 'business' }), '2026-09-28');
  assert.equal(D.dueDate('2026-11-25', { days: 2, dayType: 'calendar' }, ['2026-11-27']), '2026-11-30'); // holiday then weekend
  assert.deepEqual(D.urgency('2026-10-01', '2026-10-05'), { left: -4, level: 'overdue' });
  assert.equal(D.urgency('2026-10-05', '2026-10-05').level, 'today');
  assert.equal(D.urgency('2026-10-07', '2026-10-05').level, 'soon');
  assert.equal(D.urgency('2026-10-11', '2026-10-05').level, 'week');
  assert.equal(D.urgency('2026-11-05', '2026-10-05').level, 'ok');
  assert.equal(D.todayIn('America/Denver', new Date('2026-01-01T03:00:00Z')), '2025-12-31'); // still yesterday in Denver
  assert.equal(D.todayIn('Asia/Tokyo', new Date('2026-01-01T03:00:00Z')), '2026-01-01');
});

test('permission matrix: fail closed, and representation is never gated by dues or membership', () => {
  assert.equal(can(new Set(['unit_employee']), 'no.such.action'), false);
  for (const [action, roles] of Object.entries(PERMS)) assert.ok(roles.includes('*') || roles.every((r) => ROLES.includes(r)), action);
  const nonMember = new Set(['unit_employee']);
  for (const a of ['grievance.submit', 'grievance.list', 'procedure.read', 'roles.read', 'announce.read']) assert.ok(can(nonMember, a), a);
  assert.ok(!can(nonMember, 'vote.cast'));
  assert.ok(!can(nonMember, 'finance.read'));
  assert.ok(!can(new Set(['unit_employee', 'member']), 'roster.read'));
  assert.ok(can(new Set(['unit_employee', 'member', 'treasurer']), 'ledger.record'));
  assert.ok(!can(new Set(['unit_employee', 'member', 'officer']), 'ledger.record')); // officers do not hold the books
});

test('vote rules: majority, two-thirds, plurality, ties', () => {
  assert.equal(evaluateVote([5, 4], 'majority').passed, true);
  assert.equal(evaluateVote([4, 4], 'majority').passed, false);
  assert.equal(evaluateVote([2, 1], 'two_thirds').passed, true);
  assert.equal(evaluateVote([6, 4], 'two_thirds').passed, false);
  assert.deepEqual(evaluateVote([1, 3, 2], 'plurality'), { total: 6, passed: true, winner: 1 });
  assert.equal(evaluateVote([3, 3, 0], 'plurality').passed, false);
  assert.equal(evaluateVote([0, 0], 'majority').passed, false);
});

test('compliance calendar dates come from the founding date and fiscal year', () => {
  const t = complianceTasks({ createdOn: '2026-01-10', fiscalYearStart: '01-01', today: '2026-09-28', receiptsCents: 0 });
  assert.equal(t.find((x) => x.key === 'lm1').dueOn, '2026-04-10'); // 90 days
  const ar = t.find((x) => x.key === 'annual_report');
  assert.equal(ar.dueOn, '2027-03-31'); // FY ends 2026-12-31, +90 days
  assert.match(ar.title, /LM-4/);
  assert.equal(t.find((x) => x.key === 'irs').dueOn, '2027-05-15');
  assert.match(complianceTasks({ createdOn: '2026-01-10', today: '2026-09-28', receiptsCents: 30_000_000 }).find((x) => x.key === 'annual_report').title, /LM-2/);
});

test('rate limiter: per-key windows, strict bucket, nothing stored about the ip itself', () => {
  const allow = makeLimiter({ max: 3, strictMax: 1 });
  assert.ok(allow('1.2.3.4') && allow('1.2.3.4') && allow('1.2.3.4'));
  assert.ok(!allow('1.2.3.4'));
  assert.ok(allow('5.6.7.8'));
  assert.ok(allow('9.9.9.9', true));
  assert.ok(!allow('9.9.9.9', true));
});

test('frontend hygiene: nothing that could turn data into markup, and no inline handlers or eval', () => {
  const dir = path.resolve(import.meta.dirname, '../web/src');
  const bad = /\.(innerHTML|outerHTML)|insertAdjacentHTML|document\.write|\beval\s*\(|new Function\s*\(|\bon(click|error|load)\s*=\s*["']/;
  for (const f of readdirSync(dir)) assert.ok(!bad.test(readFileSync(path.join(dir, f), 'utf8')), 'unsafe DOM use in ' + f);
  const html = readFileSync(path.resolve(dir, '../index.html'), 'utf8');
  assert.ok(!/<script(?![^>]*\bsrc=)[^>]*>/.test(html), 'inline script in index.html');
  assert.ok(!/style\s*=\s*"/.test(html), 'inline style in index.html');
});

test('zip writer produces a valid archive, and csv cells cannot become spreadsheet formulas', () => {
  const data = new TextEncoder().encode('hello ludlow');
  const out = zip([{ name: 'a/b.txt', data }, { name: 'ñ.csv', data: new Uint8Array(0) }]);
  const dv = new DataView(out.buffer, out.byteOffset);
  assert.equal(dv.getUint32(0, true), 0x04034b50); // local header signature
  assert.equal(dv.getUint32(out.length - 22, true), 0x06054b50); // end of central directory
  assert.equal(dv.getUint16(out.length - 22 + 10, true), 2); // two entries
  assert.equal(crc32(new TextEncoder().encode('123456789')), 0xcbf43926); // the standard CRC-32 check value
  assert.equal(csvCell('=HYPERLINK("http://evil")'), '"\'=HYPERLINK(""http://evil"")"');
  assert.equal(csvCell('@SUM(A1)'), "'@SUM(A1)");
  assert.equal(csvCell('-1+1'), "'-1+1");
  assert.equal(csvCell('+15550100001'), '+15550100001'); // real phone numbers stay intact
  assert.equal(csvCell('Zoë, "Z" Q'), '"Zoë, ""Z"" Q"');
  assert.equal(toCsv([['a', 'b'], ['c', '=d']]), "a,b\r\nc,'=d\r\n");
});

test('calendar dates (deadlines!) show the same day in every time zone', async () => {
  const { formatDate } = await import('../web/src/format.js');
  const was = process.env.TZ;
  try {
    for (const tz of ['America/Los_Angeles', 'America/Denver', 'Pacific/Auckland', 'UTC']) {
      process.env.TZ = tz;
      assert.equal(formatDate('2026-10-05'), 'Oct 5, 2026', tz); // a Monday deadline never slides to Sunday
      assert.equal(formatDate('2026-01-01'), 'Jan 1, 2026', tz);
    }
  } finally { if (was === undefined) delete process.env.TZ; else process.env.TZ = was; }
  assert.equal(formatDate(''), '');
});

test('solo cards: only the founder opens them; resharing gives k-of-n and proves itself first', async () => {
  const ts = trustees(3);
  const payload = { legalName: 'Zyxwvut Qqqname' };
  const enc = C.encryptCardSolo({ campaignId: 'c1', templateVersion: 'card-v1', payload, founder: { index: 1, boxPublicKey: ts[0].keys.boxPublicKey } });
  assert.equal(enc.sealMode, 'solo');
  assert.equal(enc.sealedShares.length, 1);
  const ctx = { campaignId: 'c1', templateVersion: 'card-v1', ciphertext: enc.ciphertext, nonce: enc.nonce };
  const key = C.openShare(enc.sealedShares[0].sealed, ts[0].keys.boxPublicKey, ts[0].keys.boxSecretKey);
  assert.deepEqual(C.decryptSoloCard(ctx, key), payload);
  assert.throws(() => C.openShare(enc.sealedShares[0].sealed, ts[1].keys.boxPublicKey, ts[1].keys.boxSecretKey)); // nobody else
  assert.throws(() => C.decryptSoloCard({ ...ctx, ciphertext: flip(ctx.ciphertext) }, key), /unlock_failed/);
  assert.throws(() => C.decryptSoloCard({ ...ctx, campaignId: 'other' }, key), /unlock_failed/);
  const shares = await C.reshareCard(enc.sealedShares[0].sealed, ts[0].keys, pubs(ts), 2);
  assert.deepEqual(shares.map((s) => s.trusteeIndex), [1, 2, 3]);
  const open = (t) => C.openShare(shares.find((s) => s.trusteeIndex === t.index).sealed, t.keys.boxPublicKey, t.keys.boxSecretKey);
  assert.deepEqual(await C.decryptCard(ctx, [open(ts[1]), open(ts[2])]), payload); // trustees 2 and 3 alone, no founder
  await assert.rejects(C.decryptCard(ctx, [open(ts[0])]), /unlock_failed/); // one is not enough any more
});

test('frontend hygiene: every UI helper a page calls is imported or defined there', () => {
  const dir = path.resolve(import.meta.dirname, '../web/src');
  const helpers = ['div', 'span', 'p', 'a', 'img', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'strong', 'em', 'small', 'pre', 'code', 'hr', 'table', 'thead', 'tbody', 'tr', 'td', 'th', 'label', 'input', 'textarea', 'button', 'select', 'option', 'details', 'summary', 'blockquote', 'mark',
    'btn', 'callout', 'badge', 'field', 'textInput', 'selectBox', 'linkBtn', 'shell', 'setTitle', 'view', 'fragment', 'go', 'act', 'toast', 'copy', 'share', 'download', 'md', 'fill', 'cardBody', 'readAloud', 'svg', 'pct', 'fmtDate', 'fmtDateTime', 'ago', 'money', 'wipers', 'setKids', 'render'];
  const pages = readdirSync(dir).filter((f) => !['ui.js', 'i18n.js', 'api.js', 'store.js', 'format.js', 'zip.js', 'es.js', 'packs.js'].includes(f));
  for (const f of pages) {
    const src = readFileSync(path.join(dir, f), 'utf8');
    const imported = new Set([...src.matchAll(/import\s*\{([^}]*)\}\s*from\s*'\.\/ui\.js'/gs)].flatMap((m) => m[1].split(',').map((x) => x.trim())));
    const body = src.replace(/import[^;]*;/g, '');
    const local = new Set([...src.matchAll(/(?:const|let|function)\s+(\w+)/g)].map((m) => m[1]));
    const missing = helpers.filter((h) => new RegExp(`(?<![\\w.$'"])${h}\\(`).test(body) && !imported.has(h) && !local.has(h));
    assert.deepEqual(missing, [], `${f} uses helpers it never imports`);
  }
});

test('key words: ten words that identify a public key, stable, distinct, and they refuse a missing key', () => {
  const a = C.newKeypairs().boxPublicKey, b = C.newKeypairs().boxPublicKey;
  const w = C.keyWords(a);
  assert.equal(w, C.keyWords(a)); // stable: two people computing it independently see the same words
  const parts = w.split('-');
  assert.equal(parts.length, 10);
  assert.ok(parts.every((p) => WORDS.includes(p)));
  assert.notEqual(w, C.keyWords(b));
  assert.notEqual(w, C.keyWords(flip(a))); // changing one character of the key changes the words
  for (const bad of [null, undefined, '', 'short', 42]) assert.throws(() => C.keyWords(bad)); // two missing keys must never "match"
  const seen = new Set();
  for (let i = 0; i < 300; i++) seen.add(C.keyWords(C.newKeypairs().boxPublicKey));
  assert.equal(seen.size, 300);
});

test('committee tally signatures: bound to the vote and the counts, and only the signer verifies', () => {
  const a = C.newKeypairs(), b = C.newKeypairs();
  const sig = C.signTally(a.signSecretKey, 'vote-1', [4, 1]);
  assert.ok(C.verifyTally(a.signPublicKey, sig, 'vote-1', [4, 1]));
  assert.ok(!C.verifyTally(a.signPublicKey, sig, 'vote-2', [4, 1])); // another vote
  assert.ok(!C.verifyTally(a.signPublicKey, sig, 'vote-1', [5, 0])); // other counts
  assert.ok(!C.verifyTally(a.signPublicKey, sig, 'vote-1', [4, 1, 0])); // a different number of options
  assert.ok(!C.verifyTally(b.signPublicKey, sig, 'vote-1', [4, 1])); // someone else's key
  assert.ok(!C.verifyTally(a.signPublicKey, flip(sig), 'vote-1', [4, 1])); // a tampered signature
  assert.ok(!C.verifyTally(a.signPublicKey, 'not base64!', 'vote-1', [4, 1]));
  assert.ok(!C.verifyTally('not a key', sig, 'vote-1', [4, 1]));
  // a sign-in signature cannot be replayed as a tally signature: different message, different domain
  const login = C.signAuth(a.signSecretKey, { nonce: 'n', route: 'r', scope: 's' });
  assert.ok(!C.verifyTally(a.signPublicKey, login, 'r', []));
});

test('audit and ledger history: a chain check alone accepts a full rewrite, a pinned head catches it', () => {
  const mk = (n, edit = {}) => { let prev = C.GENESIS; return Array.from({ length: n }, (_, i) => { const e = { seq: i + 1, actorId: 'a', action: edit[i + 1] || `act${i + 1}`, type: null, id: null, at: '2026-01-01T00:00:00Z' }; e.prevHash = prev; e.hash = C.chainHash(prev, auditFields(e)); prev = e.hash; return e; }); };
  const real = mk(10);
  const pin = verifyChain(real, auditFields).head;
  assert.deepEqual(checkPinned(real, pin), { ok: true });
  // an operator rewrites entry 3 and re-hashes everything after it: internally the chain is perfect...
  const rewritten = mk(10, { 3: 'nothing to see here' });
  assert.equal(verifyChain(rewritten, auditFields).ok, true);
  // ...but it no longer matches the head this device saw before
  assert.deepEqual(checkPinned(rewritten, pin), { ok: false, why: 'changed' });
  // deleting entries and renumbering is caught too, and so is cutting the log back
  assert.deepEqual(checkPinned(mk(9), pin), { ok: false, why: 'missing' });
  // a device that has never looked can only check consistency
  assert.deepEqual(checkPinned(rewritten, null), { ok: true, first: true });
  // a long log is shown as its newest window: a pin older than the window cannot be compared, one inside it must match
  const window = real.slice(5);
  assert.deepEqual(checkPinned(window, { seq: 2, hash: real[1].hash }), { ok: true, unchecked: true });
  assert.deepEqual(checkPinned(window, { seq: 7, hash: real[6].hash }), { ok: true });
  assert.deepEqual(checkPinned(window, { seq: 7, hash: 'AAAA' }), { ok: false, why: 'changed' });
});

test('fingerprints are 80 bits, so a forged history cannot be ground into showing the same one', () => {
  const h = C.chainHash(C.GENESIS, { a: 1 });
  const f = C.fingerprint(h);
  assert.match(f, /^[0-9A-F]{4}(-[0-9A-F]{4}){4}$/);
  assert.equal(f, C.fingerprint(h));
  assert.notEqual(f, C.fingerprint(C.chainHash(C.GENESIS, { a: 2 })));
  assert.equal(C.fingerprint('not a hash!'), '');
  assert.equal(C.fingerprint(undefined), '');
});

test('shamir shares are checked before they are combined: x = 0, wrong lengths and repeats are refused', async () => {
  const ts = trustees(3);
  const enc = await C.encryptCard({ campaignId: 'c1', templateVersion: 'card-v1', payload: { n: 1 }, trustees: pubs(ts), k: 2 });
  const shares = ts.map((t) => C.openShare(enc.sealedShares.find((s) => s.trusteeIndex === t.index).sealed, t.keys.boxPublicKey, t.keys.boxSecretKey));
  const ctx = { campaignId: 'c1', templateVersion: 'card-v1', ciphertext: enc.ciphertext, nonce: enc.nonce };
  assert.deepEqual(await C.decryptCard(ctx, [shares[0], shares[1]]), { n: 1 });
  const zero = new Uint8Array(33).fill(7); zero[32] = 0; // an "x = 0" share: combine() would hand back whatever bytes the sender chose
  await assert.rejects(C.decryptCard(ctx, [shares[0], zero]), /unlock_failed/);
  await assert.rejects(C.reconstructVoteKey([shares[0], zero]), /bad_shares/);
  await assert.rejects(C.reconstructVoteKey([shares[0], shares[0]]), /bad_shares/); // the same share twice
  await assert.rejects(C.reconstructVoteKey([shares[0], shares[1].slice(0, 32)]), /bad_shares/); // wrong length
  await assert.rejects(C.reconstructVoteKey([shares[0]]), /bad_shares/); // too few
  await assert.rejects(C.reconstructVoteKey([shares[0], 'not a share']), /bad_shares/);
});

test('the client address comes from the proxy that is trusted, not from whatever the client wrote in X-Forwarded-For', () => {
  const req = (xff, remote = '10.0.0.1') => ({ headers: xff ? { 'x-forwarded-for': xff } : {}, socket: { remoteAddress: remote } });
  assert.equal(clientIp(req('6.6.6.6, 203.0.113.9'), { trustProxy: 1 }), '203.0.113.9'); // the client's own claim is at the front; the proxy appended the truth
  assert.equal(clientIp(req('203.0.113.9'), { trustProxy: 1 }), '203.0.113.9');
  assert.equal(clientIp(req('6.6.6.6, 203.0.113.9, 10.1.1.1'), { trustProxy: 2 }), '203.0.113.9'); // two proxies
  assert.equal(clientIp(req('6.6.6.6'), { trustProxy: 0 }), '10.0.0.1'); // no proxy: the header means nothing
  // A header only one hosting company's proxy sets is just client input behind any other proxy: it must never pick the address.
  const flyReq = { headers: { 'fly-client-ip': '6.6.6.6', 'x-forwarded-for': '203.0.113.9' }, socket: { remoteAddress: '10.0.0.1' } };
  assert.equal(clientIp(flyReq, { trustProxy: 1 }), '203.0.113.9');
  assert.equal(clientIp(flyReq, { trustProxy: 0 }), '10.0.0.1');
  assert.equal(loadConfig({}).trustProxy, 0);
  assert.equal(loadConfig({ TRUST_PROXY: '1' }).trustProxy, 1);
  for (const bad of ['true', 'yes', '-1', '1.5', 'x']) assert.throws(() => loadConfig({ TRUST_PROXY: bad }), /TRUST_PROXY/, bad);
  assert.equal(clientIp(req(null), { trustProxy: 1 }), '10.0.0.1');
  assert.equal(clientIp(req('1.1.1.1'), { trustProxy: 3 }), '10.0.0.1'); // fewer entries than proxies: the header was not set by them
  assert.equal(clientIp(req('6.6.6.6, 203.0.113.9'), { trustProxy: true }), '203.0.113.9'); // the old boolean setting still means one proxy
});

test('names that go into Markdown cannot turn into links, emphasis or code', async () => {
  const { plainMd } = await import('../web/src/format.js');
  for (const evil of ['[click here](https://phish.example)', '**Free** dues `now`', 'A *B* C', 'TODO(lawyer): x']) {
    const out = plainMd(evil);
    assert.ok(!/[\[\]()*`]/.test(out), out);
  }
  assert.equal(plainMd('Riverside Workers United'), 'Riverside Workers United'); // ordinary names are untouched
  assert.equal(plainMd('Local  42\n  (Cooks)'), 'Local 42 Cooks');
  assert.equal(plainMd(null), '');
});

// ---- the founder's key check and the signed roster: a lying server must not make a genuine browser seal to a key of its own ----
const rosterWorld = (n = 3, k = 2) => {
  const ts = trustees(n);
  const commit = C.founderCommit(ts[0].keys.boxPublicKey, ts[0].keys.signPublicKey);
  const listed = (enrolled = n) => ts.map((t, i) => ({ index: t.index, enrolled: i < enrolled, boxPublicKey: i < enrolled ? t.keys.boxPublicKey : null, signPublicKey: i < enrolled ? t.keys.signPublicKey : null }));
  const roster = { campaignId: 'camp-1', k, n, seats: ts.map((t) => ({ index: t.index, boxPublicKey: t.keys.boxPublicKey })) };
  const signed = { roster, signature: C.signRoster(ts[0].keys.signSecretKey, roster) };
  const raw = (over = {}) => ({ n, k, trustees: listed(), roster: signed, ...over });
  return { ts, commit, listed, roster, signed, raw };
};
const refuses = (fn, code) => assert.throws(fn, (e) => e instanceof RosterError && e.code === code, `expected ${code}`);

test('founder key check: 128 bits over both public keys, so neither can be swapped', () => {
  const a = C.newKeypairs(), b = C.newKeypairs();
  const c = C.founderCommit(a.boxPublicKey, a.signPublicKey);
  assert.match(c, /^[A-Za-z0-9_-]{22}$/);
  assert.equal(c, C.founderCommit(a.boxPublicKey, a.signPublicKey));
  assert.notEqual(c, C.founderCommit(b.boxPublicKey, a.signPublicKey)); // a different box key
  assert.notEqual(c, C.founderCommit(a.boxPublicKey, b.signPublicKey)); // a different signing key
  assert.notEqual(c, C.founderCommit(a.signPublicKey, a.boxPublicKey)); // order matters
});

test('roster signatures: bound to the exact committee, the campaign and the threshold; nothing else the founder signs can be a roster', () => {
  const w = rosterWorld(), F = w.ts[0].keys;
  assert.ok(C.verifyRoster(F.signPublicKey, w.signed.signature, w.roster));
  const forge = (edit) => C.verifyRoster(F.signPublicKey, w.signed.signature, edit(structuredClone(w.roster)));
  assert.ok(!forge((r) => { r.seats[1].boxPublicKey = C.newKeypairs().boxPublicKey; return r; })); // a swapped trustee key
  assert.ok(!forge((r) => { r.k = 3; return r; })); // a changed threshold
  assert.ok(!forge((r) => { r.campaignId = 'camp-2'; return r; })); // another campaign
  assert.ok(!forge((r) => { r.seats.reverse(); return r; })); // reordered
  assert.ok(!forge((r) => { r.seats.pop(); r.n = 2; return r; })); // a smaller committee
  assert.ok(!C.verifyRoster(w.ts[1].keys.signPublicKey, w.signed.signature, w.roster)); // signed by someone else
  assert.ok(C.verifyRoster(F.signPublicKey, w.signed.signature, { ...w.roster, extra: 'ignored' })); // unknown fields are not signed and change nothing
  // the same key signs sign-in challenges and tallies: neither can be replayed as a roster
  assert.ok(!C.verifyRoster(F.signPublicKey, C.signAuth(F.signSecretKey, { nonce: 'n', route: 'POST /api/campaigns/:id/roster', scope: 'camp-1' }), w.roster));
  assert.ok(!C.verifyRoster(F.signPublicKey, C.signTally(F.signSecretKey, 'camp-1', [2, 1]), w.roster));
  // malformed rosters are refused whatever the signature says
  const bad = [{ ...w.roster, k: 1 }, { ...w.roster, k: 4 }, { ...w.roster, n: 4 }, { ...w.roster, seats: [w.roster.seats[0], w.roster.seats[0], w.roster.seats[2]] },
    { ...w.roster, seats: w.roster.seats.map((s) => ({ ...s, index: s.index + 1 })) }, { ...w.roster, campaignId: 7 }, null, 'x'];
  for (const r of bad) assert.ok(!C.verifyRoster(F.signPublicKey, C.signRoster(F.signSecretKey, w.roster), r));
});

test('a signer before the committee is confirmed seals to the founder alone, and only if the founder\'s keys match the link', () => {
  const w = rosterWorld();
  const a = authenticate(w.raw({ roster: null, trustees: w.listed(1) }), w.commit, 'camp-1');
  assert.deepEqual([a.mode, a.seats.length, a.seats[0].boxPublicKey, a.k], ['solo', 1, w.ts[0].keys.boxPublicKey, null]);
  // the server swaps the founder's keys, one at a time and both: the link's check no longer matches
  const evil = C.newKeypairs();
  for (const swap of [{ boxPublicKey: evil.boxPublicKey }, { signPublicKey: evil.signPublicKey }, { boxPublicKey: evil.boxPublicKey, signPublicKey: evil.signPublicKey }]) {
    refuses(() => authenticate(w.raw({ roster: null, trustees: w.listed(1).map((x, i) => (i === 0 ? { ...x, ...swap } : x)) }), w.commit, 'camp-1'), 'founder_mismatch');
  }
  refuses(() => authenticate(w.raw({ roster: null, trustees: w.listed(1) }), undefined, 'camp-1'), 'no_commit'); // a link without a key check cannot be verified
  refuses(() => authenticate(w.raw({ roster: null, trustees: w.listed(1) }), 'short', 'camp-1'), 'no_commit');
  refuses(() => authenticate(w.raw({ roster: null, trustees: w.listed(0) }), w.commit, 'camp-1'), 'no_founder');
  refuses(() => authenticate(w.raw({ roster: null, trustees: [] }), w.commit, 'camp-1'), 'no_founder');
  // enrolled trustees the founder has not signed for yet are NOT sealed to, even if everyone has joined
  const unconfirmed = authenticate(w.raw({ roster: null }), w.commit, 'camp-1');
  assert.deepEqual([unconfirmed.mode, unconfirmed.seats.length], ['solo', 1]);
});

test('once the founder has signed the roster, a signer seals to that committee and to nothing the server adds or swaps', () => {
  const w = rosterWorld(3, 2);
  const a = authenticate(w.raw(), w.commit, 'camp-1');
  assert.deepEqual([a.mode, a.k, a.seats.map((s) => s.index)], ['shamir', 2, [1, 2, 3]]);
  assert.deepEqual(a.seats.map((s) => s.boxPublicKey), w.ts.map((t) => t.keys.boxPublicKey));
  const evil = C.newKeypairs();
  // the server swaps a trustee's key in its list only: what was signed still wins, and the difference is reported
  refuses(() => authenticate(w.raw({ trustees: w.listed().map((x) => (x.index === 2 ? { ...x, boxPublicKey: evil.boxPublicKey } : x)) }), w.commit, 'camp-1'), 'roster_mismatch');
  // ...or in the roster it serves, which it cannot re-sign
  const forged = structuredClone(w.signed); forged.roster.seats[1].boxPublicKey = evil.boxPublicKey;
  refuses(() => authenticate(w.raw({ roster: forged, trustees: w.listed().map((x) => (x.index === 2 ? { ...x, boxPublicKey: evil.boxPublicKey } : x)) }), w.commit, 'camp-1'), 'roster_invalid');
  // a roster signed by the server's own key, or by a trustee who is not the founder
  for (const impostor of [evil, w.ts[1].keys]) {
    const r = structuredClone(w.roster); r.seats[1].boxPublicKey = evil.boxPublicKey;
    refuses(() => authenticate(w.raw({ roster: { roster: r, signature: C.signRoster(impostor.signSecretKey, r) } }), w.commit, 'camp-1'), 'roster_invalid');
  }
  // a genuine roster for a different campaign, replayed
  refuses(() => authenticate(w.raw(), w.commit, 'camp-2'), 'roster_invalid');
  // a lower threshold, or a different size, than the founder signed
  refuses(() => authenticate(w.raw({ k: 2, roster: { roster: { ...w.roster, k: 3 }, signature: w.signed.signature } }), w.commit, 'camp-1'), 'roster_invalid');
  refuses(() => authenticate(w.raw({ n: 4 }), w.commit, 'camp-1'), 'roster_mismatch');
  refuses(() => authenticate(w.raw({ k: 3 }), w.commit, 'camp-1'), 'roster_mismatch');
  // the founder's key check still has to match, so a whole invented committee signed by an invented founder fails too
  const fake = rosterWorld(3, 2);
  refuses(() => authenticate({ ...fake.raw(), campaignId: 'camp-1' }, w.commit, 'camp-1'), 'founder_mismatch');
  // a validly signed roster whose seat 1 is not the founder's key is refused
  const odd = structuredClone(w.roster); odd.seats[0].boxPublicKey = evil.boxPublicKey;
  refuses(() => authenticate(w.raw({ roster: { roster: odd, signature: C.signRoster(w.ts[0].keys.signSecretKey, odd) } }), w.commit, 'camp-1'), 'roster_invalid');
  // withholding the roster cannot make a browser use the server's list: it falls back to the founder alone
  const withheld = authenticate(w.raw({ roster: null }), w.commit, 'camp-1');
  assert.deepEqual([withheld.mode, withheld.seats.length], ['solo', 1]);
});

test('the founder signs only a roster built from their own key and the committee they checked', () => {
  const w = rosterWorld(), F = w.ts[0].keys, evil = C.newKeypairs();
  const built = rosterToSign(w.raw({ roster: null }), 'camp-1', F);
  assert.ok(C.verifyRoster(F.signPublicKey, C.signRoster(F.signSecretKey, built), built));
  assert.deepEqual(built.seats.map((s) => s.boxPublicKey), w.ts.map((t) => t.keys.boxPublicKey));
  refuses(() => rosterToSign(w.raw({ roster: null, trustees: w.listed(2) }), 'camp-1', F), 'committee_incomplete'); // someone has not joined
  // the server puts a different key in the founder's own seat (which the founder did not check against anyone)
  for (const swap of [{ boxPublicKey: evil.boxPublicKey }, { signPublicKey: evil.signPublicKey }]) {
    refuses(() => rosterToSign(w.raw({ roster: null, trustees: w.listed().map((x, i) => (i === 0 ? { ...x, ...swap } : x)) }), 'camp-1', F), 'own_seat_mismatch');
  }
  refuses(() => rosterToSign(w.raw({ roster: null, trustees: w.listed().map((x) => (x.index === 3 ? { ...x, boxPublicKey: 'short' } : x)) }), 'camp-1', F), 'committee_incomplete');
});

test('the founder signs the threshold they chose, not one the server reports', () => {
  const w = rosterWorld(5, 4), F = w.ts[0].keys;
  assert.equal(rosterToSign(w.raw({ roster: null }), 'camp-1', F, { k: 4, n: 5 }).k, 4);
  refuses(() => rosterToSign(w.raw({ roster: null, k: 2 }), 'camp-1', F, { k: 4, n: 5 }), 'plan_mismatch'); // the server lowered it
  refuses(() => rosterToSign(w.raw({ roster: null }), 'camp-1', F, { k: 3, n: 5 }), 'plan_mismatch');
  assert.equal(rosterToSign(w.raw({ roster: null }), 'camp-1', F).k, 4); // no remembered plan (another device): the page shows the numbers instead
});

test('a trustee invitation cannot be turned into the founder\'s seat, or point at a different founder', () => {
  const w = rosterWorld(3, 2);
  assert.equal(checkEnrollment(w.raw({ roster: null, trustees: w.listed(0) }), 1, undefined), 'founder'); // the founder's own link has no check: there is nothing to check yet
  assert.equal(checkEnrollment(w.raw({ roster: null, trustees: w.listed(1) }), 2, w.commit), 'ok');
  refuses(() => checkEnrollment(w.raw({ roster: null, trustees: w.listed(1) }), 1, w.commit), 'not_founder'); // a link with a founder check is never the founder's
  refuses(() => checkEnrollment(w.raw({ roster: null, trustees: w.listed(1) }), 2, rosterWorld().commit), 'founder_mismatch'); // seat 1 is not who the link says
  refuses(() => checkEnrollment(w.raw({ roster: null, trustees: w.listed(0) }), 2, w.commit), 'no_founder'); // seat 1 has not joined, so the check cannot be made
  assert.equal(checkEnrollment(w.raw({ roster: null, trustees: w.listed(1) }), 2, undefined), 'unchecked'); // an older link: allowed, with the existing warning
});

test('a trustee can check that the roster the founder signed contains their own key', () => {
  const w = rosterWorld();
  assert.equal(checkMySeat(w.raw({ roster: null }), w.commit, 'camp-1', 2, w.ts[1].keys.boxPublicKey), 'unsigned');
  assert.equal(checkMySeat(w.raw(), undefined, 'camp-1', 2, w.ts[1].keys.boxPublicKey), 'unknown'); // an older key file with no key check to verify against
  assert.equal(checkMySeat(w.raw(), w.commit, 'camp-1', 2, w.ts[1].keys.boxPublicKey), 'ok');
  refuses(() => checkMySeat(w.raw(), w.commit, 'camp-1', 2, C.newKeypairs().boxPublicKey), 'my_key_missing'); // the roster names a key that is not mine
  // a founder who signed a different key for seat 2 is caught by trustee 2
  const swapped = structuredClone(w.roster); swapped.seats[1].boxPublicKey = C.newKeypairs().boxPublicKey;
  const raw = w.raw({ roster: { roster: swapped, signature: C.signRoster(w.ts[0].keys.signSecretKey, swapped) }, trustees: w.listed().map((x) => (x.index === 2 ? { ...x, boxPublicKey: swapped.seats[1].boxPublicKey } : x)) });
  refuses(() => checkMySeat(raw, w.commit, 'camp-1', 2, w.ts[1].keys.boxPublicKey), 'my_key_missing');
  refuses(() => checkMySeat(w.raw(), w.commit, 'camp-2', 2, w.ts[1].keys.boxPublicKey), 'roster_invalid');
});

// The browser code may seal for the trustees only to keys shared/roster.js has authenticated, and every invitation link carries the founder's key
// check. This reads web/src and returns what breaks those rules. It is deliberately strict about shape: each sealing call must name an authenticated
// source directly, so routing the server's list through a variable, an alias or a helper is caught too.
function trustViolations(files) {
  const out = [];
  const SEALS = ['encryptCard', 'encryptCardSolo', 'sealForTrustees', 'reshareCard'];
  const args = (src, at) => { // the text between the parentheses that open at `at`
    let depth = 0;
    for (let i = at; i < src.length; i++) { if (src[i] === '(') depth++; else if (src[i] === ')' && --depth === 0) return src.slice(at + 1, i); }
    return '';
  };
  for (const [f, src] of Object.entries(files)) {
    for (const name of SEALS) {
      for (const m of src.matchAll(new RegExp(`\\b${name}\\b`, 'g'))) {
        if (src[m.index + name.length] !== '(') { out.push(`${f}: ${name} used other than by calling it (an alias?)`); continue; }
        const a = args(src, m.index + name.length).replace(/\s+/g, ' ');
        const ok = name === 'encryptCard' ? /\btrustees: sealTo\.seats\b/.test(a) && /\bk: sealTo\.k\b/.test(a)
          : name === 'encryptCardSolo' ? /\bfounder: sealTo\.seats\[0\]/.test(a)
            : name === 'sealForTrustees' ? /, sealTo\.seats, /.test(a)
              : /, seats, k$/.test(a.trim()); // reshareCard only inside relock(seats, k)
        if (!ok) out.push(`${f}: ${name}(${a.slice(0, 70)}) does not seal to authenticated keys`);
      }
    }
    // where those authenticated keys come from
    for (const m of src.matchAll(/\bsealTo\s*=\s*([A-Za-z_.]+)\(/g)) if (m[1] !== 'authenticate') out.push(`${f}: sealTo assigned from ${m[1]}()`);
    for (const m of src.matchAll(/\bsealTo\s*=(?!=)\s*(?=\S)(?![A-Za-z_.]+\()/g)) out.push(`${f}: sealTo assigned from something other than a call: ${src.slice(m.index, m.index + 50)}`);
    for (const m of src.matchAll(/\brelock\(([^)]*)\)/g)) {
      const a = m[1].replace(/\s+/g, ' ').trim();
      if (a === 'seats, k') continue; // its own definition
      if (!['roster.seats, roster.k', 'a.seats, a.k'].includes(a)) out.push(`${f}: relock(${a}) with keys that were not signed`);
    }
    if (/\brelock\(/.test(src)) {
      if (!/\bconst roster = rosterToSign\(/.test(src) || /\broster = (?!rosterToSign\()/.test(src)) out.push(`${f}: roster does not come from rosterToSign()`);
      if (!/\bconst a = authenticate\(/.test(src) || /\ba = (?!authenticate\()/.test(src.replace(/\bconst a = authenticate\(/g, ''))) out.push(`${f}: a does not come from authenticate()`);
    }
    // invitation and member links: an object literal carrying f (the founder's own first link cannot: their keys do not exist yet)
    for (const m of src.matchAll(/linkTo\('\/(j|t|m)',\s*/g)) {
      const rest = src.slice(m.index + m[0].length);
      if (rest[0] !== '{') { out.push(`${f}: a /${m[1]} link is built from something other than an object literal`); continue; }
      let depth = 0, end = 0;
      for (let i = 0; i < rest.length; i++) { if (rest[i] === '{') depth++; else if (rest[i] === '}' && --depth === 0) { end = i; break; } }
      const obj = rest.slice(0, end + 1);
      const firstFounderLink = m[1] === 't' && /\be: tok\b/.test(obj);
      if (!firstFounderLink && !/\bf: (?!undefined\b|null\b|''|"")[A-Za-z_]/.test(obj)) out.push(`${f}: a /${m[1]} link is built without the founder's key check: ${obj.slice(0, 80)}`);
    }
  }
  return out;
}

test('frontend trust: everything sealed for the trustees goes through the roster check, and invitation links carry the founder\'s key check', () => {
  const dir = path.resolve(import.meta.dirname, '../web/src');
  const files = Object.fromEntries(readdirSync(dir).filter((f) => f.endsWith('.js')).map((f) => [f, readFileSync(path.join(dir, f), 'utf8')]));
  assert.deepEqual(trustViolations(files), []);
  // The check itself must catch the ways this has gone wrong or nearly did (the first is the code before the roster existed).
  const mutate = (f, from, to) => { assert.ok(files[f].includes(from), `mutation no longer applies: ${from}`); return { ...files, [f]: files[f].replace(from, to) }; };
  const mutants = {
    'relock to the server\'s list': mutate('trustee.js', 'await relock(roster.seats, roster.k);', '{ const trustees = raw.trustees.map((x) => ({ index: x.index, boxPublicKey: x.boxPublicKey })); await relock(trustees, raw.k); }'),
    'report to the server\'s list via a variable': mutate('organize.js', 'sealTo.seats, rid)', 'fromServer, rid)'),
    'card to the server\'s list via a variable': mutate('organize.js', 'trustees: sealTo.seats, k: sealTo.k', 'trustees: all, k: raw.k'),
    'sealTo from the server': mutate('organize.js', 'sealTo = authenticate(raw, fc, c);', 'sealTo = { mode: raw.roster ? "shamir" : "solo", seats: raw.trustees, k: raw.k };'),
    'aliased seal function': mutate('organize.js', 'C.encryptCard({', '(0, C.encryptCard)({'),
    'invitation with f: undefined': mutate('organize.js', "linkTo('/j', { i: token, k, c, f: saved.founder })", "linkTo('/j', { i: token, k, c, f: undefined })"),
    'invitation built from a variable': mutate('organize.js', "linkTo('/j', { i: token, k, c, f: saved.founder })", 'linkTo(\'/j\', P)'),
    'member link without f': mutate('organize.js', "linkTo('/m', { s: R.secret, k, c, f: fc })", "linkTo('/m', { s: R.secret, k, c })"),
    'trustee seat link without f': mutate('trustee.js', 'c: T.campaignId, f: T.founder }); // the link carries', 'c: T.campaignId }); // the link carries'),
  };
  for (const [name, m] of Object.entries(mutants)) assert.ok(trustViolations(m).length > 0, `the tripwire misses: ${name}`);
});

test('master key: the development key file is never made for a server reachable from other machines', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'ludlow-kms-'));
  const cfg = (host, extra = {}) => ({ host, production: false, masterKey: '', dbPath: path.join(dir, host.replace(/[^a-z0-9]/gi, '_'), 'x.db'), ...extra });
  for (const host of ['0.0.0.0', '::', '192.168.1.20', 'example.org']) {
    assert.throws(() => loadMasterKey(cfg(host)), /WORKSPACE_MASTER_KEY/, host);
    assert.equal(existsSync(path.join(path.dirname(cfg(host).dbPath), 'dev-master.key')), false, host);
  }
  for (const host of ['127.0.0.1', '127.0.0.2', '::1', 'localhost']) assert.equal(loadMasterKey(cfg(host)).length, 32, host);
  const key = C.b64(C.randomBytes(32));
  assert.equal(loadMasterKey(cfg('0.0.0.0', { masterKey: key })).length, 32); // a real key is fine anywhere
  assert.throws(() => loadMasterKey(cfg('127.0.0.1', { production: true })), /required in production/);
});

test('the database never runs in WAL mode, where one commit would put a voter\'s "has voted" next to their ballot', () => {
  const file = path.join(mkdtempSync(path.join(tmpdir(), 'ludlow-db-')), 'x.db');
  const pre = new Database(file); pre.pragma('journal_mode = WAL'); pre.close(); // a file someone switched to WAL, say with the sqlite3 shell
  const db = openDb(file);
  try { assert.equal(db.pragma('journal_mode', { simple: true }), 'delete'); } finally { db.close(); }
});
