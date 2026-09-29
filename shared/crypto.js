// Project Ludlow — ALL cryptography lives here. Runs in the browser and in Node (server-side
// signature checks, tests). Only libsodium + Shamir secret sharing; nothing hand-rolled (rule 8).
import sodium from 'libsodium-wrappers-sumo';
import { split, combine } from 'shamir-secret-sharing';
import { WORDS } from './words.js';

export const ready = sodium.ready;

// ---------- encoding ----------
export const b64 = (u8) => sodium.to_base64(u8, sodium.base64_variants.URLSAFE_NO_PADDING);
export const unb64 = (s) => sodium.from_base64(s, sodium.base64_variants.URLSAFE_NO_PADDING);
export const utf8 = (s) => sodium.from_string(s);
export const unutf8 = (u) => sodium.to_string(u);
export const randomBytes = (n) => sodium.randombytes_buf(n);
export const wipe = (...bufs) => bufs.forEach((b) => b && b.length && sodium.memzero(b));

export function canonicalJson(v) {
  if (Array.isArray(v)) return '[' + v.map(canonicalJson).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().filter((k) => v[k] !== undefined)
      .map((k) => JSON.stringify(k) + ':' + canonicalJson(v[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}

// ---------- tokens (all generated client-side; the server only ever stores hashes) ----------
export const newToken = () => b64(randomBytes(32));
// crypto.randomUUID() and crypto.subtle only exist in secure contexts; a phone opening http://192.168.x.x is not one.
export function uuid() {
  const b = randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
  const h = sodium.to_hex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
export const sha256Hex = (text) => sodium.to_hex(sodium.crypto_hash_sha256(utf8(text)));
export const sha256HexBytes = (u8) => sodium.to_hex(sodium.crypto_hash_sha256(u8));
const sha256b64 = (u8) => b64(sodium.crypto_hash_sha256(u8));
export const hashToken = (token) => {
  try { return sha256b64(unb64(String(token))); } catch { return sha256b64(utf8('invalid|' + String(token))); }
};

// ---------- authenticated symmetric encryption (XChaCha20-Poly1305) ----------
const aadBytes = (a) => (typeof a === 'string' ? utf8(a) : a ?? new Uint8Array(0));
export function aeadSeal(key, plaintext, aad) {
  const nonce = randomBytes(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aadBytes(aad), null, nonce, key);
  return { nonce: b64(nonce), ciphertext: b64(ct) };
}
export function aeadOpen(key, { nonce, ciphertext }, aad) {
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, unb64(ciphertext), aadBytes(aad), unb64(nonce), key);
}
export const sealJson = (key, obj, aad) => aeadSeal(key, utf8(canonicalJson(obj)), aad);
export const openJson = (key, box, aad) => JSON.parse(unutf8(aeadOpen(key, box, aad)));

// ---------- sealed boxes (anonymous public-key encryption) ----------
export const boxSeal = (publicKeyB64, u8) => b64(sodium.crypto_box_seal(u8, unb64(publicKeyB64)));
export const boxOpen = (sealedB64, publicKeyB64, secretKeyB64) =>
  sodium.crypto_box_seal_open(unb64(sealedB64), unb64(publicKeyB64), unb64(secretKeyB64));
export const publicFromSecret = (secretKeyB64) => b64(sodium.crypto_scalarmult_base(unb64(secretKeyB64)));

// ---------- campaign metadata ----------
export const newCampaignKey = () => b64(randomBytes(32));
export const encryptMeta = (campaignKey, meta, campaignId) => sealJson(unb64(campaignKey), meta, 'meta|' + campaignId);
export const decryptMeta = (campaignKey, box, campaignId) => openJson(unb64(campaignKey), box, 'meta|' + campaignId);

// ---------- keypairs (trustees and workspace members) ----------
export function newKeypairs() {
  const box = sodium.crypto_box_keypair();
  const sign = sodium.crypto_sign_keypair();
  return {
    boxPublicKey: b64(box.publicKey), boxSecretKey: b64(box.privateKey),
    signPublicKey: b64(sign.publicKey), signSecretKey: b64(sign.privateKey),
  };
}

// ---------- passphrase-protected key files (Argon2id + XChaCha20-Poly1305) ----------
const KDF_LIMITS = { maxMem: 1024 * 1024 * 1024, maxOps: 10 };
function kdfParams(fast) {
  return fast
    ? { opslimit: sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE, memlimit: sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE }
    : { opslimit: sodium.crypto_pwhash_OPSLIMIT_MODERATE, memlimit: sodium.crypto_pwhash_MEMLIMIT_MODERATE };
}
const derive = (passphrase, salt, opslimit, memlimit) =>
  sodium.crypto_pwhash(32, utf8(passphrase.normalize('NFKC')), salt, opslimit, memlimit, sodium.crypto_pwhash_ALG_ARGON2ID13);

export function makeKeyFile({ format, header, secrets, passphrase, fast = false }) {
  const salt = randomBytes(sodium.crypto_pwhash_SALTBYTES);
  let params = kdfParams(fast), key;
  // A very low-memory phone may not be able to allocate 256 MB; fall back to the lighter setting rather than fail.
  try { key = derive(passphrase, salt, params.opslimit, params.memlimit); }
  catch (e) { if (fast) throw e; params = kdfParams(true); key = derive(passphrase, salt, params.opslimit, params.memlimit); }
  const box = sealJson(key, secrets, format + '|' + canonicalJson(header));
  wipe(key);
  return { format, ...header, kdf: { alg: 'argon2id13', salt: b64(salt), opslimit: params.opslimit, memlimit: params.memlimit }, nonce: box.nonce, ciphertext: box.ciphertext };
}

export function openKeyFile(file, passphrase) {
  const { format, kdf, nonce, ciphertext, ...header } = file || {};
  if (!format || !kdf || kdf.alg !== 'argon2id13' || kdf.memlimit > KDF_LIMITS.maxMem || kdf.opslimit > KDF_LIMITS.maxOps) throw new Error('bad_keyfile');
  const key = derive(passphrase, unb64(kdf.salt), kdf.opslimit, kdf.memlimit);
  try { return openJson(key, { nonce, ciphertext }, format + '|' + canonicalJson(header)); }
  catch { throw new Error('wrong_passphrase'); }
  finally { wipe(key); }
}

// ---------- member identity: one secret in the member link gives two independent keys ----------
// The server only ever sees `authToken` (and stores its hash). `lockerKey`, which opens the worker's
// private record, is derived on the device and never leaves it.
export function deriveMember(secretB64) {
  const master = unb64(secretB64);
  const authToken = b64(sodium.crypto_kdf_derive_from_key(32, 1, 'ludlowm1', master));
  const lockerKey = sodium.crypto_kdf_derive_from_key(32, 2, 'ludlowm1', master);
  wipe(master);
  return { authToken, lockerKey };
}

// ---------- reports shared with the committee: sealed separately to each trustee ----------
export function sealForTrustees(payload, trustees, id) {
  const key = randomBytes(32);
  const box = sealJson(key, payload, 'report|' + id);
  const sealedKeys = trustees.map((t) => ({ trusteeIndex: t.index, sealed: boxSeal(t.boxPublicKey, key) }));
  wipe(key);
  return { ...box, sealedKeys };
}
export function openReport(report, trusteeIndex, boxPublicKey, boxSecretKey) {
  const entry = report.sealedKeys.find((s) => s.trusteeIndex === trusteeIndex);
  if (!entry) throw new Error('not_for_you');
  const key = boxOpen(entry.sealed, boxPublicKey, boxSecretKey);
  try { return openJson(key, report, 'report|' + report.id); } finally { wipe(key); }
}

// ---------- tamper-evident history (ledger + audit log) ----------
export const GENESIS = 'GENESIS';
export const sha256Text = (s) => sha256b64(utf8(s));
export const chainHash = (prev, fields) => sha256b64(utf8(prev + '|' + canonicalJson(fields)));
// A fingerprint short enough to read aloud ("compare this with a coworker") but long enough that nobody can grind out a forged history that shows the
// same one: 80 bits, as 20 hex digits in groups of four. (The old eight base64 characters, case-folded, were only about 40 bits: hours on a graphics card.)
export const fingerprint = (hash) => {
  try { return sodium.to_hex(unb64(hash).subarray(0, 10)).toUpperCase().replace(/(.{4})(?=.)/g, '$1-'); } catch { return ''; }
};

// ---------- word-based codes ----------
const word = () => WORDS[sodium.randombytes_uniform(WORDS.length)];
export const generatePassphrase = (n = 6) => Array.from({ length: n }, word).join('-');
export const vouchCode = () => (word() + '-' + word()).toUpperCase();
export const normalizeCode = (c) => String(c).trim().toUpperCase().replace(/[\s_]+/g, '-');
export const vouchHash = (cardId, code) => sha256b64(utf8('vouch|' + cardId + '|' + normalizeCode(code)));
export const passphraseOk = (p) => typeof p === 'string' && (p.length >= 14 || p.trim().split(/[\s-]+/).length >= 4 && p.length >= 12);

// Words that stand for a public key, so two people can check it aloud ("read me the words on your screen"). They identify a key and are
// not secret. The list has 205 words (about 7.7 bits each), so ten words are about 77 bits: enough that nobody can grind out a different
// key that shows the same words. Fewer would not be, which is why this is not the 6-word passphrase length.
export const keyWords = (publicKeyB64) => {
  if (typeof publicKeyB64 !== 'string' || publicKeyB64.length < 20) throw new Error('keyWords needs a public key'); // never let a missing key "match" another missing key
  const h = sodium.crypto_hash_sha256(utf8('ludlow key words v1|' + publicKeyB64));
  return Array.from({ length: 10 }, (_, i) => WORDS[((h[3 * i] << 16) | (h[3 * i + 1] << 8) | h[3 * i + 2]) % WORDS.length]).join('-');
};

// ---------- card encryption (Section 5.2 of the spec) ----------
export async function encryptCard({ campaignId, templateVersion, payload, trustees, k }) {
  const cardKey = randomBytes(32);
  const box = sealJson(cardKey, payload, campaignId + '|' + templateVersion);
  const shares = await split(cardKey, trustees.length, k);
  const sealedShares = trustees.map((t, i) => ({ trusteeIndex: t.index, sealed: boxSeal(t.boxPublicKey, shares[i]) }));
  wipe(cardKey, ...shares);
  return { ciphertext: box.ciphertext, nonce: box.nonce, sealedShares, templateVersion, sealMode: 'shamir' };
}

// A card signed before the committee is complete is sealed to the founder (trustee 1) ALONE. That is a real
// trade-off, and the UI says so: until the committee exists, one person can open it. The founder later
// re-locks it to the whole committee with reshareCard().
export function encryptCardSolo({ campaignId, templateVersion, payload, founder }) {
  const cardKey = randomBytes(32);
  const box = sealJson(cardKey, payload, campaignId + '|' + templateVersion);
  const sealedShares = [{ trusteeIndex: founder.index, sealed: boxSeal(founder.boxPublicKey, cardKey) }];
  wipe(cardKey);
  return { ciphertext: box.ciphertext, nonce: box.nonce, sealedShares, templateVersion, sealMode: 'solo' };
}
export function decryptSoloCard({ campaignId, templateVersion, ciphertext, nonce }, cardKey) {
  try { return openJson(cardKey, { nonce, ciphertext }, campaignId + '|' + templateVersion); } catch { throw new Error('unlock_failed'); }
}
// Open the founder's sealed key, split it k-of-n, seal a share to each trustee, and PROVE the shares rebuild
// the key before anything is uploaded: a bad reshare would destroy the card.
export async function reshareCard(sealedSolo, founderKeys, trustees, k) {
  const cardKey = boxOpen(sealedSolo, founderKeys.boxPublicKey, founderKeys.boxSecretKey);
  const shares = await split(cardKey, trustees.length, k);
  const back = await combine(shares.slice(0, k));
  const same = back.length === cardKey.length && back.every((v, i) => v === cardKey[i]);
  const sealed = trustees.map((t, i) => ({ trusteeIndex: t.index, sealed: boxSeal(t.boxPublicKey, shares[i]) }));
  wipe(cardKey, back, ...shares);
  if (!same) throw new Error('reshare_failed');
  return sealed;
}
export const openShare = (sealed, boxPublicKey, boxSecretKey) => boxOpen(sealed, boxPublicKey, boxSecretKey);
// A share is the secret's length plus one byte: the x coordinate. x = 0 would BE the secret (the polynomial's value at zero), so combine() returns
// whatever bytes a sender puts in an x = 0 "share". Refuse those, wrong lengths, and the same share twice, before combining anything.
function checkShares(shares, secretLen = 32) {
  if (!Array.isArray(shares) || shares.length < 2) throw new Error('bad_shares');
  const xs = new Set();
  for (const s of shares) {
    if (!(s instanceof Uint8Array) || s.length !== secretLen + 1 || s[s.length - 1] === 0) throw new Error('bad_shares');
    xs.add(s[s.length - 1]);
  }
  if (xs.size !== shares.length) throw new Error('bad_shares');
}
export async function decryptCard({ campaignId, templateVersion, ciphertext, nonce }, shares) {
  let cardKey;
  try {
    checkShares(shares);
    cardKey = await combine(shares);
    return openJson(cardKey, { nonce, ciphertext }, campaignId + '|' + templateVersion);
  } catch { throw new Error('unlock_failed'); }
  finally { wipe(cardKey); }
}

// ---------- challenge–response signatures (trustees and workspace members) ----------
const authMsg = ({ nonce, route, scope }) => utf8(`${nonce}|${route}|${scope}`);
export const signAuth = (signSecretKey, parts) => b64(sodium.crypto_sign_detached(authMsg(parts), unb64(signSecretKey)));
export function verifyAuth(signPublicKey, sig, parts) {
  try { return sodium.crypto_sign_verify_detached(unb64(sig), authMsg(parts), unb64(signPublicKey)); } catch { return false; }
}

// A committee member signs the counts they saw. When the ballot key is not published the server cannot recount, so it requires k different
// committee members to stand behind the same counts. The message names the vote and the domain, so a signature cannot be reused for anything else.
const tallyMsg = (voteId, counts) => utf8(`ludlow tally v1|${voteId}|${counts.join(',')}`);
export const signTally = (signSecretKey, voteId, counts) => b64(sodium.crypto_sign_detached(tallyMsg(voteId, counts), unb64(signSecretKey)));
export function verifyTally(signPublicKey, sig, voteId, counts) {
  try { return sodium.crypto_sign_verify_detached(unb64(sig), tallyMsg(voteId, counts), unb64(signPublicKey)); } catch { return false; }
}

// ---------- secret ballots ----------
// The vote's private key is split k-of-n among the election committee and never stored whole.
export async function newVoteKeys(committee, k) {
  const kp = sodium.crypto_box_keypair();
  const shares = await split(kp.privateKey, committee.length, k);
  const out = {
    votePublicKey: b64(kp.publicKey), thresholdK: k,
    committee: committee.map((m, i) => ({ memberId: m.memberId, sealed: boxSeal(m.boxPublicKey, shares[i]) })),
  };
  wipe(kp.privateKey, ...shares);
  return out;
}
const RECEIPT_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
export const receiptHash = (code) => sha256b64(utf8('receipt|' + normalizeCode(code)));
export function castBallot(votePublicKey, optionIndex) {
  const plain = randomBytes(32); // fixed size: option in byte 0, random padding after
  plain[0] = optionIndex;
  const ciphertext = b64(sodium.crypto_box_seal(plain, unb64(votePublicKey)));
  const raw = Array.from({ length: 16 }, () => RECEIPT_ALPHABET[sodium.randombytes_uniform(RECEIPT_ALPHABET.length)]).join('');
  const receiptCode = raw.match(/.{4}/g).join('-');
  return { ciphertext, receiptCode, receiptHash: receiptHash(receiptCode) };
}
export async function reconstructVoteKey(shares) { checkShares(shares); const sk = await combine(shares); const out = b64(sk); wipe(sk); return out; }
export function countBallots(votePublicKey, voteSecretKey, ballots, nOptions) {
  const counts = Array(nOptions).fill(0); let invalid = 0;
  for (const ct of ballots) {
    try {
      const plain = boxOpen(ct, votePublicKey, voteSecretKey);
      if (plain.length === 32 && plain[0] < nOptions) counts[plain[0]]++; else invalid++;
    } catch { invalid++; }
  }
  return { counts, invalid };
}
