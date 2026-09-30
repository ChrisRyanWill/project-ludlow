// Tamper-evidence any member's browser can check on its own. Every ledger and audit entry commits to
// the one before it (hash chain), so history cannot be rewritten without every later hash changing.
// The server publishes the chain; the client re-derives every hash and compares.
import { chainHash, GENESIS, sha256Hex, sha256Text, keyWords } from './crypto.js';
import { REDACTED_CATEGORIES } from './constants.js';

// A card carries the SHA-256 of the exact text the signer saw. When the trustees open it, the text must still match: a card that does not was
// made by altered code (or has a bug), and is flagged rather than trusted. (The encryption already stops anyone else changing it.)
export function cardTextMatches(payload) {
  return typeof payload?.cardText === 'string' && typeof payload.cardTextSha256 === 'string' && sha256Hex(payload.cardText) === payload.cardTextSha256.toLowerCase();
}

export const ledgerFields = (e) => ({ seq: e.seq, date: e.date, kind: e.kind, cents: e.cents, cat: e.cat, rev: e.rev, at: e.at, commit: e.commit });
export const auditFields = (e) => ({ seq: e.seq, actor: e.actorId, action: e.action, type: e.type, id: e.id, at: e.at });

// entries must be in ascending seq order. `anchored` means the list starts at the very first entry.
export function verifyChain(entries, fieldsOf, { anchored = true } = {}) {
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    const prev = i === 0 ? (anchored ? GENESIS : e.prevHash) : entries[i - 1].hash;
    if (i > 0 && e.seq !== entries[i - 1].seq + 1) return { ok: false, brokenAt: e.seq, why: 'gap' };
    if (e.prevHash !== prev) return { ok: false, brokenAt: e.seq, why: 'link' };
    if (chainHash(prev, fieldsOf(e)) !== e.hash) return { ok: false, brokenAt: e.seq, why: 'hash' };
  }
  const head = entries.at(-1);
  return { ok: true, count: entries.length, head: head ? { seq: head.seq, hash: head.hash } : null };
}

// Compare what the server shows now with the head this device pinned on an earlier visit.
// `entries` may be only the newest window of a long log: a pin older than the window cannot be compared (`unchecked`), but one inside it must match.
export function checkPinned(entries, pin) {
  if (!pin) return { ok: true, first: true };
  if (entries.length && pin.seq < entries[0].seq) return { ok: true, unchecked: true };
  const e = entries.find((x) => x.seq === pin.seq);
  if (!e) return { ok: false, why: 'missing' }; // history was cut back
  return e.hash === pin.hash ? { ok: true } : { ok: false, why: 'changed' }; // history was rewritten
}

// The ledger's private text (payee, memo) sits outside the hash chain, encrypted; each entry's hash covers a commitment H(salt|payee|memo) instead.
// A member who is shown the payee, memo and salt re-derives the commitment and compares it with the one in the chain, so the text cannot be
// swapped afterwards (even by someone holding the master key) without the chain, or the pinned head, noticing. Redacted entries carry no salt
// and are skipped. `entries` come from the summary, `chain` from the chain route.
export function checkCommitments(entries, chain) {
  // Walk the VERIFIED chain, not the summary: which entries are redacted, their category and their amount all come from the chain, so a server
  // cannot relabel an entry to have it skipped, change the amount shown, or leave an entry out.
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const visible = [...chain].filter((c) => !REDACTED_CATEGORIES.includes(c.cat)).sort((a, b) => a.seq - b.seq);
  for (const c of [...chain].sort((a, b) => a.seq - b.seq)) {
    const e = bySeq.get(c.seq);
    if (!e || e.category !== c.cat || e.amountCents !== c.cents) return { ok: false, checked: visible.length, brokenAt: c.seq };
    if (REDACTED_CATEGORIES.includes(c.cat)) continue;
    // Every entry the app writes has a salt, so a visible one that arrives without it was tampered with.
    if (typeof e.salt !== 'string' || sha256Text(`${e.salt}|${e.payee || ''}|${e.memo || ''}`) !== c.commit) return { ok: false, checked: visible.length, brokenAt: c.seq };
  }
  return { ok: true, checked: visible.length, brokenAt: null };
}

// The audit page lists entries with names attached; the browser checked a separate copy (the chain, without names). What is shown must be what was checked.
export function auditRows(entries, chain, count) {
  // Rows are the newest `count` entries of the VERIFIED chain; a row the server leaves out of its page is still listed. The page supplies only the
  // actor's name, and only when it names the same actor as the chain.
  const names = new Map(entries.map((e) => [e.seq, e]));
  return [...chain].sort((a, b) => b.seq - a.seq).slice(0, count).map((c) => {
    const e = names.get(c.seq);
    return { seq: c.seq, actor: e && e.hash === c.hash && e.actorId === c.actorId ? e.actor ?? null : null, action: c.action, at: c.at, ok: true };
  });
}

// The public keys of the people a member's browser seals to (chief stewards, stewards, the election committee) come from the server. Each device
// remembers them; a key that changes is reported, with its key words, before anything is sealed to it (#37, stage 1). Returns the pins to keep if
// the person goes ahead; the pins passed in are not changed. First sight is remembered silently: this cannot catch a key that was false from the start.
export function compareKeyPins(pins, holders) {
  const next = { ...pins }, changed = [];
  for (const h of holders) {
    if (pins[h.memberId] && pins[h.memberId] !== h.boxPublicKey) changed.push({ memberId: h.memberId, name: h.name, words: keyWords(h.boxPublicKey) });
    next[h.memberId] = h.boxPublicKey;
  }
  return { changed, pins: next };
}
