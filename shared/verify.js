// Tamper-evidence any member's browser can check on its own. Every ledger and audit entry commits to
// the one before it (hash chain), so history cannot be rewritten without every later hash changing.
// The server publishes the chain; the client re-derives every hash and compares.
import { chainHash, GENESIS, sha256Hex } from './crypto.js';

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
