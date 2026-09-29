// Which public keys a browser may seal to. The server supplies keys, and a server that lies must not be able to make a genuine browser seal to one of its own,
// so nothing here takes the server's word: what it lists is checked against the founder's key check from the invitation link, and against the roster the
// founder signed. Every place that seals something for the trustees goes through authenticate(); see docs/PROTOCOL.md section 1a.
import { founderCommit, verifyRoster, rosterShapeOk } from './crypto.js';

export class RosterError extends Error {
  constructor(code) { super(code); this.name = 'RosterError'; this.code = code; }
}
const KEY43 = /^[A-Za-z0-9_-]{43}$/;
const isKey = (s) => typeof s === 'string' && KEY43.test(s);
export const isCommit = (s) => typeof s === 'string' && /^[A-Za-z0-9_-]{22}$/.test(s);

// raw: the campaign meta the server returned; commit: the founder key check carried by the invitation link; campaignId: the campaign the link is for.
// Returns { mode: 'solo' | 'shamir', founder, seats, k }: 'solo' means seal to seat 1 alone, 'shamir' means split k-of-n across every seat.
// Throws RosterError with a code: no_commit (the link has no key check), no_founder, founder_mismatch, roster_invalid, roster_mismatch.
export function authenticate(raw, commit, campaignId) {
  if (!isCommit(commit)) throw new RosterError('no_commit');
  const seat1 = Array.isArray(raw?.trustees) ? raw.trustees.find((x) => x?.index === 1) : null;
  if (!seat1 || !seat1.enrolled || !isKey(seat1.boxPublicKey) || !isKey(seat1.signPublicKey)) throw new RosterError('no_founder');
  if (founderCommit(seat1.boxPublicKey, seat1.signPublicKey) !== commit) throw new RosterError('founder_mismatch');
  const founder = { boxPublicKey: seat1.boxPublicKey, signPublicKey: seat1.signPublicKey };
  if (!raw.roster) return { mode: 'solo', founder, seats: [{ index: 1, boxPublicKey: founder.boxPublicKey }], k: null };
  const { roster, signature } = raw.roster;
  if (!verifyRoster(founder.signPublicKey, signature, roster) || roster.campaignId !== campaignId) throw new RosterError('roster_invalid');
  if (roster.seats[0].boxPublicKey !== founder.boxPublicKey) throw new RosterError('roster_invalid'); // seat 1 is the founder
  // The server's own list must agree with what was signed. It cannot change what we seal to, but a difference means something is wrong.
  if (roster.n !== raw.n || roster.k !== raw.k || roster.seats.some((s) => raw.trustees.find((x) => x.index === s.index)?.boxPublicKey !== s.boxPublicKey)) throw new RosterError('roster_mismatch');
  return { mode: 'shamir', founder, seats: roster.seats.map((s) => ({ index: s.index, boxPublicKey: s.boxPublicKey })), k: roster.k };
}

// The founder's side: the roster to sign, built from the committee as the server lists it. The founder has checked each trustee's key words against
// exactly these keys, and their own seat must be their own keys (a server could otherwise put a different key in the founder's seat).
export function rosterToSign(raw, campaignId, ownKeys) {
  const seats = Array.isArray(raw?.trustees) ? [...raw.trustees].sort((a, b) => a.index - b.index) : [];
  if (!seats.length || seats.length !== raw.n || seats.some((x, i) => x.index !== i + 1 || !x.enrolled || !isKey(x.boxPublicKey))) throw new RosterError('committee_incomplete');
  if (seats[0].boxPublicKey !== ownKeys.boxPublicKey || seats[0].signPublicKey !== ownKeys.signPublicKey) throw new RosterError('own_seat_mismatch');
  const roster = { campaignId, k: raw.k, n: raw.n, seats: seats.map((x) => ({ index: x.index, boxPublicKey: x.boxPublicKey })) };
  if (!rosterShapeOk(roster)) throw new RosterError('roster_invalid');
  return roster;
}

// A trustee's own check on a roster that has been signed: does the founder's signature verify, and is MY key in my seat?
// `commit` is the founder key check this trustee's key file holds. Returns 'ok', 'unsigned' (nothing to check yet), or 'unknown' (no key check to verify against);
// throws RosterError when the roster is invalid or does not contain this trustee's key.
export function checkMySeat(raw, commit, campaignId, index, boxPublicKey) {
  if (!raw?.roster) return 'unsigned';
  if (!isCommit(commit)) return 'unknown';
  const a = authenticate(raw, commit, campaignId);
  if (a.seats.find((s) => s.index === index)?.boxPublicKey !== boxPublicKey) throw new RosterError('my_key_missing');
  return 'ok';
}
