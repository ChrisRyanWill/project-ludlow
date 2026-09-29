import { signAuth } from '../../shared/crypto.js';

export class ApiError extends Error {
  constructor(status, code, extra) { super(code); this.status = status; this.code = code; this.extra = extra; }
}

export async function api(method, path, { body, auth } = {}) {
  let r;
  try {
    r = await fetch(path, { method, headers: { 'Content-Type': 'application/json', ...(auth ? { Authorization: auth } : {}) }, body: body ? JSON.stringify(body) : undefined });
  } catch { throw new ApiError(0, 'offline'); }
  let j = null;
  try { j = await r.json(); } catch { /* empty body */ }
  if (!r.ok) throw new ApiError(r.status, j?.error || 'error', j);
  return j;
}
export const bearer = (t) => 'Bearer ' + t;

// A trustee call: fetch a one-time challenge, sign `nonce | route | campaignId` with the trustee's
// signing key, and send the signature instead of any password. The route string names the action.
export async function tcall(T, route, { body, params = {} } = {}) {
  const [method, pattern] = route.split(' ');
  const path = pattern.replace(/:(\w+)/g, (_, k) => encodeURIComponent(params[k] ?? T.campaignId));
  const ch = await api('POST', '/api/auth/challenge');
  const sig = signAuth(T.keys.signSecretKey, { nonce: ch.nonce, route, scope: T.campaignId });
  return api(method, path, { body, auth: `Sig ${ch.challengeId}.${T.index}.${sig}` });
}

const FRIENDLY = {
  offline: 'You seem to be offline. Check your connection and try again.',
  rate_limited: 'Too many tries. Wait a minute and try again.',
  unauthorized: 'That link, key or sign-in is not valid any more.',
  session_expired: 'Your session ended. Please sign in again.',
  forbidden: 'You do not have permission to do that.',
  not_found: 'That could not be found.',
  invalid_invite: 'This invitation link is no longer valid. Ask for a new one.',
  campaign_not_active: 'This campaign is not accepting cards right now.',
  wrong_code: 'That code is not right.',
  locked: 'Too many wrong codes. This card is locked.',
  already_voted: 'You have already voted.',
  vote_closed: 'This vote is closed.',
  stage_required: 'This is only available once your union is recognized.',
  no_chief_steward: 'No chief steward has set up an account yet, so nobody could read this. Ask an officer to assign one.',
  own_request: 'You cannot approve your own request.',
  conflict: 'That has already been done.',
  committee_conflict: 'Candidates cannot sit on the committee that runs their own election.',
  feature_disabled: 'This feature is turned off until your attorney approves it.',
  email_failed: 'We could not send the confirmation email.',
  last_officer: 'There must be at least one officer.',
  threshold_not_met: 'The cards stay locked until enough people have signed.',
  committee_changed: 'The committee just changed. Please try again.',
  founder_only: 'Only the founder (trustee 1) can do that.',
  bad_key: 'This link is missing part of its key. Ask for it to be sent again and copy the whole link.',
  // The keys the website gave this device did not check out. Nothing is signed, sealed or sent.
  no_commit: "This invitation is from an older version, so it cannot check the trustees' keys. Ask whoever invited you for a new link.",
  no_founder: 'The founder has not set up their key yet. Please try again later.',
  founder_mismatch: 'The keys this website gave your phone do not match your invitation, so nothing was signed or sent. The website may have been tampered with, or the link may have been changed. Tell whoever invited you, in person or by phone, and do not try again from this link.',
  roster_invalid: 'The committee this website showed is not the one the founder signed, so nothing was signed or sent. The website may have been tampered with. Tell whoever invited you, in person or by phone.',
  roster_mismatch: 'The committee this website lists does not match the roster that was signed, so nothing was signed or sent. If you were invited to sign a card, the website may have been tampered with: tell whoever invited you, in person or by phone. If you are trustee 1, look again and check your key words.',
  committee_incomplete: 'Not every trustee has joined yet.',
  own_seat_mismatch: 'The website put a key in your own seat that is not yours. Do not confirm the committee: something is wrong. Tell the other trustees.',
  my_key_missing: 'The committee the founder signed does not contain your key. Talk to trustee 1 before you trust this campaign.',
  roster_not_confirmed: 'The founder has not confirmed the committee yet.',
  roster_exists: 'The committee has already been confirmed.',
  bad_signature: 'That confirmation could not be checked. Please try again.',
};
export const friendly = (e) => FRIENDLY[e?.code] || 'Something went wrong. Please try again.';
