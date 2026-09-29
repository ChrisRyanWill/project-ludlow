// Challenge–response authentication. A challenge is single-use, expires in 2 minutes, and lives only in
// memory. The client signs `nonce | route | scope` with its private signing key (see shared/crypto.js).
import { randomUUID } from 'node:crypto';
import { randomBytes, b64 } from '../shared/crypto.js';

const challenges = new Map();

export function issueChallenge() {
  const challengeId = randomUUID();
  const nonce = b64(randomBytes(24));
  challenges.set(challengeId, { nonce, exp: Date.now() + 120_000 });
  if (challenges.size > 5000) { const t = Date.now(); for (const [k, v] of challenges) if (v.exp < t) challenges.delete(k); }
  return { challengeId, nonce };
}

// Taking a challenge consumes it, so a replayed signature always fails.
export function takeChallenge(id) {
  const c = challenges.get(id);
  challenges.delete(id);
  return c && c.exp > Date.now() ? c.nonce : null;
}

export const bearer = (headers) => { const m = /^Bearer (\S{1,200})$/.exec(headers.authorization || ''); return m ? m[1] : null; };
export const sigHeader = (headers) => {
  const m = /^Sig ([\w-]{1,64})\.(\d{1,3})\.([\w-]{1,200})$/.exec(headers.authorization || '');
  return m ? { challengeId: m[1], index: m[2], sig: m[3] } : null;
};
