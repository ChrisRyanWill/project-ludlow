// In-memory rate limiting keyed by SHA-256(ip + a salt that rotates daily). Nothing about IPs is
// ever persisted or logged (rule 7); when the salt rotates the old keys become unlinkable.
import { createHash, randomBytes } from 'node:crypto';

export function makeLimiter({ disabled = false, windowMs = 60_000, max = 300, strictMax = 20 } = {}) {
  let salt = randomBytes(16);
  let saltDay = new Date().getUTCDate();
  const buckets = new Map();
  return function allow(ip, strict) {
    if (disabled) return true;
    const day = new Date().getUTCDate();
    if (day !== saltDay) { salt = randomBytes(16); saltDay = day; buckets.clear(); }
    const now = Date.now();
    if (buckets.size > 20_000) for (const [k, v] of buckets) if (v.reset < now) buckets.delete(k);
    const key = createHash('sha256').update(salt).update(String(ip)).update(strict ? 's' : 'g').digest('base64');
    let b = buckets.get(key);
    if (!b || b.reset < now) { b = { n: 0, reset: now + windowMs }; buckets.set(key, b); }
    return ++b.n <= (strict ? strictMax : max);
  };
}
