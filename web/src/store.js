// Everything a browser remembers lives here, behind try/catch: private windows and blocked storage
// must never break the app. Secrets stored here are either encrypted key files or the member's own
// link secret (which the person is told to save elsewhere too). No cookies, ever.
const P = 'ludlow.';
export const store = {
  get(k) { try { const v = localStorage.getItem(P + k); return v == null ? null : JSON.parse(v); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(P + k, JSON.stringify(v)); return true; } catch { return false; } },
  del(k) { try { localStorage.removeItem(P + k); } catch { /* ignore */ } },
  keys(prefix) {
    try { return Object.keys(localStorage).filter((k) => k.startsWith(P + prefix)).map((k) => k.slice(P.length)); } catch { return []; }
  },
};
