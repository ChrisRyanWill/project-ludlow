// Envelope encryption for workspace personal data (V2 rule 2). Each workspace has a random data key,
// wrapped by the master key (WORKSPACE_MASTER_KEY; later a cloud KMS). Personal fields are stored only
// as ciphertext, so a database dump alone reveals nothing. End-to-end records (grievances) never use
// this: the server holds no key that opens them.
import fs from 'node:fs';
import path from 'node:path';
import { aeadSeal, aeadOpen, randomBytes, unb64, b64, utf8, unutf8 } from '../shared/crypto.js';

export function loadMasterKey(cfg) {
  if (cfg.masterKey) {
    const k = unb64(cfg.masterKey.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
    if (k.length !== 32) throw new Error('WORKSPACE_MASTER_KEY must be 32 bytes, base64 encoded');
    return k;
  }
  if (cfg.production) throw new Error('WORKSPACE_MASTER_KEY is required in production');
  // Development convenience only: a key file next to the database.
  const file = path.join(path.dirname(cfg.dbPath), 'dev-master.key');
  if (cfg.dbPath !== ':memory:' && fs.existsSync(file)) return unb64(fs.readFileSync(file, 'utf8').trim());
  const k = randomBytes(32);
  if (cfg.dbPath !== ':memory:') { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, b64(k), { mode: 0o600 }); }
  return k;
}

export function makeKms(masterKey) {
  const cache = new Map();
  const wrap = (dk) => { const b = aeadSeal(masterKey, dk, 'data-key'); return b.nonce + '.' + b.ciphertext; };
  const unwrap = (w) => { const [nonce, ciphertext] = w.split('.'); return aeadOpen(masterKey, { nonce, ciphertext }, 'data-key'); };
  return {
    newDataKey() { const dk = randomBytes(32); return { dk, wrapped: wrap(dk) }; },
    dataKey(workspaceId, wrapped) {
      let dk = cache.get(workspaceId);
      if (!dk) { dk = unwrap(wrapped); cache.set(workspaceId, dk); }
      return dk;
    },
    // The AAD binds each ciphertext to its column, so values cannot be swapped between fields.
    enc(dk, text, aad) {
      if (text == null || text === '') return null;
      const b = aeadSeal(dk, utf8(String(text)), aad);
      return 'v1.' + b.nonce + '.' + b.ciphertext;
    },
    dec(dk, s, aad) {
      if (!s) return '';
      const [, nonce, ciphertext] = s.split('.');
      return unutf8(aeadOpen(dk, { nonce, ciphertext }, aad));
    },
  };
}
