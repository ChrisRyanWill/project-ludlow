// Envelope encryption for workspace personal data (V2 rule 2). Each workspace has a random data key,
// wrapped by the master key (WORKSPACE_MASTER_KEY; later a cloud KMS). Personal fields are stored only
// as ciphertext, so a database dump alone does not reveal them. (Columns that are NOT encrypted, such as shift, location, membership status, who voted and who filed a case, are listed in docs/THREAT_MODEL.md.) End-to-end records (grievances) never use
// this: the server holds no key that opens them.
import fs from 'node:fs';
import path from 'node:path';
import { aeadSeal, aeadOpen, randomBytes, unb64, b64, utf8, unutf8 } from '../shared/crypto.js';
import { ConfigError } from './config.js';

const isLoopback = (host) => String(host).toLowerCase() === 'localhost' || host === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(String(host));

export function loadMasterKey(cfg) {
  if (cfg.masterKey) {
    const k = unb64(cfg.masterKey.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
    if (k.length !== 32) throw new ConfigError('WORKSPACE_MASTER_KEY must be 32 bytes, base64 encoded (generate one with: openssl rand -base64 32)');
    return k;
  }
  if (cfg.production) throw new ConfigError('WORKSPACE_MASTER_KEY is required in production (generate one with: openssl rand -base64 32, and keep it apart from the backups)');
  // Development convenience only: a key file next to the database. A server other machines can reach is not
  // development, and a key stored beside the data it protects protects nothing, so refuse rather than write one.
  const file = path.join(path.dirname(cfg.dbPath), 'dev-master.key');
  if (!isLoopback(cfg.host)) {
    throw new ConfigError(`WORKSPACE_MASTER_KEY is required when HOST (${cfg.host}) is reachable from other machines. ` +
      `If this database already holds data made in development, start with the key it was written with: WORKSPACE_MASTER_KEY="$(cat ${file})". ` +
      'For a new server, generate one: openssl rand -base64 32. See docs/DEPLOY.md.');
  }
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
    // The AAD binds each ciphertext to its column AND its row ('v2'), so a value cannot be moved to another field or to another person's
    // record: it would fail to decrypt instead of being shown as theirs. 'v1' values (column only) were written before; they are still read.
    enc(dk, text, aad, rowId) {
      if (text == null || text === '') return null;
      if (!rowId) throw new Error('kms.enc needs the row id');
      const b = aeadSeal(dk, utf8(String(text)), aad + '|' + rowId);
      return 'v2.' + b.nonce + '.' + b.ciphertext;
    },
    dec(dk, s, aad, rowId) {
      if (!s) return '';
      const [v, nonce, ciphertext] = s.split('.');
      if (v === 'v2') { if (!rowId) throw new Error('kms.dec needs the row id'); return unutf8(aeadOpen(dk, { nonce, ciphertext }, aad + '|' + rowId)); }
      if (v === 'v1') return unutf8(aeadOpen(dk, { nonce, ciphertext }, aad));
      throw new Error('unknown format');
    },
  };
}
