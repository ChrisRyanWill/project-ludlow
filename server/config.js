import path from 'node:path';
import { fileURLToPath } from 'node:url';

// A setting the operator must fix. The server prints the message alone, without a stack trace.
export class ConfigError extends Error { constructor(msg) { super(msg); this.name = 'ConfigError'; } }

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// A typo here silently changes whose address the rate limits count, so anything but a whole number stops the server.
function trustProxy(v) {
  if (v == null || v === '') return 0;
  if (!/^\d{1,2}$/.test(String(v).trim())) throw new ConfigError(`TRUST_PROXY must be the number of reverse proxies in front of the server (0, 1, 2...), not "${String(v).slice(0, 20)}"`);
  return Number(v);
}

export function loadConfig(env = process.env, overrides = {}) {
  const port = Number(env.PORT) || 8787;
  return {
    root,
    port,
    host: env.HOST || '127.0.0.1',
    production: env.NODE_ENV === 'production',
    appName: env.APP_NAME || 'Project Ludlow',
    baseUrl: env.APP_BASE_URL || `http://localhost:${port}`,
    dbPath: env.DATABASE_PATH || path.join(root, 'data', 'ludlow.db'),
    staticDir: path.join(root, 'web', 'dist'),
    emailProvider: env.EMAIL_PROVIDER || 'dev', // dev = in-memory outbox (never persisted); postmark = real
    postmarkToken: env.POSTMARK_SERVER_TOKEN || '',
    emailFrom: env.EMAIL_FROM || 'noreply@localhost',
    replyTo: env.CONFIRMATION_REPLY_TO || '',
    inactivityDays: Number(env.CAMPAIGN_INACTIVITY_DAYS) || 180,
    groupTtlHours: Number(env.GROUP_INVITE_TTL_HOURS) || 72,
    directTtlDays: Number(env.DIRECT_INVITE_TTL_DAYS) || 7,
    masterKey: env.WORKSPACE_MASTER_KEY || '',
    onlineOfficerElections: env.ONLINE_OFFICER_ELECTIONS === 'true',
    // The shortest a vote may stay open. Members need real time to see it; a few seconds would let it close unseen (0 turns the rule off, for tests).
    minVoteHours: env.MIN_VOTE_HOURS != null && env.MIN_VOTE_HOURS !== '' && Number.isFinite(Number(env.MIN_VOTE_HOURS)) ? Math.max(0, Number(env.MIN_VOTE_HOURS)) : 24,
    sessionIdleHours: Number(env.SESSION_IDLE_HOURS) || 12,
    sessionMaxDays: Number(env.SESSION_MAX_DAYS) || 30,
    trustProxy: trustProxy(env.TRUST_PROXY), // how many reverse proxies sit in front (1 for Caddy or nginx)
    confirmationsPerCampaignPerDay: Number(env.CONFIRMATIONS_PER_CAMPAIGN_PER_DAY) || 2000, // caps how much mail a single campaign can make this server send
    rateLimitDisabled: env.RATE_LIMIT_DISABLED === '1',
    rateStrictPerMin: Number(env.RATE_STRICT_PER_MIN) || 90, // sensitive routes per client per minute; 3 calls per signer, and groups often share one Wi-Fi
    ...overrides,
  };
}
