import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

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
    sessionIdleHours: Number(env.SESSION_IDLE_HOURS) || 12,
    sessionMaxDays: Number(env.SESSION_MAX_DAYS) || 30,
    trustProxy: env.TRUST_PROXY === '1',
    rateLimitDisabled: env.RATE_LIMIT_DISABLED === '1',
    rateStrictPerMin: Number(env.RATE_STRICT_PER_MIN) || 90, // sensitive routes per client per minute; 3 calls per signer, and groups often share one Wi-Fi
    ...overrides,
  };
}
