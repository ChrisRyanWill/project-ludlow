import { pathToFileURL } from 'node:url';
import { loadConfig, ConfigError } from './config.js';
import { openDb } from './db.js';
import { Router, createHttpServer } from './http.js';
import { makeLimiter } from './rate.js';
import { makeMailer } from './mail.js';
import { loadMasterKey, makeKms } from './kms.js';
import { campaignRoutes, sweepInactive } from './campaign.js';
import { workspaceRoutes } from './workspace.js';
import { logInfo } from './log.js';
import { ready } from '../shared/crypto.js';

export async function createApp(overrides = {}) {
  const cfg = loadConfig(process.env, overrides);
  await ready;
  const db = openDb(cfg.dbPath);
  const router = new Router();
  const mail = makeMailer(cfg);
  const kms = makeKms(loadMasterKey(cfg));
  campaignRoutes({ router, db, cfg, mail });
  workspaceRoutes({ router, db, cfg, kms });
  const server = createHttpServer({ router, cfg, limiter: makeLimiter({ disabled: cfg.rateLimitDisabled, strictMax: cfg.rateStrictPerMin }) });

  // Campaigns nobody has touched for CAMPAIGN_INACTIVITY_DAYS are hard-deleted: the safest data is none.
  const sweep = () => { const n = sweepInactive(db, cfg.inactivityDays); if (n) logInfo(`expired ${n} inactive campaign(s)`); };
  sweep();
  const timer = setInterval(sweep, 6 * 3600_000);
  timer.unref();

  return {
    cfg, db, router, mail, server, kms, sweep,
    listen: (port = cfg.port, host = cfg.host) => new Promise((resolve) => server.listen(port, host, () => resolve(server.address().port))),
    close: () => new Promise((resolve) => { clearInterval(timer); server.closeAllConnections?.(); server.close(() => { db.close(); resolve(); }); }),
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let app;
  try { app = await createApp(); } catch (e) {
    if (!(e instanceof ConfigError)) throw e;
    process.stderr.write(e.message + '\n'); // a setting to fix, not a bug: the message alone
    process.exit(1);
  }
  const port = await app.listen();
  logInfo(`${app.cfg.appName} is listening on port ${port}`);
}
