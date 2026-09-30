// Minimal HTTP layer: router, JSON bodies, security headers on every response (rules 12–13),
// static file serving with SPA fallback, and allowlist logging. No framework, no cookies.
import http from 'node:http';
import path from 'node:path';
import { readFile, stat } from 'node:fs/promises';
import { gzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { logRequest, logError } from './log.js';

export class HttpError extends Error {
  constructor(status, code, extra) { super(code); this.status = status; this.code = code; this.extra = extra; }
}
export const fail = (status, code, extra) => { throw new HttpError(status, code, extra); };

export class Router {
  routes = [];
  add(method, pattern, opts, handler) {
    const keys = [];
    const re = new RegExp('^' + pattern.replace(/:([A-Za-z]+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '$');
    this.routes.push({ method, pattern, re, keys, opts: opts || {}, handler });
  }
  match(method, pathname) {
    for (const r of this.routes) {
      if (r.method !== method) continue;
      const m = r.re.exec(pathname);
      if (!m) continue;
      const params = {};
      try { r.keys.forEach((k, i) => (params[k] = decodeURIComponent(m[i + 1]))); } catch { return null; }
      return { route: r, params };
    }
    return null;
  }
}

// 'wasm-unsafe-eval' only lets the browser compile libsodium's WebAssembly; it does NOT allow JS eval.
export const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  'Referrer-Policy': 'no-referrer',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'X-Content-Type-Options': 'nosniff',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cache-Control': 'no-store',
};

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8', '.md': 'text/markdown; charset=utf-8', '.webmanifest': 'application/manifest+json',
};

export function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Length', Buffer.byteLength(body));
  res.end(body);
}

async function readJson(req, limit) {
  const chunks = [];
  let n = 0;
  for await (const c of req) { n += c.length; if (n > limit) fail(413, 'too_large'); chunks.push(c); }
  if (!n) return { v: {}, raw: '' };
  const raw = Buffer.concat(chunks).toString('utf8');
  let v;
  try { v = JSON.parse(raw); } catch { fail(400, 'bad_json'); }
  if (v === null || typeof v !== 'object' || Array.isArray(v)) fail(400, 'bad_json');
  return { v, raw }; // the exact text too: a trustee's signature covers it
}

const staticCache = new Map();
async function loadStatic(file, st) {
  const hit = staticCache.get(file);
  if (hit && hit.mtimeMs === st.mtimeMs) return hit;
  const buf = await readFile(file);
  const entry = { mtimeMs: st.mtimeMs, buf, gz: gzipSync(buf), etag: '"' + createHash('sha256').update(buf).digest('base64url').slice(0, 20) + '"' };
  staticCache.set(file, entry);
  return entry;
}

async function serveStatic(req, res, url, dir) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { error: 'method_not_allowed' });
  let p;
  try { p = decodeURIComponent(url.pathname); } catch { return send(res, 400, { error: 'bad_request' }); }
  if (p.includes('\0')) return send(res, 400, { error: 'bad_request' });
  const root = path.resolve(dir);
  let file = path.join(root, path.normalize(p));
  if (file !== root && !file.startsWith(root + path.sep)) return send(res, 403, { error: 'forbidden' });
  let st = await stat(file).catch(() => null);
  if (!st || st.isDirectory()) {
    if (path.extname(p)) return send(res, 404, { error: 'not_found' });
    file = path.join(root, 'index.html'); // single-page app: unknown paths get the app shell
    st = await stat(file).catch(() => null);
    if (!st) return send(res, 404, { error: 'not_built' });
  }
  const entry = await loadStatic(file, st);
  res.setHeader('Content-Type', MIME[path.extname(file)] || 'application/octet-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('ETag', entry.etag);
  res.setHeader('Vary', 'Accept-Encoding');
  if (req.headers['if-none-match'] === entry.etag) { res.statusCode = 304; return res.end(); }
  const gz = /\bgzip\b/.test(req.headers['accept-encoding'] || '') && entry.gz.length < entry.buf.length;
  const body = gz ? entry.gz : entry.buf;
  if (gz) res.setHeader('Content-Encoding', 'gzip');
  res.setHeader('Content-Length', body.length);
  res.statusCode = 200;
  return res.end(req.method === 'HEAD' ? undefined : body);
}

// Behind N trusted proxies, each one APPENDS the address it saw, so whatever a client writes into X-Forwarded-For itself sits at the front and cannot be
// trusted. Count from the end: with one proxy the last entry is the real client. Fewer entries than proxies means the header was not set by them.
export function clientIp(req, cfg) {
  const hops = cfg.trustProxy === true ? 1 : Number(cfg.trustProxy) || 0;
  if (hops > 0) {
    const parts = String(req.headers['x-forwarded-for'] || '').split(',').map((x) => x.trim()).filter(Boolean);
    const fwd = parts[parts.length - hops]; // no vendor headers (Fly-Client-IP and the like): behind any other proxy they are whatever the client wrote
    if (fwd) return fwd;
  }
  return req.socket.remoteAddress || 'unknown';
}

export function createHttpServer({ router, cfg, limiter }) {
  return http.createServer(async (req, res) => {
    const t0 = performance.now();
    let route = 'static';
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
    try {
      let url;
      try { url = new URL(req.url, 'http://localhost'); } catch { route = '(bad-url)'; return send(res, 400, { error: 'bad_request' }); }
      if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/dev/')) {
        const m = router.match(req.method, url.pathname);
        if (!m) { route = '(unmatched)'; return send(res, 404, { error: 'not_found' }); }
        route = m.route.pattern; // the pattern, never the raw path (which may contain ids)
        if (!limiter(clientIp(req, cfg), m.route.opts.strict)) return send(res, 429, { error: 'rate_limited' });
        const { v: body, raw: rawBody } = req.method === 'GET' || req.method === 'HEAD' ? { v: {}, raw: '' } : await readJson(req, m.route.opts.maxBody || 1_000_000);
        const out = await m.route.handler({ req, params: m.params, body, rawBody, query: Object.fromEntries(url.searchParams), headers: req.headers });
        return send(res, 200, out ?? {});
      }
      return await serveStatic(req, res, url, cfg.staticDir);
    } catch (e) {
      if (e instanceof HttpError) {
        if (e.status === 413) res.setHeader('Connection', 'close'); // an unread oversized body must not poison a reused connection
        return send(res, e.status, { error: e.code, ...(e.extra || {}) });
      }
      logError({ route, kind: e?.code || e?.name || 'error' });
      return send(res, 500, { error: 'server_error' });
    } finally {
      logRequest({ method: req.method, route, status: res.statusCode, ms: Math.round(performance.now() - t0) });
    }
  });
}
