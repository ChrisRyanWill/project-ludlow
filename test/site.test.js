// The public project page: it builds, loads under its strict CSP with no outside requests, and the
// "Try the lock" demo really behaves the way the page says it does (using the app's real cryptography).
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { homedir } from 'node:os';
import path from 'node:path';
import { chromium } from 'playwright-core';

const root = path.resolve(import.meta.dirname, '..');
const dist = path.join(root, 'site-dist');
const findChrome = () => {
  if (process.env.CHROME_PATH && existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  const base = path.join(homedir(), '.cache/ms-playwright');
  if (!existsSync(base)) return null;
  for (const d of readdirSync(base).filter((x) => x.startsWith('chromium-'))) for (const sub of ['chrome-linux64/chrome', 'chrome-linux/chrome']) if (existsSync(path.join(base, d, sub))) return path.join(base, d, sub);
  return null;
};
const CHROME = findChrome();
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png' };

describe('project site (GitHub Pages)', { skip: CHROME ? false : 'no Chromium found (set CHROME_PATH)' }, () => {
  let server, base, browser;
  const problems = [];
  before(async () => {
    execFileSync('node', ['scripts/build-site.js'], { cwd: root });
    server = http.createServer((req, res) => {
      const p = new URL(req.url, 'http://x').pathname;
      const file = path.join(dist, p === '/' ? 'index.html' : p);
      if (!file.startsWith(dist) || !existsSync(file)) { res.statusCode = 404; return res.end('nope'); }
      res.setHeader('Content-Type', TYPES[path.extname(file)] || 'application/octet-stream');
      res.end(readFileSync(file));
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${server.address().port}`;
    browser = await chromium.launch({ executablePath: CHROME, headless: true, args: ['--no-sandbox'] });
  });
  after(async () => { await browser?.close(); server?.close(); });

  it('loads under its content policy, tracks no one, and every image and link target exists', async () => {
    const page = await (await browser.newContext({ viewport: { width: 375, height: 812 }, baseURL: base })).newPage();
    page.on('pageerror', (e) => problems.push(e.message));
    page.on('console', (m) => { if (/content security policy|refused to/i.test(m.text())) problems.push(m.text()); });
    page.on('request', (r) => { if (!r.url().startsWith(base) && !r.url().startsWith('data:')) problems.push('outside request: ' + r.url()); });
    await page.goto('/');
    await page.getByRole('heading', { level: 1, name: /A union nobody can silence/ }).waitFor();
    // lazy images below the fold never load until scrolled to, so force them to load before checking they exist
    await page.locator('img').evaluateAll((imgs) => Promise.all(imgs.map((i) => { i.loading = 'eager'; return i.complete ? 0 : new Promise((r) => { i.onload = i.onerror = r; }); })));
    const broken = await page.locator('img').evaluateAll((imgs) => imgs.filter((i) => i.naturalWidth === 0).map((i) => i.getAttribute('src')));
    assert.deepEqual(broken, []);
    assert.equal(await page.locator('a[href="#try"]').count() > 0, true);
    assert.match(await page.locator('.status').innerText(), /Early prototype/); // the honest status is the first thing you see
    assert.deepEqual(problems, []);
  });

  it('the "Try the lock" demo behaves as promised: k of n opens, fewer does not, the release number and tampering are enforced', async () => {
    const page = await (await browser.newContext({ viewport: { width: 375, height: 812 }, baseURL: base })).newPage();
    page.on('pageerror', (e) => problems.push(e.message));
    page.on('request', (r) => { if (!r.url().startsWith(base) && !r.url().startsWith('data:')) problems.push('outside request: ' + r.url()); });
    await page.goto('/');
    await page.getByRole('button', { name: 'Start the demo' }).click();
    await page.getByRole('button', { name: 'Seal the card' }).click();
    await page.getByText('What the server holds.').waitFor();
    const ask = () => page.getByRole('button', { name: /Ask the server/ }).click();
    const result = () => page.locator('.result');
    await ask(); // 37 of the 51 needed
    assert.match(await result().innerText(), /The server refused to hand over the sealed card: 37 of the 51/);
    await page.locator('input[type=range]').fill('60');
    await ask(); // enough signatures, but only two trustees
    assert.match(await result().innerText(), /Could not open it\. 2 trustees cannot rebuild the key: 3 are needed/);
    await page.locator('label.chip', { hasText: 'Cy' }).click(); // a third trustee
    await ask();
    assert.match(await result().innerText(), /Opened: "Alex Rivera, alex@example.org, 555-0100"\. 3 trustees together were enough/);
    await page.locator('label.chip', { hasText: 'Tamper' }).click();
    await ask();
    assert.match(await result().innerText(), /changed after it was sealed/);
    assert.deepEqual(problems, []);
  });
});
