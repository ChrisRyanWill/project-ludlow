// Smoke-tests the DEPLOYED project page in real Chromium: policy violations (CSP, console errors), requests to
// anywhere but the site, broken images, horizontal scroll on phones, and the "Try the lock" demo flow. It then
// saves screenshots. Use it after a change to `main` has been deployed by the `Project site` workflow.
//
// Kept from the local session's scratch space for the handoff. Changes from that copy: paths are portable
// (playwright-core is found from the directory you run this in; screenshots go to $SHOTS or the OS temp dir;
// $CHROME_PATH is honored) and $LIVE_URL can point it elsewhere.
//
// Run from the repository root, after `npm ci` and with a Chromium installed (`npx playwright-core install chromium`):
//   node handoff/tools/live-check.mjs
//
// The demo assertions below match the demo wording on `main` and on the review branches (checked 2026-09-30).
// If the wording of the "Try the lock" demo (site/src/try.js) changes, update the regular expressions to match.
// Exit code is 0 when every check passes, 1 otherwise.
import { createRequire } from 'node:module';
import { existsSync, readdirSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import path from 'node:path';
const require = createRequire(path.join(process.cwd(), 'package.json'));
const { chromium } = require('playwright-core');

const LIVE = process.env.LIVE_URL || 'https://chrisryanwill.github.io/project-ludlow/';
const SHOTS = process.env.SHOTS || tmpdir();
let exe = process.env.CHROME_PATH && existsSync(process.env.CHROME_PATH) ? process.env.CHROME_PATH : null;
const base = path.join(homedir(), '.cache/ms-playwright');
if (!exe && existsSync(base)) for (const d of readdirSync(base).filter((x) => x.startsWith('chromium-'))) for (const sub of ['chrome-linux64/chrome', 'chrome-linux/chrome']) if (existsSync(path.join(base, d, sub))) exe = path.join(base, d, sub);
if (!exe) { console.error('No Chromium found. Set CHROME_PATH, or run: npx playwright-core install chromium'); process.exit(2); }
const browser = await chromium.launch({ executablePath: exe, headless: true, args: ['--no-sandbox'] });
const problems = []; const checks = [];
const ok = (name, cond, extra = '') => { checks.push(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`); if (!cond) problems.push(name); };

async function run(label, viewport, colorScheme) {
  const ctx = await browser.newContext({ viewport, colorScheme });
  const page = await ctx.newPage();
  const outside = [];
  page.on('pageerror', (e) => problems.push(`[${label}] pageerror: ${e.message}`));
  page.on('console', (m) => { if (/content security policy|refused to|failed to load/i.test(m.text())) problems.push(`[${label}] console: ${m.text()}`); });
  page.on('request', (r) => { const u = r.url(); if (!u.startsWith(LIVE) && !u.startsWith('data:')) outside.push(u); });
  await page.goto(LIVE, { waitUntil: 'load' });
  await page.getByRole('heading', { level: 1, name: /A union nobody can silence/ }).waitFor({ timeout: 20000 });
  await page.locator('img').evaluateAll((imgs) => Promise.all(imgs.map((i) => { i.loading = 'eager'; return i.complete ? 0 : new Promise((r) => { i.onload = i.onerror = r; }); })));
  const broken = await page.locator('img').evaluateAll((imgs) => imgs.filter((i) => i.naturalWidth === 0).map((i) => i.getAttribute('src')));
  ok(`[${label}] all screenshots load`, broken.length === 0, broken.join(','));
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  ok(`[${label}] no horizontal page scroll`, overflow <= 0, `overflow=${overflow}px`);
  await page.screenshot({ path: path.join(SHOTS, `live-${label}.png`), fullPage: false });
  if (label === 'mobile-light') {
    await page.getByRole('button', { name: 'Start the demo' }).click();
    await page.getByRole('button', { name: 'Seal the card' }).click();
    await page.getByText('What the server holds.').waitFor({ timeout: 30000 });
    const ask = () => page.getByRole('button', { name: /Ask the server/ }).click();
    const result = () => page.locator('.result').innerText();
    await ask(); ok('[demo] locked below the release number', /server refused to hand over the sealed card: 37 of the 51/.test(await result()));
    await page.locator('input[type=range]').fill('60');
    await ask(); ok('[demo] enough signatures but too few trustees cannot open it', /2 trustees cannot rebuild the key: 3 are needed/.test(await result()));
    await page.locator('label.chip', { hasText: 'Cy' }).click();
    await ask(); ok('[demo] three trustees open it', /Opened: "Alex Rivera, alex@example.org, 555-0100"\. 3 trustees together were enough/.test(await result()));
    await page.locator('label.chip', { hasText: 'Tamper' }).click();
    await ask(); ok('[demo] tampering is detected', /changed after it was sealed/.test(await result()));
    await page.locator('#try').scrollIntoViewIfNeeded();
    await page.screenshot({ path: path.join(SHOTS, 'live-demo.png') });
  }
  ok(`[${label}] no requests outside the site`, outside.length === 0, outside.join(' '));
  await ctx.close();
}
await run('mobile-light', { width: 375, height: 812 }, 'light');
await run('desktop-light', { width: 1280, height: 900 }, 'light');
await run('mobile-dark', { width: 375, height: 812 }, 'dark');
await browser.close();
console.log(checks.join('\n'));
console.log(problems.length ? `\n${problems.length} PROBLEM(S):\n${problems.join('\n')}` : '\nALL LIVE CHECKS PASSED');
console.log(`screenshots: ${SHOTS}`);
process.exit(problems.length ? 1 : 0);
