// Real browser, real CSP, real crypto: the whole product driven the way people would use it.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright-core';
import { existsSync, mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { tmpdir, homedir } from 'node:os';
import path from 'node:path';
import * as C from '../shared/crypto.js';
import { startApp, makeCampaign, makeInvite } from './helpers.js';

const root = path.resolve(import.meta.dirname, '..');
const findChrome = () => {
  if (process.env.CHROME_PATH && existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  const base = path.join(homedir(), '.cache/ms-playwright');
  if (!existsSync(base)) return null;
  for (const d of readdirSync(base).filter((x) => x.startsWith('chromium-'))) {
    for (const sub of ['chrome-linux64/chrome', 'chrome-linux/chrome']) if (existsSync(path.join(base, d, sub))) return path.join(base, d, sub);
  }
  return null;
};
const CHROME = findChrome();
const SHOTS = process.env.SHOTS; // set to a folder to save screenshots of key screens
const shot = async (page, name) => {
  if (!SHOTS) return;
  await page.evaluate(() => document.querySelector('.toast')?.remove()); // a stray toast must not end up in a screenshot
  await page.screenshot({ path: path.join(SHOTS, name + '.png'), fullPage: true });
};

describe('browser: organize, open the cards, then run the union', { skip: CHROME ? false : 'no Chromium found (set CHROME_PATH)' }, () => {
  let h, browser, tmp;
  const problems = [];
  const trustee = {}; // index -> { keyFile, pass }
  const account = {}; // name -> { keyFile, pass }
  const pages = {};
  let links = {};

  before(async () => {
    execFileSync('node', ['scripts/build.js'], { cwd: root });
    h = await startApp();
    tmp = mkdtempSync(path.join(tmpdir(), 'ludlow-e2e-'));
    browser = await chromium.launch({ executablePath: CHROME, headless: true, args: ['--no-sandbox'] });
  });
  after(async () => { await browser?.close(); await h?.stop(); });

  async function newPage(name) {
    const ctx = await browser.newContext({ viewport: { width: 375, height: 812 }, acceptDownloads: true, baseURL: h.base, colorScheme: process.env.SCHEME === 'dark' ? 'dark' : 'light' });
    const page = await ctx.newPage();
    page.setDefaultTimeout(90_000); // key derivation (256 MB Argon2) is slow on a busy or shared machine
    page.on('dialog', (d) => d.accept());
    page.on('request', (r) => {
      const u = new URL(r.url());
      if (!['data:', 'blob:'].includes(u.protocol) && u.origin !== h.base && u.hostname !== 'www.wikipedia.org') problems.push(`${name}: third-party request ${r.url()}`);
    });
    page.on('pageerror', (e) => problems.push(`${name}: ${e.message}`));
    page.on('console', (m) => { if (/content security policy|refused to/i.test(m.text())) problems.push(`${name}: CSP ${m.text()}`); });
    pages[name] = page;
    return page;
  }
  const btn = (page, name) => page.getByRole('button', { name, exact: false });
  const saveDownload = async (page, click, file) => {
    const [dl] = await Promise.all([page.waitForEvent('download'), click()]);
    const dest = path.join(tmp, file);
    await dl.saveAs(dest);
    return dest;
  };
  const nextStep = (page) => btn(page, /^Next$/).click();

  async function enroll(page, link, index) {
    await page.goto(link);
    await page.locator('.passphrase').waitFor();
    assert.equal(await page.evaluate(() => location.hash), ''); // the link's secrets are not left in the address bar or the history
    const pass = (await page.locator('.passphrase').innerText()).trim();
    const keyFile = await saveDownload(page, () => btn(page, 'Create my key file').click(), `trustee-${index}.json`);
    await shot(page, '03-trustee-enroll-' + index);
    await page.locator('.check input').check();
    await btn(page, 'Finish enrollment').click();
    await page.getByRole('heading', { name: 'You are enrolled' }).waitFor();
    const words = (await page.locator('.keywords').first().innerText()).trim(); // what this trustee reads aloud to the founder
    assert.equal(words.split('-').length, 10);
    trustee[index] = { keyFile, pass, words };
  }
  async function unlockDashboard(page, index) {
    await page.goto('/t/dashboard');
    await page.locator('input[type=file]').setInputFiles(trustee[index].keyFile);
    await page.locator('input[type=password]').fill(trustee[index].pass);
    await btn(page, /^Unlock$/).click();
    await page.getByRole('heading', { name: 'Riverside Workers United' }).waitFor();
    await shot(page, '06-trustee-dashboard');
  }
  async function sign
    (page, link, who) {
    await page.goto(link);
    await btn(page, 'Read the card').click();
    assert.equal(await page.evaluate(() => location.hash), ''); // the invitation's secrets are not left in the address bar or the history
    await page.getByLabel('Full legal name').fill(who.name);
    await page.getByLabel('Personal email').fill(who.email);
    await page.getByLabel('Mobile phone').fill(who.phone);
    await page.getByLabel('Type your full name to sign').fill(who.name);
    await page.locator('.check input').check();
    if (who.shot) await shot(page, who.shot);
    await btn(page, 'Sign the card').click();
    await page.getByRole('heading', { name: /Your card is signed and counted|Almost done/ }).waitFor();
    if (who.shot) await shot(page, who.shot + '-done');
    const memberLink = (await page.locator('.link-box').innerText()).trim();
    const vouch = (await page.locator('.code').count()) ? (await page.locator('.code').first().innerText()).trim() : null;
    return { memberLink, vouch };
  }

  it('the home page loads under the strict CSP, and quick exit really leaves', async () => {
    const page = await newPage('visitor');
    await page.goto('/');
    await page.getByRole('heading', { name: /Start a union at your workplace/ }).waitFor();
    await shot(page, '01-home');
    assert.match(await page.title(), /Project Ludlow/);
    await page.route('https://www.wikipedia.org/**', (r) => r.fulfill({ status: 200, contentType: 'text/html', body: 'neutral page' }));
    await btn(page, 'Quick exit').click();
    await page.waitForURL(/wikipedia\.org/);
    await page.goto('/');
    for (let i = 0; i < 3; i++) await page.keyboard.press('Escape'); // three Escapes also leave
    await page.waitForURL(/wikipedia\.org/);
    assert.deepEqual(problems, []);
  });

  it('one person creates a campaign with a release lock, makes a key, and it is live at once', async () => {
    const page = await newPage('trustees');
    await page.goto('/start');
    await nextStep(page); // where: United States
    await page.getByLabel('Union name').fill('Riverside Workers United'); await nextStep(page);
    await page.getByLabel('Employer\'s legal name').fill('Riverside Coffee LLC'); await nextStep(page);
    await page.getByLabel('Who is included?').fill('All baristas and shift leads at the Main Street store'); await nextStep(page);
    await page.getByLabel('Number of coworkers').fill('10'); await nextStep(page);
    await page.getByText('3 people', { exact: true }).click(); await nextStep(page); // the lock: no one can open the cards until 3 people have signed
    await page.getByLabel('Your first name or nickname').fill('Alice');
    await page.getByLabel('Trustee 2: first name or nickname').fill('Bob');
    await page.getByLabel('Trustee 3: first name or nickname').fill('Dan'); await nextStep(page);
    await page.getByText('I, the undersigned employee of Riverside Coffee LLC').waitFor();
    await btn(page, 'Create my campaign').click();
    await page.getByRole('heading', { name: 'Your campaign is ready' }).waitFor();
    await shot(page, '02-campaign-ready');
    const l1 = await page.getByRole('link', { name: 'Set up my key' }).getAttribute('href');
    assert.match(l1, /\/t#e=.+&k=.+&c=.+/);
    assert.equal(h.app.db.prepare('SELECT release_min r FROM campaigns').get().r, 3);
    await enroll(page, l1, 1); // only the founder: nobody else has to be recruited before people can sign
    assert.match(await page.locator('body').innerText(), /1 of 3 trustees have set up their keys/);
    assert.match(await page.locator('body').innerText(), /You can start inviting coworkers now/);
    assert.equal(h.app.db.prepare('SELECT status s FROM campaigns').get().s, 'active');
    assert.deepEqual(problems, []);
  });

  let direct, group, memberLinkA, vouchB, vouchC;
  it('a trustee invites coworkers; people sign cards on their own phones and get a confirmation email', async () => {
    const page = pages.trustees;
    await unlockDashboard(page, 1);
    await btn(page, 'Invite one person').click();
    await page.locator('.invite-box .link-box').first().waitFor();
    direct = (await page.locator('.invite-box .link-box').first().innerText()).trim();
    await btn(page, 'Create a group link').click();
    await page.locator('.invite-box .link-box').nth(1).waitFor();
    group = (await page.locator('.invite-box .link-box').first().innerText()).trim();
    assert.match(direct, /\/j#i=/); assert.match(group, /\/j#i=/);
    await btn(page, 'Show QR code').first().click(); // in-person handover with no message trail
    await page.locator('img.qr').first().waitFor();
    assert.ok(await page.locator('img.qr').first().evaluate((i) => i.complete && i.naturalWidth > 40));
    await btn(page, 'Hide QR code').first().click();

    const A = await sign(await newPage('alice-phone'), direct, { name: 'Alice Anderson', email: 'alice.anderson@example.org', phone: '(555) 010-0001', shot: '04-sign-card' });
    memberLinkA = A.memberLink;
    assert.equal(A.vouch, null); // a direct invite counts at once
    assert.deepEqual(h.app.db.prepare('SELECT DISTINCT seal_mode m FROM cards').all().map((r) => r.m), ['solo']); // sealed to the founder alone until the committee exists
    const B = await sign(await newPage('bob-phone'), group, { name: 'Bob Baker', email: 'bob.baker@example.org', phone: '555-010-0002' });
    const C2 = await sign(await newPage('cara-phone'), group, { name: 'Cara Cruz', email: 'cara.cruz@example.org', phone: '555-010-0003' });
    assert.match(B.vouch, /^[A-Z]+-[A-Z]+$/); vouchB = B.vouch; vouchC = C2.vouch;

    const mail = h.app.mail.outbox;
    assert.equal(mail.length, 3);
    const a = mail.find((m) => m.to === 'alice.anderson@example.org');
    for (const s of ['Alice Anderson', 'alice.anderson@example.org', '+15550100001', 'Riverside Coffee LLC', 'Riverside Workers United', 'I, the undersigned employee', '/d#t=']) assert.ok(a.text.includes(s), 'confirmation lacks ' + s);
    assert.deepEqual(problems, []);
  });

  it('pending cards are confirmed in person by a trustee; a member invites a coworker from their own page', async () => {
    const page = pages.trustees;
    await unlockDashboard(page, 1);
    await page.getByRole('heading', { name: 'Cards waiting to be confirmed' }).waitFor();
    const rows = page.locator('.vouch');
    assert.equal(await rows.count(), 2);
    await rows.nth(0).locator('input').fill('WRONG-CODE');
    await rows.nth(0).getByRole('button', { name: 'Confirm' }).click();
    await page.getByText(/That code is not right/).waitFor();
    await rows.nth(0).locator('input').fill(vouchB.toLowerCase());
    await rows.nth(0).getByRole('button', { name: 'Confirm' }).click();
    await page.getByText('Confirmed.', { exact: true }).waitFor(); // exact: other copy on the page also mentions confirmation
    await page.waitForFunction(() => document.querySelectorAll('.vouch').length === 1);
    // the lock is enforced: only 2 of the 3 people needed are confirmed, so even the founder is handed nothing to open
    await page.goto('/t/unlock');
    await btn(page, 'Begin').click();
    await page.locator('input[type=file]').setInputFiles(trustee[1].keyFile);
    await page.locator('input[type=password]').fill(trustee[1].pass);
    await btn(page, 'Contribute my key').click();
    await page.getByText('The cards are still locked.').waitFor();
    assert.match(await page.locator('body').innerText(), /2 of the 3 people needed/);
    assert.equal(await page.locator('input[type=file]').count(), 0); // there is nothing to load or open

    const alice = pages['alice-phone'];
    await alice.goto('/m');
    await alice.getByRole('heading', { name: 'Riverside Workers United' }).waitFor();
    assert.match(await alice.locator('.progress-cap').innerText(), /2\s+of about 10/); // Alice and Bob now count
    await btn(alice, 'Invite one person').click();
    const dLink = (await alice.locator('.invite-box .link-box').first().innerText()).trim();
    await sign(await newPage('dan-phone'), dLink, { name: 'Dan Diaz', email: 'dan.diaz@example.org', phone: '555-010-0004' });
    await alice.reload();
    await alice.getByRole('heading', { name: 'Riverside Workers United' }).waitFor();
    assert.match(await alice.locator('.progress-cap').innerText(), /3\s+of about 10/);
    await shot(alice, '05-member-progress');
    // a pending signer sees only the waiting screen, never the count
    const cara = pages['cara-phone'];
    await cara.goto('/m');
    await cara.getByText('waiting to be confirmed by the coworker who invited you').waitFor();
    assert.doesNotMatch(await cara.locator('body').innerText(), /of about 10/);
  });

  it('a signer keeps a private record, shares one entry with the committee, and the trustees read it', async () => {
    const alice = pages['alice-phone'];
    await alice.goto('/m');
    await alice.getByRole('heading', { name: 'My private record' }).waitFor();
    await btn(alice, 'Add something that happened').click();
    await alice.getByLabel('What was said or done?').fill('The shift manager asked me who else had signed a card.');
    await btn(alice, 'Save privately').click();
    await alice.getByText('The shift manager asked me who else had signed').waitFor();
    await alice.getByText(/Time limit to file a charge: about \d+ days left/).waitFor();
    await btn(alice, 'Share with the committee').click();
    await btn(alice, 'Share with the committee').last().click();
    await alice.getByText('Shared with the committee.').waitFor();
    assert.deepEqual(h.leaks(['who else had signed a card']), []); // the server never saw the words

    const page = pages.trustees;
    await unlockDashboard(page, 1); // only the founder has joined so far, so the report was sealed to the founder
    await btn(page, /Read 1 report/).click();
    await page.getByText('who else had signed a card').waitFor();
  });

  it('a website that lies about the founder\'s key cannot make a phone seal a card, or a report, to keys of its own (founder-only phase)', async () => {
    const link = await freshInvite();
    assert.match(link, /&f=[A-Za-z0-9_-]{22}$/);
    const before = h.app.db.prepare('SELECT COUNT(*) c FROM cards').get().c, reports = h.app.db.prepare('SELECT COUNT(*) c FROM reports').get().c;
    await refused(swapTrusteeKey(1, 'box_public_key'), link, /do not match your invitation/); // the encryption key it hands out
    await refused(swapTrusteeKey(1, 'sign_public_key'), link, /do not match your invitation/); // the signing key that will vouch for the committee later
    // a report from a member's own phone, sealed for the committee, is refused the same way
    const alice = pages['alice-phone'];
    const undo = swapTrusteeKey(1, 'box_public_key')();
    try {
      await alice.goto('/m');
      await alice.getByRole('heading', { name: 'My private record' }).waitFor();
      await btn(alice, 'Add something that happened').click();
      await alice.getByLabel('What was said or done?').fill('Second incident: they moved my shifts after the meeting.');
      await btn(alice, 'Save privately').click();
      const entry = alice.locator('.entry', { hasText: 'Second incident' });
      await entry.getByRole('button', { name: 'Share with the committee' }).click();
      await entry.getByRole('button', { name: 'Share with the committee' }).last().click();
      await alice.getByText(/do not match your invitation/).waitFor();
      assert.equal(h.app.db.prepare('SELECT COUNT(*) c FROM reports').get().c, reports); // nothing was shared
    } finally { undo(); }
    assert.equal(h.app.db.prepare('SELECT COUNT(*) c FROM cards').get().c, before); // and no card was made
    assert.deepEqual(h.app.db.prepare('SELECT DISTINCT seal_mode m FROM cards').all().map((r) => r.m), ['solo']);
  });

  it('the other trustees join later, and the founder locks the early cards to the committee', async () => {
    const page = pages.trustees;
    // Someone opens the signing page while cards are still sealed to the founder alone, and is still filling it in when the committee is confirmed.
    const lateLink = await freshInvite();
    const late = await newPage('late-signer');
    const cardPosts = [];
    late.on('response', (r) => { if (r.request().method() === 'POST' && /\/api\/cards$/.test(r.url())) cardPosts.push(r.status()); });
    await late.goto(lateLink);
    await btn(late, 'Read the card').click();
    for (const [label, value] of [['Full legal name', 'Lena Late'], ['Personal email', 'lena@example.org'], ['Mobile phone', '+15555550177'], ['Type your full name to sign', 'Lena Late']]) await late.getByLabel(label).fill(value);
    await late.locator('.check input').check();
    await unlockDashboard(page, 1);
    await page.getByRole('heading', { name: 'Your committee' }).waitFor();
    assert.match(await page.locator('body').innerText(), /Only trustee 1 can open the cards right now/);
    await shot(page, '06b-committee');
    for (const idx of [2, 3]) {
      await btn(page, 'Get invite link').first().click();
      await page.locator('.invite-box .link-box').first().waitFor();
      const link = (await page.locator('.invite-box .link-box').first().innerText()).trim();
      assert.match(link, /\/t#e=.+&k=.+&c=.+&f=[A-Za-z0-9_-]{22}$/); // the invitation carries a check of the founder's key
      await enroll(page, link, idx);
      if (idx === 2) { // a trustee who is not the founder cannot hand out the seat that is still empty
        await unlockDashboard(page, 2);
        await page.getByRole('heading', { name: 'Your committee' }).waitFor();
        await page.getByText('Trustee 1 sends this invitation.').waitFor();
        assert.equal(await btn(page, 'Get invite link').count(), 0);
      }
      await unlockDashboard(page, 1);
    }
    await page.getByText(/Everyone has joined. Now confirm the committee/).waitFor();
    // Confirming stays off until the founder has checked each trustee's key words with them. The words on the founder's screen come from the keys
    // the server holds, so they must equal what each trustee saw on their own screen.
    assert.equal(await btn(page, /Confirm the committee and lock \d+ early card/).isDisabled(), true);
    for (const idx of [2, 3]) await page.locator('.keycheck', { hasText: trustee[idx].words }).locator('input[type=checkbox]').check();
    await shot(page, '06c-key-words');
    assert.equal(await btn(page, /Confirm the committee and lock \d+ early card/).isDisabled(), false);
    assert.equal(h.app.db.prepare('SELECT roster_json j FROM campaigns').get().j, null); // nothing is signed until the founder does it
    await btn(page, /Confirm the committee and lock \d+ early card/).click();
    await page.getByText(/Done\. The committee is confirmed and the early cards are locked to it/).waitFor(); // the roster is signed and the re-lock has really finished
    await page.locator('.callout.ok', { hasText: 'Any 2 of 3 trustees together can open the cards.' }).waitFor();
    assert.deepEqual(h.app.db.prepare('SELECT DISTINCT seal_mode m FROM cards').all().map((r) => r.m), ['shamir']);
    assert.ok(h.app.db.prepare('SELECT roster_json j FROM campaigns').get().j);
    // The late signer now presses Sign. Their page sealed for the founder alone; the server refuses that (committee_changed), and the page checks
    // the committee again, re-seals to the signed roster and sends it, without asking the person anything.
    await btn(late, 'Sign the card').click();
    await late.getByRole('heading', { name: /Your card is signed and counted|Almost done/ }).waitFor();
    assert.deepEqual(cardPosts, [409, 200]);
    assert.deepEqual(h.app.db.prepare('SELECT DISTINCT seal_mode m FROM cards').all().map((r) => r.m), ['shamir']);
    // Lena then withdraws her card (as any signer can), so the rest of this journey counts the same cards as before.
    const lateSecret = new URLSearchParams((await late.locator('.link-box').innerText()).trim().split('#')[1]).get('s');
    assert.equal((await h.call('DELETE', '/api/cards/me', { auth: 'Bearer ' + C.deriveMember(lateSecret).authToken })).status, 200);
    await late.context().close(); delete pages['late-signer'];
    // another trustee checks the roster against their own invitation: the founder's signature holds, and their own key is in it
    await unlockDashboard(page, 2);
    await page.getByText('Your key is in the roster the founder signed.').waitFor();
    assert.deepEqual(problems, []);
  });

  // A website that has been altered to hand out keys of its own: the invitation must be refused, before anything is asked of the person and before
  // anything is sent. The server here is the real one with its rows changed, and the browser is the real, unmodified app.
  const evilKey = () => randomBytes(32).toString('base64url');
  const campaignId = () => h.app.db.prepare('SELECT id FROM campaigns').get().id;
  const swapTrusteeKey = (index, col) => () => {
    const args = [campaignId(), index];
    const was = h.app.db.prepare(`SELECT ${col} v FROM trustees WHERE campaign_id=? AND trustee_index=?`).get(...args).v;
    h.app.db.prepare(`UPDATE trustees SET ${col}=? WHERE campaign_id=? AND trustee_index=?`).run(evilKey(), ...args);
    return () => h.app.db.prepare(`UPDATE trustees SET ${col}=? WHERE campaign_id=? AND trustee_index=?`).run(was, ...args);
  };
  async function freshInvite() {
    const page = pages.trustees;
    await unlockDashboard(page, 1);
    await btn(page, 'Invite one person').click();
    await page.locator('.invite-box .link-box').first().waitFor();
    return (await page.locator('.invite-box .link-box').first().innerText()).trim(); // the newest link is listed first
  }
  async function refused(edit, link, expected) {
    const name = 'signer-' + randomBytes(3).toString('hex');
    const page = await newPage(name);
    const sent = [];
    page.on('request', (r) => { if (r.method() === 'POST' && /\/api\/(cards|reports)/.test(r.url())) sent.push(r.url()); });
    const undo = edit();
    try {
      await page.goto(link);
      await page.getByRole('heading', { name: 'Your card was not signed' }).waitFor();
      await page.getByText(expected).waitFor();
      assert.equal(await page.getByLabel('Full legal name').count(), 0); // no form was even shown
      assert.deepEqual(sent, []); // and nothing was sent
    } finally { undo(); await page.context().close(); delete pages[name]; }
  }

  it('a website that lies about the committee cannot make a phone seal a card to keys the founder did not sign (after the roster is signed)', async () => {
    const link = await freshInvite();
    const before = h.app.db.prepare('SELECT COUNT(*) c FROM cards').get().c;
    await refused(swapTrusteeKey(2, 'box_public_key'), link, /does not match the roster that was signed/); // swaps a trustee's key in its list
    await refused(swapTrusteeKey(1, 'box_public_key'), link, /do not match your invitation/); // swaps the founder's key
    // ...and one that also rewrites the signed roster it serves, which it cannot re-sign
    const editRoster = () => {
      const was = h.app.db.prepare('SELECT roster_json j FROM campaigns').get().j;
      const r = JSON.parse(was); r.seats[1].boxPublicKey = evilKey();
      const undoKey = swapTrusteeKey(2, 'box_public_key')();
      h.app.db.prepare('UPDATE campaigns SET roster_json=?').run(JSON.stringify(r));
      return () => { h.app.db.prepare('UPDATE campaigns SET roster_json=?').run(was); undoKey(); };
    };
    await refused(editRoster, link, /is not the one the founder signed/);
    assert.equal(h.app.db.prepare('SELECT COUNT(*) c FROM cards').get().c, before);
    assert.deepEqual(problems, []);
  });

  let zipPath;
  it('k trustees open the cards in one browser; the package is built locally and inspected', async () => {
    const page = pages.trustees;
    await page.goto('/t/unlock');
    await page.getByRole('heading', { name: 'Open the cards' }).waitFor();
    assert.match(await page.locator('.link-box').first().innerText(), /^[0-9a-f]{64}$/); // the software fingerprint
    await btn(page, 'Begin').click();
    const contribute = async (index) => {
      await page.locator('input[type=file]').setInputFiles(trustee[index].keyFile);
      await page.locator('input[type=password]').fill(trustee[index].pass);
      await btn(page, 'Contribute my key').click();
    };
    await contribute(1); // below a majority: the confirm() dialog is accepted by the test
    await page.getByRole('heading', { name: 'Trustee 2 of 2' }).waitFor();
    await contribute(3);
    await btn(page, 'Open the cards').click();
    await page.getByRole('heading', { name: 'The cards are open' }).waitFor();
    await shot(page, '07-unlock-review');
    assert.match(await page.locator('.card').first().innerText(), /3\s+cards opened/);
    assert.match(await page.locator('body').innerText(), /not yet a majority/i);
    zipPath = await saveDownload(page, () => btn(page, 'Download package (ZIP)').click(), 'package.zip');

    const py = `
import zipfile, json, sys
z = zipfile.ZipFile(sys.argv[1]); assert z.testzip() is None
r = lambda n: z.read(n).decode('utf-8')
print(json.dumps({'names': z.namelist(), 'roster': r('roster.csv'), 'letter': r('recognition-demand-letter-DRAFT.md'), 'decl': r('declaration-DRAFT.md'), 'log': r('confirmations-log.csv'),
  'pdf': z.read('cards.pdf')[:5].decode('latin1'), 'pdfs': z.read('declaration-DRAFT.pdf')[:5].decode('latin1')}))`;
    const z = JSON.parse(execFileSync('python3', ['-c', py, zipPath]).toString());
    for (const n of ['roster.csv', 'cards.pdf', 'confirmations-log.csv', 'declaration-DRAFT.md', 'declaration-DRAFT.pdf', 'recognition-demand-letter-DRAFT.md', 'form-502-worksheet-DRAFT.md', 'NEXT-STEPS.md', 'README.txt']) assert.ok(z.names.includes(n), 'missing ' + n);
    assert.equal(z.pdf, '%PDF-'); assert.equal(z.pdfs, '%PDF-');
    for (const s of ['Alice Anderson', 'Bob Baker', 'Dan Diaz', '+15550100001', 'alice.anderson@example.org']) assert.ok(z.roster.includes(s), 'roster lacks ' + s);
    assert.ok(!z.roster.includes('Cara Cruz'), 'an unconfirmed card must not be exported');
    assert.equal(z.roster.trim().split('\r\n').length, 4); // header + 3
    assert.match(z.letter, /NOT YET A MAJORITY/); // the software refuses to claim a majority it does not have
    assert.ok(z.decl.includes('Riverside Workers United') && z.decl.includes('3 authorization cards') && !z.decl.includes('{{'));
    assert.ok(!z.letter.includes('{{'));
    assert.ok(z.log.split('\r\n')[1].includes('dev-')); // provider message ids are logged
    assert.deepEqual(problems, []);
  });

  it('the trustees start the workspace: they must confirm the union has gone public', async () => {
    const page = pages.trustees;
    await page.getByRole('heading', { name: 'Start your union workspace' }).waitFor();
    await page.getByText('Creating a workspace copies the names').waitFor();
    assert.equal(await btn(page, 'Create the workspace').count(), 0); // nothing to click until they confirm
    await page.locator('.founding .check input').first().check();
    await page.locator('.founding select').first().selectOption('recognized');
    await btn(page, 'Create the workspace').click();
    await page.getByRole('heading', { name: 'Your workspace is ready' }).waitFor();
    const csv = readFileSync(await saveDownload(page, () => btn(page, 'Download all links (CSV)').click(), 'claims.csv'), 'utf8').trim().split('\r\n').slice(1);
    assert.equal(csv.length, 3);
    for (const line of csv) { const [name, ...rest] = line.split(','); links['claim:' + name.split(' ')[0]] = rest.join(','); }
    assert.ok(links['claim:Alice'] && links['claim:Bob'] && links['claim:Dan']);
  });

  async function claim(name) {
    const page = await newPage('ws-' + name);
    await page.goto(links['claim:' + name]);
    await page.getByRole('heading', { name: /Welcome to Riverside Workers United/ }).waitFor();
    assert.equal(await page.evaluate(() => location.hash), ''); // the claim token is not left in the address bar or the history
    const pass = (await page.locator('.passphrase').innerText()).trim();
    const keyFile = await saveDownload(page, () => btn(page, 'Create my key file').click(), `account-${name}.json`);
    await page.locator('.check input').check();
    await btn(page, 'Claim my account').click();
    await page.getByRole('heading', { name: `Hello, ${name}` }).waitFor();
    if (name === 'Alice') await shot(page, '08-workspace-home');
    account[name] = { keyFile, pass };
    return page;
  }
  it('everyone claims their own account with a key file; a claim link works once', async () => {
    for (const n of ['Alice', 'Bob', 'Dan']) await claim(n);
    const again = await newPage('reuse');
    await again.goto(links['claim:Alice']);
    await again.getByText(/already used or is not valid/).waitFor();
    // roles came from the founding step: Alice is an officer, treasurer and election committee member
    assert.match(await pages['ws-Alice'].locator('body').innerText(), /Officer.*Treasurer|Treasurer.*Officer/s);
    assert.deepEqual(problems, []);
  });

  const nav = (page, name) => page.locator('.tabs').getByRole('link', { name }).click();
  it('a secret-ballot vote: the committee counts in the browser and a member recounts it', async () => {
    const alice = pages['ws-Alice'];
    await nav(alice, 'Votes');
    await btn(alice, 'Start a vote').click();
    await alice.getByLabel('What are members deciding?').fill('Set our monthly dues');
    await alice.getByLabel('Kind of decision').selectOption('dues_change');
    await alice.getByLabel('Amount per month').fill('35');
    await btn(alice, 'Open the vote').click();
    await alice.getByRole('link', { name: 'Set our monthly dues' }).waitFor();
    for (const n of ['Alice', 'Bob', 'Dan']) {
      const p = pages['ws-' + n];
      await nav(p, 'Votes');
      await p.getByRole('link', { name: 'Set our monthly dues' }).click();
      await p.getByRole('heading', { name: 'Cast your secret ballot' }).waitFor();
      await p.locator('.choice').first().click(); // "Yes"
      await btn(p, 'Cast my ballot').click();
      await p.getByText('You have voted.').waitFor();
      assert.match(await p.locator('.code').innerText(), /^[A-Z2-9]{4}(-[A-Z2-9]{4}){3}$/); // the receipt
    }
    // nobody can vote twice: the vote page now shows the receipt and no ballot form
    assert.equal(await pages['ws-Bob'].getByRole('heading', { name: 'Cast your secret ballot' }).count(), 0);

    await alice.goto('/w'); // a full page load proves the session really lives only in memory
    await alice.getByRole('heading', { name: 'Open your union workspace' }).waitFor();
    await alice.locator('input[type=file]').setInputFiles(account.Alice.keyFile);
    await alice.locator('input[type=password]').fill(account.Alice.pass);
    await btn(alice, /^Unlock$/).click();
    await alice.getByRole('heading', { name: 'Hello, Alice' }).waitFor();
    await nav(alice, 'Votes');
    await alice.getByRole('link', { name: 'Set our monthly dues' }).click();
    await btn(alice, 'Close voting now').click();
    await alice.getByRole('heading', { name: 'Voting is closed' }).waitFor();
    await alice.getByRole('link', { name: 'Count the ballots' }).click();
    await alice.getByText('1 of 2 committee members have contributed.').waitFor();
    await alice.locator('input[type=file]').setInputFiles(account.Bob.keyFile);
    await alice.locator('input[type=password]').fill(account.Bob.pass);
    await btn(alice, 'Contribute').click();
    await alice.getByRole('heading', { name: 'Counted' }).waitFor();
    await alice.getByText('This passes.').waitFor();
    await btn(alice, 'Publish the results').click();
    await alice.getByRole('heading', { name: 'Results' }).waitFor();
    await alice.getByText('This decision has been carried out automatically.').waitFor();
    await shot(alice, '09-vote-results');
    await btn(alice, 'Recount every ballot in my browser').click();
    await alice.getByText(/recounted 3 ballots and got exactly the published result/).waitFor();
    // Dan checks his own receipt appears in the counted list
    const dan = pages['ws-Dan'];
    await nav(dan, 'Votes');
    await dan.getByRole('link', { name: 'Set our monthly dues' }).click();
    await dan.getByText(/Your receipt is in the list, so your vote was recorded/).waitFor();
    assert.deepEqual(problems, []);
  });

  it('the books: dues set by the vote, an unbroken ledger chain checked in the browser', async () => {
    const alice = pages['ws-Alice'];
    await nav(alice, 'Money');
    await alice.getByText(/Checked in your browser: all 0 ledger entries form an unbroken chain/).waitFor();
    await alice.getByText('Current dues: Standard dues, $35.00 per month.').waitFor();
    await shot(alice, '10-money');
    await alice.locator('summary', { hasText: 'Record money received' }).click();
    await alice.locator('details[open] input[type=number]').fill('120.50');
    await btn(alice, /^Record$/).click();
    await alice.getByText(/Checked in your browser: all 1 ledger entries/).waitFor();
    await alice.getByText('$120.50').first().waitFor();
    assert.deepEqual(problems, []);
  });

  it('a worker files a concern that only the chief steward can read; the case cannot close without a fair process', async () => {
    const dan = pages['ws-Dan'];
    await nav(dan, 'Get help');
    await dan.getByLabel('What happened?').fill('My hours were cut right after I signed the card.');
    await btn(dan, 'Send it, encrypted').click();
    await dan.getByText('My hours were cut right after I signed the card.').waitFor(); // he can read it: he holds the key
    assert.deepEqual(h.leaks(['My hours were cut right after']), []);
    const bob = pages['ws-Bob'];
    await nav(bob, 'Get help');
    await bob.getByRole('heading', { name: 'All cases' }).waitFor();
    await bob.getByRole('link', { name: /Step 1/ }).click();
    await bob.getByText('My hours were cut right after I signed the card.').waitFor(); // the chief steward holds a key
    await btn(bob, 'Assign').click();
    await bob.getByRole('heading', { name: 'Work on this case' }).waitFor();
    await shot(bob, '11-case');
    await btn(bob, 'Close the case').click();
    await bob.getByText(/Before closing: record a decision, give a reason, tell the worker/).waitFor();
    await bob.getByLabel('Reason (the worker will read this)').fill('The contract covers scheduling changes.');
    await btn(bob, 'Record decision').click();
    await bob.getByText('The worker has not been told yet.').waitFor();
    await btn(bob, 'Tell the worker').click();
    await bob.getByText('The worker has been told.').waitFor();
    await btn(bob, 'Close the case').click();
    await bob.getByText('Closed').first().waitFor();
    // the worker reads the decision and the reason, decrypted with the key only they and the stewards hold
    const dan2 = pages['ws-Dan'];
    await nav(dan2, 'Get help');
    await dan2.getByRole('link', { name: /Step 1/ }).click();
    await dan2.getByText('The contract covers scheduling changes.').waitFor();
    await dan2.getByText('We will pursue this').waitFor();
    assert.deepEqual(h.leaks(['The contract covers scheduling changes']), []);
    // Locking ends the session on the server too, not only in this tab
    const sessions = () => h.app.db.prepare('SELECT COUNT(*) c FROM ws_sessions').get().c;
    const before = sessions();
    const [logout] = await Promise.all([dan2.waitForResponse((r) => r.url().endsWith('/api/ws/auth/logout')), btn(dan2, 'Lock').click()]);
    assert.equal(logout.status(), 200);
    assert.equal(sessions(), before - 1);
    assert.deepEqual(problems, []);
  });

  it('the home page and the whole signing flow work in Spanish, with the Spanish card recorded as such', async () => {
    const camp = await makeCampaign(h, { meta: { unionName: 'Sindicato de Prueba', employerName: 'Café Río', jurisdiction: 'us-nlra', estimatedUnitSize: 10 } });
    const inv = await makeInvite(h, camp);
    const f = C.founderCommit(camp.trustees[0].keys.boxPublicKey, camp.trustees[0].keys.signPublicKey); // the founder's key check, which an invitation link carries
    const page = await newPage('spanish');
    await page.goto('/');
    await page.locator('select.lang').selectOption('es');
    await page.getByRole('heading', { name: 'Forma un sindicato en tu lugar de trabajo, de forma segura.' }).waitFor();
    await btn(page, 'Salida rápida').waitFor();
    // a website that swaps the founder's key is refused, and the refusal is in Spanish
    const evil = randomBytes(32).toString('base64url');
    const real = h.app.db.prepare('SELECT box_public_key k FROM trustees WHERE campaign_id=? AND trustee_index=1').get(camp.id).k;
    h.app.db.prepare('UPDATE trustees SET box_public_key=? WHERE campaign_id=? AND trustee_index=1').run(evil, camp.id);
    await page.goto(`/j#i=${inv.token}&k=${camp.campaignKey}&c=${camp.id}&f=${f}`);
    await page.getByRole('heading', { name: 'Tu tarjeta no se firmó' }).waitFor();
    await page.getByText(/no coinciden con tu invitación/).waitFor();
    h.app.db.prepare('UPDATE trustees SET box_public_key=? WHERE campaign_id=? AND trustee_index=1').run(real, camp.id);
    await page.goto(`/j#i=${inv.token}&k=${camp.campaignKey}&c=${camp.id}&f=${f}`);
    await page.getByRole('heading', { name: 'Antes de firmar' }).waitFor();
    await btn(page, 'Leer la tarjeta').click();
    await page.getByText('Yo, el/la abajo firmante, empleado/a de Café Río, autorizo a Sindicato de Prueba').waitFor();
    await page.getByLabel('Nombre legal completo').fill('María Fernández');
    await page.getByLabel('Correo electrónico personal').fill('maria.fernandez@example.org');
    await page.getByLabel('Teléfono móvil').fill('555-010-0077');
    await page.getByLabel('Escribe tu nombre completo para firmar').fill('María Fernández');
    await page.locator('.check input').check();
    await btn(page, 'Firmar la tarjeta').click();
    await page.getByRole('heading', { name: 'Tu tarjeta está firmada y contada' }).waitFor();
    assert.equal(h.app.db.prepare('SELECT template_version v FROM cards WHERE campaign_id=?').get(camp.id).v, 'card-v1-es');
    const sealed = h.app.db.prepare('SELECT seal_mode m, sealed_shares s FROM cards WHERE campaign_id=?').get(camp.id);
    assert.equal(sealed.m, 'shamir'); // this campaign's committee was confirmed by its founder, so the card is split among exactly that committee
    assert.deepEqual(JSON.parse(sealed.s).map((x) => x.trusteeIndex), [1, 2, 3]);
    const mail = h.app.mail.outbox.at(-1);
    assert.ok(mail.text.includes('María Fernández') && mail.text.includes('Yo, el/la abajo firmante')); // the confirmation restates the exact Spanish card
    assert.deepEqual(problems, []);
  });
});
