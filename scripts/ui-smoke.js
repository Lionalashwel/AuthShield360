// ui-smoke.js — Puppeteer smoke of the redesigned SPA (admin full tour)
// usage: node scripts/ui-smoke.js  (expects server on :4000)
import puppeteer from 'puppeteer-core';
import { existsSync } from 'node:fs';

const BASE = process.env.AS360_BASE || 'http://localhost:4000';
const CANDIDATES = [
    process.env.AS360_BROWSER, process.env.EDGE_PATH, process.env.CHROME_PATH,
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
].filter(Boolean);
const browserPath = CANDIDATES.find((p) => existsSync(p));
if (!browserPath) { console.error('No Edge/Chrome found. Set AS360_BROWSER to the executable path.'); process.exit(1); }

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const errors = [];
const browser = await puppeteer.launch({ executablePath: browserPath, headless: true, args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1280, height: 800 } });
const page = await browser.newPage();
page.on('pageerror', (e) => errors.push('PAGEERROR: ' + e.message));
page.on('console', (m) => { if (m.type() === 'error') errors.push('CONSOLE: ' + m.text().slice(0, 300)); });
const ok = (name, cond) => { console.log((cond ? '  PASS ' : '  FAIL ') + name); if (!cond) errors.push('CHECK: ' + name); };
const txt = (sel) => page.evaluate((s) => document.querySelector(s)?.textContent || '', sel);
const visible = (sel) => page.evaluate((s) => { const el = document.querySelector(s); return !!el && !el.classList.contains('hidden') && getComputedStyle(el).display !== 'none'; }, sel);
const js = (fn, ...a) => page.evaluate(fn, ...a);

// demo OTP for a user
const demoOtp = async (uname) => (await page.evaluate(async (b) => (await fetch(b + '/api/identity/otps')).json(), BASE)).otps.find((o) => o.username === uname)?.demoOtp;

try {
  await page.goto(BASE, { waitUntil: 'domcontentloaded' }); await sleep(1000);
  ok('ingest visible', await visible('#view-ingest'));
  ok('app hidden initially', !(await visible('#view-app')));

  // admin login (scenario 3, OTP + email)
  await js(() => { const set = (id, v) => { const el = document.getElementById(id); el.value = v; el.dispatchEvent(new Event('input', { bubbles: true })); };
    set('li-user', 'admin'); set('li-pass', 'Admin@123'); document.getElementById('li-scenario').value = '3'; });
  const code = await demoOtp('admin');
  await js((v) => { const set = (id, val) => { const el = document.getElementById(id); el.value = val; el.dispatchEvent(new Event('input', { bubbles: true })); }; set('li-otp', v); set('li-email', v); }, code);
  await js(() => document.getElementById('login-form').dispatchEvent(new Event('submit', { cancelable: true })));
  for (let i = 0; i < 20; i++) { if (await visible('#view-app')) break; await sleep(700); }
  ok('admin logged in → app shell', await visible('#view-app'));
  ok('default tab = SOC', await visible('#view-soc'));
  ok('5 tabs rendered', (await page.evaluate(() => document.querySelectorAll('#w-tabs .wtab').length)) === 5);
  ok('role shown', (await txt('#w-role')) === 'ADMINISTRATOR');
  await sleep(700);

  // SOC panels
  await page.evaluate(() => [...document.querySelectorAll('.side .nav')].find((b) => b.dataset.panel === 'blacklist').click()); await sleep(500);
  ok('blacklist panel switches', await visible('#panel-blacklist'));
  await page.evaluate(() => document.querySelector('#bl-ip').value = '198.51.100.7');
  await page.evaluate(() => document.getElementById('btn-bl-add').click()); await sleep(600);
  ok('blacklist add row', (await page.evaluate(() => document.querySelectorAll('#blacklist tbody tr').length)) > 0);
  await page.evaluate(() => [...document.querySelectorAll('.side .nav')].find((b) => b.dataset.panel === 'overview').click()); await sleep(400);

  // audit filter
  await page.evaluate(() => [...document.querySelectorAll('.side .nav')].find((b) => b.dataset.panel === 'audit').click()); await sleep(500);
  await js(() => { const s = document.getElementById('af-outcome'); s.value = 'SUCCESS'; document.getElementById('af-apply').click(); }); await sleep(600);
  const auditRows = await page.evaluate(() => document.querySelectorAll('#audit tbody tr').length);
  ok('audit filtered rows present', auditRows > 0);

  // Portal tab
  await page.evaluate(() => [...document.querySelectorAll('#w-tabs .wtab')].find((b) => b.dataset.wtab === 'portal').click()); await sleep(900);
  ok('portal visible', await visible('#view-portal'));
  ok('portal overview cards', (await page.evaluate(() => document.querySelectorAll('#p-overview .kv-card').length)) >= 4);
  ok('module nav has users+matrix (admin)', (await page.evaluate(() => [...document.querySelectorAll('.p-mod')].map((b) => b.dataset.pmod).join(','))).includes('users,matrix'));
  await js(() => [...document.querySelectorAll('.p-mod')].find((b) => b.dataset.pmod === 'courses').click()); await sleep(700);
  ok('courses table loads', (await page.evaluate(() => document.querySelectorAll('#portal-content .tbl tbody tr').length)) > 0);
  await js(() => [...document.querySelectorAll('.p-mod')].find((b) => b.dataset.pmod === 'matrix').click()); await sleep(700);
  ok('matrix table loads', (await page.evaluate(() => document.querySelectorAll('#portal-content .tbl tbody tr').length)) > 0);

  // Forensics tab
  await page.evaluate(() => [...document.querySelectorAll('#w-tabs .wtab')].find((b) => b.dataset.wtab === 'forensics').click()); await sleep(900);
  ok('forensics visible', await visible('#view-forensics'));
  ok('summary cards', (await page.evaluate(() => document.querySelectorAll('#fx-summary .kv-card').length)) >= 6);
  await js(() => { document.getElementById('fx-user').value = 'admin'; document.getElementById('fx-search').click(); }); await sleep(700);
  ok('timeline rows for admin', (await page.evaluate(() => document.querySelectorAll('#fx-timeline .tl-row').length)) > 0);
  await js(() => { document.getElementById('fx-c-title').value = 'UI smoke case'; const s = document.getElementById('fx-c-sev'); s.value = 'CRITICAL'; document.getElementById('fx-c-user').value = 'admin'; document.getElementById('fx-c-create').click(); }); await sleep(900);
  ok('drawer opens with evidence', await visible('#fx-drawer'));
  ok('drawer evidence rows', (await page.evaluate(() => document.querySelectorAll('#fxd-timeline .tl-row').length)) > 0);
  ok('case row in table', (await page.evaluate(() => document.querySelectorAll('#fx-cases tbody tr').length)) > 0);
  await js(() => document.getElementById('fxd-close').click()); await sleep(300);
  ok('drawer closes', !(await visible('#fx-drawer')));

  // Benchmark tab
  await page.evaluate(() => [...document.querySelectorAll('#w-tabs .wtab')].find((b) => b.dataset.wtab === 'bench').click()); await sleep(900);
  ok('benchmark visible', await visible('#view-bench'));
  ok('benchmark rows x3', (await page.evaluate(() => document.querySelectorAll('#bm-table tbody tr').length)) === 3);

  // Security Center tab
  await page.evaluate(() => [...document.querySelectorAll('#w-tabs .wtab')].find((b) => b.dataset.wtab === 'user').click()); await sleep(900);
  ok('security center visible', await visible('#view-user'));
  ok('recovery panel present', !!(await page.evaluate(() => document.getElementById('rc-request-btn'))));
  ok('my devices table', (await page.evaluate(() => document.querySelectorAll('#u-devices tbody tr').length)) > 0);

  // logout
  await page.evaluate(() => document.getElementById('w-logout').click()); await sleep(800);
  ok('logged out → ingest', await visible('#view-ingest'));
} catch (e) {
  ok('tour exception', false); errors.push('EXC: ' + (e && e.message ? e.message : e));
} finally {
  await browser.close();
}
console.log(errors.length ? '\nERRORS:\n' + errors.join('\n') : '\nUI SMOKE: ALL CHECKS PASSED');
process.exit(errors.length ? 1 : 0);