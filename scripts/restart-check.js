/**
 * AuthShield 360 — NFR restart-persistence test (SRS 1.9 / availability).
 *
 * Boots an ISOLATED instance on port 4001 with a private temp SQLite DB,
 * performs real writes through the public API, then hard-restarts the
 * server process and verifies every record survived: users, trusted devices,
 * audit trail (incl. elapsed_ms benchmarks), sessions, cases, attack runs.
 *
 * Usage: node scripts/restart-check.js        (independent of :4000 server)
 */
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const PORT = 4001;
const BASE = `http://localhost:${PORT}`;
const pass = []; const fail = [];
const ok = (n, c, x = '') => (c ? pass : fail).push({ n, x });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const waitFor = async (fn, ms = 20000) => {
    const t0 = Date.now();
    while (Date.now() - t0 < ms) { try { if (await fn()) return true; } catch { /* retry */ } await sleep(400); }
    return false;
};

function bootServer(dir) {
    const child = spawn(process.execPath, ['backend/index.js'], {
        cwd: process.cwd(), env: { ...process.env, PORT: String(PORT), AS360_DB_PATH: join(dir, 'test.db') },
        stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stderr.on('data', (d) => { const s = String(d); if (/error/i.test(s)) console.log('  [boot stderr]', s.trim().slice(0, 200)); });
    return child;
}
const killChild = async (child) => {
    if (!child || child.exitCode !== null) return;
    child.kill('SIGKILL');
    await Promise.race([new Promise((r) => child.once('exit', r)), sleep(3000)]);
};
const api = async (p, opts = {}) => { const res = await fetch(BASE + p, opts); return { status: res.status, json: () => res.json() }; };
const Json = (b) => ({ 'Content-Type': 'application/json', ...b });

const work = mkdtempSync(join(tmpdir(), 'as360-restart-'));
let srv = null;
let adminH = { 'X-Fp': 'fp-restart-admin' };

try {
    // ── boot #1 ──────────────────────────────────────────────
    srv = bootServer(work);
    ok('boot #1 healthy', await waitFor(async () => (await fetch(BASE + '/api/health')).ok));
    const init1 = await (await api('/api/identity/init')).json();
    ok('seed: 5 accounts on fresh DB', init1.seedAccounts?.length === 5);

    // admin session (for forensic + simulation APIs)
    const adminOtp = init1.seedAccounts.find((s) => s.username === 'admin').demoOtp;
    const adminLogin = await (await api('/api/auth/login', { method: 'POST', headers: Json({ 'X-Fp': adminH['X-Fp'] }), body: JSON.stringify({ identifier: 'admin', password: 'Admin@123', scenario: 3, otp: adminOtp, emailCode: adminOtp }) })).json();
    ok('admin S3 login (pre-restart)', adminLogin.outcome === 'SUCCESS' && !!adminLogin.session?.sid);
    adminH['X-Session-Side'] = adminLogin.session.sid;

    // registered user + trusted device + session
    const stamp = Date.now();
    const regReq = { fullName: 'Restart 検証', email: `rt${stamp}@campus.edu`, nationalId: `SCH-RT-${stamp}`, password: 'Restart@Pass1' };
    const reg = await (await api('/api/auth/register', { method: 'POST', headers: Json(), body: JSON.stringify(regReq) })).json();
    ok('registration ok', reg.ok);
    const ver = await fetch(BASE + '/api/verify?token=' + reg.verifyUrl.split('token=')[1] + '&fp=fp-restart-1');
    const cookie = (ver.headers.get('set-cookie') || '').split(';')[0];
    ok('verify → trust cookie', cookie.startsWith('as360_trust='));
    const otp1 = (await (await api('/api/identity/otps')).json()).otps.find((o) => o.username === reg.username).demoOtp;
    const login = await (await api('/api/auth/login', { method: 'POST', headers: Json({ 'X-Fp': 'fp-restart-1', 'X-Forwarded-For': '10.10.4.15', Cookie: cookie }), body: JSON.stringify({ identifier: reg.username, password: 'Restart@Pass1', scenario: 2, otp: otp1 }) })).json();
    ok('S2 login persists session/audit/success', login.outcome === 'SUCCESS' && !!login.session?.sid);

    const case1 = await (await api('/api/forensics/cases', { method: 'POST', headers: Json(adminH), body: JSON.stringify({ title: 'Restart case', severity: 'CRITICAL', user: reg.username }) })).json();
    const caseRef = case1.case?.id;
    const caseEv = caseRef ? (await (await api('/api/forensics/cases/' + caseRef, { headers: Json(adminH) })).json()) : null;
    ok('forensic case opened with captured evidence', !!caseRef && !!caseEv?.ok && caseEv.timeline.length > 0);

    await api('/api/simulate', { method: 'POST', headers: Json(adminH), body: JSON.stringify({ type: 'A', title: 'restart-attack' }) });
    await sleep(2600);

    const sum1 = await (await api('/api/forensics/summary', { headers: Json(adminH) })).json();
    const audit1 = sum1.summary.auditEvents;
    const sessions1 = sum1.summary.activeSessions;
    ok(`pre-restart state: audit=${audit1} sessions=${sessions1}`, audit1 > 0 && sessions1 > 0);

    // ── hard restart (new process, same DB file) ─────────────
    await killChild(srv); await sleep(1200);
    srv = bootServer(work);
    ok('boot #2 after restart', await waitFor(async () => (await fetch(BASE + '/api/health')).ok));

    const init2 = await (await api('/api/identity/init')).json();
    ok('users survived restart (5 demo + registered)', init2.seedAccounts.some((s) => s.username === reg.username) && init2.seedAccounts.length >= 6);

    const audit2 = await (await api('/api/audit')).json();
    ok('audit trail persisted across restart', audit2.events.length >= audit1);
    ok('successful-login events survived', audit2.events.some((e) => e.outcome === 'SUCCESS'));

    // fresh admin session post-restart → forensics + sim + benchmark still work
    const otps2 = await (await api('/api/identity/otps')).json();
    ok('TOTP secrets persisted (user can still log in)', otps2.otps.some((o) => o.username === reg.username && o.demoOtp !== '000000'));
    const aOtp2 = otps2.otps.find((o) => o.username === 'admin').demoOtp;
    const aLogin2 = await (await api('/api/auth/login', { method: 'POST', headers: Json({ 'X-Fp': 'fp-restart-admin2' }), body: JSON.stringify({ identifier: 'admin', password: 'Admin@123', scenario: 3, otp: aOtp2, emailCode: aOtp2 }) })).json();
    const H2 = { 'X-Fp': 'fp-restart-admin2', 'X-Session-Side': aLogin2.session.sid };

    const sum2 = await (await api('/api/forensics/summary', { headers: Json(H2) })).json();
    ok('sessions + devices survived restart', sum2.summary.activeSessions >= sessions1 && sum2.summary.trustedDevices >= 1);

    const cases2 = await (await api('/api/forensics/cases', { headers: Json(H2) })).json();
    ok('forensic case + evidence survived restart', (cases2.cases || []).some((c) => c.id === caseRef && c.items > 0));

    const mk2 = await (await api('/api/forensics/cases/' + caseRef + '/export', { method: 'POST', headers: Json(H2) })).json();
    ok('case markdown export after restart', mk2.ok && /# Forensic Case/.test(mk2.markdown));

    const sims2 = await (await api('/api/simulations')).json();
    ok('attack runs survived restart', (sims2.simulations || []).some((s) => s.title === 'restart-attack'));

    const bench2 = await (await api('/api/benchmark')).json();
    ok('benchmark (real elapsed_ms) works after restart', bench2.ok && bench2.benchmark.scenarios.length === 3);
} catch (e) {
    ok('restart-check harness', false, String((e && e.message) || e));
} finally {
    if (srv) await killChild(srv);
    if (existsSync(work)) rmSync(work, { recursive: true, force: true });
}

console.log(`restart-check → pass ${pass.length} / fail ${fail.length}`);
for (const p of pass) console.log('  ✓ ' + p.n);
for (const f of fail) console.error('  ✗ ' + f.n + (f.x ? ' [' + f.x + ']' : ''));
process.exit(fail.length ? 1 : 0);