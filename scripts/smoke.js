/**
 * AuthShield 360 - Automated smoke test (v2)
 * Exercises risk engine + all three SRS scenarios + registration →
 * email verification → trusted device → login, headlessly (no browser).
 *   npm test
 */
import { attemptAuthentication, registerAccount, verifyEmail, decisionOnPending, finalizeApprovedLogin } from '../backend/auth.js';
import { evaluateRisk } from '../backend/risk-engine.js';
import { initDb, addTrustedDevice, getDb } from '../backend/db.js';
import { releaseLockout } from '../backend/auth.js';
import { totpNow } from '../backend/totp.js';
import { hashPassword } from '../backend/utils.js';

initDb(false);
const db = getDb();
let pass = 0, fail = 0;
function assert(name, cond, extra = '') {
    if (cond) { pass++; console.log('  ok  ', name); }
    else { fail++; console.error('  FAIL', name, extra); }
}

const UB = 'teach1-safe';
const FP = (n) => 'smoke-fp-' + UB + '-' + n;
const fire = (o) => attemptAuthentication(o);

/** Deterministic warmup: mark a subnet as known + device as trusted => risk LOW regardless of hour. */
function warmup(username, fp, subnet = '10.10.4.0/24', ip = '10.10.4.25') {
    const u = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    db.prepare(`INSERT INTO success_logins (sid, username, role, ip, subnet, network, device_hash, risk, level, scenario, mfa, ts)
        VALUES ('warm', ?, ?, ?, ?, 'Corporate Campus LAN', ?, 0, 'LOW', 1, 'NONE', datetime('now'))`)
        .run(username, u.role, ip, subnet, fp);
    addTrustedDevice({ userId: u.id, fingerprint: fp, label: 'warm', ip, ua: 'smoke', cookieId: null });
}

// ---------------------------------------------------------------- risk engine
assert('risk: new device alone = 30 (LOW)', evaluateRisk({ unrecognizedDevice: true }).score === 30);
assert('risk: new device + time anomaly = 45 (MEDIUM)', evaluateRisk({ unrecognizedDevice: true, timeAnomaly: true }).level === 'MEDIUM' && evaluateRisk({ unrecognizedDevice: true, timeAnomaly: true }).score === 45);
assert('risk: blacklisted IP + new device = 75 (HIGH)', evaluateRisk({ unrecognizedDevice: true, blacklistedIp: true }).level === 'HIGH');
assert('risk: returns reasons[]', Array.isArray(evaluateRisk({ newIp: true }).reasons) && evaluateRisk({ newIp: true }).reasons.includes('NEW_IP'));
assert('risk: baseline LOW', evaluateRisk({}).level === 'LOW');
assert('risk: clamp 0..100', evaluateRisk({ unrecognizedDevice: true, blacklistedIp: true, impossibleTravel: true, timeAnomaly: true, consecutiveFailures: 6 }).score <= 100);

// ---------------------------------------------------------------- S1
warmup('student1', FP(1));
let r = await fire({ identifier: 'student1', password: 'Student@123', scenario: 1, ip: '10.10.4.25', ua: 'smoke', fingerprint: FP(1), browser: 'desktop' });
assert('S1 warm direct -> SUCCESS (LOW)', r.outcome === 'SUCCESS');
r = await fire({ identifier: 'student1', password: 'wrong', scenario: 1, ip: '10.10.4.25', ua: 'smoke', fingerprint: FP(1) });
assert('S1 wrong pw -> FAILED_PASSWORD', r.outcome === 'FAILED_PASSWORD');

// ---------------------------------------------------------------- S2
warmup('teacher1', FP(2));
r = await fire({ identifier: 'teacher1', password: 'Teacher@123', scenario: 2, ip: '10.10.4.25', ua: 'smoke', fingerprint: FP(2) });
assert('S2 requests OTP (scenario mandate)', r.outcome === 'STEP_UP' && r.needsOTP === true);
const t = db.prepare('SELECT * FROM users WHERE username = ?').get('teacher1');
r = await fire({ identifier: 'teacher1', password: 'Teacher@123', otp: totpNow(t.totp_secret), scenario: 2, ip: '10.10.4.25', ua: 'smoke', fingerprint: FP(2) });
assert('S2 valid OTP -> SUCCESS', r.outcome === 'SUCCESS');
r = await fire({ identifier: 'teacher1', password: 'Teacher@123', otp: '000000', scenario: 2, ip: '10.10.4.25', ua: 'smoke', fingerprint: FP(2) });
assert('S2 invalid OTP -> INVALID_OTP', r.outcome === 'INVALID_OTP');

// ---------------------------------------------------------------- S3
warmup('admin', FP(3));
const a = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
r = await fire({ identifier: 'admin', password: 'Admin@123', otp: totpNow(a.totp_secret), emailCode: totpNow(a.totp_secret), scenario: 3, ip: '10.10.4.25', ua: 'smoke', fingerprint: FP(3) });
assert('S3 OTP+Email+RBAC -> SUCCESS', r.outcome === 'SUCCESS');

// ---------------------------------------------------------------- lockout
warmup('student2', FP(4));
await fire({ identifier: 'student2', password: 'x1', scenario: 1, ip: '10.10.4.25', ua: 'smoke', fingerprint: FP(4) });
await fire({ identifier: 'student2', password: 'x2', scenario: 1, ip: '10.10.4.25', ua: 'smoke', fingerprint: FP(4) });
r = await fire({ identifier: 'student2', password: 'x3', scenario: 1, ip: '10.10.4.25', ua: 'smoke', fingerprint: FP(4) });
assert('>=2 failures -> HIGH_RISK_BLOCK', r.outcome === 'HIGH_RISK_BLOCK');
releaseLockout('student2');

// ---------------------------------------------------------------- registration -> verify -> trusted login
const email = 'new.student' + Date.now() + '@campus.edu';
const reg = await registerAccount({ email, password: 'Secure#Pass9', nationalId: 'SCH-X' + Date.now(), fullName: 'New Student', baseUrl: 'http://localhost:4000' });
assert('register -> verification_pending (+ real mail attempt)', reg.ok && reg.status === 'verification_pending');
const token = (reg.verifyUrl || '').split('token=')[1];
assert('verification link issued', !!token);
const v = verifyEmail(token, { ip: '10.10.4.25', ua: 'smoke' });
assert('verify -> trusted device + cookie', v.ok && !!v.cookieToken && !!v.fingerprint);
warmup(reg.username, v.fingerprint);
const check = await attemptAuthentication({
    identifier: email, password: 'Secure#Pass9', scenario: 1,
    ip: '10.10.4.25', ua: 'smoke', browser: 'desktop', deviceLabel: 'smoke', fingerprint: v.fingerprint,
});
assert('new registered user (trusted fp) direct SUCCESS', check.outcome === 'SUCCESS');

console.log(`\n  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);