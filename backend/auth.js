/**
 * AuthShield 360 - Authentication Service (v2 Enterprise)
 *
 * Implements the real-data identity workflows:
 *  - Account registration + REAL e-mail verification (Nodemailer/Ethereal)
 *  - Trusted-Device designation (encrypted persistent cookie + table)
 *  - Cross-Device Approval (Apple/Google style) with offline fallback
 *  - Adaptive risk scoring (time/location/device/velocity) 0-100
 *  - SRS scenario envelopes (S1/S2/S3) preserved
 *
 * EVERY attempt persists a fully-correlated audit row and is broadcast live.
 */
import { POLICY } from './config.js';
import { analyzeNetwork, distanceKm } from './network.js';
import { evaluateRisk } from './risk-engine.js';
import { verifyTotp, totpNow } from './totp.js';
import { hashPassword, nowIso, newSid, randomToken, stableHash } from './utils.js';
import { sealTrustCookie, openTrustCookie } from './cookie.js';
import { sendMail } from './mailer.js';
import { computeFingerprint } from './fingerprint.js';
import {
    dbHelpers,
    createUser, findUserByEmail, findUserByNationalId, userById, markEmailVerified,
    insertToken, getToken, useToken,
    addTrustedDevice, touchTrustedDevice, listTrustedDevices, isTrustedDevice, revokeTrustedDevice,
    insertPendingApproval, pendingApproval, setPendingStatus, setPendingFallback,
    insertAudit, insertSuccess, insertAlert,
    createSession, getSession, deleteSession, listSessions,
    upsertFactor, getFactor, factorExpired, removeFactor, clearAllFactors, listFactors,
    auditList, auditCount, successList, alertList, alertCountSync,
    logRecognizedDevice, getDevice,
    whitelistAll, whitelistAdd, whitelistRemove, blacklistAll, blacklistAdd, blacklistRemove,
    updatePasswordAndSecret, storeRecoveryCodes, recoveryCodeValid, createMfaReset, verifyMfaReset,
    completeMfaReset,
} from './db.js';
import { publish } from './events.js';

// ---------------------------------------------------------------------------
// Audit + alert helpers
// ---------------------------------------------------------------------------
function commitAudit(base, outcome, { risk, factors, sid, detail, elapsed_ms }) {
    const e = { ...base, outcome, risk: risk ?? 0, factors: (factors || []).filter(Boolean), sid: sid || null, detail: detail || '', elapsed_ms };
    insertAudit(e);
    publish('audit', { type: 'audit', data: e });
    return e;
}
function flagAlert({ severity = 'CRITICAL', category = 'ACCOUNT_LOCK', title, detail, username, risk, ip }) {
    const a = { severity, category, ref: newSid(), title, detail, username, risk, ip: ip || null, ts: nowIso() };
    insertAlert(a);
    publish('alert', { type: 'alert', data: a });
    return a;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function isLocked(username) {
    const f = getFactor(`LOCKOUT:${username}`);
    return f && !factorExpired(`LOCKOUT:${username}`);
}
function failStreak(username) {
    const f = getFactor(`FAILSTREAK:${username}`);
    if (!f || factorExpired(`FAILSTREAK:${username}`)) return 0;
    return parseInt(f.label, 10) || 0;
}
function bumpStreak(username) {
    const n = failStreak(username) + 1;
    upsertFactor(`FAILSTREAK:${username}`, String(n), POLICY.LOCK_WINDOW_MS);
    return n;
}
function resetStreak(username) {
    removeFactor(`FAILSTREAK:${username}`);
    removeFactor(`INVALID_OTP:${username}`);
}

function hourAnomaly(d = new Date()) {
    const h = d.getHours();
    return h < POLICY.NORMAL_HOURS.start || h >= POLICY.NORMAL_HOURS.end;
}

function lastLoginIpFor(uid) {
    const row = getDbUnscoped().prepare(
        'SELECT s.ip FROM success_logins s JOIN users u ON u.username = s.username WHERE u.id = ? ORDER BY s.id DESC LIMIT 1'
    ).get(uid);
    return row ? row.ip : null;
}
function getDbUnscoped() { return dbHelpers._raw(); }

// ---------------------------------------------------------------------------
// REGISTRATION
// ---------------------------------------------------------------------------
export async function registerAccount({ email, password, nationalId, fullName, baseUrl }) {
    email = String(email || '').trim().toLowerCase();
    if (!/.+@.+\..+/.test(email)) return { ok: false, error: 'invalid_email' };
    if (!password || password.length < 8) return { ok: false, error: 'weak_password' };
    if (!nationalId) return { ok: false, error: 'national_id_required' };
    if (findUserByEmail(email)) return { ok: false, error: 'email_taken' };
    if (findUserByNationalId(String(nationalId).trim())) return { ok: false, error: 'national_id_taken' };

    const uid = 'usr-' + Date.now().toString(36) + randomToken(4);
    const username = (String(email).split('@')[0]).replace(/[^a-z0-9_.-]/gi, '').slice(0, 24) || 'user' + randomToken(3);
    await createUser({
        id: uid, username, displayName: fullName || username, role: 'STUDENT',
        department: 'Registered Student', pwHash: hashPassword(password),
        totpSecret: genTotpSecret(), email, nationalId: String(nationalId).trim().toUpperCase(),
    });

    const token = randomToken(32);
    const tokenHash = stableHash(token);
    insertToken({ tokenHash, userId: uid, email, purpose: 'verify' });

    let mail = null;
    try {
        const verifyUrl = `${baseUrl.replace(/\/$/, '')}/api/verify?token=${encodeURIComponent(token)}`;
        mail = await sendMail({
            to: email,
            subject: 'AuthShield 360 — Verify your email',
            text: `Welcome to AuthShield 360.\nVerify your account to activate your trusted device:\n${verifyUrl}`,
            html: `<h2>Welcome to AuthShield 360</h2><p>Click to verify your email and register this device as trusted:</p>
                   <p><a href="${verifyUrl}">Verify my email</a></p><p style="color:#888">${verifyUrl}</p>`,
        });
    } catch (err) {
        mail = { status: 'degraded', previewUrl: null, error: String(err?.message || err) };
    }

    return {
        ok: true, userId: uid, username, email, status: 'verification_pending',
        verifyUrl: `${baseUrl.replace(/\/$/, '')}/api/verify?token=${encodeURIComponent(token)}`,
        mail,
    };
}

// ---------------------------------------------------------------------------
// EMAIL VERIFICATION → TRUSTED DEVICE DESIGNATION
// ---------------------------------------------------------------------------
export function verifyEmail(token, { ip, ua, fallbackFingerprint }) {
    const th = stableHash(String(token || ''));
    const tok = getToken(th);
    if (!tok || tok.used) return { ok: false, error: 'invalid_token' };
    if (Date.parse(tok.expires_at) < Date.now()) return { ok: false, error: 'token_expired' };

    useToken(th);
    markEmailVerified(tok.user_id);
    const user = userById(tok.user_id);
    if (!user) return { ok: false, error: 'no_user' };

    // Designate THIS device as trusted, then seal the persistent cookie.
    const fp = (fallbackFingerprint || computeFingerprint({ userAgent: ua, ip }).replace(/^fp:/, '')).replace(/^fp:/, '');
    const label = deviceLabelFromUa(ua);
    addTrustedDevice({ userId: user.id, fingerprint: fp, label, ip, browser: ua, ua, cookieId: null });

    const cookieToken = sealTrustCookie({ fp: fp, uid: user.id });
    return { ok: true, user: sanitizeUser(user), fingerprint: fp, cookieToken };
}

export function readTrust(cookieToken) {
    if (!cookieToken) return null;
    try { return openTrustCookie(cookieToken); } catch { return null; }
}

// ---------------------------------------------------------------------------
// /api/me - does THIS device hold a valid trust cookie?
// ---------------------------------------------------------------------------
export function currentTrustedSession(cookieToken) {
    const t = readTrust(cookieToken);
    if (!t) return { trusted: false };
    const user = userById(t.uid);
    const valid = user && isTrustedDevice(t.uid, t.fp);
    return { trusted: !!valid, user: valid ? sanitizeUser(user) : null, deviceFingerprint: valid ? t.fp : null };
}

// ---------------------------------------------------------------------------
// LOGIN  (core v2 orchestrator)
// ---------------------------------------------------------------------------
export async function attemptAuthentication({ identifier, username, password, otp, emailCode, scenario,
    ip, ua, browser, deviceLabel, fingerprint, cookieToken }) {
    const net = analyzeNetwork(ip);
    const user = findByIdentifier(identifier || username);
    const uname = user ? user.username : String(identifier || username || '').trim();
    const fpNorm = fingerprint || 'anon';

    const base = {
        ts: nowIso(), username: user ? user.username : uname,
        role: user ? user.role : 'UNKNOWN', user_id: user ? user.id : 'unknown',
        ip: net.ip, subnet: net.subnet, network: net.network,
        device_name: deviceLabel || deviceLabelFromUa(ua), browser: browser || 'desktop',
        user_agent: ua || '', fingerprint: fpNorm,
        scenario: Number(scenario) || 1,
    };
    // local commit helper that timestamps every security event (benchmark NFR)
    const t0 = Date.now();
    const commit = (outcome, o) => commitAudit(base, outcome, { ...o, elapsed_ms: Date.now() - t0 });

    // 0) defense standby gate (window for Burp/ZAP failure testing)
    if (POLICY.DEFENSE_STANDBY) {
        commit( 'FAILED_PASSWORD', { risk: 100, factors: ['DEFENSE_STANDBY'], detail: 'platform in defense-standby' });
        return { outcome: 'FAILED_PASSWORD', message: 'Authentication suspended (defense standby)', risk: 100, level: 'HIGH', reasons: ['DEFENSE_STANDBY'] };
    }

    // 1) blocked identity (lockout / blacklisted IP)
    const ipBanned = blacklistAll().some((b) => b.ip === net.ip);
    if (isLocked(uname) || ipBanned) {
        const e = commit( 'HIGH_RISK_BLOCK', {
            risk: 100, factors: isLocked(uname) ? ['ACCOUNT_LOCKED'] : ['IP_BLACKLISTED'],
            detail: `blocked: ${isLocked(uname) ? 'lockout' : 'blacklisted ip'}`,
        });
        flagAlert({ title: 'Blocked sign-in', detail: `${uname} blocked from ${net.ip}`, username: uname, risk: 100, ip: net.ip });
        return { outcome: 'HIGH_RISK_BLOCK', message: 'Access blocked (lockout/blacklist)', risk: 100, level: 'HIGH', reasons: isLocked(uname) ? ['ACCOUNT_LOCKED'] : ['IP_BLACKLISTED'] };
    }

    // 2) unknown identity -> deferred failure (no oracle)
    if (!user) {
        commit( 'FAILED_PASSWORD', { risk: 60, factors: ['UNKNOWN_USER'], detail: 'no such account' });
        return { outcome: 'FAILED_PASSWORD', message: 'Invalid credentials', risk: 60, level: 'MEDIUM', reasons: ['UNKNOWN_USER'] };
    }

    // 3) contextual signals
    const trust = deviceTrustFor(user, fpNorm, cookieToken);            // {trusted, via}
    const netKnown = networkKnownFor(user, net);                        // {known, via}
    const travel = await travelAssessment(user, net);                   // {impossibleTravel, distanceKm, lastIp, speedKmMin}
    const streak = failStreak(uname);
    const risk = evaluateRisk({
        timeAnomaly: hourAnomaly(),
        newIp: !netKnown.known,
        impossibleTravel: travel.impossibleTravel,
        unrecognizedDevice: !trust.trusted,
        consecutiveFailures: streak,
        blacklistedIp: ipBanned,
    });

    // 4) primary credential gate
    const pwOk = user && hashPassword(password || '') === user.pw_hash;
    if (!pwOk) {
        const s = bumpStreak(uname);
        commit( 'FAILED_PASSWORD', {
            risk: evaluateRisk({ ...riskCtx(user, net, trust, travel, ipBanned), consecutiveFailures: s }).score,
            factors: risk.reasons, detail: `invalid password (streak ${s})`,
        });
        if (s >= POLICY.MAX_FAILED_PASSWORD) {
            upsertFactor(`LOCKOUT:${uname}`, 'account_locked', POLICY.LOCK_WINDOW_MS);
            flagAlert({ category: 'ACCOUNT_LOCK', title: 'Brute-force quarantine', detail: `${uname} locked after ${s} failed attempts`, username: uname, risk: 100, ip: net.ip });
        }
        return { outcome: 'FAILED_PASSWORD', message: 'Invalid credentials', risk: risk.score, level: risk.level, reasons: risk.reasons, user: sanitizeUser(user) };
    }

    // 5) HIGH RISK -> account lockdown + admin alert (v2 policy)
    if (risk.level === 'HIGH') {
        upsertFactor(`LOCKOUT:${user.username}`, 'account_locked', POLICY.LOCK_WINDOW_MS);
        const e = commit( 'HIGH_RISK_BLOCK', {
            risk: risk.score, factors: risk.reasons, detail: `HIGH-RISK (${risk.score}) account lockdown: ${risk.reasons.join(', ')}`,
        });
        flagAlert({ category: 'HIGH_RISK', title: 'High-risk sign-in locked down', detail: `${uname} @ ${net.ip} reasons=${risk.reasons.join(',')}`, username: uname, risk: risk.score, ip: net.ip });
        return { outcome: 'HIGH_RISK_BLOCK', message: 'Account lockdown — high risk activity', risk: risk.score, level: 'HIGH', reasons: risk.reasons, user: sanitizeUser(user) };
    }

    // 6) Step-up requirement matrix (SRS scenario + adaptive band)
    const requireBaseOtp = scenario >= 2;
    const requireBaseEmail = scenario >= 3;
    const medium = risk.level === 'MEDIUM';

    // 6a) Cross-Device Approval (Apple/Google style) — MEDIUM risk + unrecognized device + a trusted device exists
    if (medium && !trust.trusted) {
        const trusted = listTrustedDevices(user.id);
        if (trusted.length > 0) {
            const pendingId = newSid();
            const loc = net.network;
insertPendingApproval({
                id: pendingId, userId: user.id, newFp: fpNorm, newIp: net.ip,
                newLabel: base.device_name, location: loc, ua,
                ttlMs: POLICY.PENDING_APPROVAL_TTL_MS,
            });
            // push to all trusted browsers of THIS user (real-time channel)
            publish('cross:' + user.id, {
                type: 'crossdevice', data: {
                    pendingId, userId: user.id, username: user.username,
                    device: base.device_name, ip: net.ip, location: loc, reason: risk.reasons, risk: risk.score,
                },
            });
            commit( 'STEP_UP', {
                risk: risk.score, factors: ['CROSS_DEVICE_PENDING', ...risk.reasons],
                detail: `Cross-device approval requested (${base.device_name} @ ${net.ip})`,
            });
            return {
                outcome: 'PENDING_APPROVAL', message: 'Approve this sign-in from your trusted device',
                pendingId, risk: risk.score, level: risk.level, reasons: risk.reasons,
                user: sanitizeUser(user), fallbackAt: POLICY.PENDING_APPROVAL_FALLBACK_MS,
            };
        }
    }

    // 6b) OTP / email step-up (scenario or medium fallback)
    const requireOtp = requireBaseOtp || medium;
    const requireEmail = requireBaseEmail || (medium && risk.reasons.includes('IMPOSSIBLE_TRAVEL'));
    if ((requireOtp || requireEmail) && !otp) {
        const e = commit( 'STEP_UP', {
            risk: risk.score, factors: risk.reasons, detail: `step-up ${requireEmail ? 'otp+email' : 'otp'} challenge`,
        });
        return { outcome: 'STEP_UP', message: 'Step-up verification required', needsOTP: requireOtp, needsEmail: requireEmail, risk: risk.score, level: risk.level, reasons: risk.reasons, user: sanitizeUser(user), step: requireEmail ? 'email' : 'otp' };
    }

    // 7) mobile OTP gate
    if (otp) {
        const v = verifyTotp(user.totp_secret, otp);
        if (!v.ok) {
            const reason = v.reason === 'EXPIRED_OTP' ? 'EXPIRED_OTP' : 'INVALID_OTP';
            commit( reason, { risk: risk.score, factors: [...risk.reasons, 'OTP'], detail: v.reason });
            return { outcome: reason, message: 'Invalid OTP', risk: risk.score, level: risk.level, reasons: risk.reasons, user: sanitizeUser(user) };
        }
    }

    // 8) email step-up gate
    if (requireEmail) {
        const v = verifyTotp(user.totp_secret, emailCode);
        if (!v.ok) {
            const reason = v.reason === 'EXPIRED_OTP' ? 'EXPIRED_OTP' : 'INVALID_OTP';
            commit( reason, { risk: risk.score + 10, factors: [...risk.reasons, 'EMAIL_STEPUP'], detail: `email ${v.reason}` });
            return { outcome: reason, message: 'Invalid email code', risk: risk.score, level: risk.level, reasons: risk.reasons, user: sanitizeUser(user) };
        }
    }

    // 9) RBAC (SRS Scenario 3)
    if (scenario === 3 && user.role === 'STUDENT') {
        upsertFactor(`UNAUTHORIZED_ROUTE:${user.id}`, 'unauthorized_route', POLICY.LOCK_WINDOW_MS);
        const e = commit( 'HIGH_RISK_BLOCK', { risk: 100, factors: ['UNAUTHORIZED_ROUTE'], detail: 'STUDENT attempted admin area' });
        flagAlert({ category: 'RBAC', title: 'Unauthorized route attempt', detail: `${uname} denied admin route`, username: uname, risk: 100, ip: net.ip });
        return { outcome: 'HIGH_RISK_BLOCK', message: 'Route denied by RBAC policy', risk: 100, level: 'HIGH', reasons: ['UNAUTHORIZED_ROUTE'] };
    }

    // 10) SUCCESS
    resetStreak(uname);
    const session = createSession({ username: user.username, role: user.role, user_id: user.id, ip: net.ip, fingerprint: fpNorm });
    const mfa = otp ? (emailCode ? 'OTP+EMAIL' : 'OTP') : 'NONE';
    const e = commit( 'SUCCESS', {
        risk: risk.score, factors: risk.reasons, sid: session.sid,
        detail: `scenario ${scenario} ${mfa}${trust.trusted ? '' : ' new-device-stepup'}`,
    });
    insertSuccess({ sid: session.sid, username: user.username, role: user.role, ip: net.ip, subnet: net.subnet, network: net.network, device_hash: fpNorm, risk: risk.score, level: risk.level, scenario, mfa, ts: e.ts });

    // auto-trust after OTP-verified new device (possession proof)
    if (!trust.trusted && (otp || emailCode)) addTrustedDevice({ userId: user.id, fingerprint: fpNorm, label: base.device_name, ip: net.ip, browser: ua, ua, cookieId: null });

    return {
        outcome: 'SUCCESS', message: 'Authenticated', risk: risk.score, level: risk.level, reasons: risk.reasons,
        user: sanitizeUser(user),
        session: { sid: session.sid, token: session.token, expires: session.expires, role: user.role },
    };
}

// ---------------------------------------------------------------------------
// Cross-device decision + new-device finalize
// ---------------------------------------------------------------------------
export function decisionOnPending({ pendingId, approve, decisionIp }) {
    const p = pendingApproval(pendingId);
    if (!p || p.status !== 'pending') return { ok: false, error: 'not_pending' };
    if (Date.parse(p.expires_at) < Date.now()) { setPendingStatus(pendingId, 'expired'); return { ok: false, error: 'expired' }; }
    const user = userById(p.user_id);

    if (approve) {
        addTrustedDevice({ userId: p.user_id, fingerprint: p.new_fp, label: p.new_label, ip: p.new_ip, browser: p.ua, ua: p.ua, cookieId: null });
        setPendingStatus(pendingId, 'approved');
        publish('cross:' + p.user_id, { type: 'crossdevice', data: { pendingId, decision: 'approved', ts: nowIso() } });
        const net = analyzeNetwork(p.new_ip);
        commitAudit({
            username: user ? user.username : p.user_id, role: user ? user.role : 'UNKNOWN',
            user_id: p.user_id, ip: p.new_ip, subnet: net.subnet, network: net.network,
            device_name: p.new_label, browser: p.ua, user_agent: p.ua, fingerprint: p.new_fp, ts: nowIso(),
        }, 'SUCCESS', { risk: 0, factors: ['TRUSTED_DEVICE_APPROVAL'], detail: 'cross-device approved — device now trusted' });
        return { ok: true, status: 'approved' };
    }

    setPendingStatus(pendingId, 'denied');
    flagAlert({ category: 'CROSS_DEVICE', title: 'Sign-in denied on trusted device', detail: `${user ? user.username : ''} new device ${p.new_label} @ ${p.new_ip} denied`, username: user ? user.username : p.user_id, risk: 100, ip: p.new_ip });
    publish('cross:' + p.user_id, { type: 'crossdevice', data: { pendingId, decision: 'denied', ts: nowIso() } });
    return { ok: true, status: 'denied' };
}

export function pendingStatus(pendingId) {
    const p = pendingApproval(pendingId);
    if (!p) return { status: 'unknown' };
    if (p.status === 'pending' && Date.parse(p.expires_at) < Date.now()) {
        setPendingStatus(pendingId, 'expired');
        return { status: 'expired', fallback: true };
    }
    if (p.status === 'expired') return { status: 'expired', fallback: true };
    return { status: p.status, location: p.location, device: p.new_label, ip: p.new_ip, riskReason: p.location };
}

/** Finalize a login that was approved on a trusted device: create session. */
export function finalizeApprovedLogin({ pendingId, fp }) {
    const p = pendingApproval(pendingId);
    if (!p || p.status !== 'approved') return { ok: false, error: 'not_approved' };
    const user = userById(p.user_id);
    if (!user) return { ok: false, error: 'no_user' };
    const session = createSession({ username: user.username, role: user.role, user_id: user.id, ip: p.new_ip, fingerprint: p.new_fp });
    const net = analyzeNetwork(p.new_ip);
    insertSuccess({ sid: session.sid, username: user.username, role: user.role, ip: p.new_ip, subnet: net.subnet, network: net.network, device_hash: p.new_fp, risk: 0, level: 'LOW', scenario: 3, mfa: 'APPROVAL', ts: nowIso() });
    addTrustedDevice({ userId: user.id, fingerprint: p.new_fp, label: p.new_label || 'Approved device', ip: p.new_ip, browser: '', ua: '', cookieId: null });
    return {
        ok: true, outcome: 'SUCCESS',
        user: sanitizeUser(user),
        session: { sid: session.sid, token: session.token, expires: session.expires, role: user.role },
    };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------
function riskCtx(user, net, trust, travel, ipBanned) {
    return {
        timeAnomaly: hourAnomaly(), newIp: !networkKnownFor(user, net).known,
        impossibleTravel: travel.impossibleTravel, unrecognizedDevice: !trust.trusted,
        consecutiveFailures: failStreak(user.username), blacklistedIp: ipBanned,
    };
}
function findByIdentifier(id) {
    if (!id) return null;
    const byUser = dbHelpers.getUser(String(id).trim());
    if (byUser) return byUser;
    return findUserByEmail(String(id).trim());
}
function deviceTrustFor(user, fp, cookieToken) {
    if (isTrustedDevice(user.id, fp)) return { trusted: true, via: 'table' };
    const t = readTrust(cookieToken);
    if (t && t.uid === user.id && t.fp === fp && isTrustedDevice(user.id, t.fp)) {
        touchTrustedDevice(user.id, t.fp);
        return { trusted: true, via: 'cookie' };
    }
    return { trusted: false, via: 'none' };
}
function networkKnownFor(user, net) {
    const known = getDbUnscoped().prepare(
        'SELECT 1 k FROM success_logins WHERE username = ? AND subnet = ? LIMIT 1').get(user.username, net.subnet);
    return { known: !!known, via: known ? 'subnet' : 'none' };
}
async function travelAssessment(user, net) {
    const lastIp = lastLoginIpFor(user.id);
    if (!lastIp || lastIp === net.ip) return { impossibleTravel: false, lastIp };
    const d = distanceKm(lastIp, net.ip);
    const elapsedMin = minutesSinceLastLogin(user.id);
    const speedKmMin = d / Math.max(elapsedMin, 0.02);
    const impossible = !!(d > 0) && speedKmMin > POLICY.IMPOSSIBLE_TRAVEL_KM;
    return { impossibleTravel: impossible, distanceKm: Math.round(d), lastIp, speedKmMin: Math.round(speedKmMin) };
}
function minutesSinceLastLogin(uid) {
    const r = getDbUnscoped().prepare(
        'SELECT ts FROM success_logins WHERE username = (SELECT username FROM users WHERE id = ?) ORDER BY id DESC LIMIT 1').get(uid);
    if (!r) return 999;
    return (Date.now() - Date.parse(r.ts)) / 60000;
}
function deviceLabelFromUa(ua = '') {
    const os = (ua.match(/\((.*?)\)/) || [])[1] || 'Unknown Device';
    return 'DEV-' + stableHash(ua ? os : 'none').slice(0, 6) + ' | ' + os;
}
function genTotpSecret() {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let s = '';
    const rnd = randomToken(24).replace(/[-_]/g, '');
    for (const ch of rnd) s += alphabet[ch.charCodeAt(0) % 32];
    return s.slice(0, 16);
}
function sanitizeUser(user) {
    if (!user) return null;
    return {
        id: user.id, username: user.username, role: user.role,
        displayName: user.display_name, email: user.email, phone: user.phone,
        department: user.department, emailVerified: !!user.email_verified,
    };
}

// ---------------------------------------------------------------------------
// Account recovery / MFA reset (optional SRS features)
// ---------------------------------------------------------------------------
function recoveryBase(user, ip, ua = '') {
    const net = analyzeNetwork(ip);
    return {
        ts: nowIso(), username: user.username, role: user.role, user_id: user.id,
        ip: net.ip, subnet: net.subnet, network: net.network,
        device_name: deviceLabelFromUa(ua), browser: ua ? 'desktop' : 'unknown',
        user_agent: ua || '', fingerprint: 'recovery' ,
    };
}

export function requestAccountRecovery({ identifier, ip, ua }) {
    const user = findByIdentifier(identifier);
    if (!user) return { ok: false, error: 'unknown_identifier' };
    const verifyCode = String(Math.floor(100000 + Math.random() * 900000));
    const note = 'recovery requested via registered identity';
    createMfaReset(user.id, stableHash('rr:' + verifyCode), note);
    commitAudit(recoveryBase(user, ip, ua), 'RECOVERY_REQUEST', { risk: 0, factors: [], detail: note });
    return {
        ok: true, userId: user.id, username: user.username,
        verifyCode, note: 'demo channel — code returned once (replace with real email/SMS in production)',
    };
}

export function resetAccountMfa({ identifier, verifyCode, newPassword, ip, ua }) {
    const user = findByIdentifier(identifier);
    if (!user) return { ok: false, error: 'unknown_identifier' };
    const v = verifyMfaReset(user.id, stableHash('rr:' + String(verifyCode || '')));
    if (!v.ok) return { ok: false, error: v.error };
    if (!newPassword || String(newPassword).length < 8) return { ok: false, error: 'weak_password' };

    const newSecret = genTotpSecret();
    updatePasswordAndSecret(user.id, hashPassword(String(newPassword)), newSecret);
    const codes = Array.from({ length: 10 }, () => (Math.random().toString(36).slice(2, 6) + Math.random().toString(36).slice(2, 6)).toUpperCase());
    storeRecoveryCodes(user.id, codes);
    completeMfaReset(user.id);
    commitAudit(recoveryBase(user, ip, ua), 'RECOVERY_RESET', { risk: 0, factors: ['MFA_RESET'], detail: 'password changed + TOTP rotated + recovery codes issued' });
    flagAlert({ severity: 'INFO', category: 'MFA_RESET', title: 'MFA reset completed', detail: `${user.username} rotated TOTP + recovery codes`, username: user.username, risk: 0, ip });
    return {
        ok: true, username: user.username, role: user.role,
        newRecoveryCodes: codes, note: 'single-use recovery codes — store them safely. Rotation notified.',
    };
}

export function validateRecoveryCode({ identifier, code }) {
    const user = findByIdentifier(identifier);
    if (!user) return { ok: false, error: 'unknown_identifier' };
    const ok = recoveryCodeValid(user.id, String(code || ''));
    if (ok) commitAudit(recoveryBase(user, '127.0.0.1'), 'RECOVERY_CODE_VALID', { risk: 0, factors: [], detail: 'recovery code redeemed' });
    return { ok, username: user.username, note: ok ? 'code valid & consumed' : 'invalid or expired code' };
}

// ---------------------------------------------------------------------------
// Sessions / factors / counters
// ---------------------------------------------------------------------------
export function revokeSession(sid) { const s = getSession(sid); if (s) deleteSession(sid); return !!s; }
export function listActiveSessions() { return listSessions(); }
export function myDevices(userId) { return listTrustedDevices(userId); }
export function revokeDevice(userId, fingerprint) { revokeTrustedDevice(userId, fingerprint); }

export function dashboardCounters() {
    const outcomes = ['SUCCESS', 'FAILED_PASSWORD', 'INVALID_OTP', 'EXPIRED_OTP', 'HIGH_RISK_BLOCK', 'STEP_UP'];
    const counters = {};
    for (const o of outcomes) counters[o] = auditCount(o);
    counters.TOTAL = auditCount();
    counters.ALERTS = alertCountSync();
    counters.BLOCKED_IPS = dbHelpers._raw().prepare('SELECT COUNT(*) n FROM blacklist').get().n;
    return counters;
}
export function lockFactors() { return listFactors(); }
export function releaseLockout(username) {
    removeFactor(`LOCKOUT:${username}`); removeFactor(`FAILSTREAK:${username}`); removeFactor(`INVALID_OTP:${username}`);
}
export function getPolicyData() { return { ...POLICY }; }

// Re-exports for routes
export {
    totpNow, auditList, auditCount, successList, alertList, listFactors, clearAllFactors,
    whitelistAll, whitelistAdd, whitelistRemove, blacklistAll, blacklistAdd, blacklistRemove,
    randomToken, analyzeNetwork,
};
