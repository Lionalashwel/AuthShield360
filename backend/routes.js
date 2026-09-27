/**
 * AuthShield 360 - HTTP API router (single mounted router under /api)
 *
 * Sections:
 *   meta          · health, identity init, demo OTPs, roles, SSE stream
 *   registration  · register + real e-mail verify → trusted device
 *   authentication· login orchestrator (S1/S2/S3), pending approvals
 *   sessions      · active sessions, remote termination
 *   user          · self-service security center, devices
 *   recovery      · account recovery / MFA reset (optional SRS features)
 *   portal        · fictional school modules with strict RBAC (SRS 1.6)
 *   soc           · monitoring dashboard, audit filtering, factors, policy
 *   lists         · whitelist / blacklist management
 *   benchmarks    · authentication-mode comparison (real measured data)
 *   simulations   · controlled attack engine A/B/C
 *   forensics     · digital forensic investigations with reconstructed timelines
 */
import express from 'express';
import {
    attemptAuthentication, registerAccount, verifyEmail, currentTrustedSession,
    decisionOnPending, pendingStatus, finalizeApprovedLogin,
    revokeSession, listActiveSessions, myDevices, revokeDevice,
    releaseLockout, dashboardCounters,
    auditList, auditCount, successList, alertList, listFactors, clearAllFactors,
    totpNow, whitelistAll, whitelistAdd, whitelistRemove,
    blacklistAll, blacklistAdd, blacklistRemove, analyzeNetwork,
    requestAccountRecovery, resetAccountMfa, validateRecoveryCode,
} from './auth.js';
import { createSimulation, listSimulations, ATTACK_TYPES } from './sme.js';
import { listenerCount, subscribeEvents } from './events.js';
import { dbHelpers, userById, listTrustedDevices, auditFiltered, getCase } from './db.js';
import { POLICY } from './config.js';
import { publishedHealth, setHealthFlag } from './health.js';
import { validatePortalSession, requireRoles, portalOverview, portalSvc } from './portal.js';
import { benchmarkAll } from './benchmark.js';
import {
    entityFacets, forensicsSummary, reconstructedTimeline, openInvestigation,
    caseTimeline, updateCase, attachToCase, closeCase, removeCase,
    listOpenCases, exportCaseMarkdown,
} from './forensics.js';

const r = express.Router();
const HTTP = { OK: 200, CREATED: 201, BAD: 400, UNAUTH: 401, FORBIDDEN: 403, NOTFOUND: 404 };

const parseCookies = (hdr = '') => Object.fromEntries(
    hdr.split(';').filter(Boolean).map((p) => { const i = p.indexOf('='); return [p.slice(0, i).trim(), p.slice(i + 1).trim()]; }),
);

function ctxOf(req) {
    const ua = req.headers['user-agent'] || '';
    const cookie = parseCookies(req.headers.cookie || '');
    return {
        ip: (req.headers['x-forwarded-for'] || req.headers['cf-connecting-ip'] || '').split(',')[0].trim() || req.socket.remoteAddress || '127.0.0.1',
        ua,
        fingerprint: (req.headers['x-fp'] || '').trim() || `${ua}|${req.socket.remoteAddress}|gen`,
        browser: req.headers['sec-ch-ua-mobile'] ? 'mobile' : 'desktop',
        deviceLabel: (req.headers['x-device'] || '').trim() || 'Unknown Device',
        cookieToken: cookie[POLICY.TRUST_COOKIE] || null,
    };
}
function baseUrl(req) {
    return `${req.protocol}://${req.get('host')}`;
}
function adminGate(req, res, next) {
    const sid = req.headers['x-session-side'];
    const ok = sid && req.app.locals.sidSet && req.app.locals.sidSet.has(sid);
    if (!ok) return res.status(HTTP.FORBIDDEN).json({ ok: false, error: 'ADMIN_SESSION_REQUIRED' });
    next();
}
function portalGate(roles) {
    return (req, res, next) => {
        const v = validatePortalSession({ sid: req.headers['x-session-sid'], userId: req.headers['x-user-id'] });
        if (!v.ok) return res.status(HTTP.UNAUTH).json({ ok: false, error: v.error });
        if (roles && !requireRoles(v.user, roles)) {
            return res.status(HTTP.FORBIDDEN).json({ ok: false, error: 'PORTAL_RBAC_DENIED', role: v.user.role, requires: roles });
        }
        req.portalUser = v.user;
        req.portalSession = v.session;
        next();
    };
}
function trackSession(app, session) {
    const map = (app.locals.sidSet = app.locals.sidSet || new Map());
    if (session && session.sid) map.set(session.sid, true);
}

// ---------------------------------------------------------------------------
// Health / meta
// ---------------------------------------------------------------------------
r.get('/health', (_req, res) => {
    res.json({ ok: true, service: 'authshield360', listeners: listenerCount(), health: publishedHealth(), defenseStandby: POLICY.DEFENSE_STANDBY, ts: new Date().toISOString() });
});
r.get('/identity/init', (req, res) => {
    const net = analyzeNetwork(req.socket.remoteAddress);
    res.json({
        ok: true,
        seedAccounts: dbHelpers.listUsersWithSecrets().map((u) => ({
            username: u.username, role: u.role, department: u.department,
            displayName: u.display_name, email: u.email, phone: u.phone,
            demoOtp: totpNow(u.totp_secret),
        })),
        network: net,
        scenarioLabels: {
            1: 'Password-only baseline',
            2: 'Password + Mobile OTP MFA',
            3: 'Password + Mobile OTP + Email Step-Up + RBAC',
        },
        attackTypes: ATTACK_TYPES,
    });
});
r.get('/identity/otps', (req, res) => {
    try {
        res.json({ ok: true, otps: dbHelpers.listUsersWithSecrets().map((u) => ({ username: u.username, demoOtp: totpNow(u.totp_secret) })) });
    } catch { res.status(HTTP.BAD).json({ ok: false, error: 'totp_error' }); }
});

// ---------------------------------------------------------------------------
// Registration → verification (real e-mail)
// ---------------------------------------------------------------------------
r.post('/auth/register', async (req, res) => {
    const body = req.body || {};
    const out = await registerAccount({
        email: body.email, password: body.password, nationalId: body.nationalId,
        fullName: body.fullName, baseUrl: baseUrl(req),
    });
    res.status(out.ok ? HTTP.CREATED : HTTP.BAD).json(out);
});

r.get('/verify', async (req, res) => {
    const token = req.query.token || '';
    const ctx = ctxOf(req);
    const out = verifyEmail(token, { ip: ctx.ip, ua: ctx.ua, fallbackFingerprint: String(req.query.fp || req.headers['x-fp'] || '').trim() || undefined });
    if (!out.ok) {
        res.status(HTTP.BAD).send(`<meta charset="utf-8"><body style="background:#05070d;color:#f87171;font-family:sans-serif;padding:40px"><h1>Verification failed</h1><p>${out.error}</p></body>`);
        return;
    }
    res.setHeader('Set-Cookie', `${POLICY.TRUST_COOKIE}=${out.cookieToken}; HttpOnly; Path=/; Max-Age=31536000; SameSite=Lax`);
    res.send(`<!doctype html><html><body style="background:#05070d;color:#e6ecff;font-family:sans-serif;padding:40px">
      <h1 style="color:#34d399">Email verified ✓</h1>
      <p>This browser/device is now <b>Trusted</b> for <b>${out.user.username}</b>.</p>
      <p>Open <a href="/" style="color:#38bdf8">the login</a> in a DIFFERENT browser/incognito window and sign in
      to trigger the Cross-Device Approval flow.</p>
      <p style="color:#8fa3c8;font-size:13px">Trusted fingerprint: <code>${out.fingerprint}</code></p>
      <script>fetch('/api/me').then(r=>r.json()).then(d=>{ if(d.trusted){ document.title='trusted'; } });</script>
    </body></html>`);
});

r.get('/me', (req, res) => {
    const ctx = ctxOf(req);
    res.json(currentTrustedSession(ctx.cookieToken));
});

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------
r.post('/auth/login', async (req, res) => {
    const body = req.body || {};
    const ctx = ctxOf(req);
    const result = await attemptAuthentication({
        identifier: body.identifier || body.username, username: body.username,
        password: body.password, otp: body.otp, emailCode: body.emailCode,
        scenario: Number(body.scenario) || 1,
        ip: ctx.ip, ua: ctx.ua, browser: ctx.browser, deviceLabel: ctx.deviceLabel,
        fingerprint: ctx.fingerprint, cookieToken: ctx.cookieToken,
    });
    trackSession(req.app, result.session);
    if (result.trustCookieToken) {
        res.setHeader('Set-Cookie', `${POLICY.TRUST_COOKIE}=${result.trustCookieToken}; HttpOnly; Path=/; Max-Age=31536000; SameSite=Lax`);
    }
    res.json(result);
});

// ---------------------------------------------------------------------------
// Cross-device approvals
// ---------------------------------------------------------------------------
r.post('/pending/:id/approve', (req, res) => res.json(decisionOnPending({ pendingId: req.params.id, approve: true })));
r.post('/pending/:id/deny', (req, res) => res.json(decisionOnPending({ pendingId: req.params.id, approve: false })));
r.get('/pending/:id/status', (req, res) => res.json(pendingStatus(req.params.id)));
r.post('/pending/:id/finalize', (req, res) => {
    const out = finalizeApprovedLogin({ pendingId: req.params.id, fp: (req.body || {}).fp });
    trackSession(req.app, out.session);
    if (out.trustCookieToken) {
        res.setHeader('Set-Cookie', `${POLICY.TRUST_COOKIE}=${out.trustCookieToken}; HttpOnly; Path=/; Max-Age=31536000; SameSite=Lax`);
    }
    res.json(out);
});

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------
r.post('/session/demote', (req, res) => {
    const sid = (req.headers['x-session'] || req.body?.sid || '').trim();
    if (!sid) return res.status(HTTP.BAD).json({ ok: false, error: 'sid_required' });
    res.json({ ok: true, sid, revoked: revokeSession(sid) });
});
r.get('/sessions', (req, res) => res.json({ ok: true, sessions: listActiveSessions() }));

// ---------------------------------------------------------------------------
// User (self-service) security center
// ---------------------------------------------------------------------------
r.get('/my', (req, res) => {
    const uid = (req.query.userId || req.headers['x-user-id'] || '').trim();
    const user = uid && userById(uid);
    if (!user) return res.status(HTTP.BAD).json({ ok: false, error: 'user_unknown' });
    const devices = myDevices(uid);
    const mySessions = listActiveSessions().filter((s) => s.user_id === uid);
    const myActivity = auditList(200).filter((a) => a.user_id === uid && a.outcome !== 'STEP_UP').slice(0, 25)
        .map((a) => ({ ts: a.ts, outcome: a.outcome, ip: a.ip, network: a.network, risk: a.risk, scenario: a.scenario, reasons: JSON.parse(a.factors || '[]') }));
    res.json({ ok: true, user: { ...user, pw_hash: undefined, totp_secret: undefined }, devices, sessions: mySessions, activity: myActivity, recoveryAvailable: true });
});
r.post('/my/device/revoke', (req, res) => {
    const uid = String(req.body?.userId || '').trim();
    const fp = String(req.body?.fingerprint || '').trim();
    if (!uid || !fp) return res.status(HTTP.BAD).json({ ok: false, error: 'params' });
    revokeDevice(uid, fp);
    res.json({ ok: true, revoked: fp });
});
r.get('/devices', adminGate, (req, res) => res.json({ ok: true, devices: listTrustedDevices() }));

// ---------------------------------------------------------------------------
// Account recovery / MFA reset (optional SRS features)
// ---------------------------------------------------------------------------
r.post('/recovery/request', (req, res) => {
    const ctx = ctxOf(req);
    const out = requestAccountRecovery({ identifier: (req.body || {}).identifier, ip: ctx.ip, ua: ctx.ua });
    res.status(out.ok ? HTTP.OK : HTTP.BAD).json(out);
});
r.post('/recovery/reset', (req, res) => {
    const ctx = ctxOf(req);
    const b = req.body || {};
    const out = resetAccountMfa({ identifier: b.identifier, verifyCode: b.verifyCode, newPassword: b.newPassword, ip: ctx.ip, ua: ctx.ua });
    res.status(out.ok ? HTTP.OK : HTTP.BAD).json(out);
});
r.post('/recovery/validate', (req, res) => {
    const b = req.body || {};
    res.json(validateRecoveryCode({ identifier: b.identifier, code: b.code }));
});

// ---------------------------------------------------------------------------
// School portal (fictional modules, strict RBAC)
// ---------------------------------------------------------------------------
r.get('/portal/session', portalGate(), (req, res) => {
    const user = req.portalUser;
    res.json({ ok: true, user: { id: user.id, username: user.username, role: user.role, displayName: user.display_name, department: user.department }, overview: portalOverview(user) });
});
r.get('/portal/courses', portalGate(), (req, res) => res.json({ ok: true, courses: portalSvc.courses(req.portalUser.role, req.portalUser.username) }));
r.get('/portal/grades', portalGate(['STUDENT', 'TEACHER', 'ADMINISTRATOR']), (req, res) => res.json({ ok: true, grades: portalSvc.grades(req.portalUser.role, req.portalUser.username) }));
r.get('/portal/assignments', portalGate(), (req, res) => res.json({ ok: true, assignments: portalSvc.assignments(req.portalUser.role, req.portalUser.username) }));
r.get('/portal/attendance', portalGate(), (req, res) => res.json({ ok: true, attendance: portalSvc.attendance(req.portalUser.role, req.portalUser.username) }));
r.get('/portal/rosters', portalGate(['TEACHER', 'ADMINISTRATOR']), (req, res) => res.json({ ok: true, rosters: portalSvc.rosters(req.portalUser.role, req.portalUser.username) }));
r.get('/portal/matrix', portalGate(['ADMINISTRATOR']), (req, res) => res.json({ ok: true, matrix: portalSvc.matrix() }));
r.get('/portal/users', portalGate(['ADMINISTRATOR']), (req, res) => res.json({ ok: true, users: portalSvc.users('ADMINISTRATOR') }));

// ---------------------------------------------------------------------------
// SOC dashboard + audit filtering
// ---------------------------------------------------------------------------
r.get('/dashboard', (req, res) => {
    res.json({
        ok: true,
        counters: dashboardCounters(),
        events: auditList(50).map((e) => ({
            ts: e.ts, outcome: e.outcome, username: e.username, role: e.role,
            risk: e.risk, factors: JSON.parse(e.factors || '[]'), network: e.network, ip: e.ip, scenario: e.scenario,
        })),
        alerts: alertList(30),
    });
});
r.get('/audit', (req, res) => {
    const q = req.query;
    res.json({
        ok: true,
        events: auditFiltered({
            outcome: q.outcome || null, role: q.role || null,
            username: q.user || null, from: q.from || null, to: q.to || null,
            limit: Math.min(Number(q.limit) || 200, 500),
        }),
    });
});

// ---------------------------------------------------------------------------
// Benchmark: authentication-mode comparison
// ---------------------------------------------------------------------------
r.get('/benchmark', (req, res) => res.json({ ok: true, benchmark: benchmarkAll() }));
r.get('/benchmark/scenario/:n', (req, res) => {
    const n = Number(req.params.n);
    if (![1, 2, 3].includes(n)) return res.status(HTTP.BAD).json({ ok: false, error: 'scenario_invalid' });
    const all = benchmarkAll();
    res.json({ ok: true, scenario: all.scenarios.find((s) => s.scenario === n) });
});

// ---------------------------------------------------------------------------
// Threat factors / policy
// ---------------------------------------------------------------------------
r.get('/factors', (req, res) => res.json({ ok: true, factors: listFactors() }));
r.delete('/factors', (req, res) => { clearAllFactors(); res.json({ ok: true, cleared: true }); });
r.delete('/factors/lockout', (req, res) => {
    const username = (req.query.username || '').trim();
    if (!username) return res.status(HTTP.BAD).json({ ok: false, error: 'username_required' });
    releaseLockout(username);
    res.json({ ok: true, released: username });
});
r.put('/security-policy', adminGate, (req, res) => {
    const standby = String(req.query.standby || '').toLowerCase() === 'true';
    setHealthFlag({ defenseStandby: standby, note: 'policy updated by admin' });
    res.json({ ok: true, defenseStandby: POLICY.DEFENSE_STANDBY, note: 'policy written' });
});
r.post('/arm-mode', adminGate, (req, res) => {
    clearAllFactors();
    setHealthFlag({ defenseStandby: false, note: 'armed. brute-force testing live.' });
    res.json({ ok: true, armed: true });
});

// ---------------------------------------------------------------------------
// Whitelist / Blacklist
// ---------------------------------------------------------------------------
r.get('/lists', adminGate, (req, res) => res.json({ ok: true, whitelist: whitelistAll(), blacklist: blacklistAll() }));
r.post('/whitelist', adminGate, (req, res) => {
    const { ip, label } = req.body || {};
    if (!ip) return res.status(HTTP.BAD).json({ ok: false, error: 'ip_required' });
    whitelistAdd(ip, label || 'manual'); res.json({ ok: true });
});
r.delete('/whitelist', adminGate, (req, res) => {
    const ip = (req.query.ip || '').trim();
    if (!ip) return res.status(HTTP.BAD).json({ ok: false, error: 'ip_required' });
    whitelistRemove(ip); res.json({ ok: true });
});
r.post('/blacklist', adminGate, (req, res) => {
    const { ip, reason } = req.body || {};
    if (!ip) return res.status(HTTP.BAD).json({ ok: false, error: 'ip_required' });
    blacklistAdd(ip, reason || 'manual block'); res.json({ ok: true });
});
r.delete('/blacklist', adminGate, (req, res) => {
    const ip = (req.query.ip || '').trim();
    if (!ip) return res.status(HTTP.BAD).json({ ok: false, error: 'ip_required' });
    blacklistRemove(ip); res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Attack simulations
// ---------------------------------------------------------------------------
r.post('/simulate', adminGate, (req, res) => {
    const type = String((req.body && req.body.type) || 'A').toUpperCase();
    const hasType = ATTACK_TYPES.some((t) => t.type === type);
    const title = (req.body && req.body.title) || (hasType ? ATTACK_TYPES.find((t) => t.type === type).label : 'Attack simulation');
    const run = createSimulation(hasType ? type : 'A', title);
    res.json({ ok: true, id: run.id, status: 'RUNNING', note: 'streaming on SSE' });
});
r.get('/simulations', (req, res) => res.json({ ok: true, simulations: listSimulations() }));

// ---------------------------------------------------------------------------
// Forensics (digital investigation dashboard)
// ---------------------------------------------------------------------------
r.get('/forensics/summary', adminGate, (_req, res) => res.json({ ok: true, summary: forensicsSummary() }));
r.get('/forensics/entities', adminGate, (_req, res) => res.json({ ok: true, facets: entityFacets() }));
r.get('/forensics/timeline', adminGate, (req, res) => {
    const q = req.query;
    const from = q.from ? new Date(q.from).toISOString() : null;
    const to = q.to ? new Date(q.to).toISOString() : null;
    res.json({
        ok: true,
        timeline: reconstructedTimeline({
            user: q.user || null, ip: q.ip || null, device: q.device || null,
            outcome: q.outcome || null, from, to,
            limit: Math.min(Number(q.limit) || 500, 1500),
        }),
    });
});
r.post('/forensics/cases', adminGate, (req, res) => {
    const b = req.body || {};
    const c = b.scope && Object.keys(b.scope).length ? b.scope : { user: b.user, ip: b.ip, device: b.device, outcome: b.outcome };
    const created = openInvestigation({ title: b.title, severity: b.severity || 'MEDIUM', scope: c, summary: b.summary, createdBy: 'admin' });
    res.json({ ok: true, case: created });
});
r.get('/forensics/cases', adminGate, (_req, res) => res.json({ ok: true, cases: listOpenCases() }));
r.get('/forensics/cases/:id', adminGate, (req, res) => {
    const c = getCase(req.params.id);
    if (!c) return res.status(HTTP.NOTFOUND).json({ ok: false, error: 'case_not_found' });
    res.json({ ok: true, case: c, timeline: caseTimeline(req.params.id) });
});
r.post('/forensics/cases/:id/items', adminGate, (req, res) => {
    const b = req.body || {};
    const c = attachToCase(req.params.id, { kind: b.kind || 'note', ref: b.ref || 'note-' + Date.now(), payload: b.payload, note: b.note, ts: b.ts });
    res.json({ ok: true, case: c });
});
r.patch('/forensics/cases/:id', adminGate, (req, res) => {
    const c = updateCase(req.params.id, { status: (req.body || {}).status, summary: (req.body || {}).summary });
    res.json({ ok: true, case: c });
});
r.post('/forensics/cases/:id/export', adminGate, (req, res) => {
    const md = exportCaseMarkdown(req.params.id);
    if (md === null) return res.status(HTTP.NOTFOUND).json({ ok: false, error: 'case_not_found' });
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.json({ ok: true, markdown: md, filename: `${req.params.id}-evidence.md` });
});
r.delete('/forensics/cases/:id', adminGate, (req, res) => {
    removeCase(req.params.id);
    res.json({ ok: true });
});
r.post('/forensics/cases/:id/close', adminGate, (req, res) => res.json({ ok: true, case: closeCase(req.params.id) }));

// ---------------------------------------------------------------------------
// Real-time SSE (global + filtered per-user cross-device)
// ---------------------------------------------------------------------------
r.get('/stream', (req, res) => {
    const ctx = ctxOf(req);
    const trust = currentTrustedSession(ctx.cookieToken);
    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();
    const topics = ['*'];
    if (trust.trusted && trust.user) topics.push('cross:' + trust.user.id);
    const off = subscribeEvents((json) => res.write(`data: ${json}\n\n`), topics);
    res.write(`event: hello\ndata: ${JSON.stringify({ ts: new Date().toISOString(), listeners: listenerCount(), trusted: trust.trusted })}\n\n`);
    req.on('close', () => off());
});

r.get('/meta/roles', (req, res) => res.json({ ok: true, roles: ['STUDENT', 'TEACHER', 'ADMINISTRATOR'] }));

export default r;