/**
 * AuthShield 360 - Digital Forensic Investigation Service
 *
 * Reconstructs a correlated, chronological event chain ("timeline") straight
 * from the persisted database — audit trail, sessions, successful logins,
 * alerts, pending approvals and attack runs — for any entity (user, IP,
 * device fingerprint) or time window. Investigators can wrap that timeline
 * into a Case and export a Markdown evidence report (Security Test Evidence,
 * SRS 1.9).
 *
 * Every event is self-describing: { ts, kind, ref, title, username, role, ip,
 * network, risk, level, outcome, detail, factors } so the timeline UI can
 * render without extra lookups.
 */
import { rawDb, createCase, listCases, getCase, updateCaseStatus, updateCaseSummary, deleteCase, addCaseItem, listCaseItems } from './db.js';
import { auditList as _audit } from './db.js';

// ---------------------------------------------------------------------------
// Facet counts for drill-down navigation
// ---------------------------------------------------------------------------
export function entityFacets() {
    const db = rawDb();
    const topUsers = db.prepare(
        'SELECT username, COUNT(*) n FROM audit_trail GROUP BY username ORDER BY n DESC LIMIT 12').all();
    const topIps = db.prepare(
        'SELECT ip, network, COUNT(*) n FROM audit_trail GROUP BY ip ORDER BY n DESC LIMIT 12').all();
    const topDevices = db.prepare(
        'SELECT fingerprint, device_name, COUNT(*) n FROM audit_trail GROUP BY fingerprint ORDER BY n DESC LIMIT 12').all();
    const outcomes = db.prepare(
        'SELECT outcome, COUNT(*) n FROM audit_trail GROUP BY outcome ORDER BY n DESC').all();
    const roles = db.prepare(
        'SELECT role, COUNT(*) n FROM audit_trail GROUP BY role ORDER BY n DESC').all();
    return { users: topUsers, ips: topIps, devices: topDevices, outcomes, roles };
}

export function forensicsSummary() {
    const db = rawDb();
    const one = (sql) => Number(db.prepare(sql).get().n);
    return {
        auditEvents: one('SELECT COUNT(*) n FROM audit_trail'),
        alerts: one('SELECT COUNT(*) n FROM alerts'),
        successes: one('SELECT COUNT(*) n FROM success_logins'),
        activeSessions: one('SELECT COUNT(*) n FROM sessions'),
        trustedDevices: one('SELECT COUNT(*) n FROM trusted_devices'),
        attackRuns: one('SELECT COUNT(*) n FROM attack_runs'),
        pendingApprovals: one('SELECT COUNT(*) n FROM pending_approvals'),
        cases: one('SELECT COUNT(*) n FROM cases'),
        caseItems: one('SELECT COUNT(*) n FROM case_items'),
    };
}

// ---------------------------------------------------------------------------
// Timeline reconstruction
// ---------------------------------------------------------------------------
function filterRow(row, f) {
    if (f.user && ![row.username, row.user_id].includes(f.user)) return false;
    if (f.ip && row.ip && row.ip !== f.ip) return false;
    if (f.device && row.fingerprint !== f.device && row.device_hash !== f.device) return false;
    if (f.outcome && row.outcome !== f.outcome) return false;
    if (f.from && row.ts && row.ts < f.from) return false;
    if (f.to && row.ts && row.ts > f.to) return false;
    return true;
}

export function reconstructedTimeline(filters = {}, limit = 500) {
    const db = rawDb();
    const events = [];
    const f = { user: filters.user || null, ip: filters.ip || null, device: filters.device || null, outcome: filters.outcome || null, from: filters.from || null, to: filters.to || null };

    for (const row of db.prepare('SELECT * FROM audit_trail').all()) {
        if (!filterRow(row, f)) continue;
        let factors = [];
        try { factors = JSON.parse(row.factors || '[]'); } catch { /* ignore */ }
        events.push({
            ts: row.ts, kind: 'auth', ref: 'audit-' + row.id, title: row.outcome,
            username: row.username, role: row.role, ip: row.ip,
            network: row.network, risk: row.risk, level: riskLevel(row.risk),
            outcome: row.outcome, detail: row.detail || '', factors,
            sid: row.sid, fingerprint: row.fingerprint, scenario: row.scenario,
            elapsedMs: row.elapsed_ms, deviceName: row.device_name,
        });
    }
    for (const row of db.prepare('SELECT * FROM alerts').all()) {
        if (f.from && row.ts < f.from) continue; if (f.to && row.ts > f.to) continue;
        events.push({
            ts: row.ts, kind: 'alert', ref: 'alert-' + row.id, title: row.title,
            username: row.username || '', role: '', ip: row.ip || '',
            network: '', risk: row.risk ?? 0, level: severityLevel(row.severity),
            outcome: row.category, detail: row.detail || '', factors: [], severity: row.severity,
        });
    }
    for (const row of db.prepare('SELECT * FROM success_logins').all()) {
        if (f.user && row.username !== f.user) continue;
        if (f.ip && row.ip !== f.ip) continue;
        if (f.device && row.device_hash !== f.device) continue;
        events.push({
            ts: row.ts, kind: 'success', ref: 'success-' + row.id, title: 'Successful sign-in',
            username: row.username, role: row.role, ip: row.ip, network: row.network,
            risk: row.risk, level: row.level, outcome: 'SUCCESS', detail: `scenario ${row.scenario} / MFA ${row.mfa || 'NONE'}`,
            factors: [], sid: row.sid, scenario: row.scenario, mfa: row.mfa,
        });
    }
    for (const row of db.prepare('SELECT * FROM sessions').all()) {
        if (f.user && row.username !== f.user && row.user_id !== f.user) continue;
        if (f.ip && row.ip !== f.ip) continue;
        if (f.device && row.fingerprint !== f.device) continue;
        events.push({
            ts: row.created, kind: 'session', ref: 'session-' + row.sid, title: 'Session opened',
            username: row.username, role: row.role, ip: row.ip, network: '',
            risk: 0, level: 'LOW', outcome: 'SESSION', detail: `expires ${row.expires}`,
            factors: [], sid: row.sid,
        });
    }
    for (const row of db.prepare('SELECT * FROM pending_approvals').all()) {
        if (f.user && row.user_id !== f.user) continue;
        if (f.ip && row.new_ip !== f.ip) continue;
        if (f.device && row.new_fp !== f.device) continue;
        events.push({
            ts: row.decided_at || row.created_at, kind: 'pending', ref: 'pending-' + row.id, title: 'Cross-device approval',
            username: row.user_id, role: '', ip: row.new_ip, network: row.location,
            risk: 0, level: statusLevel(row.status), outcome: String(row.status).toUpperCase(),
            detail: `${row.new_label} @ ${row.location} (fallback ${row.fallback_used ? 'used' : 'no'})`,
            factors: [], fingerprint: row.new_fp,
        });
    }
    for (const run of db.prepare('SELECT * FROM attack_runs').all()) {
        let timeline = [];
        try { timeline = JSON.parse(run.timeline || '[]'); } catch { /* ignore */ }
        for (const step of timeline) {
            if (f.from && step.ts < f.from) continue; if (f.to && step.ts > f.to) continue;
            events.push({
                ts: step.ts, kind: 'sim', ref: 'sim-' + run.id + '-' + step.phase, title: 'Attack simulation',
                username: step.username || '', role: '', ip: step.ip || '', network: run.title,
                risk: step.risk ?? 0, level: riskLevel(step.risk ?? 0), outcome: step.label || 'RUNNING',
                detail: `${run.title} · phase ${step.phase}: ${step.message || ''}`,
                factors: step.factors || [], runId: run.id, runStatus: run.status,
            });
        }
    }

    events.sort((a, b) => String(a.ts).localeCompare(String(b.ts)));
    return events.slice(0, limit);
}

function riskLevel(risk) {
    if (risk >= 70) return 'HIGH';
    if (risk >= 31) return 'MEDIUM';
    return 'LOW';
}
function severityLevel(s) { return s === 'CRITICAL' ? 'HIGH' : s === 'WARNING' ? 'MEDIUM' : 'LOW'; }
function statusLevel(s) { return s === 'approved' ? 'LOW' : 'MEDIUM'; }

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------
const caseRef = () => 'CASE-' + Date.now().toString(36).toUpperCase();

export function openInvestigation({ title, severity = 'MEDIUM', scope = {}, createdBy = 'admin', summary = '', autoCapture = true } = {}) {
    const id = caseRef();
    const now = new Date().toISOString();
    createCase({ id, ref: id, title: title || 'Untitled investigation', severity, createdBy, scope, summary, createdAt: now, updatedAt: now });
    if (autoCapture) {
        const timeline = reconstructedTimeline(scope, 1000);
        for (const ev of timeline) {
            addCaseItem({ caseId: id, source: ev.kind, sourceId: ev.ref, ts: ev.ts, payload: ev });
        }
    }
    return getCase(id);
}

export function caseTimeline(caseId) {
    return listCaseItems(caseId);
}

export function updateCase(id, patch) {
    if (patch.status) updateCaseStatus(id, patch.status);
    if (patch.summary !== undefined) updateCaseSummary(id, patch.summary);
    return getCase(id);
}

export function attachToCase(caseId, { kind, ref, payload, note, ts }) {
    addCaseItem({ caseId, source: kind, sourceId: ref, ts: ts || new Date().toISOString(), payload: payload || {}, note: note || '' });
    return getCase(caseId);
}

export function closeCase(id) { return updateCase(id, { status: 'CLOSED' }); }
export function reopenCase(id) { return updateCase(id, { status: 'OPEN' }); }
export function removeCase(id) { deleteCase(id); }

export function listOpenCases(limit = 50) { return listCases(limit); }

export function exportCaseMarkdown(caseId) {
    const c = getCase(caseId);
    if (!c) return null;
    const items = listCaseItems(caseId);
    const scope = c.scope || {};
    const lines = [];
    lines.push(`# Forensic Case — ${c.title}`);
    lines.push('');
    lines.push(`- **Case ref**: ${c.ref}`);
    lines.push(`- **Severity**: ${c.severity}  **Status**: ${c.status}`);
    lines.push(`- **Created by**: ${c.created_by} at ${c.created_at}`);
    lines.push(`- **Scope**: ${JSON.stringify(scope)}`);
    if (c.summary) lines.push(`- **Summary**: ${c.summary}`);
    lines.push('');
    lines.push(`## Evidence timeline (${items.length} events)`);
    lines.push('');
    lines.push('| Time | Kind | Actor | IP | Risk | Event / Detail |');
    lines.push('| --- | --- | --- | --- | --- | --- |');
    for (const it of items) {
        const p = it.payload || {};
        lines.push(`| ${it.ts} | ${it.source} | ${p.username || it.payload?.user_id || ''} | ${p.ip || ''} | ${p.risk ?? ''} | ${String(p.title || p.outcome || it.source).replace(/\|/g, '/')} — ${String(it.note || p.detail || '').replace(/\|/g, '/')} |`);
    }
    lines.push('');
    lines.push(`## Investigation notes`);
    lines.push(`Add-notes-here`);
    lines.push('');
    lines.push(`> Exported by AuthShield 360 Forensics at ${new Date().toISOString()}`);
    return lines.join('\n');
}