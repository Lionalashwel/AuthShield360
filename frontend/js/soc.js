/* Cornell Deep - SOC operator console view */
import { $, $$, api, toast, esc, fmtTime, fmtFull, riskBadge, outcomeChip, levelOf } from './api.js';

let socInitialized = false;

export function initSoc() {
    $('#role-chip').textContent = 'ADMINISTRATOR';
    bindSocStatic();
    refreshDashboard();
    if (!socInitialized) { setInterval(() => refreshHealth(false), 3000); socInitialized = true; }
}

function bindSocStatic() {
    $$('.side .nav').forEach((b) => b.addEventListener('click', () => switchPanel(b.dataset.panel)));
    $('#btn-clear-factors').addEventListener('click', async () => { await api('/api/factors', { method: 'DELETE' }); loadFactors(); toast('Threat factors cleared.', 'ok'); });
    $('#btn-arm').addEventListener('click', async () => { await api('/api/arm-mode', { method: 'POST' }); loadFactors(); toast('SYSTEM ARMED — testing live.', 'ok'); });
    $('#btn-standby').addEventListener('click', async () => { await api('/api/security-policy?standby=true', { method: 'PUT' }); loadFactors(); toast('Defense standby engaged.', 'warn'); });
    $('#btn-release').addEventListener('click', async () => { const u = $('#release-user').value.trim(); if (!u) return; await api('/api/factors/lockout?username=' + encodeURIComponent(u), { method: 'DELETE' }); toast('Lockout released for ' + u, 'ok'); loadFactors(); });
    $('#btn-bl-add').addEventListener('click', async () => { const ip = $('#bl-ip').value.trim(); if (!ip) return; await api('/api/blacklist', { method: 'POST', body: { ip, reason: 'manual' } }); toast('Blacklisted ' + ip, 'ok'); $('#bl-ip').value = ''; loadLists(); });
    $('#btn-sim').addEventListener('click', () => {
        if (window.__runningSim) return;
        window.__runningSim = true;
        $('#btn-sim').disabled = true;
        api('/api/simulate', { method: 'POST', body: { type: $('#sim-type').value } })
            .then((r) => {
                if (r.ok) { toast('Attack launched: ' + r.status, 'warn'); $('#sim-live').textContent = 'running · ' + $('#sim-type').value; refreshSimLive(); }
                else toast(r.error || 'simulation failed', 'crit');
            })
            .finally(() => setTimeout(() => { $('#btn-sim').disabled = false; $('#sim-live').textContent = 'idle'; window.__runningSim = false; }, 9000));
    });
    $('#af-apply').addEventListener('click', loadAudit);
    $('#af-user').addEventListener('input', () => { if (event.key === 'Enter') loadAudit(); });
}

export function switchPanel(name) {
    $$('.side .nav').forEach((b) => b.classList.toggle('on', b.dataset.panel === name));
    $$('.main .panel').forEach((p) => p.classList.toggle('hidden', p.id !== 'panel-' + name));
    loadPanel(name);
}
function loadPanel(name) {
    if (name === 'overview') refreshDashboard();
    if (name === 'sessions') loadSessions();
    if (name === 'devices') loadDevices();
    if (name === 'audit' || name === 'overview') loadAudit();
    if (name === 'factors') loadFactors();
    if (name === 'blacklist') loadLists();
    if (name === 'sim') loadSims();
}

export async function refreshDashboard() {
    const d = await api('/api/dashboard');
    if (!d.ok) return;
    const c = d.counters || {};
    $('#g-succ').textContent = c.SUCCESS || 0;
    $('#g-fail').textContent = (c.FAILED_PASSWORD || 0);
    $('#g-otp').textContent = (c.INVALID_OTP || 0) + (c.EXPIRED_OTP || 0);
    $('#g-step').textContent = c.STEP_UP || 0;
    $('#ov-feed').textContent = (d.events || []).length + ' recent events';
    $('#ov-ts').textContent = 'updated ' + fmtTime(new Date());
    renderFeed($('#feed tbody'), d.events);
}
export async function refreshHealth(clear) {
    const h = await api('/api/health');
    if (!h.ok) return;
    $('#g-live').textContent = h.listeners || 0;
    $('#arm-badge').textContent = h.health?.defenseStandby ? '⚡ STANDBY' : '🛡️ ARMED';
    const c = h.health?.counters || {};
    $('#g-block').textContent = c.blockedIps || 0;
    $('#g-alert').textContent = c.alerts || 0;
    $('#g-succ').textContent = c.success || 0;
    $('#g-fail').textContent = c.failedPassword || 0;
    $('#g-otp').textContent = (c.invalidOtp || 0) + (c.expiredOtp || 0);
    $('#g-step').textContent = c.stepUp || 0;
}
export function refreshLiveFeed(fresh) {
    api('/api/dashboard').then((d) => { if (d.ok) { renderFeed($('#feed tbody'), d.events.slice(0, 8)); if (fresh) $('#ov-feed').textContent = 'live'; } });
}

function renderFeed(tbody, events) {
    tbody.innerHTML = (events || []).map((e) => `<tr>
        <td>${fmtTime(e.ts)}</td><td>${outcomeChip(e.outcome)}</td><td>${esc(e.username || '—')}</td><td>${esc(e.role || '')}</td>
        <td>${riskBadge(e.risk, levelOf(e.risk))}</td>
        <td>${esc(e.ip || '')} · ${esc(e.network || '')}</td><td>${esc((e.factors || []).join(', ') || '—')}</td>
    </tr>`).join('') || `<tr><td colspan="7" class="empty">No events yet.</td></tr>`;
}

export async function loadAudit() {
    const q = new URLSearchParams();
    const o = $('#af-outcome').value; if (o) q.set('outcome', o);
    const role = $('#af-role').value; if (role) q.set('role', role);
    const u = $('#af-user').value.trim(); if (u) q.set('user', u);
    const d = await api('/api/audit?' + q.toString());
    const rows = (d.events || []).map((e) => `<tr>
        <td>${fmtFull(e.ts)}</td><td>${outcomeChip(e.outcome)}</td><td>${esc(e.username || '—')} <small>(${esc(e.role || '')})</small></td>
        <td>${riskBadge(e.risk, levelOf(e.risk))}</td>
        <td>${esc((e.factors ? JSON.parse(e.factors || '[]').join(', ') : '') || e.detail || e.ip || '')}</td></tr>`).join('');
    $('#audit tbody').innerHTML = rows || `<tr><td colspan="5" class="empty">Empty audit log.</td></tr>`;
}

async function loadSessions() {
    const d = await api('/api/sessions');
    $('#sess tbody').innerHTML = (d.sessions || []).map((s) => `<tr>
        <td>${esc(s.username)} <small>(${esc(s.role)})</small></td><td>${esc(s.ip)}</td><td>${esc(s.network)}</td>
        <td>${esc(s.mfa || '—')}</td><td>${fmtFull(s.created)}</td>
        <td><button class="btn sm out" data-kill="${esc(s.sid)}">Terminate</button></td></tr>`).join('');
    $('#sess tbody').querySelectorAll('[data-kill]').forEach((b) => b.addEventListener('click', async () => {
        await api('/api/session/demote', { method: 'POST', body: { sid: b.dataset.kill } }); loadSessions(); toast('Session terminated.', 'ok');
    }));
}
async function loadDevices() {
    const d = await api('/api/devices');
    $('#devices tbody').innerHTML = (d.devices || []).map((t) => `<tr>
        <td>${esc(t.username || 'user #' + t.user_id)}</td><td>${esc(t.label || '—')}</td><td>${esc(t.browser || t.ua || '—')}</td>
        <td><code>${esc(t.fingerprint || '')}</code></td><td>${fmtFull(t.last_seen)}</td></tr>`).join('');
}
async function loadFactors() {
    const d = await api('/api/factors');
    $('#factors tbody').innerHTML = (d.factors || []).map((f) => `<tr><td>${fmtFull(f.ts)}</td><td>${esc(f.risk || '')}</td><td>${esc(f.level || '')}</td><td>${esc(f.label || '')}</td></tr>`).join('');
}
async function loadLists() {
    const d = await api('/api/lists');
    $('#blacklist tbody').innerHTML = (d.blacklist || []).map((b) => `<tr>
        <td><code>${esc(b.ip)}</code></td><td>${esc(b.reason)}</td><td>${fmtFull(b.ts)}</td>
        <td><button class="btn sm out" data-unbl="${esc(b.ip)}">Unblock</button></td></tr>`).join('');
    $('#blacklist tbody').querySelectorAll('[data-unbl]').forEach((b) => b.addEventListener('click', async () => {
        await api('/api/blacklist?ip=' + encodeURIComponent(b.dataset.unbl), { method: 'DELETE' }); loadLists(); toast('Unblocked ' + b.dataset.unbl, 'ok');
    }));
}

/* sim */
export async function loadSims() {
    const d = await api('/api/simulations');
    $('#sims tbody').innerHTML = (d.simulations || []).slice().reverse().map((s) => `<tr>
        <td><code>${esc(s.id)}</code></td><td>${esc(s.title)}</td><td>${esc(s.status)}</td><td>${(s.timeline || []).length}</td></tr>`).join('');
    const latest = (d.simulations || [])[d.simulations.length - 1];
    if (latest) renderTimeline($('#timeline'), latest.timeline || []);
}
export function renderTimeline(host, tl) {
    if (!tl || !tl.length) { host.innerHTML = `<div class="empty">No telemetry yet.</div>`; return; }
    host.innerHTML = tl.map((e) => `<div class="tl-row">
        <span class="tl-dot st-${(e.status || 'INFO').toLowerCase()}"></span>
        <div class="tl-body"><div class="tl-text">${esc(e.text)}</div>
        <div class="tl-meta">${fmtTime(e.ts)} · phase ${e.phase} · ${esc(e.status)}</div></div></div>`).join('');
}
export function refreshSimLive(ev) {
    api('/api/simulations').then((d) => {
        const latest = (d.simulations || [])[d.simulations.length - 1];
        if (latest) {
            renderTimeline($('#timeline'), latest.timeline || []);
            renderTimeline($('#timeline-2'), latest.timeline || []);
            loadSims();
        }
    });
}