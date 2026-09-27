/* Cornell Deep - SPA boot, ingest, routing, realtime channels */
import { $, $$, api, toast, esc, state, saveSession, restoreSession } from './api.js';
import { initSoc, switchPanel, refreshLiveFeed, refreshSimLive, refreshHealth } from './soc.js';
import { initUser, bindRecovery } from './user.js';
import { initPortal } from './portal.js';
import { initForensics, initBench } from './forensics.js';

const $INGEST = () => $('#view-ingest');
const $APP = () => $('#view-app');

/* ───────────────────────────── themes (Light / Ocean) ───────────────────────────── */
const THEME_KEY = 'cornell-theme';
const THEMES = ['light', 'ocean'];

function activeTheme() {
    return THEMES.includes(document.documentElement.dataset.theme) ? document.documentElement.dataset.theme : 'light';
}

function applyTheme(name) {
    const theme = THEMES.includes(name) ? name : 'light';
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem(THEME_KEY, theme); } catch (e) { /* private mode */ }
    $$('.theme-btn').forEach((b) => b.classList.toggle('on', b.dataset.themeSet === theme));
    document.dispatchEvent(new CustomEvent('themechange', { detail: { theme } }));
}

function initThemes() {
    applyTheme(activeTheme());
    document.addEventListener('click', (e) => {
        const btn = e.target.closest('.theme-btn');
        if (btn) applyTheme(btn.dataset.themeSet);
    });
}

/* ───────────────────────────── boot ───────────────────────────── */
window.addEventListener('DOMContentLoaded', () => {
    initThemes();
    if (restoreSession()) enterApp();
    else showIngest();
});

function showIngest() {
    $INGEST().classList.remove('hidden');
    $APP().classList.add('hidden');
    $APP().dataset.role = '';
    $$('.tab').forEach((t) => t.addEventListener('click', () => switchTab(t.dataset.tab)));
    $('#login-form').addEventListener('submit', onLogin, { once: false });
    $('#reg-form').addEventListener('submit', onRegister);
    $('#li-pass').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#li-btn').click(); });
    $('#pb-cancel').addEventListener('click', () => { cancelPending(); });
}

function switchTab(which) {
    $$('.tab').forEach((t) => t.classList.toggle('on', t.dataset.tab === which));
    $('#login-form').classList.toggle('hidden', which !== 'login');
    $('#reg-form').classList.toggle('hidden', which !== 'register');
}

/* ───────────────────────────── register ───────────────────────────── */
async function onRegister(e) {
    e.preventDefault();
    const msg = $('#rg-msg');
    msg.className = 'msg';
    msg.textContent = 'registering…';
    const body = { fullName: $('#rg-name').value, email: $('#rg-email').value, nationalId: $('#rg-nid').value, password: $('#rg-pass').value };
    const r = await api('/api/auth/register', { method: 'POST', body });
    if (!r.ok) { msg.className = 'msg err-box'; msg.innerHTML = `<b>⚠️ ${esc(r.error || 'registration failed')}</b>`; return; }
    // Pass the browser's own persistent fingerprint so the verify route
    // designates THIS device (same fingerprint) as trusted → single match.
    const sep = (r.verifyUrl || '').includes('?') ? '&' : '?';
    const ver = (r.verifyUrl || '') + sep + 'fp=' + encodeURIComponent(state.fp);
    msg.className = 'msg ok-box';
    msg.innerHTML = `<b>✅ Account created.</b> E-mail verification sent.<br/>
        <a href="${esc(ver)}" target="_blank">${esc(ver)}</a><br/>
        <code class="mono">demo mailbox ${esc((r.mail && r.mail.previewUrl) || 'mailer degraded — code shown' )}</code><br/>
        <code class="mono">${esc(r.username || '')}</code>`;
}

/* ───────────────────────────── pending approval ───────────────────────────── */
let pendingTimer = null;
function cancelPending() {
    clearInterval(pendingTimer); pendingTimer = null;
    state.pending = null;
    $('#pending-box').classList.add('hidden');
    $('#login-form').classList.remove('hidden');
    $('#li-btn').disabled = false;
}
function startPending(p) {
    state.pending = { id: p.pendingId, fallbackAt: Number(p.fallbackAt) || 45000 };
    $('#login-form').classList.add('hidden');
    $('#reg-form').classList.add('hidden');
    $('#pending-box').classList.remove('hidden');
    $('#li-btn').disabled = true;
    const span = $('#pb-countdown');
    const tick = () => {
        const left = Math.max(0, Math.ceil((state.pending.fallbackAt - (Date.now() - state.pending.t0)) / 1000));
        span.textContent = left + ' s';
        if (left === 0) { clearInterval(pendingTimer); pendingTimer = null; toast('Approval window closed — please retry.', 'warn'); cancelPending(); }
    };
    state.pending.t0 = Date.now();
    tick();
    pendingTimer = setInterval(tick, 1000);
    pollPending();
}
async function pollPending() {
    if (!state.pending) return;
    const r = await api('/api/pending/' + state.pending.id + '/status');
    if (r.status === 'approved') {
        const fin = await api('/api/pending/' + state.pending.id + '/finalize', { method: 'POST', body: { fp: state.fp } });
        if (fin.ok && fin.session) { saveSession(fin); cancelPending(); enterApp(); toast('Signed in from trusted device approval.', 'ok'); return; }
    }
    if (r.status === 'denied') { toast('Sign-in denied on your trusted device.', 'crit'); cancelPending(); return; }
    if (r.status === 'expired') { return; }
    setTimeout(pollPending, 1200);
}

/* ───────────────────────────── login ───────────────────────────── */
async function onLogin(e) {
    e.preventDefault();
    const btn = $('#li-btn'); btn.disabled = true;
    const body = {
        identifier: $('#li-user').value.trim(),
        password: $('#li-pass').value,
        scenario: Number($('#li-scenario').value) || 1,
        otp: $('#li-otp').value.trim() || undefined,
        emailCode: $('#li-email').value.trim() || undefined,
        deviceLabel: state.deviceLabel,
    };
    const r = await api('/api/auth/login', { method: 'POST', body });
    btn.disabled = false;
    const msg = $('#li-msg');
    msg.className = 'msg';

    switch (r.outcome) {
        case 'SUCCESS':
            saveSession(r);
            msg.className = 'msg ok-box';
            msg.textContent = `✅ ${r.message} · risk ${r.risk}/${100}`;
            enterApp();
            break;
        case 'STEP_UP': {
            showStepUp(r);
            msg.className = 'msg info-box';
            msg.innerHTML = `🔐 ${esc(r.message)}<br/><small>risk ${esc(r.risk)} — ${esc((r.reasons || []).join(', ') || 'contextual')}</small>`;
            break;
        }
        case 'PENDING_APPROVAL':
            msg.innerHTML = '';
            startPending(r);
            break;
        case 'HIGH_RISK_BLOCK':
        case 'INVALID_OTP':
        case 'EXPIRED_OTP':
        case 'FAILED_PASSWORD':
        default:
            msg.className = 'msg err-box';
            msg.innerHTML = `<b>⛔ ${esc(r.message || 'authentication failed')}</b> <small>(${esc(r.outcome || '')} · risk ${esc(r.risk ?? '')} · ${esc((r.reasons || []).join(', ') || '')})</small>`;
    }
}
function showStepUp(r) {
    $('#li-stepup').classList.remove('hidden');
    $('#li-emailfld').classList.toggle('hidden', !r.needsEmail);
}

/* ───────────────────────────── app shell ───────────────────────────── */
const VIEWS = ['portal', 'user', 'soc', 'forensics', 'bench'];
const TAB_LABELS = { portal: 'Portal', user: 'Security Center', soc: 'SOC Console', forensics: 'Forensics', bench: 'Benchmark' };
const ROLE_TABS = {
    STUDENT: ['portal', 'user'],
    TEACHER: ['portal', 'user'],
    ADMINISTRATOR: ['portal', 'user', 'soc', 'forensics', 'bench'],
};
const DEFAULT_TAB = { STUDENT: 'user', TEACHER: 'portal', ADMINISTRATOR: 'soc' };

let activeView = null;

function enterApp() {
    $INGEST().classList.add('hidden');
    $APP().classList.remove('hidden');
    const role = state.session.role;
    $('#w-user').textContent = state.session.user?.displayName || state.session.user?.username || 'user';
    $('#w-role').textContent = role;
    buildTabs(role);
    connectSSE();
    activate(DEFAULT_TAB[role] || 'user');
}

function buildTabs(role) {
    const host = $('#w-tabs');
    host.innerHTML = '';
    for (const v of ROLE_TABS[role] || ROLE_TABS.STUDENT) {
        const b = document.createElement('button');
        b.className = 'wtab';
        b.dataset.wtab = v;
        b.textContent = TAB_LABELS[v];
        b.addEventListener('click', () => activate(v));
        host.appendChild(b);
    }
}

function activate(view) {
    if (activeView === view) { hostTabs(); initOnce(view); return; }
    activeView = view;
    VIEWS.forEach((v) => $('#view-' + v).classList.toggle('hidden', v !== view));
    hostTabs();
    initOnce(view);
}
function hostTabs() { $$('#w-tabs .wtab').forEach((b) => b.classList.toggle('on', b.dataset.wtab === activeView)); }

async function initOnce(view) {
    if (view === 'soc') { if (!window.__socInit) { initSoc(); window.__socInit = true; } else { switchPanel('overview'); } }
    if (view === 'user') { await initUser(); bindRecovery(); }
    if (view === 'portal') await initPortal();
    if (view === 'forensics') await initForensics();
    if (view === 'bench') await initBench();
}

/* ───────────────────────────── SSE ───────────────────────────── */
let sseConnected = false;
function connectSSE() {
    if (sseConnected) return;
    sseConnected = true;
    const ctrl = new AbortController();
    const headers = { 'X-Fp': state.fp, 'X-Device': state.deviceLabel };
    if (state.session) { headers['X-Session-Side'] = state.session.sid; }
    (async () => {
        try {
            const res = await fetch('/api/stream', { headers, signal: ctrl.signal });
            const reader = res.body.getReader();
            const dec = new TextDecoder();
            let buf = '';
            while (true) {
                const { value, done } = await reader.read();
                if (done) break;
                buf += dec.decode(value, { stream: true });
                let i;
                while ((i = buf.indexOf('\n')) >= 0) {
                    const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
                    if (!line.startsWith('data:')) continue;
                    try { handleSSE(JSON.parse(line.slice(5).trim())); } catch { /* ignore */ }
                }
            }
        } catch { /* stream closed */ }
    })();
}
function handleSSE(ev) {
    if (ev.type === 'audit') refreshLiveFeed(false);
    if (ev.type === 'sim') refreshSimLive();
    if (ev.type === 'alert') refreshHealth(false);
    if (ev.type === 'crossdevice') handleCrossDevice(ev.data);
}

function handleCrossDevice(d) {
    if (d && d.decision) { toast(d.decision === 'approved' ? 'Approved on trusted device.' : 'Denied on trusted device.', d.decision === 'approved' ? 'ok' : 'crit'); closeModal(); return; }
    if (d && d.pendingId) {
        state.modal = d.pendingId;
        $('#ap-dev').textContent = d.device || 'Unknown device';
        $('#ap-loc').textContent = `${d.ip || ''} · ${d.location || ''} for ${d.username || ''}`;
        $('#ap-risk').textContent = (d.risk ?? '—') + '/100';
        $('#ap-reasons').innerHTML = (d.reason || []).map((re) => `<span class="chip chip-warn">${esc(re)}</span>`).join('');
        $('#approve-modal').classList.remove('hidden');
    }
}
function closeModal() { $('#approve-modal').classList.add('hidden'); state.modal = null; }

/* approve/deny wiring (single listeners) */
document.addEventListener('click', async (e) => {
    if (e.target.id === 'ap-approve' && state.modal) await api('/api/pending/' + state.modal + '/approve', { method: 'POST' });
    if (e.target.id === 'ap-deny' && state.modal) await api('/api/pending/' + state.modal + '/deny', { method: 'POST' });
    if (e.target.id === 'w-logout') logout();
    if (e.target.id === 'btn-logout' || e.target.id === 'btn-user-logout') logout();
});
async function logout() {
    if (state.session) { try { await api('/api/session/demote', { method: 'POST', body: { sid: state.session.sid } }); } catch { /* ignore */ } }
    state.session = null;
    localStorage.removeItem('as360_session');
    location.reload();
}