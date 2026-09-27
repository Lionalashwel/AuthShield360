/* Cornell Deep - shared SPA client core
 * API wrapper, persistent fingerprint/device identity, session token store,
 * and tiny DOM/formatting helpers shared by every view.
 */
export const $ = (s, el = document) => el.querySelector(s);
export const $$ = (s, el = document) => [...el.querySelectorAll(s)];
export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const fmtTime = (t) => { const d = new Date(t); return Number.isNaN(d) ? t : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }); };
export const fmtFull = (t) => { const d = new Date(t); return Number.isNaN(d) ? String(t) : d.toLocaleString([], { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }); };

export const state = {
    session: null,
    fp: localStorage.getItem('as360_fp') || (() => { const f = 'fp-' + crypto.randomUUID().slice(0, 12); localStorage.setItem('as360_fp', f); return f; })(),
    deviceLabel: localStorage.getItem('as360_dev') || 'Edge · Campus PC',
    login: { id: '', pw: '', args: null },
    pending: null,
    modal: null,
};

export function api(path, { method = 'GET', body, headers = {} } = {}) {
    const h = Object.assign({ 'X-Fp': state.fp, 'X-Device': state.deviceLabel }, headers, body ? { 'Content-Type': 'application/json' } : {});
    if (state.session) { h['X-Session-Side'] = state.session.sid; h['X-User-Id'] = state.session.user?.id || ''; }
    h['X-Session-Sid'] = state.session ? state.session.sid : '';
    return fetch(path, { method, headers: h, body: body ? JSON.stringify(body) : undefined })
        .then((r) => r.json().catch(() => ({ ok: false })));
}

export function toast(msg, kind = 'info') {
    const box = $('#toasts');
    const el = document.createElement('div');
    el.className = 'toast ' + kind;
    el.innerHTML = `${kind === 'crit' ? '⛔' : kind === 'ok' ? '✅' : kind === 'warn' ? '⚠️' : 'ℹ️'} <span>${esc(msg)}</span>`;
    box.appendChild(el);
    setTimeout(() => el.classList.add('out'), 5200);
    setTimeout(() => el.remove(), 5800);
    return el;
}

export function riskBadge(score, level) {
    const cls = level === 'HIGH' ? 'r-high' : level === 'MEDIUM' ? 'r-med' : 'r-low';
    return `<span class="rb ${cls}">${score ?? '—'}</span>`;
}
export function outcomeChip(o) {
    const map = { SUCCESS: 'chip-ok', HIGH_RISK_BLOCK: 'chip-err', FAILED_PASSWORD: 'chip-err', STEP_UP: 'chip-warn', INVALID_OTP: 'chip-warn', EXPIRED_OTP: 'chip-warn', PENDING_APPROVAL: 'chip-info', DENIED: 'chip-err', RECOVERY_REQUEST: 'chip-info', RECOVERY_RESET: 'chip-warn' };
    return `<span class="chip ${map[o] || 'chip-info'}">${o}</span>`;
}
export const levelOf = (risk) => (risk >= 70 ? 'HIGH' : risk >= 31 ? 'MEDIUM' : 'LOW');

export function saveSession(r) {
    state.session = { sid: r.session.sid, token: r.session.token, role: r.session.role, user: r.user };
    localStorage.setItem('as360_session', JSON.stringify(state.session));
}
export function restoreSession() {
    try {
        const s = JSON.parse(localStorage.getItem('as360_session'));
        if (s && s.sid) { state.session = s; return true; }
    } catch { /* noop */ }
    return false;
}