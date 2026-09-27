/* Cornell Deep - self-service security center + account recovery / MFA reset */
import { $, $$, api, toast, esc, fmtFull, riskBadge, outcomeChip, levelOf, state } from './api.js';

export async function initUser() {
    const u = state.session.user;
    $('#u-role').textContent = state.session.role;
    const d = await api('/api/my?userId=' + encodeURIComponent(u.id));
    if (!d.ok || !d.user) return;
    $('#u-verified').textContent = d.user.email_verified ? '✅ Verified' : '⛔ Pending';
    $('#u-nid').textContent = d.user.national_id || '—';
    $('#u-posture').textContent = d.recoveryAvailable ? 'recovery enabled · self-service' : '—';
    $('#u-dev').textContent = (d.devices || []).length;
    $('#u-sess').textContent = (d.sessions || []).length;
    $('#u-act').textContent = (d.activity || []).length;
    $('#u-devices tbody').innerHTML = (d.devices || []).map((t) => `<tr>
        <td>${esc(t.label || '—')}</td><td>${esc(t.browser || t.ua || '—')}</td><td><code>${esc(t.fingerprint || '')}</code></td>
        <td>${fmtFull(t.last_seen)}</td>
        <td><button class="btn sm out" data-revoke="${esc(t.fingerprint)}">Revoke</button></td></tr>`).join('');
    $('#u-devices tbody').querySelectorAll('[data-revoke]').forEach((b) => b.addEventListener('click', async () => {
        await api('/api/my/device/revoke', { method: 'POST', body: { userId: u.id, fingerprint: b.dataset.revoke } });
        toast('Device revoked — next login will need re-verification.', 'warn'); initUser();
    }));
    $('#u-sessions tbody').innerHTML = (d.sessions || []).map((s) => `<tr>
        <td>${esc(s.ip)}</td><td>${esc(s.network)}</td><td>${esc(s.mfa || '—')}</td><td>${fmtFull(s.created)}</td>
        <td>${s.sid === state.session.sid ? '<i>this session</i>' : `<button class="btn sm out" data-ks="${esc(s.sid)}">End</button>`}</td></tr>`).join('');
    $('#u-sessions tbody').querySelectorAll('[data-ks]').forEach((b) => b.addEventListener('click', async () => {
        await api('/api/session/demote', { method: 'POST', body: { sid: b.dataset.ks } }); initUser(); toast('Session ended.', 'ok');
    }));
    $('#u-activity tbody').innerHTML = (d.activity || []).map((a) => `<tr>
        <td>${fmtFull(a.ts)}</td><td>${outcomeChip(a.outcome)}</td><td>${riskBadge(a.risk, levelOf(a.risk))}</td>
        <td>${esc((a.reasons || []).join(', ') || '—')}</td></tr>`).join('') || `<tr><td colspan="4" class="empty">No activity yet.</td></tr>`;
}

let recoveryIdentifier = '';
export function bindRecovery() {
    $('#rc-request-btn').addEventListener('click', async () => {
        recoveryIdentifier = $('#rc-identifier').value.trim();
        if (!recoveryIdentifier) return;
        const r = await api('/api/recovery/request', { method: 'POST', body: { identifier: recoveryIdentifier } });
        const m = $('#rc-status');
        $('#rc-step2').classList.toggle('hidden', !r.ok);
        if (r.ok) {
            m.innerHTML = `<b>✅ Recovery requested.</b> Demo channel code: <code>${esc(r.verifyCode)}</code> — proceed below (replace with e-mail/SMS in production).`;
            m.className = 'msg ok-box';
        } else {
            m.innerHTML = `<b>⚠️ ${esc(r.error || 'failed')}</b>`;
            m.className = 'msg err-box';
        }
    });
    $('#rc-reset-btn').addEventListener('click', async () => {
        const verifyCode = $('#rc-verify').value.trim();
        const newPassword = $('#rc-newpass').value;
        const r = await api('/api/recovery/reset', { method: 'POST', body: { identifier: recoveryIdentifier, verifyCode, newPassword } });
        const m = $('#rc-result');
        if (r.ok) {
            m.innerHTML = `<b>✅ MFA reset complete.</b> Password changed + TOTP rotated.<br/>Single-use <b>recovery codes</b> (store safely): <br/><code style="word-break:break-word">${esc((r.newRecoveryCodes || []).join(' · '))}</code>`;
            m.className = 'msg ok-box';
            toast('MFA reset — notification recorded.', 'ok');
        } else {
            m.innerHTML = `<b>⚠️ ${esc(r.error || 'reset failed')}</b>`;
            m.className = 'msg err-box';
        }
    });
    $('#rc-validate-btn').addEventListener('click', async () => {
        const r = await api('/api/recovery/validate', { method: 'POST', body: { identifier: $('#rc-validate-id').value.trim(), code: $('#rc-validate-code').value.trim() } });
        const m = $('#rc-validate-out');
        m.innerHTML = r.ok ? `<b>✅ ${esc(r.note)}</b>` : `<b>⚠️ ${esc(r.note || 'invalid')}</b>`;
        m.className = 'msg ' + (r.ok ? 'ok-box' : 'err-box');
    });
    $('#rc-step2').querySelectorAll('input').forEach((i) => i.addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#rc-reset-btn').click(); }));
}