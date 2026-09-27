/* Cornell Deep - forensic digital-investigation view + benchmark */
import { $, api, toast, esc, fmtFull, fmtTime, riskBadge, outcomeChip, levelOf } from './api.js';

export async function initForensics() {
    bindFxStatic();
    await loadSummary();
    await loadCases();
}

function bindFxStatic() {
    $('#fx-search').addEventListener('click', () => loadTimeline());
    $('#fx-clear').addEventListener('click', () => {
        ['#fx-user', '#fx-ip', '#fx-device'].forEach((s) => $(s).value = '');
        $('#fx-outcome').value = '';
        loadTimeline();
    });
    $('#fx-user').addEventListener('keydown', (e) => { if (e.key === 'Enter') loadTimeline(); });
    $('#fx-ip').addEventListener('keydown', (e) => { if (e.key === 'Enter') loadTimeline(); });
    $('#fx-device').addEventListener('keydown', (e) => { if (e.key === 'Enter') loadTimeline(); });
    $('#fx-c-create').addEventListener('click', createCase);
    $('#fxd-close').addEventListener('click', () => $('#fx-drawer').classList.add('hidden'));
    $('#fxd-add').addEventListener('click', addNote);
    $('#fxd-export').addEventListener('click', exportCase);
    $('#fxd-closecase').addEventListener('click', () => setCaseStatus('CLOSED'));
    $('#fxd-del').addEventListener('click', deleteCase);
}

async function loadSummary() {
    const d = await api('/api/forensics/summary');
    if (!d.ok) return;
    const s = d.summary || {};
    const counts = [['Cases', s.cases], ['Auth events', s.auditEvents], ['Alerts', s.alerts], ['Successful logins', s.successes], ['Attack runs', s.attackRuns], ['Trusted devices', s.trustedDevices]];
    $('#fx-summary').innerHTML = counts.map(([l, v]) => `<div class="kv-card"><span>${esc(l)}</span><b>${esc(v ?? 0)}</b></div>`).join('');
}

export async function loadTimeline() {
    const q = new URLSearchParams();
    const u = $('#fx-user').value.trim(); const ip = $('#fx-ip').value.trim(); const dev = $('#fx-device').value.trim();
    const oc = $('#fx-outcome').value;
    if (u) q.set('user', u); if (ip) q.set('ip', ip); if (dev) q.set('device', dev); if (oc) q.set('outcome', oc);
    const d = await api('/api/forensics/timeline?' + q.toString());
    const tl = d.timeline || [];
    const track = (e) => {
        const kind = e.severity || e.kind || 'audit';
        const dot = e.risk >= 70 ? 'st-high' : e.level === 'HIGH' ? 'st-high' : e.risk >= 31 ? 'st-med' : 'st-low';
        return `<div class="tl-row"><span class="tl-dot ${dot}"></span><div class="tl-body">
          <div class="tl-text">${outcomeChip(e.outcome || e.title)} <b>${esc(e.username || 'system')}</b> ${esc(e.detail || e.title || '')}</div>
          <div class="tl-meta">${fmtFull(e.ts)} · ${esc(e.kind)} · ${esc(e.ip || '')} · risk ${esc(e.risk ?? '—')}${e.scenario ? ' · S' + e.scenario : ''}${e.elapsedMs ? ' · ' + e.elapsedMs + ' ms' : ''}</div>
        </div></div>`;
    };
    $('#fx-timeline').innerHTML = tl.length ? tl.map(track).join('') : `<div class="empty">No evidence matched the filter. Expand the scope or clear the search.</div>`;
}

async function createCase() {
    const title = $('#fx-c-title').value.trim();
    if (!title) return toast('Case needs a title.', 'warn');
    const body = {
        title,
        severity: $('#fx-c-sev').value,
        user: $('#fx-c-user').value.trim() || undefined,
        ip: $('#fx-c-ip').value.trim() || undefined,
        device: $('#fx-c-device').value.trim() || undefined,
    };
    const d = await api('/api/forensics/cases', { method: 'POST', body });
    if (!d.ok || !d.case) return toast(d.error || 'case creation failed', 'crit');
    toast('Case ' + d.case.ref + ' opened — evidence captured.', 'ok');
    $('#fx-c-title').value = '';
    ['#fx-c-user', '#fx-c-ip', '#fx-c-device'].forEach((s) => $(s).value = '');
    await loadCases();
    openCase(d.case.id);
}

async function loadCases() {
    const d = await api('/api/forensics/cases');
    const rows = (d.cases || []);
    $('#fx-cases tbody').innerHTML = rows.map((c) => `<tr>
        <td><code>${esc(c.ref)}</code></td><td>${esc(c.title)}</td>
        <td><span class="chip ${c.severity === 'CRITICAL' ? 'chip-err' : c.severity === 'HIGH' ? 'chip-warn' : 'chip-info'}">${esc(c.severity)}</span></td>
        <td>${esc(c.status)}</td><td>${esc(c.items ?? 0)}</td><td>${fmtFull(c.created_at)}</td>
        <td><button class="btn sm" data-open="${esc(c.id)}">Open</button></td></tr>`).join('')
        || `<tr><td colspan="7" class="empty">No cases yet — open one above.</td></tr>`;
    $('#fx-cases tbody').querySelectorAll('[data-open]').forEach((b) => b.addEventListener('click', () => openCase(b.dataset.open)));
}

export async function openCase(id) {
    const d = await api('/api/forensics/cases/' + id);
    if (!d.ok || !d.case) return toast(d.error || 'case not found', 'crit');
    const c = d.case;
    const scope = c.scope || {};
    $('#fxd-title').textContent = `${c.ref} · ${c.title}`;
    $('#fxd-meta').innerHTML = [
        ['Severity', c.severity], ['Status', c.status], ['Created by', c.created_by],
        ['Scope (user)', scope.user || 'any'], ['Scope (IP)', scope.ip || 'any'], ['Scope (device)', scope.device ? scope.device.slice(0, 40) : 'any'],
        ['Summary', c.summary || '—'], ['Opened', fmtFull(c.created_at)], ['Updated', fmtFull(c.updated_at || c.created_at)],
    ].map(([l, v]) => `<div class="kv-card"><span>${esc(l)}</span><b>${esc(v)}</b></div>`).join('');
    const items = d.timeline || [];
    $('#fxd-count').textContent = items.length + ' evidence items';
    $('#fxd-timeline').innerHTML = items.length
        ? items.map((i) => {
            const p = i.payload || {};
            const event = p.title || p.outcome || p.event || i.source;
            const detail = p.detail || i.note || '';
            const risk = p.risk ?? '';
            return `<div class="tl-row"><span class="tl-dot ${risk >= 70 ? 'st-high' : risk >= 31 ? 'st-med' : 'st-low'}"></span>
              <div class="tl-body"><div class="tl-text">${esc(event)} — ${esc(detail)}</div>
              <div class="tl-meta">${fmtFull(i.ts)} · source ${esc(i.source)}${risk !== '' ? ' · risk ' + risk : ''}</div></div></div>`;
          }).join('')
        : `<div class="empty">No evidence captured yet. Re-create the case with a wider scope to pull matching events.</div>`;
    $('#fx-drawer').classList.remove('hidden');
    window.__caseId = id;
}

async function addNote() {
    const text = $('#fxd-note').value.trim();
    if (!text) return;
    const r = await api(`/api/forensics/cases/${window.__caseId}/items`, { method: 'POST', body: { kind: 'note', note: text } });
    $('#fxd-note').value = '';
    if (!r.ok) return toast(r.error || 'note failed', 'crit');
    await openCase(window.__caseId);
    toast('Note attached.', 'ok');
}
async function setCaseStatus(status) {
    await api(`/api/forensics/cases/${window.__caseId}`, { method: 'PATCH', body: { status } });
    toast('Case ' + status.toLowerCase() + '.', 'ok');
    await openCase(window.__caseId);
    await loadCases();
}
async function deleteCase() {
    if (!confirm('Permanently delete this case?')) return;
    await api(`/api/forensics/cases/${window.__caseId}`, { method: 'DELETE' });
    $('#fx-drawer').classList.add('hidden');
    toast('Case deleted.', 'warn');
    await loadCases();
}
async function exportCase() {
    const d = await api('/api/forensics/cases/' + window.__caseId + '/export', { method: 'POST', headers: { Accept: 'text/markdown' } });
    if (!d.ok || d.error) return toast(d.error || 'export failed', 'crit');
    const blob = new Blob([d.markdown || ''], { type: 'text/markdown' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = d.filename || `case-${window.__caseId}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast('Evidence exported as Markdown.', 'ok');
}

/* Benchmark */
export async function initBench() {
    const d = await api('/api/benchmark');
    if (!d.ok || !d.benchmark) { $('#bm-note').textContent = '⚠️ ' + (d.error || 'benchmark unavailable'); return; }
    const ms = (v) => (v ? v.toFixed(0) + ' ms' : '—');
    const rows = (d.benchmark.scenarios || []).map((m) => `<tr><td><b>${esc(m.label)}</b></td>
          <td>${esc(m.attempts ?? 0)}</td><td>${ms(m.averageLoginTimeMs)}</td>
          <td>${esc(m.success ?? 0)}</td><td>${esc(m.failedPassword ?? 0)}</td>
          <td>${esc(m.secondFactorFailures ?? 0)}</td><td>${esc(m.blocked ?? 0)}</td><td>${esc(m.stepUp ?? 0)}</td></tr>`);
    $('#bm-table tbody').innerHTML = rows.join('') || `<tr><td colspan="8" class="empty">Run a few logins to populate comparative timings.</td></tr>`;
    $('#bm-note').innerHTML = d.benchmark.note ? '📊 ' + esc(d.benchmark.note) : '';
}