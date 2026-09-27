/* Cornell Deep - school portal view (fictional modules, strict RBAC) */
import { $, api, toast, esc, fmtFull, state } from './api.js';

const MODULES = {
    STUDENT: ['overview', 'courses', 'grades', 'assignments', 'attendance'],
    TEACHER: ['overview', 'courses', 'grades', 'assignments', 'attendance', 'rosters'],
    ADMINISTRATOR: ['overview', 'courses', 'grades', 'assignments', 'attendance', 'rosters', 'users', 'matrix'],
};
const LABELS = {
    overview: 'Overview', courses: 'Courses', grades: 'Grades & Exams',
    assignments: 'Assignments', attendance: 'Attendance', rosters: 'Class rosters',
    users: 'User directory', matrix: 'Access matrix',
};

export async function initPortal() {
    const u = state.session.user;
    const d = await api('/api/portal/session');
    if (!d.ok) { toast('Portal unavailable: ' + (d.error || ''), 'crit'); return; }
    const overview = d.overview || {};
    const role = d.user.role;

    $('#p-sub').textContent = `fictional modules · role: ${role} · ${overview.counts?.courses || 0} courses · dummy data`;
    const modnav = $('#p-modnav');
    modnav.innerHTML = '';
    for (const m of MODULES[role] || MODULES.STUDENT) {
        const b = document.createElement('button');
        b.className = 'p-mod' + (m === 'overview' ? ' on' : '');
        b.textContent = LABELS[m] || m;
        b.dataset.pmod = m;
        b.addEventListener('click', () => {
            modnav.querySelectorAll('.p-mod').forEach((x) => x.classList.toggle('on', x === b));
            loadPortalModule(m, role);
        });
        modnav.appendChild(b);
    }

    const cards = [
        { s: 'Courses', v: overview.counts?.courses || 0 },
        { s: 'Grades', v: overview.counts?.grades || 0 },
        { s: 'Assignments', v: overview.counts?.assignments || 0 },
        { s: 'Attendance', v: overview.counts?.attendance || 0 },
    ];
    if (overview.counts?.students != null) cards.push({ s: 'Students on portal', v: overview.counts.students });
    $('#p-overview').innerHTML = cards.map((c) => `<div class="kv-card"><span>${esc(c.s)}</span><b>${esc(c.v)}</b></div>`).join('');
    loadPortalModule('overview', role);
}

function table(title, cols, rows, empty = 'No records.') {
    return `<div class="hdr rules-title"><h3>${esc(title)}</h3></div>
        <div class="table-wrap"><table class="tbl"><thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead>
        <tbody>${rows.join('') || `<tr><td colspan="${cols.length}" class="empty">${esc(empty)}</td></tr>`}</tbody></table></div>`;
}

async function loadPortalModule(m, role) {
    const host = $('#portal-content');
    if (m === 'overview') {
        const summary = role === 'STUDENT' ? 'Your academic overview — grades, assignments and attendance for your enrolled courses.'
            : role === 'TEACHER' ? 'Your teaching workload — the courses you deliver and their rosters.'
                : 'Academic administration — every course, grade, assignment and attendance record on the portal.';
        host.innerHTML = `<div class="kv-card wide"><p>${esc(summary)}</p>
            <p class="portal-note">RBAC enforced server-side: every module request is scoped to your <b>${esc(role)}</b> session.</p></div>`;
        return;
    }
    try {
        const d = await api('/api/portal/' + m);
        if (!d.ok) { host.innerHTML = `<div class="msg err-box">⚠️ ${esc(d.error || 'denied')}</div>`; return; }
        if (m === 'courses') host.innerHTML = table('Courses', ['Code', 'Title', 'Teacher', 'Semester', 'Students'], (d.courses || []).map((c) => `<tr><td><code>${esc(c.code)}</code></td><td>${esc(c.title)}</td><td>${esc(c.teacher_username)}</td><td>${esc(c.semester)}</td><td>${esc(c.students ?? '—')}</td></tr>`));
        if (m === 'grades') host.innerHTML = table('Grades & exam results', ['Student', 'Course', 'Semester', 'Exam', 'Marks', 'Grade'], (d.grades || []).map((g) => `<tr><td>${esc(g.student_username)}</td><td>${esc(g.course_code)}</td><td>${esc(g.semester)}</td><td>${esc(g.exam_name)}</td><td>${esc(g.marks)} / ${esc(g.max_marks)}</td><td><b>${esc(g.grade)}</b></td></tr>`));
        if (m === 'assignments') host.innerHTML = table('Assignments', ['Course', 'Title', 'Due date', 'Max marks', 'Description'], (d.assignments || []).map((a) => `<tr><td>${esc(a.course_code)}</td><td>${esc(a.title)}</td><td>${esc(a.due_date)}</td><td>${esc(a.max_marks)}</td><td>${esc(a.description || '')}</td></tr>`));
        if (m === 'attendance') host.innerHTML = table('Attendance', ['Student', 'Course', 'Day', 'Status'], (d.attendance || []).map((a) => `<tr><td>${esc(a.student_username)}</td><td>${esc(a.course_code)}</td><td>${esc(a.day)}</td><td><span class="chip ${a.status === 'PRESENT' ? 'chip-ok' : a.status === 'LATE' ? 'chip-warn' : 'chip-err'}">${esc(a.status)}</span></td></tr>`));
        if (m === 'rosters') host.innerHTML = table('Class rosters', ['Student', 'Course', 'Course title'], (d.rosters || []).map((r) => `<tr><td>${esc(r.student)}</td><td>${esc(r.code)}</td><td>${esc(r.title)}</td></tr>`));
        if (m === 'users') host.innerHTML = table('Portal user directory', ['Username', 'Display name', 'Role', 'Department', 'E-mail', 'Phone', 'Created'], (d.users || []).map((u2) => `<tr><td>${esc(u2.username)}</td><td>${esc(u2.display_name)}</td><td>${esc(u2.role)}</td><td>${esc(u2.department)}</td><td>${esc(u2.email)}</td><td>${esc(u2.phone)}</td><td>${esc(fmtFull(u2.createdAt))}</td></tr>`));
        if (m === 'matrix') host.innerHTML = table('User & Role Access Matrix', ['Module', 'Student', 'Teacher', 'Administrator'], (d.matrix || []).map((x) => `<tr><td>${esc(x.module)}</td><td>${esc(x.student)}</td><td>${esc(x.teacher)}</td><td>${esc(x.administrator)}</td></tr>`));
    } catch (err) {
        host.innerHTML = `<div class="msg err-box">⚠️ ${esc(err.message || 'fetch failed')}</div>`;
    }
}