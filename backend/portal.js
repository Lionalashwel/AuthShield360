/**
 * AuthShield 360 - School Portal Service (SRS 1.6.i / RBAC 1.6.ii & vii)
 *
 * A fictional school portal with Student/Teacher/Administrator modules and
 * strict role-based gating. All data is dummy lab data. Sessions are validated
 * against the DB `sessions` table (professional bearer-session checks).
 */
import { rawDb, listCourses, courseRosters, examResultsFor, attendanceFor, assignmentsFor, userById } from './db.js';

const PORTAL_ROLES = ['STUDENT', 'TEACHER', 'ADMINISTRATOR'];

export const ROLE_ACCESS_MATRIX = [
    { module: 'Courses', student: true, teacher: true, administrator: true },
    { module: 'Grades / Exam results', student: 'own', teacher: 'own courses', administrator: 'all' },
    { module: 'Assignments', student: 'enrolled', teacher: 'own courses', administrator: 'all' },
    { module: 'Attendance', student: 'own', teacher: 'own courses', administrator: 'all' },
    { module: 'Class rosters', student: false, teacher: 'own courses', administrator: 'all' },
    { module: 'User directory', student: false, teacher: false, administrator: 'all' },
    { module: 'SOC monitoring', student: false, teacher: false, administrator: true },
    { module: 'Forensic investigations', student: false, teacher: false, administrator: true },
];

export function validatePortalSession({ sid, userId } = {}) {
    if (!sid) return { ok: false, error: 'SESSION_REQUIRED' };
    const s = rawDb().prepare('SELECT * FROM sessions WHERE sid = ?').get(sid);
    if (!s) return { ok: false, error: 'SESSION_UNKNOWN' };
    if (Date.parse(s.expires) < Date.now()) return { ok: false, error: 'SESSION_EXPIRED' };
    if (userId && s.user_id !== userId) return { ok: false, error: 'SESSION_USER_MISMATCH' };
    const user = userById(s.user_id);
    if (!user) return { ok: false, error: 'NO_USER' };
    return { ok: true, session: s, user };
}

export function requireRoles(user, allowed) {
    return allowed.includes(user.role);
}

export function portalOverview(user) {
    const courses = listCourses(user.role, user.username);
    const grades = examResultsFor(user.role, user.username);
    const assignments = assignmentsFor(user.role, user.username);
    const attendance = attendanceFor(user.role, user.username);
    return {
        role: user.role,
        username: user.username,
        counts: {
            courses: courses.length,
            grades: grades.length,
            assignments: assignments.length,
            attendance: attendance.length,
            students: user.role === 'ADMINISTRATOR' ? rawDb().prepare('SELECT COUNT(*) n FROM users WHERE role = ?').get('STUDENT').n : null,
        },
        matrix: user.role === 'ADMINISTRATOR' ? ROLE_ACCESS_MATRIX : null,
    };
}

export const portalSvc = {
    courses: listCourses,
    rosters: courseRosters,
    grades: examResultsFor,
    assignments: assignmentsFor,
    attendance: attendanceFor,
    users: (role) => {
        const rows = rawDb().prepare(
            'SELECT id, username, display_name, role, department, email, phone, createdAt FROM users ORDER BY role, username').all();
        if (role === 'ADMINISTRATOR') return rows;
        return rows.filter((r) => r.role === role);
    },
    matrix: () => ROLE_ACCESS_MATRIX,
};