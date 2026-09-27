/**
 * AuthShield 360 - Database layer (SQLite via node:sqlite).
 * Persists: users, devices, successes, alerts, the audit trail, and session
 * inventory. All statements are parameterized; `max_safe_integer` guards are
 * in place where PII-in-event payloads are stored.
 */
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { DB_PATH } from './config.js';
import { hashPassword, nowIso, randomToken, newSid, stableHash } from './utils.js';

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------
const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  username      TEXT UNIQUE NOT NULL,
  display_name  TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('STUDENT','TEACHER','ADMINISTRATOR')),
  department    TEXT,
  pw_hash       TEXT NOT NULL,               -- demo hash only
  totp_secret   TEXT NOT NULL,               -- base32, demo only
  email         TEXT NOT NULL,
  email_verified INTEGER DEFAULT 1,
  phone         TEXT,
  national_id   TEXT,
  seed_flag     INTEGER DEFAULT 1,
  createdAt     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
  fingerprint  TEXT PRIMARY KEY,
  username     TEXT NOT NULL,
  label        TEXT NOT NULL,                -- "Recognized device" vs "New device"
  first_seen   TEXT NOT NULL,
  last_seen    TEXT NOT NULL,
  user_agent   TEXT
);
CREATE TABLE IF NOT EXISTS success_logins (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  sid         TEXT NOT NULL,
  username    TEXT NOT NULL,
  role        TEXT NOT NULL,
  ip          TEXT NOT NULL,
  subnet      TEXT,
  network     TEXT NOT NULL,
  device_hash TEXT NOT NULL,
  risk        INTEGER NOT NULL,              -- 0..100
  level       TEXT NOT NULL,                 -- LOW / MEDIUM / HIGH
  scenario    INTEGER NOT NULL,              -- 1 | 2 | 3
  mfa        TEXT,                            -- OTP / STEP_UP / -
  ts         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  severity   TEXT NOT NULL,                  -- CRITICAL / WARNING / INFO
  category   TEXT NOT NULL,                  -- e.g. BRUTE_FORCE
  ref        TEXT NOT NULL,                  -- stable correlation key
  title      TEXT NOT NULL,
  detail     TEXT NOT NULL,
  username   TEXT,
  risk       INTEGER,
  ip         TEXT,
  ts         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_trail (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  ts           TEXT NOT NULL,
  outcome      TEXT NOT NULL,                -- SUCCESS / FAILED_PASSWORD / ...
  username     TEXT NOT NULL,
  role         TEXT NOT NULL,
  user_id      TEXT NOT NULL,
  ip           TEXT NOT NULL,
  subnet       TEXT,
  network      TEXT NOT NULL,
  device_name  TEXT,
  browser      TEXT,
  user_agent   TEXT,
  fingerprint  TEXT NOT NULL,
  risk         INTEGER NOT NULL,
  factors      TEXT NOT NULL,                -- JSON array of triggered risk factors
  sid          TEXT,
  detail       TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
  sid        TEXT PRIMARY KEY,
  username   TEXT NOT NULL,
  role       TEXT NOT NULL,
  user_id    TEXT NOT NULL,
  ip         TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  created    TEXT NOT NULL,
  expires    TEXT NOT NULL,
  last_seen  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS threat_factors (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  type    TEXT NOT NULL,                     -- factor key
  label   TEXT NOT NULL,
  ts      TEXT NOT NULL,
  expires TEXT NOT NULL,                     -- ISO of expiry (used to auto-expire)
  UNIQUE(type)
);
CREATE TABLE IF NOT EXISTS whitelist (
  ip    TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  ts    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blacklist (
  ip    TEXT PRIMARY KEY,
  reason TEXT NOT NULL,
  ts    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attack_runs (
  id        TEXT PRIMARY KEY,
  phase     INTEGER NOT NULL,
  status    TEXT NOT NULL,                   -- RUNNING / COMPLETE / FAILED
  title     TEXT NOT NULL,
  timeline  TEXT NOT NULL,                   -- JSON
  ts        TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS trusted_devices (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  label       TEXT NOT NULL,                 -- parsed device model from UA
  ip          TEXT,
  browser     TEXT,
  ua          TEXT,
  created_at  TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  cookie_id   TEXT,
  UNIQUE(user_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS verification_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  email      TEXT NOT NULL,
  purpose    TEXT NOT NULL DEFAULT 'verify',
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used       INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS pending_approvals (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL,
  new_fp       TEXT NOT NULL,
  new_ip       TEXT NOT NULL,
  new_label    TEXT NOT NULL,                -- device label of the challenger
  location     TEXT NOT NULL,                -- network label / human location
  ua           TEXT,
  created_at   TEXT NOT NULL,
  expires_at   TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | denied | expired
  decided_at   TEXT,
  fallback_used INTEGER DEFAULT 0
);
`;

// ---------------------------------------------------------------------------
// Seed data  (SRS 3.4: three representative user roles)
// ---------------------------------------------------------------------------
const SEED_USERS = [
    { id: 'usr-1001', username: 'student1', displayName: 'Sarah Chen', role: 'STUDENT',
      department: 'Computer Science', password: 'Student@123', email: 'sarah.chen@campus.edu',
      phone: '+1-555-0101', totpSecret: 'JBSWY3DPEZLMNQYI', nationalId: 'SCH-2019001345' },
    { id: 'usr-1002', username: 'student2', displayName: 'Omar Farouk', role: 'STUDENT',
      department: 'Computer Science', password: 'Student@123', email: 'omar.farouk@campus.edu',
      phone: '+1-555-0102', totpSecret: 'KRSXG5DSNFXGO54J', nationalId: 'SCH-2021002287' },
    { id: 'usr-2001', username: 'teacher1', displayName: 'Dr. Elena Roberts', role: 'TEACHER',
      department: 'Information Security', password: 'Teacher@123', email: 'elena.roberts@campus.edu',
      phone: '+1-555-0201', totpSecret: 'MZUWY6JOFZQW65DF', nationalId: 'NID-1023399801' },
    { id: 'usr-2002', username: 'teacher2', displayName: 'Prof. Marcus Reid', role: 'TEACHER',
      department: 'Network Engineering', password: 'Teacher@123', email: 'marcus.reid@campus.edu',
      phone: '+1-555-0202', totpSecret: 'NVXG4ZBOGNSXE33T', nationalId: 'NID-1087721123' },
    { id: 'usr-3001', username: 'admin', displayName: 'Alex Morgan', role: 'ADMINISTRATOR',
      department: 'IT Security Office', password: 'Admin@123', email: 'alex.morgan@campus.edu',
      phone: '+1-555-0301', totpSecret: 'OJZXC6LVOVZWE642', nationalId: 'NID-1177STAFF044' },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
let db = null;

export function getDb() {
    if (!db) throw new Error('Database not initialized');
    return db;
}

export function initDb(reset = false) {
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    if (reset && fs.existsSync(DB_PATH)) fs.rmSync(DB_PATH);

    db = new DatabaseSync(DB_PATH);
    db.exec(SCHEMA);
    runMigrations();
    ensureColumn('users', 'national_id', 'TEXT');
    ensureColumn('users', 'seed_flag', 'INTEGER DEFAULT 1');
    seedIfEmpty();
    seedSchoolIfEmpty();
    return db;
}

// ---------------------------------------------------------------------------
// Schema migrations (versioned, idempotent)
// ---------------------------------------------------------------------------
const MIGRATIONS = [
    {
        id: 'm001_school_recovery_forensics',
        sql: `
CREATE TABLE IF NOT EXISTS courses (
  id TEXT PRIMARY KEY,
  code TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  teacher_username TEXT NOT NULL,
  semester TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS course_enrollments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  course_id TEXT NOT NULL,
  student_username TEXT NOT NULL,
  UNIQUE(course_id, student_username)
);
CREATE TABLE IF NOT EXISTS assignments (
  id TEXT PRIMARY KEY,
  course_code TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  due_date TEXT,
  max_marks INTEGER NOT NULL DEFAULT 100
);
CREATE TABLE IF NOT EXISTS exam_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_username TEXT NOT NULL,
  course_code TEXT NOT NULL,
  semester TEXT NOT NULL,
  exam_name TEXT NOT NULL,
  marks REAL NOT NULL,
  max_marks REAL NOT NULL DEFAULT 100,
  grade TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attendance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_username TEXT NOT NULL,
  course_code TEXT NOT NULL,
  day TEXT NOT NULL,
  status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS recovery_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  used INTEGER DEFAULT 0,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS mfa_resets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  verify_hash TEXT NOT NULL,
  note TEXT,
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  completed_at TEXT
);
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY,
  ref TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'OPEN',
  created_by TEXT NOT NULL,
  scope TEXT NOT NULL,
  summary TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS case_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL,
  source TEXT NOT NULL,
  source_id TEXT NOT NULL,
  ts TEXT NOT NULL,
  payload TEXT NOT NULL,
  note TEXT
);
`,
    },
    {
        id: 'm002_forensics_indexes',
        sql: `
CREATE INDEX IF NOT EXISTS idx_audit_ts   ON audit_trail (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_trail (username, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_uid  ON audit_trail (user_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_ip   ON audit_trail (ip, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_fp   ON audit_trail (fingerprint, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_scn  ON audit_trail (scenario, outcome);
CREATE INDEX IF NOT EXISTS idx_alerts_ts  ON alerts (ts DESC);
CREATE INDEX IF NOT EXISTS idx_success_ts ON success_logins (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_elapsed ON audit_trail (scenario, outcome, elapsed_ms);
`,
    },
];

function runMigrations() {
    db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (id TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`);
    ensureColumn('audit_trail', 'scenario', 'INTEGER DEFAULT 1');
    ensureColumn('audit_trail', 'elapsed_ms', 'INTEGER');
    const done = new Set(db.prepare('SELECT id FROM schema_migrations').all().map((r) => r.id));
    for (const m of MIGRATIONS) {
        if (done.has(m.id)) continue;
        db.exec(m.sql);
        db.prepare('INSERT INTO schema_migrations (id, applied_at) VALUES (?, ?)').run(m.id, nowIso());
        console.log(`[migrate] applied ${m.id}`);
    }
}

// ---------------------------------------------------------------------------
// School dataset  (dummy data only - SRS 1.6.i)
// ---------------------------------------------------------------------------
const SEED_COURSES = [
    { id: 'crs-1001', code: 'CS101', title: 'Introduction to Programming', teacher: 'teacher1', semester: '2025-F' },
    { id: 'crs-1002', code: 'CS211', title: 'Data Structures', teacher: 'teacher1', semester: '2025-F' },
    { id: 'crs-1003', code: 'NT201', title: 'Network Engineering', teacher: 'teacher2', semester: '2025-F' },
    { id: 'crs-1004', code: 'SEC301', title: 'Ethical Hacking Fundamentals', teacher: 'teacher2', semester: '2025-F' },
];
const SEED_ENROLLMENTS = {
    'crs-1001': ['student1', 'student2'],
    'crs-1002': ['student1'],
    'crs-1003': ['student2'],
    'crs-1004': ['student1', 'student2'],
};
const SEED_ASSIGNMENTS = [
    { id: 'asg-1001', code: 'CS101', title: 'Lab 1 - Control Flow', desc: 'Implement loops and conditionals', due: '2025-11-20', max: 100 },
    { id: 'asg-1002', code: 'CS101', title: 'Project - Mini Bank', desc: 'Group project', due: '2025-12-05', max: 100 },
    { id: 'asg-1003', code: 'CS211', title: 'Assignment 2 - Hash Maps', desc: 'Hash table from scratch', due: '2025-11-27', max: 50 },
    { id: 'asg-1004', code: 'NT201', title: 'Wireshark Capture Lab', desc: 'Analyse a PCAP', due: '2025-12-01', max: 100 },
    { id: 'asg-1005', code: 'SEC301', title: 'CTF - Auth Bypass', desc: 'Capture the flag', due: '2025-12-10', max: 150 },
];
const SEED_EXAMS = [
    { s: 'student1', code: 'CS101', sem: '2025-F', name: 'Midterm', marks: 87, max: 100, grade: 'A-' },
    { s: 'student1', code: 'CS211', sem: '2025-F', name: 'Midterm', marks: 74, max: 100, grade: 'B' },
    { s: 'student1', code: 'SEC301', sem: '2025-F', name: 'Midterm', marks: 91, max: 100, grade: 'A' },
    { s: 'student2', code: 'CS101', sem: '2025-F', name: 'Midterm', marks: 66, max: 100, grade: 'C+' },
    { s: 'student2', code: 'NT201', sem: '2025-F', name: 'Midterm', marks: 79, max: 100, grade: 'B+' },
    { s: 'student2', code: 'SEC301', sem: '2025-F', name: 'Midterm', marks: 84, max: 100, grade: 'A-' },
];
const SEED_ATTENDANCE = [
    ['student1', 'CS101', '2025-11-03', 'PRESENT'], ['student1', 'CS101', '2025-11-10', 'PRESENT'],
    ['student1', 'CS101', '2025-11-17', 'LATE'], ['student2', 'CS101', '2025-11-03', 'PRESENT'],
    ['student2', 'CS101', '2025-11-10', 'ABSENT'], ['student2', 'CS101', '2025-11-17', 'PRESENT'],
    ['student1', 'SEC301', '2025-11-04', 'PRESENT'], ['student2', 'SEC301', '2025-11-04', 'PRESENT'],
];

function seedSchoolIfEmpty() {
    const row = db.prepare('SELECT COUNT(*) AS n FROM courses').get();
    if (Number(row.n) > 0) return;
    const addCourse = db.prepare('INSERT INTO courses (id, code, title, teacher_username, semester) VALUES (?, ?, ?, ?, ?)');
    for (const c of SEED_COURSES) addCourse.run(c.id, c.code, c.title, c.teacher, c.semester);
    const addEnr = db.prepare('INSERT INTO course_enrollments (course_id, student_username) VALUES (?, ?)');
    for (const [cid, students] of Object.entries(SEED_ENROLLMENTS)) for (const s of students) addEnr.run(cid, s);
    const addAsg = db.prepare('INSERT INTO assignments (id, course_code, title, description, due_date, max_marks) VALUES (?, ?, ?, ?, ?, ?)');
    for (const a of SEED_ASSIGNMENTS) addAsg.run(a.id, a.code, a.title, a.desc, a.due, a.max);
    const addExam = db.prepare('INSERT INTO exam_results (student_username, course_code, semester, exam_name, marks, max_marks, grade) VALUES (?, ?, ?, ?, ?, ?, ?)');
    for (const e of SEED_EXAMS) addExam.run(e.s, e.code, e.sem, e.name, e.marks, e.max, e.grade);
    const addAtt = db.prepare('INSERT INTO attendance (student_username, course_code, day, status) VALUES (?, ?, ?, ?)');
    for (const a of SEED_ATTENDANCE) addAtt.run(a[0], a[1], a[2], a[3]);
}

function seedIfEmpty() {
    const row = db.prepare('SELECT COUNT(*) AS n FROM users').get();
    if (Number(row.n) > 0) return;

    const ins = db.prepare(
        `INSERT INTO users (id, username, display_name, role, department, pw_hash, totp_secret, email, phone, email_verified, national_id, seed_flag, createdAt)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 1, ?)`,
    );
    for (const u of SEED_USERS) {
        ins.run(u.id, u.username, u.displayName, u.role, u.department,
            hashPassword(u.password), u.totpSecret, u.email, u.phone,
            u.nationalId, nowIso());
    }
}

/** SQLite light migration: add a column when missing (keeps old DBs working). */
function ensureColumn(table, column, ddl) {
    const cols = db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
    if (!cols.includes(column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${ddl}`);
}

// ---------------------------------------------------------------------------
// Typed helpers
// ---------------------------------------------------------------------------
export const dbHelpers = {
    countUsers: () => Number(db.prepare('SELECT COUNT(*) n FROM users').get().n),
    listUsers: () => db.prepare('SELECT id, username, display_name, role, department, email, phone FROM users ORDER BY role').all(),
    listUsersWithSecrets: () => db.prepare('SELECT id, username, display_name, role, department, email, phone, totp_secret FROM users ORDER BY role').all(),
    getUser: (username) => db.prepare('SELECT * FROM users WHERE username = ?').get(username),
    getUserById: (id) => db.prepare('SELECT * FROM users WHERE id = ?').get(id),
    _raw: () => db,
    registerUser: createUser,
};

// ---------------------------------------------------------------------------
// Audit trail
// ---------------------------------------------------------------------------
export function insertAudit(e) {
    const st = `INSERT INTO audit_trail
        (ts, outcome, username, role, user_id, ip, subnet, network, device_name, browser,
         user_agent, fingerprint, risk, factors, sid, detail, scenario, elapsed_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    db.prepare(st).run(e.ts, e.outcome, e.username, e.role, e.user_id, e.ip, e.subnet, e.network,
        e.device_name, e.browser, e.user_agent, e.fingerprint, e.risk,
        JSON.stringify(e.factors.filter(Boolean)), e.sid, e.detail, e.scenario ?? null,
        Number.isFinite(e.elapsed_ms) ? e.elapsed_ms : null);
}

export function auditList(limit = 100) {
    return db.prepare('SELECT * FROM audit_trail ORDER BY id DESC LIMIT ?').all(limit);
}

/** Filtered audit query (SRS optional: "auth-log filtering by role, date, factor type or result"). */
export function auditFiltered({ outcome, role, username, from, to, limit = 200 } = {}) {
    const where = [];
    const args = [];
    if (outcome) { where.push('outcome = ?'); args.push(outcome); }
    if (role) { where.push('role = ?'); args.push(role); }
    if (username) { where.push('username = ?'); args.push(username); }
    if (from) { where.push('ts >= ?'); args.push(from); }
    if (to) { where.push('ts <= ?'); args.push(to); }
    const cl = where.length ? ' WHERE ' + where.join(' AND ') : '';
    return db.prepare(`SELECT * FROM audit_trail${cl} ORDER BY id DESC LIMIT ?`).all(...args, limit);
}

export function auditCount(type) {
    const st = type ? ' WHERE outcome = ?' : '';
    const r = db.prepare(`SELECT COUNT(*) n FROM audit_trail${st}`);
    const row = type ? r.get(type) : r.get();
    return Number(row.n);
}

// ---------------------------------------------------------------------------
// Success / alerts / sessions
// ---------------------------------------------------------------------------
export function insertSuccess(s) {
    db.prepare(`INSERT INTO success_logins
        (sid, username, role, ip, subnet, network, device_hash, risk, level, scenario, mfa, ts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(s.sid, s.username, s.role, s.ip, s.subnet, s.network, s.device_hash, s.risk, s.level, s.scenario, s.mfa, s.ts);
}

export function successList(limit = 100) {
    return db.prepare('SELECT * FROM success_logins ORDER BY id DESC LIMIT ?').all(limit);
}

export function insertAlert(a) {
    db.prepare(`INSERT INTO alerts (severity, category, ref, title, detail, username, risk, ip, ts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(a.severity, a.category, a.ref, a.title, a.detail, a.username, a.risk, a.ip, a.ts);
}

export function alertList(limit = 60) {
    return db.prepare('SELECT * FROM alerts ORDER BY id DESC LIMIT ?').all(limit);
}

export function alertCountSync() {
    return Number(db.prepare('SELECT COUNT(*) n FROM alerts').get().n);
}

export function createSession(sync = null) {
    const sid = newSid();
    const token = randomToken(32);
    const created = nowIso();
    const expires = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // config.SESSION_MAX_AGE_MIN
    db.prepare(`INSERT INTO sessions
        (sid, username, role, user_id, ip, fingerprint, created, expires, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(sid, sync.username, sync.role, sync.user_id, sync.ip, sync.fingerprint, created, expires, created);
    return { sid, token, expires };
}

export function getSession(sid) {
    return db.prepare('SELECT * FROM sessions WHERE sid = ?').get(sid);
}

export function touchSession(sid) {
    db.prepare('UPDATE sessions SET last_seen = ? WHERE sid = ?').run(nowIso(), sid);
}

export function deleteSession(sid) {
    db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
}

export function listSessions() {
    return db.prepare('SELECT * FROM sessions ORDER BY created DESC').all();
}

// ---------------------------------------------------------------------------
// Threat factor / device tables
// ---------------------------------------------------------------------------
export function getFactor(type) {
    return db.prepare('SELECT * FROM threat_factors WHERE type = ?').get(type);
}

export function upsertFactor(type, label, ttlMs = 5 * 60 * 1000) {
    const ts = nowIso();
    const expires = new Date(Date.now() + ttlMs).toISOString();
    db.prepare(`INSERT INTO threat_factors (type, label, ts, expires) VALUES (?, ?, ?, ?)
        ON CONFLICT(type) DO UPDATE SET ts = excluded.ts, expires = excluded.expires, label = excluded.label`)
        .run(type, label, ts, expires);
}

export function factorExpired(type) {
    const f = getFactor(type);
    if (!f) return true;
    const exp = Date.parse(f.expires);
    return Number.isFinite(exp) && exp < Date.now();
}

export function removeFactor(type) {
    db.prepare('DELETE FROM threat_factors WHERE type = ?').run(type);
}

export function clearAllFactors() {
    db.prepare('DELETE FROM threat_factors').run();
}

export function listFactors() {
    return db.prepare('SELECT * FROM threat_factors').all();
}

export function upsertDevice(d) {
    db.prepare(`INSERT INTO devices (fingerprint, username, label, first_seen, last_seen, user_agent)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(fingerprint) DO UPDATE SET last_seen = excluded.last_seen`)
        .run(d.fingerprint, d.username, d.label, d.first_seen, d.last_seen, d.user_agent);
}

export function getDevice(fingerprint) {
    return db.prepare('SELECT * FROM devices WHERE fingerprint = ?').get(fingerprint);
}

export function listDevices() {
    return db.prepare('SELECT * FROM devices ORDER BY last_seen DESC LIMIT 50').all();
}

export function logRecognizedDevice(username, fingerprint, userAgent) {
    upsertDevice({ fingerprint, username, label: 'Recognized device', first_seen: nowIso(), last_seen: nowIso(), user_agent: userAgent });
}

// ---------------------------------------------------------------------------
// Whitelist / Blacklist
// ---------------------------------------------------------------------------
export function whitelistAll() {
    return db.prepare('SELECT * FROM whitelist ORDER BY ts DESC').all();
}
export async function whitelistAdd(ip, label) {
    db.prepare('INSERT OR REPLACE INTO whitelist (ip, label, ts) VALUES (?, ?, ?)').run(ip, label, nowIso());
}
export async function whitelistRemove(ip) {
    db.prepare('DELETE FROM whitelist WHERE ip = ?').run(ip);
}
export function blacklistAll() {
    return db.prepare('SELECT * FROM blacklist ORDER BY ts DESC').all();
}
export async function blacklistAdd(ip, reason) {
    db.prepare('INSERT OR REPLACE INTO blacklist (ip, reason, ts) VALUES (?, ?, ?)').run(ip, reason, nowIso());
}
export async function blacklistRemove(ip) {
    db.prepare('DELETE FROM blacklist WHERE ip = ?').run(ip);
}

// ---------------------------------------------------------------------------
// Attack runs (simulation engine)
// ---------------------------------------------------------------------------
export function upsertAttackRun(id, phase, status, title, timeline) {
    db.prepare(`INSERT INTO attack_runs (id, phase, status, title, timeline, ts) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET phase = excluded.phase, status = excluded.status,
        title = excluded.title, timeline = excluded.timeline, ts = excluded.ts`)
        .run(id, phase, status, title, JSON.stringify(timeline), nowIso());
}
export function attackRuns() {
    return db.prepare('SELECT * FROM attack_runs ORDER BY ts DESC LIMIT 20').all()
        .map((r) => ({ ...r, timeline: JSON.parse(r.timeline) }));
}

// ---------------------------------------------------------------------------
// v2: Registration / trust
// ---------------------------------------------------------------------------
export async function createUser({ id, username, displayName, role, department, pwHash, totpSecret, email, nationalId }) {
    db.prepare(`INSERT INTO users
        (id, username, display_name, role, department, pw_hash, totp_secret, email, phone, email_verified, national_id, seed_flag, createdAt)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, 0, ?, 0, ?)`)
        .run(id, username, displayName, role, department, pwHash, totpSecret, email, nationalId, nowIso());
}

export function findUserByEmail(email) {
    return db.prepare('SELECT * FROM users WHERE lower(email) = lower(?)').get(email);
}
export function findUserByNationalId(nid) {
    return db.prepare('SELECT * FROM users WHERE national_id = ?').get(nid);
}
export function userById(id) {
    return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}
export function updatePasswordAndSecret(userId, pwHash, totpSecret) {
    db.prepare('UPDATE users SET pw_hash = ?, totp_secret = ? WHERE id = ?').run(pwHash, totpSecret, userId);
}
export function markEmailVerified(userId) {
    db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(userId);
}

// verification tokens
export function insertToken({ tokenHash, userId, email, purpose, ttlMs = 24 * 3600 * 1000 }) {
    const created = nowIso();
    const expires = new Date(Date.now() + ttlMs).toISOString();
    db.prepare(`INSERT INTO verification_tokens (token_hash, user_id, email, purpose, created_at, expires_at, used)
        VALUES (?, ?, ?, ?, ?, ?, 0)`)
        .run(tokenHash, userId, email, purpose, created, expires);
}
export function getToken(tokenHash) {
    return db.prepare('SELECT * FROM verification_tokens WHERE token_hash = ?').get(tokenHash);
}
export function useToken(tokenHash) {
    db.prepare('UPDATE verification_tokens SET used = 1 WHERE token_hash = ?').run(tokenHash);
}

// trusted devices
export function addTrustedDevice({ userId, fingerprint, label, ip, browser, ua, cookieId }) {
    const now = nowIso();
    db.prepare(`INSERT INTO trusted_devices (user_id, fingerprint, label, ip, browser, ua, created_at, last_seen, cookie_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, fingerprint) DO UPDATE SET
            cookie_id = excluded.cookie_id, last_seen = excluded.last_seen`)
        .run(userId, fingerprint, label, ip || null, browser || ua || '', ua || browser || '', now, now, cookieId || null);
}
export function touchTrustedDevice(userId, fingerprint) {
    db.prepare('UPDATE trusted_devices SET last_seen = ? WHERE user_id = ? AND fingerprint = ?').run(nowIso(), userId, fingerprint);
}
export function listTrustedDevices(userId = null) {
    const rows = userId
        ? db.prepare('SELECT * FROM trusted_devices WHERE user_id = ? ORDER BY last_seen DESC').all(userId)
        : db.prepare('SELECT * FROM trusted_devices ORDER BY last_seen DESC').all();
    return rows;
}
export function isTrustedDevice(userId, fingerprint) {
    return !!db.prepare('SELECT 1 k FROM trusted_devices WHERE user_id = ? AND fingerprint = ?').get(userId, fingerprint);
}
export function revokeTrustedDevice(userId, fingerprint) {
    db.prepare('DELETE FROM trusted_devices WHERE user_id = ? AND fingerprint = ?').run(userId, fingerprint);
}

// pending cross-device approvals
export function insertPendingApproval({ id, userId, newFp, newIp, newLabel, location, ua, ttlMs = 45 * 1000 }) {
    const created = nowIso();
    const expires = new Date(Date.now() + ttlMs).toISOString();
    db.prepare(`INSERT INTO pending_approvals (id, user_id, new_fp, new_ip, new_label, location, ua, created_at, expires_at, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')`)
        .run(id, userId, newFp, newIp, newLabel, location, ua, created, expires);
}
export function pendingApproval(id) {
    return db.prepare('SELECT * FROM pending_approvals WHERE id = ?').get(id);
}
export function setPendingStatus(id, status) {
    db.prepare(`UPDATE pending_approvals SET status = ?, decided_at = ? WHERE id = ?`)
        .run(status, nowIso(), id);
}
export function setPendingFallback(id) {
    db.prepare('UPDATE pending_approvals SET fallback_used = 1, status = ? WHERE id = ?')
        .run('expired', id);
}

export { stableHash };

// ---------------------------------------------------------------------------
// School portal queries (SRS 1.6.i / RBAC)
// ---------------------------------------------------------------------------
export function rawDb() { return db; }

export function listCourses(role, username) {
    const all = db.prepare(`SELECT c.*, (SELECT COUNT(*) FROM course_enrollments e WHERE e.course_id = c.id) AS students
        FROM courses c ORDER BY c.code`).all();
    if (role === 'ADMINISTRATOR') return all;
    if (role === 'TEACHER') return all.filter((c) => c.teacher_username === username);
    const mine = new Set(db.prepare(
        'SELECT c.id FROM courses c JOIN course_enrollments e ON e.course_id = c.id WHERE e.student_username = ?').all(username).map((r) => r.id));
    return all.filter((c) => mine.has(c.id));
}

export function courseRosters(role, username) {
    if (role === 'STUDENT') return db.prepare(`SELECT e.student_username AS student, c.code, c.title
        FROM course_enrollments e JOIN courses c ON c.id = e.course_id WHERE e.student_username = ? ORDER BY c.code`).all(username);
    const whereTeacher = role === 'TEACHER' ? ` WHERE c.teacher_username = ?` : '';
    if (role === 'TEACHER') return db.prepare(`SELECT e.student_username AS student, c.code, c.title
        FROM course_enrollments e JOIN courses c ON c.id = e.course_id${whereTeacher} ORDER BY c.code`).all(username);
    return db.prepare(`SELECT e.student_username AS student, c.code, c.title
        FROM course_enrollments e JOIN courses c ON c.id = e.course_id ORDER BY c.code`).all();
}

export function examResultsFor(role, username) {
    if (role === 'STUDENT') return db.prepare(`SELECT * FROM exam_results WHERE student_username = ? ORDER BY id`).all(username);
    if (role === 'TEACHER') return db.prepare(`SELECT r.* FROM exam_results r JOIN courses c ON c.code = r.course_code WHERE c.teacher_username = ? ORDER BY r.id`).all(username);
    return db.prepare('SELECT * FROM exam_results ORDER BY id').all();
}

export function attendanceFor(role, username) {
    if (role === 'STUDENT') return db.prepare('SELECT * FROM attendance WHERE student_username = ? ORDER BY day').all(username);
    if (role === 'TEACHER') return db.prepare(`SELECT a.* FROM attendance a JOIN courses c ON c.code = a.course_code WHERE c.teacher_username = ? ORDER BY a.day`).all(username);
    return db.prepare('SELECT * FROM attendance ORDER BY day').all();
}

export function assignmentsFor(role, username) {
    if (role === 'ADMINISTRATOR') return db.prepare('SELECT * FROM assignments ORDER BY due_date').all();
    if (role === 'TEACHER') return db.prepare(`SELECT a.* FROM assignments a JOIN courses c ON c.code = a.course_code WHERE c.teacher_username = ? ORDER BY a.due_date`).all(username);
    const mine = db.prepare(`SELECT DISTINCT a.* FROM assignments a
        JOIN courses c ON c.code = a.course_code
        JOIN course_enrollments e ON e.course_id = c.id
        WHERE e.student_username = ? ORDER BY a.due_date`).all(username);
    return mine;
}

// ---------------------------------------------------------------------------
// Recovery / MFA reset (optional SRS features)
// ---------------------------------------------------------------------------
export function storeRecoveryCodes(userId, codes, ttlMs = 365 * 24 * 3600 * 1000) {
    const ins = db.prepare('INSERT INTO recovery_codes (user_id, code_hash, created_at, expires_at) VALUES (?, ?, ?, ?)');
    const created = nowIso();
    const expires = new Date(Date.now() + ttlMs).toISOString();
    for (const c of codes) ins.run(userId, stableHash('rc:' + c), created, expires);
}
export function recoveryCodeValid(userId, code) {
    const row = db.prepare('SELECT * FROM recovery_codes WHERE user_id = ? AND code_hash = ? AND used = 0').get(userId, stableHash('rc:' + code));
    if (!row) return false;
    if (Date.parse(row.expires_at) < Date.now()) return false;
    db.prepare('UPDATE recovery_codes SET used = 1 WHERE id = ?').run(row.id);
    return true;
}
export function countValidRecoveryCodes(userId) {
    return Number(db.prepare('SELECT COUNT(*) n FROM recovery_codes WHERE user_id = ? AND used = 0').get(userId).n);
}
export function createMfaReset(userId, verifyHash, note) {
    const created = nowIso();
    const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    db.prepare('INSERT INTO mfa_resets (user_id, verify_hash, note, requested_at, expires_at) VALUES (?, ?, ?, ?, ?)')
        .run(userId, verifyHash, note, created, expires);
    return { requestedAt: created, expiresAt: expires };
}
export function verifyMfaReset(userId, verifyHash) {
    const row = db.prepare('SELECT * FROM mfa_resets WHERE user_id = ? AND verify_hash = ? AND completed_at IS NULL').get(userId, verifyHash);
    if (!row) return { ok: false, error: 'invalid_code' };
    if (Date.parse(row.expires_at) < Date.now()) return { ok: false, error: 'expired' };
    return { ok: true, row };
}
export function completeMfaReset(userId) {
    db.prepare('UPDATE mfa_resets SET completed_at = ? WHERE user_id = ? AND completed_at IS NULL').run(nowIso(), userId);
}

// ---------------------------------------------------------------------------
// Forensic investigation cases (digital forensics dashboard)
// ---------------------------------------------------------------------------
export function createCase(c) {
    db.prepare(`INSERT INTO cases (id, ref, title, severity, status, created_by, scope, summary, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?)`)
        .run(c.id, c.ref, c.title, c.severity, c.createdBy, JSON.stringify(c.scope || {}), c.summary || '', c.createdAt, c.updatedAt);
}
export function listCases(limit = 50) {
    return db.prepare(`SELECT id, ref, title, severity, status, created_by, summary, created_at, updated_at,
        (SELECT COUNT(*) FROM case_items i WHERE i.case_id = cases.id) AS items
        FROM cases ORDER BY created_at DESC LIMIT ?`).all(limit);
}
export function getCase(id) {
    const c = db.prepare('SELECT * FROM cases WHERE id = ?').get(id);
    if (!c) return null;
    c.scope = JSON.parse(c.scope || '{}');
    return c;
}
export function updateCaseStatus(id, status) {
    db.prepare('UPDATE cases SET status = ?, updated_at = ? WHERE id = ?').run(status, nowIso(), id);
}
export function updateCaseSummary(id, summary) {
    db.prepare('UPDATE cases SET summary = ?, updated_at = ? WHERE id = ?').run(summary, nowIso(), id);
}
export function deleteCase(id) {
    db.prepare('DELETE FROM case_items WHERE case_id = ?').run(id);
    db.prepare('DELETE FROM cases WHERE id = ?').run(id);
}
export function addCaseItem({ caseId, source, sourceId, ts, payload, note }) {
    db.prepare(`INSERT INTO case_items (case_id, source, source_id, ts, payload, note)
        VALUES (?, ?, ?, ?, ?, ?)`)
        .run(caseId, source, sourceId, ts, JSON.stringify(payload || {}), note || '');
    db.prepare('UPDATE cases SET updated_at = ? WHERE id = ?').run(nowIso(), caseId);
}
export function listCaseItems(caseId) {
    return db.prepare('SELECT * FROM case_items WHERE case_id = ? ORDER BY ts').all(caseId)
        .map((i) => ({ ...i, payload: JSON.parse(i.payload || '{}') }));
}