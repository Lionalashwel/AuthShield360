/**
 * AuthShield 360 - Low-level helpers (time, tokens, math, obfuscation).
 * All helper functions here are intentionally "test-friendly": pure, and free
 * of side effects, so the Adaptive Risk Engine and Audit pipeline can be
 * exercised by the automated Identity_Security_Test_Matrix jobs.
 */
import crypto from 'node:crypto';

/** ISO-8601 UTC timestamp with milliseconds (SRS: "Precise ISO/UTC timestamp"). */
export function nowIso(d = new Date()) {
    return d.toISOString();
}

export function epochNow() {
    return Math.floor(Date.now() / 1000);
}

/** Deterministic 32-bit hash from a stable string (device + ip + label). */
export function stableHash(str) {
    const h = crypto.createHash('sha1').update(String(str)).digest('hex');
    return (parseInt(h.slice(0, 8), 16) >>> 0).toString(16).padStart(8, '0');
}

/** Non-deterministic session token (must not be predictable). */
export function randomToken(len = 32) {
    return crypto.randomBytes(len).toString('base64url');
}

/** Minimal password "hash" -- demo only, replace with scrypt in production. */
export function hashPassword(pw) {
    return crypto.createHash('sha256').update('as360::' + pw + '::pepper').digest('hex');
}

export function clampScore(n) {
    return Math.min(100, Math.max(0, n));
}

/**
 * Obfuscated network identity:
 *   subnet  '10.10.4.0/24' -> CIDR block of the first non-loopback host
 *   masked  '10.10.*.*'
 */
export function subnetOf(ip) {
    const p = String(ip || '').split('.');
    if (p.length < 3 || p.some((x) => !/^\d+$/.test(x))) return null;
    return p.slice(0, 3).join('.') + '.0/24';
}
export function maskIp(ip) {
    const p = String(ip || '').split('.');
    if (p.length < 2) return '?.?.?';
    return p.slice(0, 2).concat('*', '*').join('.');
}

/** Human readable session UID (SID:123456-abc...). */
export function newSid() {
    return 'SID:' + Math.floor(Math.random() * 1e15).toString(36) + '-' +
        crypto.randomBytes(4).toString('hex').toUpperCase();
}

export function shortText(s, n = 72) {
    s = String(s || '');
    return s.length > n ? s.slice(0, n - 3) + '...' : s;
}

/** Pretty print risk level names (internal helpers used by UI templates). */
export const RISK_LEVELS = {
    LOW: 'LOW',
    MEDIUM: 'MEDIUM',
    HIGH: 'HIGH',
};