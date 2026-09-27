/**
 * AuthShield 360 - Device Fingerprint
 * Client emits a deterministic SHA-256 of a stable-collected fingerprint.
 * The server wraps it with the requesting IP to prevent trivial copy/paste,
 * producing the persisted `fingerprint_hash`.
 */
import crypto from 'node:crypto';

/** SHA-256 hex digest of the raw browser fingerprint string. */
export function digestFingerprint(raw, ip) {
    return crypto.createHash('sha256')
        .update(`as360::${raw || ''}::${ip || ''}`)
        .digest('hex');
}

/**
 * The authoritative fingerprint used by the Risk Engine and `devices` table.
 * When a clean browser fingerprint is unavailable (headless test clients)
 * we fall back to a deterministic MAC-like id derived from UA + IP.
 */
export function computeFingerprint({ userAgent = '', ip = '' } = {}) {
    const seed = `${userAgent}|${ip}`;
    return 'fp:' + crypto.createHash('sha256').update(seed).digest('hex').slice(0, 32);
}

/** Browser "model" extracted from a User-Agent header string. */
export function uaModel(ua = '') {
    ua = String(ua || 'Unknown Browser');
    const m = ua.match(/\(([^)]+)\)/);
    return m ? m[1] : 'Unknown OS';
}