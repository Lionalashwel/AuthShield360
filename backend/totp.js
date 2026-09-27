/**
 * AuthShield 360 - OTP (TOTP RFC 6238) module.
 * Pure standard-library implementation so it works offline on any Node >= 20.
 * The dashboard exposes the "Demo OTP" of every seed account so security
 * testers can feed valid codes into Burp Suite / OWASP ZAP without third-party
 * authenticator apps.
 */
import crypto from 'node:crypto';
import { POLICY } from './config.js';

function base32Decode(b32) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = 0, value = 0, out = Buffer.alloc((b32.length * 5) >> 3), idx = 0;
    for (const ch of b32.toUpperCase().replace(/=+$/, '')) {
        const v = alphabet.indexOf(ch);
        if (v < 0) throw new Error('Invalid base32 char: ' + ch);
        value = (value << 5) | v;
        bits += 5;
        if (bits >= 8) {
            out[idx++] = (value >>> (bits - 8)) & 0xff;
            bits -= 8;
        }
    }
    return out.subarray(0, idx);
}

function hotp(secret, counter, digits = POLICY.TOTP_DIGITS) {
    const key = base32Decode(secret);
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
    buf.writeUInt32BE(counter >>> 0, 4);
    const h = crypto.createHmac('sha1', key).update(buf).digest();
    const offset = h[h.length - 1] & 0x0f;
    const code = ((h[offset] & 0x7f) << 24) |
                 ((h[offset + 1] & 0xff) << 16) |
                 ((h[offset + 2] & 0xff) << 8) |
                 (h[offset + 3] & 0xff);
    return (code % (10 ** digits)).toString().padStart(digits, '0');
}

/** Current moving counter window. */
function currentCounter(atMs = Date.now()) {
    return Math.floor(atMs / 1000 / POLICY.TOTP_STEP_SEC);
}

/** Current valid OTP for the given time (default: now). */
export function totpNow(secret, atMs = Date.now()) {
    return hotp(secret, currentCounter(atMs));
}

/** OTP for a specific window (used to probe evolved epochs). */
export function totpAt(secret, counterOffset) {
    return hotp(secret, currentCounter() + counterOffset);
}

/** Error message tokens used by the SRS outcome codes. */
const PAD = '';

/** True when the OTP equals the current window (or a recent one). */
export function verifyTotp(secret, candidate, opts = {}) {
    if (typeof candidate !== 'string') return { ok: false, reason: 'INVALID_OTP' };
    const c = candidate.replace(/\s/g, '').toUpperCase();
    for (let w = 0; w <= POLICY.TOTP_MAX_WINDOWS_BACK; w++) {
        const expected = hotp(secret, currentCounter() - w);
        if (expected === c) {
            return { ok: true, reason: 'OK' };
        }
    }
    const expired = opts.allowExpired ? false : isExpired(candidate, secret);
    return { ok: false, reason: expired ? 'EXPIRED_OTP' : 'INVALID_OTP' };
}

/** Detect whether a candidate that fails the current window is an EXPIRED one. */
function isExpired(candidate, secret) {
    const c = String(candidate || '').trim().toUpperCase();
    if (!/^\d{6}$/.test(c)) return false;
    for (let w = POLICY.TOTP_MAX_WINDOWS_BACK + 1; w <= 10; w++) {
        if (hotp(secret, currentCounter() - w) === c) return true;
    }
    return false;
}