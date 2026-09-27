/**
 * AuthShield 360 - Trusted-Device cookie
 * AES-256-GCM envelope carrying { fp, uid, iat }. HTTP-only, persistent,
 * issued only after email verification (trusted-device designation).
 */
import crypto from 'node:crypto';
import { POLICY } from './config.js';

const KEY = crypto.scryptSync(POLICY.SECRET, 'as360-trust', 32);
const ALGO = 'aes-256-gcm';

/** Encode {fp, uid} into an opaque, tamper-evident token. */
export function sealTrustCookie({ fp, uid }) {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv(ALGO, KEY, iv);
    const payload = JSON.stringify({ fp, uid, iat: Date.now() });
    const enc = Buffer.concat([c.update(payload, 'utf8'), c.final()]);
    const tag = c.getAuthTag();
    return Buffer.concat([iv, tag, enc]).toString('base64url');
}

/** Decode + authenticate. Returns null on any tamper/failure. */
export function openTrustCookie(token) {
    try {
        const buf = Buffer.from(token, 'base64url');
        if (buf.length < 28) return null;
        const iv = buf.subarray(0, 12);
        const tag = buf.subarray(12, 28);
        const enc = buf.subarray(28);
        const d = crypto.createDecipheriv(ALGO, KEY, iv);
        d.setAuthTag(tag);
        const json = Buffer.concat([d.update(enc), d.final()]).toString('utf8');
        const o = JSON.parse(json);
        if (!o.fp || !o.uid) return null;
        return o;
    } catch {
        return null;
    }
}

/** Build the `Set-Cookie` express options for the trust cookie. */
export function trustCookieOptions() {
    return {
        httpOnly: true,
        secure: false,                 // local HTTP demo; set true behind TLS
        sameSite: 'lax',
        maxAge: Math.floor(POLICY.TRUST_COOKIE_MAX_AGE_MS / 1000),
        path: '/',
    };
}