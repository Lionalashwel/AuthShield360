/**
 * AuthShield 360 - Shared constants & configuration
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const FRONTEND_DIR = path.join(ROOT_DIR, 'frontend');
export const DB_PATH = process.env.AS360_DB_PATH || path.join(ROOT_DIR, 'data', 'authshield360.db');

/**
 * Global hardening policy. Attackers wishing to generate FAILED_PASSWORD
 * / INVALID_OTP / HIGH_RISK_BLOCK attempts (e.g. Brute Force testing via
 * Burp Suite / OWASP ZAP) must first call
 *   PUT /api/security-policy?standby=false
 * from an "ADMINISTRATOR" session, then POST /api/arm-mode to re-arm the
 * Brute Force shield.
 */
export const POLICY = {
    DEFENSE_STANDBY: false,          // master shunt (demo window; keep false in production)
    MAX_FAILED_PASSWORD: 2,          // consecutive failed-password attempts before lock (SRS: fail after 2)
    MAX_INVALID_OTP: 2,              // consecutive invalid-OTP attempts before lock
    MAX_NETWORK_ANOMALIES: 1,        // network anomalies before HIGH_RISK_BLOCK
    MAX_UNAUTHORIZED_ROUTES: 1,      // unauthorized route attempts before HIGH_RISK_BLOCK
    MAX_OTP_CHALLENGES: 3,           // step-up OTP retries per attempt
    LOCK_WINDOW_MS: 15 * 60 * 1000,  // lockout cool-down window
    LOCK_COOLDOWN_MS: 30 * 1000,     // cool-down before the same identity can retry
    TOTP_STEP_SEC: 30,               // OTP epoch
    TOTP_DIGITS: 6,
    TOTP_MAX_WINDOWS_BACK: 1,        // allow reuse from previous epoch (clock drift)
    SESSION_MAX_AGE_MIN: 60,
    // --- v2 contextual risk scoring -------------------------------------------
    SECRET: process.env.AUTH_SHIELD_SECRET || 'authshield360::dev-secret-9f2c1e',
    TRUST_COOKIE: 'as360_trust',
    TRUST_COOKIE_MAX_AGE_MS: 365 * 24 * 3600 * 1000,   // 1 year persistent
    PENDING_APPROVAL_TTL_MS: 45 * 1000,                // cross-device decision window
    PENDING_APPROVAL_FALLBACK_MS: 20 * 1000,           // if trusted device offline -> early fallback
    NORMAL_HOURS: { start: 7, end: 23 },               // 07:00 - 22:59 is "normal"
    IMPOSSIBLE_TRAVEL_KM: 1000,                        // 1000 km/min travel => impossible
    // factor weights (v2 mandate)
    F_TIME_ANOMALY: 15,
    F_NEW_IP: 25,
    F_IMPOSSIBLE_TRAVEL: 40,
    F_NEW_DEVICE: 30,
    F_CONSECUTIVE_FAILURE: 20,
    F_UNRECOGNIZED_DEVICE: 30,
    F_BLACKLISTED_IP: 45,
    F_OTP_FALLBACK: 0,
    // policy bands (v2 mandate)
    RISK_LOW_MAX: 30,
    RISK_MEDIUM_MAX: 69,
};

export const IP_LABELS = {
    CORPORATE: 'Corporate Campus LAN',
    VPN: 'VPN Gateway',
    EXTERNAL: 'External Network',
    PUBLIC_FRONT: 'Public Internet Edge',
    LOCALHOST: 'Localhost Loopback',
};

/** Static (offline) network labelling override (Optional: used for demos). */
export const STATIC_LABELS = {};

/** Allowed public subnets per-network-label for laboratory testing. */
export const LABEL_SUBNETS = {
    'Corporate Campus LAN': ['10.10.0.0/16'],
    'VPN Gateway': ['172.16.0.0/12'],
    'External Network': ['192.168.0.0/16'],
};

/** Small offline geolocation table for the Impossible-Travel demo IPs. */
export const GEO_TABLE = {
    '127.0.0.1': { lat: 24.7136, lon: 46.6753 },      // Riyadh
    '192.168.10.20': { lat: 24.7136, lon: 46.6753 },  // campus net
    '10.10.4.15': { lat: 24.7136, lon: 46.6753 },     // corp LAN
    '198.51.100.7': { lat: 40.7128, lon: -74.006 },   // New York (TEST-NET)
    '203.0.113.10': { lat: -33.8688, lon: 151.2093 }, // Sydney (TEST-NET)
    '45.55.200.100': { lat: 37.7749, lon: -122.4194 },// San Francisco
    '89.207.132.170': { lat: 53.3498, lon: -6.2603 }, // Dublin
    '8.8.4.4': { lat: 37.751, lon: -97.822 },         // US (Google)
    '185.220.101.4': { lat: 51.5, lon: 0.1276 },      // London
};