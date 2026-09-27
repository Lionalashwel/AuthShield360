/**
 * AuthShield 360 - Network Intelligence
 * Pure, offline geolocation/subnet labelling. Public IPs are categorized into
 * "Public Internet Edge"; private ranges get the corresponding network label
 * (Corporate Campus LAN / VPN Gateway / External Network).
 */
import { IP_LABELS, GEO_TABLE } from './config.js';
import { subnetOf } from './utils.js';

const CONFIDENTIAL_RANGES = [
    { cidr: '10.0.0.0/8', label: IP_LABELS.CORPORATE },
    { cidr: '172.16.0.0/12', label: IP_LABELS.VPN },
    { cidr: '192.168.0.0/16', label: IP_LABELS.EXTERNAL },
];

function ipToLong(ip) {
    const p = String(ip || '').split('.');
    if (p.length !== 4 || p.some((x) => !/^\d{1,3}$/.test(x))) return null;
    return p.reduce((acc, o) => (acc << 8) + parseInt(o, 10), 0) >>> 0;
}

function cidrToRange(cidr) {
    const [ip, bitsRaw] = cidr.split('/');
    const bits = parseInt(bitsRaw, 10) || 0;
    const addr = ipToLong(ip);
    if (addr === null) return [0, 0];
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return [addr & mask, (addr & mask) | ~mask >>> 0];
}

function normalizeIp(ip) {
    const v = String(ip || '').trim();
    if (!v) return null;
    // IPv6 loopback / IPv4-mapped loopback -> 127.0.0.1
    if (v === '::1' || v === '::ffff:127.0.0.1') return '127.0.0.1';
    const m = v.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    return m ? m[1] : null;
}

/**
 * Returns { ip, subnet, network, isPrivate } for a raw socket address.
 * Priority: header-provided (X-Forwarded-For / CF-Connecting-IP) then local.
 */
export function analyzeNetwork(rawIp, extraLabels = {}) {
    const ip = normalizeIp(rawIp);
    if (!ip) return { ip: 'unknown', subnet: null, network: IP_LABELS.EXTERNAL, isPrivate: false };

    const subnet = subnetOf(ip);
    const long = ipToLong(ip);

    let label = null;
    if (ip === '127.0.0.1' || ip === '::1') label = 'Localhost Loopback';
    for (const range of CONFIDENTIAL_RANGES) {
        const [lo, hi] = cidrToRange(range.cidr);
        if (long >= lo && long <= hi) { label = range.label; break; }
    }

    // Overrides from lab/demo config (STATIC_LABELS in config.js).
    const override = extraLabels[ip];
    label = override || label || IP_LABELS.PUBLIC_FRONT;

    return {
        ip,
        subnet,
        network: label,
        isPrivate: long >= ipToLong('10.0.0.0') && long <= ipToLong('192.168.255.255'),
    };
}

/** Convenience: does `ip` fall inside an allowed subnet list? */
export function ipInAny(ip, cidrs) {
    const long = ipToLong(ip);
    if (long === null) return false;
    return cidrs.some((cidr) => {
        const [lo, hi] = cidrToRange(cidr);
        return long >= lo && long <= hi;
    });
}

const EARTH_R = 6371; // km

/** Approximate geodesic distance (km) between two IPs, via GEO_TABLE. */
export function distanceKm(ipA, ipB) {
    const gA = GEO_TABLE[ipA];
    const gB = GEO_TABLE[ipB];
    if (!gA || !gB) return -1; // unknown -> cannot conclude (not impossible)
    const toRad = (d) => (d * Math.PI) / 180;
    const dLat = toRad(gB.lat - gA.lat);
    const dLon = toRad(gB.lon - gA.lon);
    const h = Math.sin(dLat / 2) ** 2 +
        Math.cos(toRad(gA.lat)) * Math.cos(toRad(gB.lat)) * Math.sin(dLon / 2) ** 2;
    return 2 * EARTH_R * Math.asin(Math.sqrt(h));
}

/** Human-readable geo label for an IP (used in the cross-device dialog). */
export function geoLabel(ip) {
    const g = GEO_TABLE[ip];
    return g ? `${ip} (~${g.lat.toFixed(1)},${g.lon.toFixed(1)})` : ip;
}