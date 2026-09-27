/**
 * AuthShield 360 - Health / readiness snapshot
 * Mirrors defense posture, SSE listeners and REAL database COUNT()s for the
 * SOC status bar without hammering the DB on every poll.
 */
import { POLICY } from './config.js';
import { listenerCount } from './events.js';
import { auditCount, alertCountSync } from './db.js';
import { blacklistAll } from './db.js';

const state = { defenseStandby: POLICY.DEFENSE_STANDBY, note: 'initialized' };

export function setHealthFlag({ defenseStandby, note }) {
    state.defenseStandby = defenseStandby;
    state.note = note;
}

export function publishedHealth() {
    return {
        defenseStandby: state.defenseStandby,
        note: state.note,
        listeners: listenerCount(),
        counters: {
            success: auditCount('SUCCESS'),
            failedPassword: auditCount('FAILED_PASSWORD'),
            invalidOtp: auditCount('INVALID_OTP'),
            expiredOtp: auditCount('EXPIRED_OTP'),
            highRiskBlock: auditCount('HIGH_RISK_BLOCK'),
            stepUp: auditCount('STEP_UP'),
            alerts: alertCountSync(),
            blockedIps: blacklistAll().length,
        },
        ts: new Date().toISOString(),
    };
}

/** Used by any admin action that changes posture. */
export function healthFlag() { return state; }