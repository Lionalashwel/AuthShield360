/**
 * AuthShield 360 - Adaptive Risk Scoring Engine (v2 contextual)
 *
 * Every sign-in is scored 0-100 with EXPLICIT REASONS:
 *   TIME_ANOMALY            +15   - login outside normal hours (07:00-22:59)
 *   NEW_IP / SUBNET_CHANGE  +25   - never-seen IP or subnet
 *   IMPOSSIBLE_TRAVEL       +40   - two locations too far apart too fast
 *   UNRECOGNIZED_DEVICE     +30   - unknown device footprint
 *   CONSECUTIVE_FAILURES    +20/ea- velocity / repeated failures
 *   BLACKLISTED_IP          +45   - toxic / blacklisted source network
 *
 * Policy bands (v2 mandate):
 *   LOW    0-30   -> direct login
 *   MEDIUM 31-69  -> cross-device approval OR OTP
 *   HIGH   70-100 -> account lockdown + admin alert
 */
import { POLICY } from './config.js';
import { clampScore } from './utils.js';

/**
 * ctx: {
 *   timeAnomaly:boolean, newIp:boolean, impossibleTravel:boolean,
 *   unrecognizedDevice:boolean, consecutiveFailures:number,
 *   blacklistedIp:boolean
 * }
 * @returns {{score:number, level:'LOW'|'MEDIUM'|'HIGH', reasons:string[]}}
 */
export function evaluateRisk(ctx = {}) {
    const reasons = [];

    if (ctx.timeAnomaly) reasons.push('TIME_ANOMALY');
    if (ctx.newIp) reasons.push('NEW_IP');
    if (ctx.impossibleTravel) reasons.push('IMPOSSIBLE_TRAVEL');
    if (ctx.unrecognizedDevice) reasons.push('UNRECOGNIZED_DEVICE');
    if (ctx.consecutiveFailures > 0) {
        reasons.push('CONSECUTIVE_FAILURES');
        if (ctx.consecutiveFailures > 5) reasons.push('RECURRING_FAILURES');
    }
    if (ctx.blacklistedIp) reasons.push('BLACKLISTED_IP');
    if (reasons.length === 0) reasons.push('BASELINE');

    let score = 0;
    score += ctx.timeAnomaly ? POLICY.F_TIME_ANOMALY : 0;
    score += ctx.newIp ? POLICY.F_NEW_IP : 0;
    score += ctx.impossibleTravel ? POLICY.F_IMPOSSIBLE_TRAVEL : 0;
    score += ctx.unrecognizedDevice ? POLICY.F_UNRECOGNIZED_DEVICE : 0;
    score += clampScore((ctx.consecutiveFailures || 0) * POLICY.F_CONSECUTIVE_FAILURE);
    score += ctx.blacklistedIp ? POLICY.F_BLACKLISTED_IP : 0;

    score = clampScore(score);

    let level = 'LOW';
    if (score >= POLICY.RISK_MEDIUM_MAX + 1) level = 'HIGH';
    else if (score >= POLICY.RISK_LOW_MAX + 1) level = 'MEDIUM';

    return { score, level, reasons: [...new Set(reasons)] };
}