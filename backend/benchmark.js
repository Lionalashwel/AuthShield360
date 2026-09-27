/**
 * AuthShield 360 - Authentication mode comparison (Benchmark Service)
 *
 * SRS 1.2 "Comparison of Authentication Modes": the portal must compare
 *   Password-Only  |  Password + OTP  |  Password + OTP + E-mail step-up
 * using REAL measured data persisted in the audit trail (elapsed_ms),
 * e.g. average login time, successful/failed sign-ins, second-factor
 * failures, blocked attempts. Figures are aggregated from at least the
 * runs stored in the database (≥3 runs per scenario recommended).
 */
import { rawDb } from './db.js';
import { POLICY } from './config.js';

const METRICS = ['SUCCESS', 'FAILED_PASSWORD', 'INVALID_OTP', 'EXPIRED_OTP', 'HIGH_RISK_BLOCK', 'STEP_UP', 'RECOVERY_REQUEST', 'RECOVERY_RESET'];

export function auditTotals() {
    const db = rawDb();
    const rows = db.prepare('SELECT outcome, COUNT(*) n FROM audit_trail GROUP BY outcome').all();
    const map = Object.fromEntries(rows.map((r) => [r.outcome, Number(r.n)]));
    return Object.fromEntries(METRICS.map((m) => [m, map[m] || 0]));
}

function scenarioStats(scenario) {
    const db = rawDb();
    const rows = db.prepare(
        'SELECT COUNT(*) n, AVG(elapsed_ms) avgms FROM audit_trail WHERE scenario = ? AND outcome IN (?,?,?,?,?,?)'
    ).all(scenario, 'SUCCESS', 'FAILED_PASSWORD', 'INVALID_OTP', 'EXPIRED_OTP', 'HIGH_RISK_BLOCK', 'STEP_UP');
    const total = Number(rows[0].n);
    const avgOverall = rows[0].avgms ? Math.round(rows[0].avgms) : 0;

    const succ = db.prepare('SELECT COUNT(*) n, AVG(elapsed_ms) avgms FROM audit_trail WHERE scenario = ? AND outcome = ?')
        .get(scenario, 'SUCCESS');
    const secFactorFail = db.prepare('SELECT COUNT(*) n FROM audit_trail WHERE scenario = ? AND outcome IN (?, ?)')
        .get(scenario, 'INVALID_OTP', 'EXPIRED_OTP');

    return {
        scenario,
        label: scenarioLabels()[scenario],
        attempts: total,
        averageLoginTimeMs: succ.avgms ? Math.round(succ.avgms) : 0,
        averageAttemptTimeMs: avgOverall,
        success: Number(succ.n),
        failedPassword: countBy(scenario, 'FAILED_PASSWORD'),
        secondFactorFailures: Number(secFactorFail.n),
        invalidOtp: countBy(scenario, 'INVALID_OTP'),
        expiredOtp: countBy(scenario, 'EXPIRED_OTP'),
        blocked: countBy(scenario, 'HIGH_RISK_BLOCK'),
        stepUp: countBy(scenario, 'STEP_UP'),
        recovery: countBy(scenario, 'RECOVERY_REQUEST') + countBy(scenario, 'RECOVERY_RESET'),
    };
}

export function scenarioLabels() {
    return {
        1: 'Password-only baseline (S1)',
        2: 'Password + Mobile OTP MFA (S2)',
        3: 'Password + OTP + E-mail step-up + RBAC (S3)',
    };
}

function countBy(scenario, outcome) {
    return Number(rawDb().prepare('SELECT COUNT(*) n FROM audit_trail WHERE scenario = ? AND outcome = ?').get(scenario, outcome).n);
}

export function benchmarkAll() {
    const totals = auditTotals();
    return {
        scenarios: [1, 2, 3].map(scenarioStats),
        totals,
        policyBand: { low: POLICY.RISK_LOW_MAX, medium: POLICY.RISK_MEDIUM_MAX },
        note: 'Measured from real audit trail (elapsed_ms) — run each scenario ≥3 times for a stable average.',
    };
}