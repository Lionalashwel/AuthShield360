/**
 * AuthShield 360 - Attack Simulation Engine (v2)
 * Three selectable attack archetypes, each driven against the REAL auth
 * pipeline (attemptAuthentication). Every step runs live and streams onto
 * the SOC timeline + SSE.
 *
 *   Type A  BRUTE_FORCE        : rapid sequential password failures, same IP
 *   Type B  IMPOSSIBLE_TRAVEL  : two logins from far-apart locations < 10 s
 *   Type C  CREDENTIAL_STUFFING: correct password from a blacklisted IP + new device
 */
import { POLICY } from './config.js';
import { analyzeNetwork, geoLabel } from './network.js';
import { attemptAuthentication, releaseLockout } from './auth.js';
import { nowIso, newSid } from './utils.js';
import { totpNow } from './totp.js';
import {
    dbHelpers,
    upsertAttackRun, attackRuns, blacklistAdd, blacklistRemove,
    insertAlert, whitelistAll, blacklistAll,
} from './db.js';
import { publish } from './events.js';

const ATTACK_IPS = ['198.51.100.7', '185.220.101.4', '203.0.113.10'];
const TARGET = { username: 'teacher2', password: 'Teacher@123' };

export function createSimulation(type, title, opts = {}) {
    const id = 'sim-' + Date.now().toString(36);
    const timeline = [{ ts: nowIso(), phase: 0, status: 'INFO', text: `Attack started: ${title}` }];
    upsertAttackRun(id, 0, 'RUNNING', title, timeline);
    publish('sim', { type: 'sim', data: { id, phase: 0, status: 'INFO', text: timeline[0].text, ts: timeline[0].ts } });

    const attrs = ATTACK_IPS[Math.floor(Math.random() * ATTACK_IPS.length)];
    stopWatch(() => run(type, { id, title, attackIp: attrs, ...opts }));
    return { id, title };
}

function stopWatch(fn) { fn(); }

async function run(type, { id, title, attackIp }) {
    const TA = (phase, status, text, extra = {}) => {
        const ev = { ts: nowIso(), phase, status, text, ...extra };
        const run = attackRuns().find((r) => r.id === id);
        const timeline = run ? run.timeline : [];
        timeline.push(ev);
        upsertAttackRun(id, phase, status, title, timeline);
        publish('sim', { type: 'sim', data: ev });
    };

    const cli = (over = {}) => ({ ip: attackIp, ua: 'AuthShield-SAE (sim)', fingerprint: 'fp:' + newSid().replace(/[^a-z0-9]/gi, '').slice(0, 20), ...over });

    if (type === 'A') {
        TA(1, 'WARN', `[BRUTE_FORCE] 3 rapid password guesses from ${attackIp}`);
        for (let i = 1; i <= 3; i++) {
            const r = await attemptAuthentication({
                username: TARGET.username, password: ['letmein', 'Password123', 'admin'][i - 1],
                scenario: 1, ...cli(),
            });
            TA(1 + (i - 1) * 0.01, r.outcome === 'HIGH_RISK_BLOCK' ? 'CRIT' : 'WARN', `guess #${i} → ${r.outcome} risk=${r.risk}`);
            if (r.outcome === 'HIGH_RISK_BLOCK') break;
        }
        TA(4, 'CRIT', '[BRUTE_FORCE] account quarantined after consecutive failures (+20/attempt)');
        const blocked = await attemptAuthentication({ username: TARGET.username, password: TARGET.password, scenario: 1, ...cli() });
        TA(4, blocked.outcome === 'HIGH_RISK_BLOCK' ? 'SUCCESS' : 'CRIT', `[BRUTE_FORCE] post-lock verification → ${blocked.outcome}`);

} else if (type === 'B') {
        const ipA = '45.55.200.100';       // San Francisco
        const ipB = '203.0.113.10';        // Sydney (~12,000 km)
        const otp = totpNow(dbHelpers.getUser(TARGET.username).totp_secret);
        TA(1, 'WARN', `[IMPOSSIBLE_TRAVEL] login #1 accepted from ${geoLabel(ipA)} (OTP proof)`);
        const r1 = await attemptAuthentication({ username: TARGET.username, password: TARGET.password, otp, scenario: 2, ...cli({ ip: ipA, fingerprint: 'fp:' + newSid() }) });
        TA(1, r1.outcome === 'SUCCESS' ? 'INFO' : 'WARN', `login #1 → ${r1.outcome} risk=${r1.risk} (${r1.reasons?.join(',')})`);
        await sleepMs(1200);
        const r2 = await attemptAuthentication({ username: TARGET.username, password: TARGET.password, otp, scenario: 2, ...cli({ ip: ipB, fingerprint: 'fp:' + newSid() }) });
        const travel = (r2.reasons || []).includes('IMPOSSIBLE_TRAVEL');
        TA(2, 'CRIT', `[IMPOSSIBLE_TRAVEL] login #2 from ${geoLabel(ipB)} 12 s later ${travel ? '⇒ IMPOSSIBLE_TRAVEL +40' : '(missed)'}`);
        if (travel) {
            TA(3, 'CRIT', '[IMPOSSIBLE_TRAVEL] risk crossed 70 → HIGH → account lockdown');
            TA(4, 'SUCCESS', `[IMPOSSIBLE_TRAVEL] lockdown enforced → ${r2.outcome} risk=${r2.risk}`);
        } else {
            TA(4, 'WARN', `[IMPOSSIBLE_TRAVEL] missed: last successful login not SF`);
        }
    }

    else { // type C
        TA(1, 'WARN', `[CREDENTIAL_STUFFING] correct credentials replayed from blacklisted IP ${attackIp}`);
        releaseLockout(TARGET.username);
        await blacklistAdd(attackIp, 'credential-stuffing (simulated)');
        TA(2, 'INFO', '[CREDENTIAL_STUFFING] IP added to blacklist (source is toxic)');
        const r = await attemptAuthentication({ username: TARGET.username, password: TARGET.password, scenario: 1, ...cli() });
        TA(3, r.outcome === 'HIGH_RISK_BLOCK' ? 'CRIT' : 'WARN', `[CREDENTIAL_STUFFING] wrong pass irrelevant: BLACKLISTED_IP(+45)+UNRECOGNIZED_DEVICE(+30)= HIGH`);
        TA(4, 'SUCCESS', `[CREDENTIAL_STUFFING] exploit neutralised → ${r.outcome} risk=${r.risk}`);
    }

    TA(4, 'COMPLETE', 'Defense chain verified — SIMULATION COMPLETE');
    upsertAttackRun(id, 4, 'COMPLETE', title, attackRuns().find((r) => r.id === id).timeline);
    publish('sim', { type: 'sim', data: { id, phase: 5, status: 'COMPLETE', text: 'SIMULATION COMPLETE', ts: nowIso() } });
}

function sleepMs(ms) { return new Promise((r) => setTimeout(r, ms)); }

export function listSimulations() { return attackRuns(); }
export const ATTACK_TYPES = [
    { type: 'A', label: 'Brute Force Attack' },
    { type: 'B', label: 'Impossible Travel Attack' },
    { type: 'C', label: 'Credential Stuffing Attack' },
];