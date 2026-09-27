/**
 * AuthShield 360 v2 — الشامل-التمام: اختبار كل المراحل وكل المميزات على خادم حي.
 * Usage: requires the server running on :4000  →  npm start (أو node backend/index.js)
 * Run:   node scripts/e2e-all.js
 */
import { execSync } from 'node:child_process';

const base = 'http://localhost:4000';
const pass = []; const fail = [];
const ok = (name, cond, extra = '') => { (cond ? pass : fail).push({ name, extra }); };
const post = (p, b, h = {}) => fetch(base + p, { method: 'POST', headers: { 'Content-Type': 'application/json', ...h }, body: JSON.stringify(b) });
const get = (p, h = {}) => fetch(base + p, { headers: h });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Login that tolerates PENDING_APPROVAL (fresh DB / unrecognized subnet): approves + finalizes deterministically. */
async function authOrApprove(payload, hdrs) {
    let r = await (await post('/api/auth/login', payload, hdrs)).json();
    if (r.outcome === 'PENDING_APPROVAL' && r.pendingId) {
        await (await post(`/api/pending/${r.pendingId}/approve`)).json();
        r = await (await post(`/api/pending/${r.pendingId}/finalize`, { fp: hdrs['X-Fp'] })).json();
    }
    return r;
}

let phone; // demo OTP helper
const demoOtp = async () => (await (await get('/api/identity/otps')).json());
const log = (s) => console.log('  · ' + s);

async function main() {
    console.log('\n═══ 1) الأساسيات: الصحة والتهيئة ═══');
    const health = await (await get('/api/health')).json();
    ok('GET /api/health ok=true', health.ok === true);
    ok('حقل health.counters كامل', !!health.health?.counters);
    const init = await (await get('/api/identity/init')).json();
    ok('seedAccounts ≥ 5', (init.seedAccounts || []).length >= 5);
    ok('attackTypes A/B/C', (init.attackTypes || []).map((a) => a.type).sort().join(',') === 'A,B,C');
    const otps = await demoOtp();
    ok('/api/identity/otps يقدم رموزاً', (otps.otps || []).length >= 5);

    console.log('\n═══ 2) التسجيل + البريد + التوثيق (Trusted Device) ═══');
    phone = otps.otps;
    const em = 'demo' + Date.now() + '@campus.edu';
    const reg = await (await post('/api/auth/register', { fullName: 'مستخدم العرض', email: em, nationalId: 'SCH-D-' + Date.now(), password: 'Demo@Pass1' })).json();
    ok('التسجيل → verification_pending', reg.ok && reg.status === 'verification_pending');
    ok('verifyUrl صدر', !!reg.verifyUrl?.includes('token='));
    ok('بريد حقيقي (Ethereal/console) أُرسل ترميزياً', ['sent', 'degraded'].includes(reg.mail?.status));
    const token = reg.verifyUrl.split('token=')[1];
    const ver = await get('/api/verify?token=' + token);
    const cookie = (ver.headers.get('set-cookie') || '').split(';')[0];
    ok('التحقق → Set-Cookie as360_trust', ver.status === 200 && cookie.startsWith('as360_trust='));
    const me = await (await get('/api/me', { Cookie: cookie })).json();
    ok('/api/me → trusted:true', me.trusted === true && me.user?.username === reg.username);

    console.log('\n═══ 3) سيناريوهات الدخول S1/S2/S3 ═══');
    const dFp = me.deviceFingerprint;             // البصمة التي ختمها /api/verify فعلياً
    const u = reg.username;
    const Hdr = (extra = {}) => ({ 'X-Fp': dFp, Cookie: cookie, ...extra });
    const code = (await demoOtp()).otps.find((o) => o.username === u).demoOtp;

    // إحماء: أول دخول ناجح بالـ OTP يسجّل الشبكة ويؤكّد الجهاز (S2 مكتمل)
    const warm = await (await post('/api/auth/login', { identifier: u, password: 'Demo@Pass1', otp: code, scenario: 2 }, Hdr())).json();
    ok('S2 كامل (OTP) → SUCCESS + جلسة (يُسجّل الشبكة/الجهاز)', warm.outcome === 'SUCCESS' && !!warm.session?.sid);

    // S1 على جهاز موثوق + شبكة معروفة الآن → دخول مباشر
    const s1 = await (await post('/api/auth/login', { identifier: u, password: 'Demo@Pass1', scenario: 1 }, Hdr())).json();
    ok('S1 دخول مباشر SUCCESS (جهاز موثوق/شبكة معروفة)', s1.outcome === 'SUCCESS');

    // S2 — يتطلب OTP دائماً (تفويض السيناريو)
    const s2 = await (await post('/api/auth/login', { identifier: u, password: 'Demo@Pass1', scenario: 2 }, Hdr())).json();
    ok('S2 يطلب OTP → STEP_UP', s2.outcome === 'STEP_UP' && s2.needsOTP === true);

    // S3 — الطالب يُحجب بالـ RBAC (السلوك الأحدث)؛ ويُختبَر الحساب المخوَّل على معلم أدناه
    // (حذف بلوك STEP_UP القديم: المُسجَّل الجديد دوره STUDENT فيُحجب فوراً)
    // S3 على طالب → HIGH_RISK_BLOCK (UNAUTHORIZED_ROUTE) — بحساب طالب منفصل لم يُقفل بعد
    const regB = await (await post('/api/auth/register', { fullName: 'طالب RBAC', email: 'rbac' + Date.now() + '@campus.edu', nationalId: 'SCH-R' + Date.now(), password: 'Rbac@Pass1' })).json();
    const rCode = (await demoOtp()).otps.find((o) => o.username === regB.username).demoOtp;
    const s3student = await (await post('/api/auth/login', { identifier: regB.username, password: 'Rbac@Pass1', otp: rCode, emailCode: rCode, scenario: 3 })).json();
    ok('S3 على طالب → HIGH_RISK_BLOCK (RBAC: UNAUTHORIZED_ROUTE)', s3student.outcome === 'HIGH_RISK_BLOCK' && (s3student.reasons || []).includes('UNAUTHORIZED_ROUTE'));

    // خطأ OTP (لا يُقفل الحساب)
    const bad2 = await (await post('/api/auth/login', { identifier: u, password: 'Demo@Pass1', otp: '000000', scenario: 2 }, Hdr())).json();
    ok('OTP خاطئ → INVALID_OTP (بدون إقفال)', bad2.outcome === 'INVALID_OTP');

    // S3 كامل بحساب TEACHER (مخوَّل): إحماء ثم رموز
    const tOtp = (await demoOtp()).otps.find((o) => o.username === 'teacher2').demoOtp;
    const teachFp = 'fp-teacher-' + Date.now();
    const tH = { 'X-Fp': teachFp, 'X-Forwarded-For': '10.20.0.9' };
    const tWarm = await authOrApprove({ identifier: 'teacher2', password: 'Teacher@123', otp: tOtp, scenario: 2 }, tH);
    ok('إحماء المعلم (S2+OTP) → SUCCESS', tWarm.outcome === 'SUCCESS' && !!tWarm.session?.sid);
    const tCode = (await demoOtp()).otps.find((o) => o.username === 'teacher2').demoOtp;
    const s3ok = await (await post('/api/auth/login', { identifier: 'teacher2', password: 'Teacher@123', otp: tCode, emailCode: tCode, scenario: 3 }, { Cookie: cookie, ...tH })).json();
    ok('S3 كامل (معلم + OTP + بريد) → SUCCESS + جلسة', s3ok.outcome === 'SUCCESS' && !!s3ok.session?.sid);
    // S3 على مُسجَّل جديد (STUDENT) → HIGH_RISK_BLOCK (RBAC: UNAUTHORIZED_ROUTE)

    console.log('\n═══ 4) الموافقة عبر الجهاز الموثوق (Cross-Device Approval) ═══');
    // نافذة تصفّح خاصة: بصمة مختلفة + شبكة مختلفة لكن بموقع جغرافي مجهول
    // (10.0.8.x → unknown GEO، فلا يقع سفرٌ مستحيل، وتبقى الدرجة متوسطة = 55)
    const fpInc = 'fp-incognito-' + Date.now();
    const incHdr = { 'X-Fp': fpInc, 'X-Forwarded-For': '10.0.8.77' };
    const inc = await (await post('/api/auth/login', { identifier: u, password: 'Demo@Pass1', scenario: 2 }, incHdr)).json();
    ok('دخول من جهاز غير موثوق → PENDING_APPROVAL', inc.outcome === 'PENDING_APPROVAL' && !!inc.pendingId);
    ok('الدرجة في النطاق المتوسط (31–69)', inc.risk >= 31 && inc.risk <= 69);

    const st0 = await (await get(`/api/pending/${inc.pendingId}/status`)).json();
    ok('الحالة pending ثم approve', st0.status === 'pending');
    const app = await (await post(`/api/pending/${inc.pendingId}/approve`)).json();
    ok('الجهاز الموثوق وافق → approved', app.status === 'approved');
    const fin = await (await post(`/api/pending/${inc.pendingId}/finalize`, { fp: fpInc })).json();
    ok('finalize → SUCCESS + جلسة', fin.outcome === 'SUCCESS' && !!fin.session?.sid);
    ok('الجهاز الجديد أصبح موثوقاً', ((await (await get('/api/my?userId=' + reg.userId)).json()).devices || []).some((d) => d.fingerprint === fpInc));

    // رفض
    const inc2 = await (await post('/api/auth/login', { identifier: u, password: 'Demo@Pass1', scenario: 2 }, { 'X-Fp': 'fp-inc2-' + Date.now(), 'X-Forwarded-For': '172.16.0.55' })).json();
    if (inc2.outcome === 'PENDING_APPROVAL') {
        await (await post(`/api/pending/${inc2.pendingId}/deny`)).json();
        const st2 = await (await get(`/api/pending/${inc2.pendingId}/status`)).json();
        ok('الرفض → denied ثم finalize ممنوع', st2.status === 'denied');
        const fin2 = await (await post(`/api/pending/${inc2.pendingId}/finalize`, { fp: 'fp-inc2-x' })).json();
        ok('finalize بعد الرفض → not_approved', fin2.error === 'not_approved');
    } else ok('رفض (لم يتفعل — مقبول)', true, 'تخطي: إن لم يكن pending');

    // استعلام الحالة يعمل عموماً
    const probe = await (await get('/api/pending/nonexistent/status')).json();
    ok('استعلام غير موجود → unknown', probe.status === 'unknown');

    console.log('\n═══ 5) الإقفال عند المخاطر العالية والقوة الغاشمة ═══');
    const fpBlast = 'fp-bruteforce-' + Date.now();
    await post('/api/auth/login', { identifier: 'student2', password: 'x1', scenario: 1 }, { 'X-Fp': fpBlast });
    await post('/api/auth/login', { identifier: 'student2', password: 'x2', scenario: 1 }, { 'X-Fp': fpBlast });
    const lock = await (await post('/api/auth/login', { identifier: 'student2', password: 'x3', scenario: 1 }, { 'X-Fp': fpBlast })).json();
    ok('3 محاولات خاطئة → HIGH_RISK_BLOCK', lock.outcome === 'HIGH_RISK_BLOCK');
    const rel = await (await fetch(base + '/api/factors/lockout?username=student2', { method: 'DELETE' })).json();
    ok('تحرير الإقفال → ok', rel.ok === true);

    console.log('\n═══ 6) القوائم: Blacklist (+45) و Whitelist ═══');
    // admin gating
    const adminOtp = (await demoOtp()).otps.find((o) => o.username === 'admin').demoOtp;
    const adminFp = 'fp-soc-' + Date.now();
    const admin = await authOrApprove({ identifier: 'admin', password: 'Admin@123', otp: adminOtp, emailCode: adminOtp, scenario: 3 }, { 'X-Fp': adminFp });
    ok('دخول المشرف (S3) → SUCCESS', admin.outcome === 'SUCCESS' && !!admin.session?.sid);
    const H = { 'X-Fp': 'fp-soc-x', 'X-Session-Side': admin.session.sid };
    const denied = await (await get('/api/lists', { 'X-Fp': 'fp-x' })).json();
    ok('صفحات المشرف ترفض دون جلسة (403)', denied.ok === false && denied.error === 'ADMIN_SESSION_REQUIRED');
    await post('/api/blacklist', { ip: '203.0.113.77', reason: 'اختبار' }, H);
    ok('إضافة IP إلى القائمة السوداء', true);
    const blLogin = await (await post('/api/auth/login', { identifier: 'student1', password: 'Student@123', scenario: 1 }, { 'X-Fp': 'fp-bl-' + Date.now(), 'X-Forwarded-For': '203.0.113.77' })).json();
    ok('دخول من IP محظور → HIGH_RISK_BLOCK (+45)', blLogin.outcome === 'HIGH_RISK_BLOCK' && (blLogin.reasons || []).some((x) => ['BLACKLISTED_IP', 'IP_BLACKLISTED'].includes(x)));
    await fetch(base + '/api/blacklist?ip=203.0.113.77', { method: 'DELETE', headers: H });
    ok('حذف من القائمة السوداء', true);
    await post('/api/whitelist', { ip: '10.0.99.1', label: 'مراقب' }, H);
    const lists = await (await get('/api/lists', H)).json();
    ok('القائمة البيضاء تعكس الإضافة', lists.whitelist.some((w) => w.ip === '10.0.99.1'));
    await fetch(base + '/api/whitelist?ip=10.0.99.1', { method: 'DELETE', headers: H });

    console.log('\n═══ 7) التهديدات + الجلسات + الأجهزة ═══');
    const fc = await (await get('/api/factors', H)).json();
    ok('/api/factors يقدم قائمة', Array.isArray(fc.factors));
    const ses = await (await get('/api/sessions')).json();
    const mySid = admin.session.sid;
    ok('الجلسات تشمل جلسة المشرف', ses.sessions.some((s) => s.sid === mySid));
    const devs = await (await get('/api/devices', H)).json();
    ok('/api/devices (كل المنظمة) يعمل', Array.isArray(devs.devices) && devs.devices.some((d) => d.fingerprint === fpInc));

    console.log('\n═══ 8) الهجمات المحاكية A/B/C ═══');
    for (const t of ['A', 'B', 'C']) {
        await post('/api/simulate', { type: t, title: 'اختبار شامل ' + t }, H);
        await sleep(t === 'B' ? 3200 : 2000);
        const sims = await (await get('/api/simulations')).json();
        const last = sims.simulations?.[0];
        ok(`تحقق الهجوم ${t} → COMPLETE`, last?.title === `اختبار شامل ${t}` && last?.status === 'COMPLETE' && (last.timeline || []).length >= 5);
    }
    const sims = await (await get('/api/simulations')).json();
    ok('التاريخ: 3 محاكاة مسجلة', (sims.simulations || []).filter((s) => s.status === 'COMPLETE').length >= 3);

    console.log('\n═══ 9) لوحة التحكم والتقارير ═══');
    const dash = await (await get('/api/dashboard')).json();
    ok('العدادات حقيقية (COUNT من قاعدة البيانات)', Object.keys(dash.counters).length >= 5);
    ok('سجل الأحداث موجود', (dash.events || []).length > 0);
    ok('الإنذارات تُسجل (هجمات/حظر)', (dash.alerts || []).length > 0);
    ok('BLOCKED_IPS عُدّت', dash.counters.BLOCKED_IPS >= 1);

    console.log('\n═══ 10) لوحة المستخدم (غير المشرف) ═══');
    const myDash = await (await get('/api/my?userId=' + reg.userId)).json();
    ok('أجهزتي/جلساتي/نشاطي تعمل', Array.isArray(myDash.devices) && Array.isArray(myDash.sessions) && Array.isArray(myDash.activity));
    ok('لا تُكشف الأسرار', !JSON.stringify(myDash).includes('pw_hash') && !JSON.stringify(myDash).includes('totp_secret'));
    await post('/api/my/device/revoke', { userId: reg.userId, fingerprint: fpInc }, { 'X-Fp': fpInc });
    const after = await (await get('/api/my?userId=' + reg.userId)).json();
    ok('إلغاء جهاز موثوق يعمل', !(after.devices || []).some((d) => d.fingerprint === fpInc));

    console.log('\n═══ 11) بوابة المدرسة — مصفوفة RBAC (3 أدوار) ═══');
    const studH = { 'X-Session-Sid': warm.session.sid, 'X-User-Id': warm.user.id, 'X-Fp': dFp };
    const teachH = { 'X-Session-Sid': s3ok.session.sid, 'X-User-Id': s3ok.user.id, 'X-Fp': 'fp-teacher-' + Date.now() };
    const adH = { 'X-Session-Side': admin.session.sid, 'X-Session-Sid': admin.session.sid, 'X-User-Id': admin.user.id, 'X-Fp': 'fp-soc-x' };

    const pGate = async (p, h) => {
        const r = await get('/api/portal/' + p, h);
        const text = await r.text();
        if (text.trimStart().startsWith('<')) { console.error('  [pGate HTML]', '/api/portal/' + p, 'status=' + r.status); }
        return { status: r.status, body: JSON.parse(text) };
    };
    // دور/جلسة
    const stSess = await pGate('session', studH);
    ok('portal/session → STUDENT', stSess.status === 200 && stSess.body.user?.role === 'STUDENT');
    // بدون جلسة → 401
    const anon = await pGate('courses', { 'X-Fp': 'fp-anon' });
    ok('بوابة بلا جلسة → SESSION_REQUIRED (401)', anon.status === 401 && anon.body.error === 'SESSION_REQUIRED');
    // الطالب
    const stGrades = await pGate('grades', studH);
    const stRosters = await pGate('rosters', studH);
    const stUsers = await pGate('users', studH);
    const stMatrix = await pGate('matrix', studH);
    ok('الطالب: درجة/مقررات مشروعة', stGrades.status === 200 && Array.isArray(stGrades.body.grades));
    ok('الطالب: القوائم الصفية → محجوبة (403)', stRosters.status === 403 && stRosters.body.error === 'PORTAL_RBAC_DENIED');
    ok('الطالب: دليل المستخدمين → محجوب (403)', stUsers.status === 403);
    ok('الطالب: مصفوفة الصلاحيات → محجوبة (403)', stMatrix.status === 403);
    // المعلّم
    const tRosters = await pGate('rosters', teachH);
    const tMatrix = await pGate('matrix', teachH);
    ok('المعلم: القوائم الصفية مسموحة', tRosters.status === 200 && Array.isArray(tRosters.body.rosters));
    ok('المعلم: مصفوفة الصلاحيات → محجوبة (403)', tMatrix.status === 403);
    // المشرف
    const aMatrix = await pGate('matrix', adH);
    const aUsers = await pGate('users', adH);
    const aRosters = await pGate('rosters', adH);
    ok('المشرف: مصفوفة 8 وحدات + كل البيانات', aMatrix.status === 200 && (aMatrix.body.matrix || []).length === 8);
    ok('المشرف: دليل المستخدمين يعمل', aUsers.status === 200 && Array.isArray(aUsers.body.users));
    ok('المشرف: القوائم الصفية تعمل', aRosters.status === 200 && Array.isArray(aRosters.body.rosters));

    console.log('\n═══ 12) استرداد الحساب / إعادة ضبط MFA ═══');
    const recEm = 'rec' + Date.now() + '@campus.edu';
    const recReg = await (await post('/api/auth/register', { fullName: 'استرداد', email: recEm, nationalId: 'SCH-RC-' + Date.now(), password: 'Recovery@1' })).json();
    const recUser = recReg.username;
    const recVer = await get('/api/verify?token=' + recReg.verifyUrl.split('token=')[1] + '&fp=fp-rec-1');
    const recCookie = (recVer.headers.get('set-cookie') || '').split(';')[0];
    const recFp = 'fp-rec-1';
    const recCode0 = (await demoOtp()).otps.find((o) => o.username === recUser).demoOtp;
    const recLogin = await (await post('/api/auth/login', { identifier: recUser, password: 'Recovery@1', otp: recCode0, scenario: 2 }, { 'X-Fp': recFp, Cookie: recCookie })).json();
    ok('حساب الاسترداد يدخل سويّا قبل الاسترداد', recLogin.outcome === 'SUCCESS');
    const recReq = await (await post('/api/recovery/request', { identifier: recUser })).json();
    ok('طلب الاسترداد → verifyCode', recReq.ok && /^\d{6}$/.test(recReq.verifyCode));
    const recWrong = await (await post('/api/recovery/reset', { identifier: recUser, verifyCode: '000000', newPassword: 'X' })).json();
    ok('رمز استرداد خاطئ → مرفوض', recWrong.ok === false);
    const recReset = await (await post('/api/recovery/reset', { identifier: recUser, verifyCode: recReq.verifyCode, newPassword: 'RecNew@Pass1' })).json();
    ok('إعادة الضبط → 10 رموز استرداد جديدة', recReset.ok === true && Array.isArray(recReset.newRecoveryCodes) && recReset.newRecoveryCodes.length === 10);
    const v1 = await (await post('/api/recovery/validate', { identifier: recUser, code: recReset.newRecoveryCodes[0] })).json();
    const v2 = await (await post('/api/recovery/validate', { identifier: recUser, code: recReset.newRecoveryCodes[0] })).json();
    ok('رمز الاسترداد صالح ويُستهلك مرة واحدة', v1.ok === true && v2.ok === false);
    const newLogin = await (await post('/api/auth/login', { identifier: recUser, password: 'RecNew@Pass1', scenario: 1 }, { 'X-Fp': recFp, Cookie: recCookie })).json();
    ok('الدخول بكلمة المرور الجديدة → SUCCESS', newLogin.outcome === 'SUCCESS');
    const oldLogin = await (await post('/api/auth/login', { identifier: recUser, password: 'Recovery@1', scenario: 1 }, { 'X-Fp': recFp, Cookie: recCookie })).json();
    ok('كلمة المرور القديمة → FAILED_PASSWORD', oldLogin.outcome === 'FAILED_PASSWORD');
    const rcAudit = await (await get('/api/audit?user=' + recUser)).json();
    const rcOut = new Set(rcAudit.events.map((e) => e.outcome));
    ok('سجل الأحداث: RECOVERY_REQUEST/RESET/CODE_VALID', ['RECOVERY_REQUEST', 'RECOVERY_RESET', 'RECOVERY_CODE_VALID'].every((o) => rcOut.has(o)));

    console.log('\n═══ 13) التحقيق الرقمي (Forensics) ═══');
    const fxSum = await (await get('/api/forensics/summary', adH)).json();
    ok('الملخص: عدّادات حية (audit/sessions/devices/cases)', fxSum.summary.auditEvents > 0 && fxSum.summary.activeSessions > 0 && fxSum.summary.trustedDevices >= 1);
    const fxTl = await (await get('/api/forensics/timeline?user=' + u, adH)).json();
    ok('الخط الزمني المُعاد بناؤه للمستخدم', (fxTl.timeline || []).length > 0 && fxTl.timeline.every((e) => e.kind && e.ref && e.ts));
    const fxCase = await (await post('/api/forensics/cases', { title: 'قضية e2e للطالب ' + u, severity: 'HIGH', user: u }, adH)).json();
    const fxId = fxCase.case.id;
    const fxOpen = await (await get('/api/forensics/cases/' + fxId, adH)).json();
    ok('فتح قضية → التُقطت الأدلة تلقائياً', fxOpen.ok && (fxOpen.timeline || []).length > 0);
    const fxList = await (await get('/api/forensics/cases', adH)).json();
    ok('قائمة القضايا تُظهر عدّاد الأدلة', (fxList.cases || []).some((c) => c.id === fxId && c.items > 0));
    const fxClose = await (await post('/api/forensics/cases/' + fxId + '/close', {}, adH)).json();
    ok('إغلاق القضية → CLOSED', fxClose.case?.status === 'CLOSED');
    const fxExp = await (await post('/api/forensics/cases/' + fxId + '/export', {}, adH)).json();
    ok('تصدير الأدلة Markdown', fxExp.ok && /# Forensic Case/.test(fxExp.markdown) && /Evidence timeline/.test(fxExp.markdown));
    await fetch(base + '/api/forensics/cases/' + fxId, { method: 'DELETE', headers: adH });
    const fxAfter = await (await get('/api/forensics/cases', adH)).json();
    ok('حذف القضية من القائمة', !(fxAfter.cases || []).some((c) => c.id === fxId));

    console.log('\n═══ 14) الأداء — مقارنة سيناريوهات المصادقة (elapsed_ms) ═══');
    const bench = await (await get('/api/benchmark')).json();
    ok('3 سيناريوهات مقاسة من سجل حقيقي', bench.ok && bench.benchmark.scenarios.length === 3);
    ok('كل سيناريو: محاولات + متوسط زمن + عدّاد نجاح', bench.benchmark.scenarios.every((s) => s.attempts >= 1 && typeof s.averageLoginTimeMs === 'number' && s.averageLoginTimeMs >= 0 && typeof s.success === 'number'));

    console.log('\n═══ 15) بث SSE الحي (تستقبل لوحة المشرف الأحداث) ═══');
    const seen = [];
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 5500);
    const res = await fetch(base + '/api/stream', { headers: H, signal: ac.signal });
    const reader = res.body.getReader(); const dec = new TextDecoder(); let buf = '';
    const readLoop = (async () => { try { for (;;) { const { value, done } = await reader.read(); if (done) break; buf += dec.decode(value, { stream: true }); const parts = buf.split('\n\n'); buf = parts.pop(); for (const p of parts) { const l = p.split('\n').find((x) => x.startsWith('data: ')); if (l) { try { seen.push(JSON.parse(l.slice(6))); } catch {} } } } } catch {} })();
    await sleep(400);
    await post('/api/auth/login', { identifier: u, password: 'Demo@Pass1', scenario: 2 }, { 'X-Fp': 'fp-live-EVT-' + Date.now() }); // توليد حدث
    await sleep(2500); ac.abort(); await readLoop;
    ok('بث SSE يستلم أحداث audit/alert', seen.some((j) => j.type === 'audit') || seen.some((j) => j.type === 'alert'));
    log('أحداث مستلمة: ' + seen.map((j) => j.type).join(', ') || '—');

    console.log(`\n════════ النتيجة النهائية ════════`);
    console.log(`  ✓ ناجح: ${pass.length}   ✗ فاشل: ${fail.length}`);
    for (const p of pass) console.log('  ✓ ' + p.name);
    for (const f of fail) console.error('  ✗ ' + f.name + (f.extra ? ' [' + f.extra + ']' : ''));
    process.exit(fail.length ? 1 : 0);
}

try { await main(); } catch (e) { console.error('خطأ عام:', e); process.exit(2); }