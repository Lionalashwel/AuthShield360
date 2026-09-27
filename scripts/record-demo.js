// record-demo.js — تسجيل فيديو حي للمراحل والمميزات كاملة عبر المتصفح الحقيقي
// headless Edge + puppeteer-core → لقطات → ffmpeg → demo.mp4
import puppeteer from 'puppeteer-core';
import { path as FFMPEG } from '@ffmpeg-installer/ffmpeg';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdirSync, existsSync, rmSync, readdirSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import { createWriteStream } from 'node:fs';

const run = promisify(execFile);
const BASE = process.env.AS360_BASE || 'http://localhost:4000';
const OUT = join(process.cwd(), 'demo-render');
const CANDIDATES = [
    process.env.AS360_BROWSER, process.env.EDGE_PATH, process.env.CHROME_PATH,
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
].filter(Boolean);
const browserPath = CANDIDATES.find((p) => existsSync(p));
if (!browserPath) { console.error('No Edge/Chrome found. Set AS360_BROWSER to the executable path.'); process.exit(1); }

if (existsSync(OUT)) rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const uniq = (p) => p + '-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6);

const browser = await puppeteer.launch({
    executablePath: browserPath,
    headless: true,
    args: ['--no-sandbox', '--disable-gpu', '--mute-audio', '--window-size=1280,800'],
    defaultViewport: { width: 1280, height: 800 },
    userDataDir: join(process.cwd(), '.tmp-rec-profile'),
});
const page = await browser.newPage();
await page.setViewport({ width: 1280, height: 800 });

// frame ticker: يلتقط لقطة كل ~180ms طوال العرض
let frameNo = 0;
let recording = true;
(async () => {
    while (recording) {
        const f = String(frameNo++).padStart(4, '0');
        await page.screenshot({ path: join(OUT, f + '.png') }).catch(() => {});
        await sleep(180);
    }
})();

const frameCount = () => frameNo;

const clickSel = (sel) => page.evaluate((s) => { const el = document.querySelector(s); if (el) el.click(); return !!el; }, sel);
const clickTab = (which) => page.evaluate((w) => { const t = [...document.querySelectorAll('[data-tab]')].find((x) => x.dataset.tab === w) || [...document.querySelectorAll('[data-tab]')].find((x) => x.textContent.includes(w)); if (t) { t.click(); return true; } return false; }, which);
const clickW = (v) => page.evaluate((x) => { const t = [...document.querySelectorAll('#w-tabs .wtab')].find((b) => b.dataset.wtab === x); if (t) { t.click(); return true; } return false; }, v);
const clickPmod = (m) => page.evaluate((x) => { const t = [...document.querySelectorAll('.p-mod')].find((b) => b.dataset.pmod === x); if (t) { t.click(); return true; } return false; }, m);
const shot = () => page.screenshot({ path: join(OUT, String(frameNo++).padStart(4, '0') + '.png') }).catch(() => {});

async function nav(url = BASE) {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 }).catch(() => {});
    await sleep(900);
}
const setMsg = (msg) => console.log('  ›', msg);

const titleCard = (title, sub) => `<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><style>
  html,body{margin:0;height:100%;background:radial-gradient(1200px 700px at 70% 20%,#123, #0b1626 60%,#060b14);color:#eaf3ff;font-family:'Segoe UI',Tahoma,sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center}
  .k{font-size:74px;font-weight:800;letter-spacing:1px;color:#7de3c0;text-shadow:0 0 26px #0affbe55}
  h1{font-size:44px;margin:26px 0 10px}
  p{font-size:24px;color:#9fb6d4;max-width:840px}
  .badge{position:absolute;top:34px;right:44px;font-size:20px;color:#7de3c0;border:1px solid #2c5f7a;padding:8px 16px;border-radius:999px}
  .foot{position:absolute;bottom:30px;font-size:18px;color:#54708f}
</style></head><body><div class="badge">AuthShield 360 · Real-Time Edition</div>
<div class="k">${title}</div>
${sub ? `<h1>${sub}</h1>` : ''}
${title === 'تسجيل الشاشة' ? '<p>عرض مباشر لكل مرحلة وكل ميزة: تسجيل، توثيق بالبريد، جهاز موثوق، دخول متدرج، منصة الأمان، هجمات محاكاة، قائمة سوداء وجلسات</p>' : ''}
<div class="foot">بث مباشر لسير عمل حقيقي — خادم حي وقاعدة بيانات حقيقية</div>
</body></html>`;

const cards = {
    open: titleCard('تسجيل الشاشة', ''),
    s1: titleCard('1', 'Intake: توثيق البريد + الجهاز الموثوق'),
    s2: titleCard('2', 'Step-up: OTP والبريد + بوابة المدرسة والاسترداد'),
    s3: titleCard('3', 'دفاع: التحقيق الرقمي، المصفوفة، القياسات، والشبكة SOC'),
    end: titleCard('شكرًا', 'تم اختبار كل المراحل — دخول متدرج، بوابة، استرداد، طب شرعي، وقياسات'),
};

const done = [];
const mark = (k) => done.push(k);

try {
    // ── شاشة افتتاحية
    await nav('about:blank');
    await page.setContent(cards.open); await sleep(2600); mark('title-open');

    // ── الصفحة الرئيسية (تسجيل/دخول)
    await nav(BASE); await sleep(900);
    await clickTab('register');
    await sleep(700); mark('landing');

    // ── تسجيل حساب جديد
    const email = uniq('rec.demo') + '@campus.edu';
    const nid = 'SCH-' + Date.now();
    setMsg('تسجيل حساب جديد…');
    await page.type('#rg-name', 'مستخدم العرض التوضيحي');
    await page.type('#rg-email', email);
    await page.type('#rg-nid', nid);
    await page.type('#rg-pass', 'Demo@Pass1');
    await page.screenshot({ path: join(OUT, String(frameNo++).padStart(4, '0') + '.png') });
    await clickSel('#reg-form button');
    await page.waitForFunction(() => document.querySelector('#rg-msg')?.textContent.includes('Account created'), { timeout: 25000 });
    const verifyUrl = await page.evaluate(() => [...document.querySelectorAll('#rg-msg a')].map((a) => a.href).find((h2) => h2.includes('/verify')) || null);
    const uname = await page.evaluate(() => { const cs = [...document.querySelectorAll('#rg-msg code')].map((c) => c.textContent); return { u: cs[1] || '', comments: cs[0] || '' }; }).then((r) => r.u || email.split('@')[0]);
    setMsg('حساب: ' + uname);
    await sleep(1600); mark('registered');

    // ── بطاقة ثم فتح رابط البريد (التوثيق)
    await page.setContent(cards.s1); await sleep(2200);
    setMsg('فتح رابط التوثيق من البريد…');
    await nav(verifyUrl.startsWith('http') ? verifyUrl : BASE + verifyUrl);
    await sleep(1400);
    await page.screenshot({ path: join(OUT, String(frameNo++).padStart(4, '0') + '.png') });
    await sleep(700); mark('verified-trusted');
    await page.setContent(cards.s1); await sleep(900);

    // ── الدخول المتدرج S2 (OTP) ثم الدخول العادي S1 بعد أن تُعرف الشبكة
    const demoOtp = async (uname) => {
        const r = await page.evaluate(async (b) => (await fetch(b + '/api/identity/otps')).json(), BASE);
        return r.otps.find((o) => o.username === uname)?.demoOtp || '000000';
    };
    const unameLog = email.split('@')[0];

    await page.setContent(cards.s2); await sleep(1900);
    await nav(BASE); await sleep(600);
    setMsg('دخول بسيناريو 2 (OTP) ثم S1 المباشر…');
    await clickTab('login');
    await sleep(400);
    await page.type('#li-user', email); await page.type('#li-pass', 'Demo@Pass1');
    await page.select('#li-scenario', '2');
    await page.evaluate((v) => { const el = document.getElementById('li-otp'); el.value = v; el.dispatchEvent(new Event('input', { bubbles: true })); }, await demoOtp(uname));
    await sleep(300);
    await clickSel('#li-btn');
    await page.waitForFunction(() => { const v = document.querySelector('#view-user'); return v && !v.classList.contains('hidden'); }, { timeout: 20000 });
    await sleep(1800); mark('s2-stepup');

    // ── طالب: بوابة المدرسة (درجاته + تكليفاته)
    setMsg('عرض بوابة المدرسة للطالب…');
    await clickW('portal'); await sleep(1400); await shot();
    await clickPmod('grades'); await sleep(1000); await shot(); mark('student-portal-grades');
    await clickW('user'); await sleep(700);

    await page.evaluate(() => document.querySelector('#btn-user-logout')?.click());
    await sleep(1600);
    await clickTab('login');
    await sleep(400);
    await page.type('#li-user', email); await page.type('#li-pass', 'Demo@Pass1');
    await page.select('#li-scenario', '1');
    await clickSel('#li-btn');
    await page.waitForFunction(() => { const v = document.querySelector('#view-user'); return v && !v.classList.contains('hidden'); }, { timeout: 20000 });
    await sleep(1800); mark('s1-trusted');

await page.evaluate(() => document.querySelector('#btn-user-logout')?.click());
    await sleep(900);
    await page.setContent(cards.s3); await sleep(2000);

    // ── خروج ودخول المشرف (S3): إعادة محاولة تلقائية للرمز
    await nav(BASE); await sleep(600);
    await clickTab('login');
    const fillLogin = (code) => page.evaluate((v) => {
        const set = (id, val) => { const el = document.getElementById(id); if (!el) return; el.value = val; el.dispatchEvent(new Event('input', { bubbles: true })); };
        set('li-user', 'admin'); set('li-pass', 'Admin@123');
        document.getElementById('li-scenario').value = '3';
        set('li-otp', v); set('li-email', v);
    }, code);
    let socIn = false;
    for (let i = 0; i < 6 && !socIn; i++) {
        const code = await demoOtp('admin');
        if (!code || code === '000000') { await sleep(1500); continue; }
        await fillLogin(code);
        await page.evaluate(() => document.getElementById('login-form').dispatchEvent(new Event('submit', { cancelable: true })));
        await sleep(2800);
        socIn = await page.evaluate(() => { const v = document.querySelector('#view-soc'); return v && !v.classList.contains('hidden'); });
        if (socIn) break;
        await sleep(1200);
    }
    if (!socIn) throw new Error('admin-login-failed');
    await sleep(2000); mark('admin-soc');

    // ── مشرف: بوابة المدرسة + مصفوفة الصلاحيات
    setMsg('عرض بوابة المشرف ومصفوفة الصلاحيات…');
    await clickW('portal'); await sleep(1500); await shot();
    await clickPmod('matrix'); await sleep(1100); await shot(); mark('admin-portal-matrix');
    await clickW('soc'); await sleep(800);

    // ── التحقيق الرقمي: بحث + فتح قضية + تصدير
    setMsg('لوحة التحقيق الرقمي: إعادة بناء الخط الزمني…');
    await clickW('forensics'); await sleep(1500); await shot();
    await page.evaluate(() => { document.getElementById('fx-user').value = 'admin'; document.getElementById('fx-search').click(); });
    await sleep(1400); await shot();
    setMsg('فتح قضية تحقيق (حالة Impossible-Travel)…');
    await page.evaluate(() => { document.getElementById('fx-c-title').value = 'Impossible-travel blitz review'; document.getElementById('fx-c-user').value = 'admin'; document.getElementById('fx-c-create').click(); });
    await sleep(1600); await shot(); mark('forensics-case');
    await page.evaluate(() => document.getElementById('fxd-close').click()); await sleep(600);

    // ── المقارنة بين أوضاع المصادقة
    await clickW('bench'); await sleep(1500); await shot(); mark('benchmark');
    await clickW('soc'); await sleep(800);

    // ── الهجمات المحاكية A/B/C
    for (const t of ['A', 'B', 'C']) {
        setMsg('تشغيل الهجوم المحاكي ' + t + '…');
        await page.evaluate((ty) => { const s = document.querySelector('#sim-type'); s.value = ty; }, t);
        await page.screenshot({ path: join(OUT, String(frameNo++).padStart(4, '0') + '.png') });
        await clickSel('#btn-sim');
        await sleep(4500); // يظهر الانتهاء + النتيجة ثم يُفعَّل الزر
        await page.screenshot({ path: join(OUT, String(frameNo++).padStart(4, '0') + '.png') });
        await sleep(1200); mark('sim-' + t);
    }

    // ── القائمة السوداء: إضافة IP عن طريق الواجهة
    setMsg('إضافة IP إلى القائمة السوداء…');
    await page.evaluate(() => { document.querySelector('#bl-ip').value = '31.13.99.5'; });
    await clickSel('#btn-bl-add');
    await sleep(1800); mark('blacklist-add');

    await page.screenshot({ path: join(OUT, String(frameNo++).padStart(4, '0') + '.png') });
    await sleep(1400);

    // ── بطاقة ختامية
    await page.setContent(cards.end); await sleep(2800); mark('title-end');
} catch (e) {
    console.error('recorder error:', e && e.message ? e.message.slice(0, 200) : e);
} finally {
    recording = false;
    await sleep(400);
    console.log('frames:', frameNo, '| stages:', done.join(' · '));
    await browser.close().catch(() => {});
}

// ── فك الشفرة: PNGs → demo.mp4 (h264)
setMsg('ترقيم اللقطات…');
// اللقطات قد تحتوي فجوات في الترقيم (سباق بين الـ ticker و shot) فيتوقف ffmpeg مبكرًا
// → نعيد ترقيمها تسلسليًا في مجلد مؤقت قبل الترميز.
const SEQ = join(OUT, 'seq');
rmSync(SEQ, { recursive: true, force: true });
mkdirSync(SEQ, { recursive: true });
const shots = readdirSync(OUT).filter((f) => f.endsWith('.png')).sort();
shots.forEach((f, i) => renameSync(join(OUT, f), join(SEQ, String(i).padStart(5, '0') + '.png')));
console.log('frames encoded:', shots.length, '→', (shots.length / 6).toFixed(1) + 's @ 6fps');

setMsg('تشغيل ffmpeg…');
const FR = 6;
const mp4 = join(process.cwd(), 'demo.mp4');
await run(FFMPEG, ['-y', '-framerate', String(FR), '-i', join(SEQ, '%05d.png'), '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-preset', 'medium', '-crf', '23', '-movflags', '+faststart', mp4]).catch((e) => {
    console.error('ffmpeg:', e.message.split('\n').slice(0, 6).join('\n'));
});
rmSync(SEQ, { recursive: true, force: true });
setMsg('done: ' + mp4);