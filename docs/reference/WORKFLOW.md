# WORKFLOW — AuthShield 360 v2 (Real-Time Enterprise Edition)

توثيق سير العمل التقني الكامل: كيف تتحرك البيانات داخل المنصة، وأين تُتخذ القرارات، وما نقاط التحقق.

---

## 1) البنية العامة

```
┌─────────────────────────────┐     HTTP/JSON      ┌──────────────────────────────┐
│  المتصفح (SPA)              │ ──────────────────▶ │  خادم Express (Node/Node24)  │
│  frontend/index.html        │  ◀─────────────────  │  backend/index.js            │
│  frontend/js/*.js (مُجزّأ)   │   Set-Cookie + SSE  │                              │
└─────────────────────────────┘                     │  ┌────────────────────────┐  │
                                                    │  │ محرك الدخول auth.js    │  │
                                                    │  │ محرك الخطر risk-engine │  │
                                                    │  │ بوابة مدرسية portal.js │  │
                                                    │  │ تحقق جنائي forensics.js│  │
                                                    │  │ قياس أداء benchmark.js │  │
                                                    │  │ محرك الهجمات sme.js    │  │
                                                    │  │ شبكة network.js        │  │
                                                    │  │ بريد mailer.js         │  │
                                                    │  │ أحداث events.js        │  │
                                                    │  │ جلسات/أجهزة cookie.js  │  │
                                                    │  └────────────────────────┘  │
                                                    │           │                   │
                                                    │     SQLite (node:sqlite)     │
                                                    │     data/authshield.db       │
                                                    └──────────────────────────────┘
```

- **لا توجد تبعيات خارجية:** SQLite مضمن، ولا يحتاج النظام سوى Node ≥ 20.
- **البريد:** Nodemailer + Ethereal (صندوق مؤقت). عند انقطاع الشبكة → `ensureMailer()` يهبط خلال 8 ثوانٍ إلى مخرج الطرفية، والتطبيق يبقى قابلًا للاختبار بالكامل.

---

## 2) دورة حياة المستخدم (التسجيل → الجهاز الموثوق)

```
[POST] /api/auth/register
  fullName, email, nationalId, password
  │  التحقق: صيغة بريد · طول كلمة المرور ≥ 8 · تفرد البريد والرقم الوطني
  ▼
إنشاء مستخدم بدور STUDENT + سر TOTP + رمز توثيق (32 بايت) مخزّن كـ hash
  ▼
إرسال بريد حقيقي يحوي رابط:
  /api/verify?token=<token>&fp=<بصمة المتصفح>   ← SPA تضيف fp= تلقائيًا
  ▼
[GET] /api/verify
  فحص الرمز حيًا (استُخدم؟ انتهى؟) → markEmailVerified
  addTrustedDevice(userId, fingerprint=fp)      ← هذا المتصفح يصبح موثوقًا
  sealTrustCookie({fp, uid})                    ← Set-Cookie: as360_trust (HttpOnly, 1 سنة)
```

> **القرار المُوحَّد:** بصمة الجهاز هي قيمة `X-Fp` كما هي (بدون بادئات). كل المسارات (verify/OTP/finalize) تخزِّنها بصيغة واحدة لإعادة تطابق التحقق.

---

## 3) محرك الدخول والدرجة (attemptAuthentication — backend/auth.js)

```
POST /api/auth/login { identifier, password, otp, emailCode, scenario }
   │
   ▼
 0) بوابة الدفاع (DEFENSE_STANDBY) — نافذة اختبار أدوات الاختراق
 1)  حظر فوري: الحساب مقفل؟ IP في القائمة السوداء؟  → HIGH_RISK_BLOCK (أسباب: ACCOUNT_LOCKED / IP_BLACKLISTED)
 2)  هوية غير معروفة → FAILED_PASSWORD (بدون إعطاء إشارة عن وجود الحساب)
 3)  التقاط السياق:
       trust   = deviceTrustFor(user, fp, cookie)        → «الجهاز موثوق؟»
       netKnown= networkKnownFor(user, net)              → «الشبكة معهودة؟»
       travel  = travelAssessment(user, net)             → «سفر مستحيل؟» distanceKm(آخِر IP → IP الحالي)
       streak  = failStreak(user)
       risk    = evaluateRisk({timeAnomaly, newIp, impossibleTravel, unrecognizedDevice, consecutiveFailures, blacklistedIp})
 4)  البوابة الأساسية: كلمة المرور (تجميع محاولات فاشلة؛ 2 فاشلتان → LOCKOUT)
 5)  درجة عالية (≥70) → LOCKOUT + إنذار + HIGH_RISK_BLOCK  (لا يمر حتى بكلمة مرور صحيحة)
 6a) متوسطة + جهاز غير موثوق + يوجد جهاز موثوق → PENDING_APPROVAL (موافقة عبر تطبيق آخر)
 6b) وإلا خطوة إضافية: OTP وبريد (S3 يفرض البريد دائمًا)
 7)  بوابة OTP (TOTP RFC 6238؛ الرمز الخاطئ لا يقفل الحساب)
 8)  بوابة البريد (تحت الحالات التي تتطلبها)
 9)  RBAC: سيناريو 3 + دور STUDENT → HIGH_RISK_BLOCK (UNAUTHORIZED_ROUTE)
10)  نجاح: جلسة + سجل success_logins + تسجيل الجهاز تلقائيًا بعد إثبات الملكية (OTP)
```

### أوزان عوامل الخطر (config.js)

| العامل | الزيادة |
|--------|---------|
| TIME_ANOMALY (ساعة 22:00–07:00) | +15 |
| NEW_IP (شبكة /24 غير معهودة) | +25 |
| IMPOSSIBLE_TRAVEL (سرعة km/دقيقة فوق الحد) | +40 |
| UNRECOGNIZED_DEVICE | +30 |
| محاولة كلمة مرور فاشلة (عدد) | +20 |
| BLACKLISTED_IP | +45 |

أنواع الخطر: **LOW 0–30 / MEDIUM 31–69 / HIGH 70–100**.

---

## 4) الموافقة عبر الجهاز (Cross-Device Approval)

```
دخول من جهاز/شبكة غريبة (متوسطة 55 مثلًا) ويملك المستخدم جهازًا موثوقًا
        │
        ▼
insertPendingApproval(...)            → PK pendingId + رمز محلي
publish('cross:<uid>')                ← بث SSE إلى الجهاز الموثوق (لوحة/المتصفح المفتوح)
        │
        ▼  المتصفح الموثوق يعرض نافذة موافقة (GET /pending/:id/status دوريًا + دفع SSE)
   POST /pending/:id/approve   أو  /deny
        │
        ▼
   POST /pending/:id/finalize { fp }  → يختم الجهاز الجديد كموثوق + جلسة
   outcomes: SUCCESS / not_approved / expired
```

---

## 5) البث المباشر (SSE)

- المشرف: `[GET] /api/stream?scope=t:<userId>` → أحداث `audit` و`alert` و`crossdevice`.
- المستخدم: `?scope=u` أو `t:<uid>` يتبدل تلقائيًا في SPA (`syncTrustScope`) بمجرد ظهور الكوكي الموثوق.
- خط الأنابيب: `events.js` (EventEmitter) ← `publish(channel, payload)` ← `writeSSE`.

---

## 6) لوحة SOC والتقارير (لوحة المشرف)

| النقطة | الوظيفة |
|--------|---------|
| `GET /api/dashboard` | عدادات حقيقية `COUNT()` من قاعدة البيانات (نجاح/فشل/OTP/حظر/إنذار) |
| `GET /api/sessions` | جلسات حيّة (سايد واحدة لكل دخول) |
| `GET /api/devices` | أجهزة كل المؤسسة مع التصنيف (معروف/جديد) |
| `GET /api/factors` | عوامل الكشف الحيّة (LOCKOUT, UNAUTHORIZED_ROUTE, ...) |
| `GET /api/lists` | القائمتان البيضاء والسوداء |
| `GET /api/simulations` | سجل الهجمات المحاكية (الأحدث أولًا) |
| `POST /api/arm-mode` | تفعيل الدفاع للاختبار الحي |

**الحماية:** لوحة المشرف ترفض (403) دون جلسة `ADMINISTRATOR` صادرة (`x-session-side` + `x-user-id`).

---

## 7) الهجمات المحاكية (SME — backend/sme.js)

| النوع | السيناريو | النتيجة المتوقعة |
|-------|-----------|------------------|
| **A** | 3 محاولات قوة غاشمة لأحد الطلاب بكلمات خاطئة | درجة 55 → 75 → 100 ثم LOCKOUT + إنذار BRUTE_FORCE |
| **B** | حجز من الرياض ثم من سان فرانسيسكو خلال 12 ثانية | IMPOSSIBLE_TRAVEL +40 ← درجة 95 HIGH ← إقفال |
| **C** | دخول من IP في القائمة السوداء (كلمة مرور صحيحة) | BLACKLISTED_IP +45 ← HIGH ← حظر فورًا |

كل هجوم يُسجَّل في `attack_runs` بخط زمني (timeline) ويظهر فورًا في لوحة SOC عبر البث المباشر.

---

## 8) مسار البيانات في اختبار الدخول الناجح

```
إلغاء القفل → resetStreak → createSession → insertSuccess(subnet/network/device_hash/risk/scenario/mfa)
   أحرف المعاملات: mfa ∈ { NONE, OTP, OTP+EMAIL }
   🔊 publish('audit') → لوحة SOC تتحدث لحظيًا
   تذكرة: إذا كان الجهاز جديدًا ومرر OTP → addTrustedDevice(auto).
```

---

## 9) الأمانات والقرارات المعيارية

- القفل (LOCKOUT) **يُحتسب على كلمات المرور الفاشلة فقط**؛ رمز OTP الخاطئ لا يقفل الحساب.
- ال التحقق من البريد الصالح يجعل المتصفح من «الجهاز الموثوق» — الشرط الفعلي لتدفق الموافقات المتقاطعة.
- تخزين الرموز: كلمات المرور `hashPassword` (SHA-256 مُملَّحة)، كلمات التوثيق `stableHash` للاستخدام الفردي المركزي.
- لا تُكشف أي أسرار في الواجهات: الأعمدة الحسّاسة مستثناة من استجابات API (`sanitizeUser`).
- القرارات متدرجة: عالية = تجميد أمني حتى لو كلمة المرور صحيحة؛ متوسطة = خطوة إضافية؛ منخفضة = دخول مباشر.

---

## 10) التحويل الجديد (v2) — بوابة/استرداد/تحقيق/أداء

### البوابة المدرسية و RBAC
- `portalGate(roles)` يتحقق من الجلسة (`x-session-sid` + `x-user-id`) ومن الدور (401 بلا جلسة، 403 عند مخالفة).
- مصفوفة `ROLE_ACCESS_MATRIX` (8 وحدات × 3 أدوار) في `backend/portal.js`؛ التصفح مقسّم حسب الدور في SPA.
- سيناريو 3 من طالب → `HIGH_RISK_BLOCK` بسبب `UNAUTHORIZED_ROUTE` (قبل نجاح الدخول).

### استرداد الحساب / إعادة ضبط MFA
```
POST /api/recovery/request    → verifyCode (6 خانات)  → تُسجَّل mfa_reset
POST /api/recovery/reset      → تدوير TOTP + تغيير pw + 10 رموز استرداد أحادية الاستخدام
POST /api/recovery/validate   → استهلاك رمز واحد (مرة واحدة)
كل خطوة تُسجَّل: RECOVERY_REQUEST / RECOVERY_RESET / RECOVERY_CODE_VALID + إنذار.
```

### التحقيق الرقمي
- `reconstructedTimeline(filters)` يعيد ربط أحداث `audit_trail` بترتيب زمني عبر المستخدم/IP/الجهاز/النتيجة.
- `openInvestigation()` تلتقط الأدلة تلقائيًا في `case_items`؛ التصدير Markdown (`exportCaseMarkdown`).

### الأداء (elapsed_ms)
- `audit_trail.elapsed_ms` يُسجَّل لكل محاولة؛ `benchmarkAll()` يقرأه لمقارنة السيناريوهات 1/2/3 (متوسط زمن/عدادات).

---

## 11) التحقق النهائي (يُنفَّذ قبل أي تسليم)

```
node scripts/smoke.js          # 17 تأكيدًا — الوحدات والسيناريوهات الأساسية (بدون خادم)
node scripts/e2e-all.js        # 77 تأكيدًا — كل المراحل حيًا: تسجيل/تحقق/موثوق/S1-S2-S3/موافقة/قفل/قوائم/
                               #   هجمات A-B-C/SOC/SSE + بوابة RBAC + استرداد + تحقيق + أداء
node scripts/ui-smoke.js       # 28 فحص UI عبر متصفح حقيقي
node scripts/restart-check.js  # 18 فحص NFR — بقاء البيانات بعد إعادة تشغيل العملية (منفذ معزول 4001)
```

الحالة الحالية: **17/17 + 77/77 + 28/28 + 18/18 = 140 فحصًا أخضر** على قاعدة نظيفة
(stop :4000 → `node scripts/reset-db.js` → `npm start` → تشغيل المجموعة).