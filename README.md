<div align="center">

![CI](https://github.com/Lionalashwel/AuthShield360/actions/workflows/tests.yml/badge.svg)
![Checks](https://img.shields.io/badge/140-automated%20checks-34d399)
![License](https://img.shields.io/badge/license-MIT-0ea5e9)
![Node](https://img.shields.io/badge/Node-%3E%3D24-22d3ee)

<img src="frontend/assets/logo-lockup.svg" alt="Cornell Deep" width="330" />

### Identity Protection Platform · Cornell Deep School

A step-up, context-aware identity platform implementing the **TechWiz 7 SRS**
Risk-Based Authentication mandate: granular audit telemetry, three switching
authentication scenarios, an adaptive 0–100 risk engine, and a real-time
**SOC Monitoring Dashboard**.

📊 **Live presentation (GitHub Pages):** https://lionalashwel.github.io/AuthShield360/
🎬 **Demo video:** [`demo.mp4`](demo.mp4) · 🗂️ **Docs:** [English](README.md) · [العربية](docs/02-دليل_الاختبار_والتجربة.md)
🎨 **Interface themes:** **Light** (default) and **Ocean** (green + blue) — switch with the toggle in the app header; the choice is saved in the browser.

</div>

---

## ✨ Feature Matrix

| Area | Implementation |
|------|----------------|
| **SRS Scenario 1** | Password-only baseline — Burp/OWASP ZAP friendly, no MFA in LOW risk |
| **SRS Scenario 2** | Password + **Mobile OTP** (RFC 6238 TOTP, 30 s window, expiry-aware) |
| **SRS Scenario 3** | Password + Mobile OTP + **Email Step-Up** + **RBAC** route authorization |
| 🏫 **School portal (v2)** | Fictional modules behind strict server-side RBAC (`portalGate(roles)`): Courses, Grades, Assignments, Attendance, Class rosters, User directory — 8×3 access matrix shown to admins |
| 🔑 **Account recovery / MFA reset (v2)** | `request → reset → validate`: TOTP+password rotation, 10 single-use recovery codes, audited |
| 🕵️ **Forensics (v2)** | Reconstructed chronological timelines per user/IP/device/outcome, one-click **case** with auto-captured evidence + **Markdown** export |
| ⏱️ **Benchmark (v2)** | Scenario 1/2/3 compared from real `elapsed_ms` audit telemetry (attempts, avg. login time, counters) |
| **Adaptive Risk Engine** | F_TIME_ANOMALY +15 · F_NEW_IP +25 · F_IMPOSSIBLE_TRAVEL +40 · F_NEW_DEVICE +30 · F_CONSECUTIVE_FAILURE +20/ea · F_UNRECOGNIZED_DEVICE +30 · F_BLACKLISTED_IP +45 → `{score, level, reasons[]}` |
| **Policy bands** | 🟢 LOW 0–30 direct login · 🟡 MEDIUM 31–69 **Cross-Device Approval** (Apple/Google style) or E-mail + OTP · 🔴 HIGH 70–100 immediate lock-down + admin alert |
| **Audit trail** | Timestamp, identity, device+fingerprint hash, network/subnet/label, outcome, risk, reasons — persisted per attempt |
| **Registration & E-mail** | Self-registration + **real Nodemailer/Ethereal** verification link; clicking it stamps the browser as **Trusted** |
| **Trusted-Device registry** | AES-256-GCM encrypted persistent cookie (`as360_trust`, 1 year) + device table; revocable per user |
| **Cross-Device Approval** | Real-time push (SSE `cross:<uid>`) → **Approve/Deny** from a trusted device; 45 s TTL, offline fallback to E-mail + OTP |
| **Impossible-Travel detection** | Haversine distance between last vs. current login geo-position (>1,000 km/min ⇒ +40) |
| **SOC Dashboard** | Sidebar (Overview / Audit / Sessions / Trusted Devices / Threat Factors / Blacklist / Attack Sim), SSE live feed, per-role views |
| **Attack Simulation Engine** | **Type A** brute-force · **Type B** impossible-travel · **Type C** credential-stuffing — live telemetry timeline against the real pipeline |
| **Roles** | ADMINISTRATOR → SOC console + full portal + forensics + benchmark · STUDENT/TEACHER → personal Security Center + scoped portal (`docs/technical/User_and_Role_Access_Matrix.md`) |
| **Extra controls** | Session termination, IP whitelist/blacklist, lockout release, threat factor expiry, defense re-arm, account recovery |

---

## 🚀 Quick Start

```bash
# 1. Install
npm install

# 2. (optional) clean seed database
npm run db:reset

# 3. Run
npm start             # → http://localhost:4000
```

Node **>= 24** is required (uses the built-in `node:sqlite` — no native builds).

No external database, no browser extension, no IP API services: everything
runs locally and offline. E-mail uses **Ethereal** (real SMTP *preview* inbox) via
Nodemailer and degrades gracefully to the console when offline.

> **Live OTP:** the login screen streams the current TOTP of every seed account
> (auto-refreshing every 30 s) so testers can complete MFA without a phone.
> Registered accounts receive their codes via the verification e-mail's preview.

---

## 🔑 Test Credentials (seed data)

| Username   | Password       | Role          | Department            | OTP secret (hidden) |
|------------|----------------|---------------|-----------------------|---------------------|
| `student1` | `Student@123`  | STUDENT       | Computer Science      | JBSWY3DPEZLMNQYI |
| `student2` | `Student@123`  | STUDENT       | Computer Science      | KRSXG5DSNFXGO54J |
| `teacher1` | `Teacher@123`  | TEACHER       | Information Security  | MZUWY6JOFZQW65DF |
| `teacher2` | `Teacher@123`  | TEACHER       | Network Engineering   | NVXG4ZBOGNSXE33T |
| `admin`    | `Admin@123`    | ADMINISTRATOR | IT Security Office    | OJZXC6LVOVZWE642 |

> **Live OTP:** the login screen’s **DEMO panel** streams the current TOTP of every
> account (auto-refreshing every 30 s) so testers can complete MFA without a phone.

---

## 🧭 Architecture

```
AuthShield360/
├─ frontend/                 # SPA (vanilla JS, CSS) — Light + Ocean themes, decoupled from API
│  └─ assets/                # school logo (logo.svg · logo-lockup.svg) + favicon
│  ├─ index.html             # ingest (login/register) + app shell (tabs) + approval modal + toasts
│  ├─ css/styles.css
│  └─ js/
│     ├─ api.js              # client core: $/$$, esc, fmt, state(fp/session), api(), toast, badge
│     ├─ app.js              # boot, register/verify, tabs routing, SSE, cross-device modal, logout
│     ├─ soc.js              # SOC panels: overview, audit+filters, sessions, devices, factors, lists, sim
│     ├─ user.js             # Security Center + recovery panel
│     ├─ portal.js           # school portal (RBAC modules) + overview + matrix
│     └─ forensics.js        # timeline search, cases CRUD + drawer, export, benchmark
├─ backend/
│  ├─ index.js               # Express boot + static + SPA fallback
│  ├─ config.js              # policy knobs (weights, bands, GEO_TABLE, cookie, approvals, DB path)
│  ├─ db.js                  # node:sqlite schema + migrations + seed + DAOs
│  ├─ fingerprint.js · network.js · risk-engine.js · totp.js · cookie.js · mailer.js · console.js
│  ├─ auth.js                # register/verify, trust, risk orchestration, cross-approval, RBAC, recovery
│  ├─ portal.js              # school portal: session validation, role gates, ROLE_ACCESS_MATRIX
│  ├─ forensics.js           # timeline reconstruction + case open/capture/export (Markdown)
│  ├─ benchmark.js           # scenario comparisons from real elapsed_ms
│  ├─ sme.js                 # attack simulation engine (types A / B / C)
│  ├─ routes.js              # single /api router (REST + SSE)
│  └─ events.js · health.js
├─ scripts/
│  ├─ reset-db.js            # wipe + reseed
│  ├─ smoke.js               # 17 assertions (no server required)
│  ├─ e2e-all.js             # 77 assertions against a live server (incl. portal/recovery/forensics/bench)
│  ├─ ui-smoke.js            # 28 UI checks in a real browser
│  ├─ restart-check.js       # 18 NFR checks (data survives process restart, isolated :4001)
│  └─ record-demo.js         # puppeteer-core screen-recording → demo.mp4 (h264)
├─ presentation/             # GitHub Pages deck (standalone, themed)
├─ docs/
│  ├─ 01-دليل_التشغيل_والاستخدام.md   # user guide (Arabic, non-technical)
│  ├─ 02-دليل_الاختبار_والتجربة.md    # test & demo walkthrough
│  ├─ 03-الدليل_الفني_والعلمي.md      # full technical guide (Arabic)
│  ├─ 04-دليل_تحسين_مستودع_GitHub.md  # repository improvement plan
│  ├─ technical/             # bilingual reports, matrices, Presentation_Deck.pptx/.pdf
│  └─ reference/             # WORKFLOW.md + extracted SRS text
├─ demo.mp4
└─ README.md
```

### Data flow (login)

```
Browser fingerprint ─ SHA-256 ─▶ X-FP header · (optional) as360_trust cookie
User + password ───────────────▶ POST /api/auth/login
   │  analyzeNetwork(ip) → subnet, geo, label
   │  travelAssessment() → km/min vs 1,000 km threshold
   │  evaluateRisk() → 0..100 + reasons[]   (TIME/NEW_IP/TRAVEL/DEVICE/FAIL/UNRECOGNIZED/BLACKLIST)
   ├─ LOW 0–30       → direct SUCCESS (S1) / STEP_UP OTP (S2/S3)
   ├─ MEDIUM 31–69   → Cross-Device Approval push (or E-mail + OTP fallback)
   ├─ HIGH 70–100    → HIGH_RISK_BLOCK (lockdown + admin alert)
   └─ every branch ──▶ audit_trail(row) + SSE broadcast ──▶ SOC feed/counters
```

---

## 🧪 Automated Test Matrix

```bash
node scripts/smoke.js          # 17  — risk engine, S1/S2/S3, lockout, register→verify (no server)
node scripts/e2e-all.js        # 77  — full live loop: scenarios, approval, lists, attacks A/B/C, SSE,
                               #       school portal RBAC, recovery/MFA reset, forensics+export, benchmark
node scripts/ui-smoke.js       # 28  — real-browser UI tour (playwright-less puppeteer-core)
node scripts/restart-check.js  # 18  — NFR: users/devices/audit/cases/attacks survive a hard restart
```

Clean-run recipe: stop `:4000` → `node scripts/reset-db.js` → `npm start` → run the four suites.
**Total: 140 automated checks green on a pristine DB.**

Human-readable: `docs/technical/Identity_Security_Test_Matrix.md`
Machine-readable: `docs/technical/Identity_Security_Test_Matrix.json`

## 📦 Delivery Export (non-Markdown)

```bash
python scripts/export-deliverables.py   # PDF + DOCX beside every Markdown doc, PPTX + PDF deck
node scripts/package-dist.js            # genuine ZIP → dist/AuthShield360-v2.zip (zipfile, not tar)
node scripts/build-upload-bundle.js ..  # clean upload-ready copy (no deps/runtime junk) + file manifest
```

Requires: Python 3 + `python-docx python-pptx markdown pypdf`, headless Microsoft Edge on PATH for PDFs.
Outputs sit next to their source Markdown: `docs/technical/Technical_Report_AR|EN.{pdf,docx}`,
`docs/technical/User_and_Role_Access_Matrix.{pdf,docx}`, `docs/technical/Identity_Security_Test_Matrix.{pdf,docx}`,
`docs/technical/Presentation_Deck.{pptx,pdf}`, and `docs/0*.{pdf,docx}` for the Arabic guides.

---

## 🔬 Security Testing — Burp Suite / OWASP ZAP

The API is plain JSON over HTTP, so proxy interception is one setting away.

1. Start the Cornell Deep platform (`npm start`), then point Burp **Proxy** (127.0.0.1:8080) or ZAP at
   `http://localhost:4000`.
2. Set **HTTP client fingerprint** header per request:
   - `X-FP: <32+ char stable hex>` — changing it emulates a **new device**
     (F_UNRECOGNIZED_DEVICE +30) or, on a fresh subnet, a new network (F_NEW_IP +25).
3. **Scenario 1** flows (no OTP) are perfect for active scans:

   ```
   POST /api/auth/login
   Content-Type: application/json
   X-FP: probing-device-a

   {"username":"student1","password":"Student@123","scenario":1}
   ```

4. **MFA testing:** pull a live code from `GET /api/identity/otps`, then reuse it
   in a **Session or Turbo Intruder** payload for OTP brute-force checks
   (`INVALID_OTP` / `EXPIRED_OTP` paths; OTP failures do *not* lock the account).
5. **Expired-OTP check:** take a code, wait one window, submit → `EXPIRED_OTP`.
6. **Brute-force / lockout:** send 2 wrong passwords → account locks, next attempt
   → `HIGH_RISK_BLOCK` (reasons include F_CONSECUTIVE_FAILURE). Release with
   `DELETE /api/factors/lockout?username=<user>`.
7. **To lift the demo** brute-force guard entirely, drive the control plane as admin:
   ```bash
   # admin login first, then capture result.session.sid
   PUT /api/security-policy?standby=false        (x-session-side: <sid>)
   POST /api/arm-mode                            (clear factors + re-arm)
   ```
   > `npm run db:reset` restores a pristine state after destructive scans.

### Representative Intruder request templates

```
POST /api/auth/login HTTP/1.1
Host: localhost:4000
X-FP: §1§

{"username":"student1","password":"§2§","scenario":1}
```
Payload 2 = password wordlist (S1 password-only), payload 1 = switching `X-FP`
to force NEW_DEVICE risk.

---

## 🕵️ SOC Dashboard Tour

| Panel | What it does |
|-------|--------------|
| **Overview** | Live SSRE feed (outcome, user, risk band, reasons), lockout policy, realtime Toasts on HIGH-risk, latest attack timeline |
| **Audit Log** | full telemetry per attempt, one-click **Clear threat factors** |
| **Sessions** | every active SID with one-click **Terminate** |
| **Trusted Devices** | encrypted trust registry across all users (fingerprint, browser, last seen) |
| **Threat Factors** | live factor ledger + policy legend + ARM / STANDBY / **Force unlock** controls |
| **Blacklist** | add/remove IPs; blacklisted IPs add +45 and are rejected at sign-in |
| **Attack Simulation** | **Type A** brute-force · **Type B** impossible-travel · **Type C** credential-stuffing — live telemetry timeline + past runs |

## 🌐 Recommended Demo (Cross-Device Approval in 60 s)

1. **Register** (`Create account`) with a real-looking e-mail. Open the **Ethereal
   preview** link to see the actual verification e-mail.
2. Click **Verify now** — this browser becomes a **Trusted Device** (encrypted
   cookie). `/api/me` reports `trusted: true`.
3. Open the same URL in an **incognito window**, log in with the same account
   (Scenario 2/3). The trusted browser instantly shows the **Approve?** modal
   (device, IP, reasons, risk) — click **Approve** and the incognito window
   completes the login; or **Deny** to reject it.
4. If the trusted device is offline, the requesting window falls back to
   **E-mail + OTP** after ~20 s.
5. Log in as **admin** (S3, OTP from the DEMO panel) → SOC console → **Attack
   Simulation** tab → launch **Type A/B/C** and watch the telemetry + counters
   react in real time.

> Impossible-Travel (Type B) signs in from San Francisco then Sydney seconds
> later: `distanceKm()` ≈ 12,000 km ⇒ +40 ⇒ HIGH ⇒ lockdown.

---

## 🔐 Design Decisions & Hardening

- Fingerprints are **SHA-256** of stable browser signals + the client IP, generated
  client-side and never replayed unhashed.
- Passwords are stored hashed (SHA-256 + static pepper) — *demo-grade only*; swap for
  `argon2`/`scrypt` for production.
- Session tokens are cryptographically random; revocation removes the row server-side.
- Lockout avoids creating an **account-enumeration** oracle via deferred failures and
  lock short windows, while the audit trail still records unknown-identity attempts.
- The demo **defense-standby** flag exists strictly to make intentional
  red-team testing convenient; in a hardened deployment it stays `false`
  (`backend/config.js`).

---

## 🧑‍💻 API Cheat Sheet

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/health` | readiness + counters |
| GET | `/api/identity/init` | seed accounts + scenario labels + network + attack types |
| GET | `/api/identity/otps` | live demo OTP for each seed account |
| POST | `/api/auth/register` | create account → real e-mail verification link |
| GET | `/api/verify?token=` | verify e-mail → stamp **Trusted** cookie |
| GET | `/api/me` | trusted-device status for the current cookie |
| POST | `/api/auth/login` | authentication (S1/S2/S3) |
| GET | `/api/pending/:id/status` | approval poll (pending/approved/denied/expired) |
| POST | `/api/pending/:id/approve` · `/deny` | trusted-device decision |
| POST | `/api/pending/:id/finalize` | complete approved login (creates session) |
| GET | `/api/my?userId=` | user's devices / sessions / activity |
| POST | `/api/my/device/revoke` | revoke a trusted device |
| POST | `/api/session/demote` | terminate a session |
| GET | `/api/sessions` · `/api/devices` | SOC inventories |
| GET | `/api/dashboard` | counters + events + alerts |
| GET | `/api/factors` · DELETE | threat factors (list / clear) |
| DELETE | `/api/factors/lockout` | release an account lock |
| GET | `/api/lists` | whitelist + blacklist |
| POST/DELETE | `/api/whitelist` · `/api/blacklist` | access-list management |
| POST | `/api/simulate` | start attack simulation (`type: A|B|C`) |
| GET | `/api/simulations` | simulation history |
| GET | `/api/stream` | SSE live feed (incl. `cross:<uid>` for trusted users) |
| GET | `/api/portal/session` | portal session + role overview (401 w/o session) |
| GET | `/api/portal/{courses,grades,assignments,attendance}` | per-role portal data |
| GET | `/api/portal/{rosters,users,matrix}` | gated `portalGate(roles)` — 403 on mismatch |
| POST | `/api/recovery/request` · `/reset` · `/validate` | recovery / MFA reset flows |
| GET | `/api/forensics/{summary,entities,timeline}` | forensics summary/facets/timeline |
| POST | `/api/forensics/cases` (+ `/close`, `/export`, DELETE, PATCH) | investigation cases + Markdown evidence export |
| GET | `/api/benchmark` | scenario 1/2/3 performance from real elapsed_ms |

---

## 📜 License & Disclaimer

Educational / demonstration platform. **Not** a substitute for a validated
Identity Provider (Auth0, Keycloak, Entra ID) in a production environment.


---

## Deliverables (تسليمات)

| الملف | الوصف |
|-------|--------|
| docs/technical/Technical_Report_AR.md · Technical_Report_EN.md | التقرير الشامل ثنائي اللغة (عربي/إنجليزي) لكل ما أُنجز + الأدلة |
| docs/technical/User_and_Role_Access_Matrix.md | مصفوفة الأدوار 8×3 للمنصة التعليمية |
| docs/03-الدليل_الفني_والعلمي.md | شرح المشروع كاملًا بالعربية (فهمه كما لو أنك بنيته) — PDF/DOCX مرافق |
| docs/02-دليل_الاختبار_والتجربة.md | دليل الاختبار خطوة بخطوة + جدول الحسابات والإيميلات — PDF/DOCX مرافق |
| docs/01-دليل_التشغيل_والاستخدام.md | دليل بالعربية لغير المختصين: التجربة خطوة بخطوة + حسابات جاهزة |
| docs/reference/WORKFLOW.md | توثيق سير العمل التقني الكامل (تدفق البيانات، القرارات، واجهات API) |
| docs/technical/Presentation_Deck.pptx · .pdf | عرض تقديمي جاهز للطباعة/العرض (12 شريحة) |
| presentation/index.html | العرض التقديمي التفاعلي (يُنشر تلقائيًا على GitHub Pages) |
| demo.mp4 | فيديو تسجيل شاشة حي لكل المراحل والميزات (register→verify→portal→forensics→sim) |
| scripts/record-demo.js | يقود المتصفح (puppeteer-core + Edge) ويسجّل كل المراحل ثم يشفّر h264 |
| .github/workflows/tests.yml | CI: يشغّل السويتات الأربعة (140 فحصًا) عند كل push على `main` |
| .github/workflows/pages.yml | نشر العرض التقديمي تلقائيًا على GitHub Pages |
| docs/04-دليل_تحسين_مستودع_GitHub.md | خطة تحسين المستودع احترافيًا (CI · Pages · وصف · إصدارات) |
