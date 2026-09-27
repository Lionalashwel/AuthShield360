# AuthShield 360 — Agent Coding Notes

Agentic coding instructions for this repository (opencode / dev agents). Updated for v2 (Enterprise).

## Context
- Node >= 24 required (uses built-in `node:sqlite` — do not add `better-sqlite3` or other native deps).
- ES Modules only (`"type": "module"` in package.json).
- Runtime deps: `express`, `nodemailer` only. E-mail degrades to console print when Ethereal is unreachable — keep that fallback so offline labs stay testable.
- Win32 host: no `taskkill`/`netstat`/`powershell.exe` on bash PATH — use `MSYS_NO_PATHCONV=1 /c/Windows/System32/taskkill.exe /F /PID <pid>` etc. Kill the old :4000 listener before booting a rebuilt server.

## Commands
- `npm start` — boot server on http://localhost:4000
- `npm run db:reset` — wipe database and reseed fictional accounts
- `npm test` — automated v2 smoke harness (17 assertions; must pass before committing)
- `node --check <file>` — quick syntax check for JS files
- Kill stale server: find PID via `netstat -ano | grep :4000`, then `taskkill.exe /F /PID`.

## v2 architecture invariants
- Risk engine lives ONLY in `backend/risk-engine.js` → `evaluateRisk()` returns **`{score, level, reasons[]}`** (`reasons` replaces v1 `factors`). Weights/bands/GEO_TABLE/TRUST cookie live in `backend/config.js`.
- Every auth attempt goes through `commitAudit()` in `backend/auth.js` (keeps DB + SSE feed in sync). SSE bus uses `publish(topic, event)` / `subscribeEvents(fn, topics)` with topics `'*'`, `'audit'`, `'alert'`, `'sim'`, `'cross:<uid>'`.
- Never expose `pw_hash` or `totp_secret` in any API response (`sanitizeUser`).
- Trusted device = encrypted cookie token (`sealTrustCookie`/`openTrustCookie` in `backend/cookie.js`, AES-256-GCM) PLUS `trusted_devices` table. `/api/verify` sets the cookie; `/api/me` reports status.
- Cross-device flow: MEDIUM risk + unrecognized device + existing trusted device ⇒ `PENDING_APPROVAL` + `publish('cross:<uid>', {type:'crossdevice',...})`. Trusted device Approve/Deny → `pendingStatus`/`finalizeApprovedLogin`. Timeout (45 s) → E-mail + OTP fallback.
- Lockout counts **password failures only** (2 strikes, `MAX_FAILED_PASSWORD`); wrong OTPs do not lock. HIGH risk (≥70) → immediate lockdown + admin alert regardless.
- Role split: `ADMINISTRATOR` → SOC console; STUDENT/TEACHER → personal Security Center (endpoints `/api/my`, `/api/my/device/revoke`). Admin controls gated by `x-session-side` (sid registered server-side on login).
- New UI logic → `public/js/app.js`; styles → `public/css/styles.css` (no build step). Frontend is plain vanilla ES modules + EventSource.

## Verification checklist before done
1. `npm test` passes (17 assertions: risk reasons[]/bands, S1/S2/S3, lockout, register→verify→trusted login).
2. Server boots (`npm start`), `/api/health` returns `ok:true`.
3. Live e2e: register → `/api/verify` (cookie) → `/api/me trusted:true` → incognito login → `PENDING_APPROVAL` → approve → finalize `SUCCESS` (see temp e2e script); admin S3 login → `/api/simulate` (A/B/C) updates timeline/counters.
4. SSE `/api/stream` emits `crossdevice` + `audit` events to the trusted browser.
5. Frontend assets serve HTTP 200; `node --check public/js/app.js` clean.