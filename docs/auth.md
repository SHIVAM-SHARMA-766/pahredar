# Authentication & authorization

Status: **in progress** (Phase 3 follow-on). This document is the design record
and the milestone tracker for multi-user auth.

## Goal

Pahredar is hosted as a **public threat-intelligence site** whose sensitive
actions are gated. Anonymous visitors read the intelligence and run passive
scans; named accounts do the rest. The model is role-based, with a small fixed
set of roles and a central, auditable access matrix.

## Roles

| Role | Rank | Who |
|------|------|-----|
| `anonymous` | 0 | Any visitor, not logged in |
| `viewer` | 1 | Logged-in, read-only of the private monitoring data |
| `operator` | 2 | Runs active scans, manages assets and alerts |
| `admin` | 3 | Everything, plus user management |

Roles are ordered: a guard requiring `operator` admits `operator` and `admin`.
There is no per-object ownership — this is a single-team tool; a role is a
capability tier, not a tenancy boundary.

## Access matrix

Public = anonymous and up. Each row names the **minimum** role.

| Capability | Min role | Routes |
|------------|----------|--------|
| Dashboard, CVEs, vendors, products, stats, detection, ATT&CK | public | `GET /cves*`, `/vendors*`, `/products`, `/stats/*` |
| Security news, feeds, advisories, trending, CVE articles | public | `GET /news`, `/feeds*`, `/stats/trending`, `/cves/{id}/articles` |
| Sync status | public | `GET /sync/status` |
| **Passive** scan + its results | public | `POST /scan` (passive), `POST /scan/request`, `GET /scans/{id}`, `/scan/jobs/{id}`, `/scan/config` |
| News bookmark toggle | operator | `PUT /news/bookmark` |
| Scan list (all scans) | operator | `GET /scans` |
| **Active** scan (intrusive Nuclei) | operator | `POST /scan` with `active: true` — content-based |
| Asset inventory + alerts (read) | viewer | `GET /assets*`, `GET /alerts`, `/alerts/unread-count` |
| Asset create / delete / scan | operator | `POST /assets`, `DELETE /assets/{id}`, `POST /assets/{id}/scan` |
| Alerts mark read | operator | `PUT /alerts/{id}/read`, `/alerts/read-all` |
| Trigger ingestion sync | admin | `POST /sync/{source}` |
| User management | admin | `GET/POST/PATCH/DELETE /users*` |
| Login | public | `POST /auth/login` |
| Current principal | public | `GET /auth/me` (returns anonymous when not logged in) |
| Logout | authenticated | `POST /auth/logout` |

The active-scan rule is **content-based**, not path-based: the same `POST /scan`
is public for a passive scan and operator-only when the request asks for an
active scan. The scanner handler enforces it from the principal on the context.

## Mechanism

- **Accounts** (`user` table): email (unique, lowercased), argon2id password
  hash, role, `disabled_at`. No public signup — an admin creates accounts and
  assigns roles. The first admin is seeded from `ADMIN_EMAIL` + `ADMIN_PASSWORD`
  on startup when the table is empty.
- **Passwords**: argon2id (`golang.org/x/crypto/argon2`), per-hash random salt,
  parameters encoded in the stored string so they can be raised later. Constant
  effort; never logged.
- **Sessions** (`session` table): on login the server issues a 32-byte random
  token, stores only its SHA-256 in the row, and sets it as an httpOnly cookie
  (`pahredar_session`, SameSite=Lax, `Secure` when `AUTH_COOKIE_SECURE=true`).
  Lookups hash the cookie and join the user; expired or disabled → treated as
  anonymous and the cookie is cleared. Logout deletes the row. TTL
  `AUTH_SESSION_TTL` (default 168h).
- **Principal resolution** (middleware, always runs): resolves the caller from,
  in order, a valid session cookie, then the `API_KEY` bearer/header (automation
  → admin principal), else **anonymous**. It never blocks; authorization is
  per-route. A principal is always on the context after it.
- **API key**: retained for automation and treated as `admin`. It is the machine
  credential; human access is by account.
- **Guards**: `platform.Guard(minRole, handler)` wraps a route and returns 401
  (anonymous — prompt login) or 403 (insufficient role). Routes are decorated in
  each module, so the capability lives next to its handler; this matrix is the
  single source of truth for auditing them.

## Milestones

- **M1 — auth core** (done): schema, argon2id, sessions, `Role`/`Principal`,
  login / logout / me, resolve middleware, admin bootstrap.
- **M2 — authorization** (done): `platform.Guard` applied across the matrix
  (assets/alerts, scan list, sync, news bookmark) and the content-based
  active-scan gate in the scanner. Verified end-to-end per role.
- **M3 — user management** (done): admin CRUD API — `GET/POST /users`,
  `PATCH /users/{id}` (role / disable), `PUT /users/{id}/password`,
  `DELETE /users/{id}`. Refuses demoting, disabling, or deleting the last
  enabled admin; disabling or a password reset drops that user's sessions.
- **M4 — frontend** (done): a cookie-based `AuthProvider` (reads `/auth/me`),
  a `LoginModal` (email/password, opens on 401 or "Sign in") replacing the
  API-key AuthGate, a sign-in/out chip in the sidebar, role-gated nav
  (Inventory/Monitoring need viewer; Administration — Data sync + Users — needs
  admin), an admin Users page, the active-scan toggle gated to operator, and
  viewer-read-only asset/alert pages (mutating controls hidden below operator).
  The dashboard monitoring strip only loads for authenticated users. tsc and
  the production build are green.

## Non-goals (for now)

- Per-object ownership / multi-tenancy.
- OAuth / external identity providers (self-hosted, $0).
- Password reset email flows (admin resets a user's password).
