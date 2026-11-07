# Phase 4 — Multi-tenant platform + incident management

Status: **feature-complete** (all milestones done; pending live verification on a
stack rebuild). Design record and milestone tracker. Builds on the Phase 3
multi-user auth (docs/auth.md).

## What changes and why

Pahredar is used to watch **several clients** (e.g. different companies an
operator is responsible for). Three connected shifts:

1. **Tenancy** — assets, scans, and alerts belong to a **client**. Access is
   client-scoped: an operator sees only the clients they are assigned to. Admins
   see all.
2. **One incident per asset** — instead of one alert per (asset, CVE), each
   asset has a single living **incident** that aggregates its problems. When a
   new vulnerability is found, the incident updates itself and re-notifies.
3. **Incident management (Zenduty-like)** — incidents have a lifecycle
   (triggered → acknowledged → resolved), and notifications flow through routing
   rules, escalation policies, on-call schedules, and suppression windows,
   across multiple channels.

These unify: a detector raises **alerts**; alerts are grouped into a per-asset
**incident**; the incident drives **notifications** by policy. #2 is the
grouping rule; #3 is the delivery engine.

## Tenancy model

- **client** (id, name, slug, notes, created_at): a tenant — the organisation an
  asset belongs to.
- **user_client** (user_id, client_id): which clients a user may access
  (many-to-many). An **admin** implicitly accesses all clients and manages this
  mapping; **operator**/**viewer** access only their assigned clients.
- **Scoping**: `asset.client_id` (required). `scan`, `alert`, and `incident`
  inherit the client through their asset. Every list query filters to the
  principal's accessible clients; every mutation checks the target's client is
  in that set, else 403.
- **Principal extension**: the resolved principal carries `ClientScope` — either
  "all" (admin) or an explicit set of client ids. The resolve middleware loads
  it from `user_client`. Guards still gate by role; a new helper gates by client
  access.
- **Roles stay global in meaning** (viewer < operator < admin) but their reach
  is the assigned clients. (A future step could make the role itself per-client;
  not now.)

## Incident model

- **incident** (id, client_id, asset_id unique-while-open, status, severity,
  title, opened_at, acknowledged_at, resolved_at, last_event_at, delivered_at):
  one open incident per asset. Aggregates the asset's current problems.
- **incident_item** (incident_id, kind [kev|epss|finding], cve_id, detail): the
  individual problems rolled into the incident. The old per-(type,asset,cve)
  alert rows become items.
- **Re-alert on change**: when a detector finds a new problem for an asset, the
  item is added (deduped), the incident's `last_event_at` bumps, its status
  drops back to **triggered** if it was acknowledged (configurable), and it is
  re-queued for delivery (`delivered_at` cleared). A resolved incident with a
  new problem re-opens.
- **Lifecycle**: triggered → acknowledged (someone owns it) → resolved (fixed).
  Resolving requires the items to be gone or a manual resolve; re-opening on a
  new item.

## Notification & escalation (Zenduty-like)

- **channel** (type [webhook|email|slack|telegram], config): a delivery target.
- **escalation_policy** (per client): ordered levels; each level notifies
  channels / on-call after a delay until acknowledged.
- **on_call_schedule** / **rotation**: who is on call for a client at a time.
- **routing_rule**: match incidents (by client, severity) → escalation policy.
- **suppression_window**: mute notifications for a client/asset for a period
  (maintenance), without losing the incident.
- Delivery walks the policy: notify level 1; if not acknowledged within the
  delay, escalate to level 2; and so on. Suppressed incidents record events but
  do not notify.

## Milestones

Tenancy is the foundation (everything scopes by client), so it goes first.

- **4A — Tenancy**
  - **M1** (clients + assignment) — **done**: `client` + `user_client` tables
    (migration 00027), admin client CRUD, user↔client assignment
    (`PUT /users/{id}/clients`), scoped `GET /clients`, and principal client
    scope (`AllClients` / `ClientIDs`, on `/auth/me`). No asset enforcement yet
    (4A-M2). Verified: CRUD + slug + dup 409, admin-only create, per-user scope.
  - **M2** (scope assets) — **done**: `asset.client_id` (migration 00028;
    uniqueness → (client_id, kind, value)); `ListAssets` scoped to the caller's
    clients; `GetAsset`/mutations behind an access check (tenant mismatch → 404);
    create requires an accessible `client_id`. Build-verified; live HTTP check
    deferred to the next stack rebuild (host→DB password is blocked here).
  - **M3** (frontend) — **done**: admin Clients page (CRUD), per-user client
    assignment on the Users page, client picker + filter + client column on the
    inventory, and `/auth/me` client scope in the auth context. tsc + build green.
- **4B — Incidents**
  - **M1** (model + rollup) — **done**: `incident` table (migration 00029), one
    open incident per asset. `RefreshIncidents` rolls the asset's alert rows up
    into a single incident (severity = max, item_count, title), and **re-surfaces
    it (clears read_at) and re-queues delivery (clears delivered_at) when a new
    alert appears** — the "one incident per asset, re-alert on new vuln"
    requirement. The `incidents` service (list/get/items/read, client-scoped)
    replaces the alerts service; delivery and the check loop now work on
    incidents. Alert generation (KEV/EPSS/finding) is unchanged, so the scanner
    is untouched. Build + vet green; live check deferred to the stack rebuild.
  - **M2** (lifecycle) — **done**: `PUT /incidents/{id}/acknowledge` and
    `/resolve` (operator+). `RefreshIncidents` now updates open incidents and
    opens new ones separately, so a **resolved incident re-opens only when an
    alert newer than its resolved_at arrives** (no spurious re-open while its
    alerts persist). Build + vet green; live check deferred to the stack rebuild.
  - **M3** (frontend) — **done**: Incidents page (one row per asset, Open/All
    filter, expand to see the rolled-up issues, acknowledge/resolve, mark read)
    replacing the alerts page; nav + dashboard strip + unread badge now use
    incidents. tsc + build green.
- **4C — Notification & escalation**
  - **M1** (channels + routing) — **done (backend)**: `channel` table (migration
    00030) — webhook/email targets, global (no client) or per-client. CRUD at
    `/api/v1/channels` (global channels admin-only; client channels need client
    access). Delivery now routes each incident to its client's channels plus
    global ones, falling back to the env `ALERT_WEBHOOK_URL`/SMTP when none apply;
    marked delivered on the first success. Build + vet green. *Frontend (channel
    management UI) comes with M4.*
  - **M2** (escalation) — **done (backend)**: `escalation_policy` + `escalation_step`
    (migration 00031), global or per-client, one default per scope. CRUD at
    `/api/v1/escalation-policies` (+ `/{id}/steps`). The delivery loop now walks
    the policy: notify step 0, re-notify the current step on new activity, and
    escalate to the next step once a step's `delay_minutes` passes without an
    acknowledgement (acknowledged incidents stop escalating). No policy → the M1
    one-shot channel delivery. Incident carries `policy_id`/`esc_step`/
    `esc_notified_at`. Build + vet green.
  - **M3** (on-call) — **done (backend)**: `oncall_schedule` + `oncall_shift`
    (migration 00032), global or per-client, shifts as explicit user + time
    windows. CRUD at `/api/v1/oncall-schedules` (+ `/{id}/shifts`,
    `/oncall-shifts/{id}`). An escalation step with `notify_oncall` now emails
    whoever's shift covers "now" in the incident's client schedule (else global).
    Build + vet green.
  - **M4** (suppression + frontend) — **done**: `suppression` table (migration
    00033) — mute notifications for an asset / client / globally during a window;
    the delivery walk skips a suppressed incident (keeping it in-app). CRUD at
    `/api/v1/suppressions`. **Notifications page** (frontend) manages all of 4C:
    channels, escalation policies (with a step editor), on-call schedules +
    shifts, and suppression windows. tsc + build green.

Delivered incrementally; each milestone builds and is verified before the next.
The existing `alert` tables are migrated into `incident`/`incident_item` in 4B.

## Notes

- This runs alongside other in-flight work; commits touch only this phase's files.
- Backward compatibility: the Phase 3 webhook/email delivery keeps working until
  4C replaces it with channels + policies.
