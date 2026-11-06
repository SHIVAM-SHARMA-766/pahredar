# Platform foundation

How Pahredar is structured as it grows from a set of tools into a security
**platform**, and the foundational pieces that must be right early because they
are hard to retrofit.

Read this before adding a new service, a background job, or anything that
touches the shared core. For where features are going, see
[roadmap.md](roadmap.md). For working without stepping on other in-flight
changes, see [contributing.md](contributing.md).

## The shape: a modular monolith

One deployable (one Go backend, one React app, one Postgres), split internally
into **product services** that own their domain, over a shared **core** that
owns the platform plumbing. This gives service isolation (clear boundaries,
parallel work, additive growth) without the cost of separate deployables —
which the project's constraints (single operator, $0 hosting) rule out.

```
                 ┌─────────────────────────────────────────────┐
  product        │  Intelligence   │   News   │   Scanner   │ … │
  services       └────────┬────────┴────┬─────┴──────┬──────────┘
                          │ registers routes / jobs / nav / migrations
                 ┌────────▼─────────────▼────────────▼──────────┐
  core /         │  Platform: store · config · logger · jobs ·  │
  platform       │  events · http server · fetch client · auth  │
                 └──────────────────────┬───────────────────────┘
                                   Postgres (one DB)
```

The three services today are **Vulnerability Intelligence**, **Security News**,
and **Endpoint Scanner** (see `docs/services/`). More will be added (alerting,
attack-surface monitoring, …) — the foundation below is what lets them plug in
without rewriting the core.

## Foundation pillars

Ordered by priority. "Retrofit-hard" means it gets much more expensive to add
once more services exist, so it should be done early even if minimal.

### P1 — Module/service pattern · retrofit-hard

**Problem today:** `api.Server` is a god-struct holding every dependency
(`store`, `sched`, `reports`, `scanner`, `jobs`, …) and every route is
registered in one `api.go`. Each new service edits the core — the exact
bottleneck that blocks parallel and future work.

**Target:** each service is a Go package implementing a small `Module`
interface and is handed a shared `Platform` context. The core keeps a registry;
`main.go` lists the modules. Adding a service becomes a new package plus one
register line — the core is untouched.

```go
// Platform is the shared core every module receives.
type Platform struct {
    Store  *db.Store
    Config *config.Config
    Log    *slog.Logger
    Jobs   *jobs.Queue   // P2
    Events *events.Bus   // P4
    Fetch  *fetch.Client // public-only HTTP client
}

// Module is one product service plugged into the platform.
type Module interface {
    Name() string                 // "scanner"
    Routes(mux *http.ServeMux)    // registers its own /api/v1/... handlers
    Jobs(q *jobs.Queue)           // registers its background task handlers (may be empty)
    Nav() []NavItem               // frontend nav metadata, served to the UI
}
```

Migrations stay in the single goose directory but follow the per-service number
blocks in [contributing.md](contributing.md). Effort: **M**. This is the single
change that most improves how the project grows.

### P2 — Durable job/task system · retrofit-hard

**Problem today:** endpoint scans live in an in-memory `map[int64]*scanJob`
(lost on restart, no retries, single-process). Nothing can be scheduled or
survive a deploy.

**Target:** a Postgres-backed task queue plus a worker pool, extending the
existing `syncer.Scheduler`. This is the backbone for scheduled scans, retries,
and every future async feature (alerting, monitoring, notifications).

```sql
CREATE TABLE task (
  id           bigserial PRIMARY KEY,
  type         text        NOT NULL,          -- 'scan.run', 'sync.source', 'alert.dispatch'
  payload      jsonb       NOT NULL,
  status       text        NOT NULL DEFAULT 'queued',  -- queued|running|done|error
  attempts     int         NOT NULL DEFAULT 0,
  max_attempts int         NOT NULL DEFAULT 3,
  run_at       timestamptz NOT NULL DEFAULT now(),
  locked_at    timestamptz,
  locked_by    text,
  result       jsonb,
  error        text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now()
);
```

A worker claims one row atomically with `FOR UPDATE SKIP LOCKED`, runs the
handler registered for its `type`, and records the result or reschedules with
backoff. Handlers are registered per module via `Module.Jobs`. Effort: **M**.

### P3 — Asset-centric data model · retrofit-hard

**The idea that turns tools into a platform.** Introduce a first-class `Asset`
(a domain, URL, IP, product, or repo the operator cares about). Scanner results
attach to an asset; intel matches tech → CVE per asset; future monitoring
watches assets. The operator gets an **inventory that tells them what is
wrong**, instead of three separate tools.

```sql
CREATE TABLE asset (
  id             bigserial PRIMARY KEY,
  kind           text NOT NULL,     -- domain|url|ip|product|repo
  value          text NOT NULL,     -- 'example.com', 'nginx'
  label          text,
  tags           text[] NOT NULL DEFAULT '{}',
  last_scanned_at timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (kind, value)
);
-- asset_scan: link asset -> scan.id   (scanner)
-- asset_tech: tech discovered on an asset -> product_stats for CVE match (intel)
-- asset_cve:  CVEs matched to an asset -> drives alerts (events)
```

This is the join between the services and the seed for monitoring/alerting.
Effort: **M/L**; cleanest once P1/P2 exist.

### P4 — Events + notifications · incremental

A lightweight internal event bus with a durable **outbox**: services emit
events (`scan.finding`, `kev.new`, `asset.cve_matched`); a notifications module
consumes them and delivers to a channel (in-app feed first, then webhook, then
email). Producers never know about delivery. Build when the first alert feature
lands. Effort: **M**.

### P5 — Identity/auth skeleton · retrofit-hard

Even while single-user: an API-key middleware (one key from config to start,
later an `api_key` table) that puts a `Principal{ID, Name}` on the request
context. Makes the API safe to expose, enables integrations, and avoids a
rewrite when teams/multi-user arrive. Effort: **S**.

### P6 — Contracts + observability · ongoing

Stable `/api/v1` responses; a request-ID on every request and log line; basic
counters/latency; and keeping the frontend's `api/types.ts` honest against the
backend (hand-kept now; generate from the Go types or an OpenAPI spec later).
Structured logging already exists (`slog`). Effort: **S**, continuous.

### P7 — Quality gate · ongoing

A GitHub Actions workflow: `gofmt`/`go vet`, `go build`, `go test`, `tsc`, and a
migration-applies check. Free, and it keeps quality from eroding as surface
area grows. Effort: **S**.

## What to do early vs later

| When | Pillars | Why |
|---|---|---|
| Early (hard to retrofit) | P1 module pattern, P2 durable jobs | Future-proof the core before more services pile onto it |
| When platform-feel is wanted | P3 asset model, P5 auth skeleton | The spine that makes it an application, and safe exposure |
| Incremental | P4 events/notifications, P6 contracts, P7 CI | Add with the first feature that needs them; keep improving |

## Principles that do not change

- **One deployable, clear internal seams.** No microservices; services talk
  through documented interfaces, not each other's internals.
- **$0 and self-hosted.** Every pillar above is Postgres + Go + the existing
  stack. No paid services.
- **Public-only networking stays enforced** for anything that reaches out
  (scanner, fetch client), with private targets gated by config.
- **Additive growth.** A new service adds files; it does not rewrite the core.
