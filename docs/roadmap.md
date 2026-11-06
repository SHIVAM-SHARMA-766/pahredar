# Roadmap & known gaps

Where Pahredar is going, in phases, plus the current limitations worth knowing.
The architecture that underpins this is in [foundation.md](foundation.md).

## Phases

Phases are about the **foundation and platform shape**, not a fixed schedule.
Feature work on the existing services continues in parallel.

### Phase 0 — Current state

Three services share one database and one HTTP server:
Vulnerability Intelligence, Security News, Endpoint Scanner (see
`docs/services/`). Data sync runs on a scheduler. The scanner does passive
recon, active (Nuclei + native) checks, and a request tool.

Core limitations this roadmap removes: the `api.Server` god-struct, in-memory
scan jobs, no asset inventory, no auth, no alerting.

### Phase 1 — The spine (foundation) · done

- **P1 module pattern** — `internal/platform` holds a shared `Platform` (store,
  logger, job queue); each service is its own package (`internal/intel`,
  `internal/news`, `internal/scanner`) implementing `platform.Module`, and
  `internal/api` is a thin assembler that registers them.
- **P2 durable jobs** — `task` table + `internal/jobs` worker pool; endpoint
  scans run as `scan.run` tasks and survive a restart. *(The periodic sync
  scheduler stays as-is; the queue is for discrete/triggered work.)*

Outcome: new services plug in via the registry; scans are durable.

### Phase 2 — Asset platform · in progress

- **M1 (done)** — `asset` table + `internal/assets` service (CRUD + scan an
  asset), an Inventory nav/page, and scan→asset linking (an asset shows its
  latest scan's grade). Adding the service was one line in `api.New` — the
  module foundation proven.
- **M2 (done)** — scans link to assets (`scan.asset_id`, migration 00021) and
  the asset detail page shows its latest-scan posture: tech fingerprinted on it
  with matched CVEs, a security-issues summary, a score gauge, and scan history.
- **M3 (next)** — scheduled re-scans of assets on the durable queue, and
  persisting matched CVEs per asset (`asset_cve`) to drive alerting.

Outcome: Pahredar becomes an inventory that tells the operator what is wrong,
not three separate tools.

### Phase 3 — Monitoring & alerting

- **P5 auth skeleton** so the API can be driven by automation.
- **P4 events + notifications** — emit `asset.cve_matched`, `kev.new`,
  `scan.finding`; deliver to an in-app feed, then webhook/email.
- Scheduled re-scans of assets (on the P2 queue).

Outcome: "a new KEV matches your stack → you get told", and continuous scanning.

### Phase 4 and beyond — Expansion

New services become straightforward once the spine exists:

- **Attack-surface monitoring** — auto-discover subdomains/assets and scan them
  on a cadence.
- **Integrations** — Slack/webhook out, SIEM/JSON export, an external API.
- **Compliance/reporting** — periodic posture reports per asset.
- **More intel sources** and detection content.

## Known gaps / limitations

Kept here (not in the README) on purpose.

- **No authentication.** The API is open; run it only on trusted/local
  networks until P5 lands.
- **Active scan depends on Nuclei templates bundled in the image.** They are
  pinned, not self-updating; refresh by rebuilding with a newer template tag.
- **`api/types.ts` is hand-maintained** against the Go types — they can drift;
  P6 (generation) addresses it.
- **CAA / SOA DNS records** are not collected (the Go stdlib resolver can't do
  them; needs a DNS library).
- **Single Postgres, no backups configured** in the compose dev setup.
- **No CI yet** (P7).

- **Inventory routes are `/inventory`** (not `/assets`) because the Vite build
  serves its hashed bundles under `/assets/`; the API stays `/api/v1/assets`.

## Non-goals

- Microservices / multiple deployables.
- Paid or hosted third-party services.
- Multi-region or horizontal scaling (single operator, single node).
