# Service: Vulnerability Intelligence

The CVE knowledge base — ingest vulnerabilities and enrichment from many
sources, normalize them, and let the operator explore, search, and match them.
The largest service and the source of truth other services read from.

## Owns

**API routes**

- `GET /api/v1/cves`, `GET /api/v1/cves/facets`, `GET /api/v1/cves/{id}`
- `GET /api/v1/cves/{id}/{reports,related,detection,attack,articles}`
  (articles is served here but reads News data — see Dependencies)
- `GET /api/v1/vendors`, `GET /api/v1/vendors/{vendor}`,
  `GET /api/v1/vendors/{vendor}/products/{product}`, `GET /api/v1/products`
- `GET /api/v1/stats/dashboard`, `GET /api/v1/stats/series`
- `GET /api/v1/sync/status`, `POST /api/v1/sync/{source}`

**Backend**

- `internal/intel/`: `service.go` (module + routes), `cves.go`, `vendors.go`,
  `related.go`, `reports.go`, `sync.go`, `detection_attack.go`, `assess_test.go`
- `internal/db/`: `cve_read.go`, `cve_write.go`, `vendor_read.go`,
  `enrichment_write.go`, `detection.go`, `related_read.go`, `dashboard_read.go`,
  `series_read.go`, `report_cache.go`, `vulncheck.go`, `context.go`,
  `sync_state.go`
- `internal/syncer/` — the ingestion orchestrator and scheduler
- `internal/sources/*` — one package per upstream (nvd, cvelist, kev, epss,
  euvd, exploits, cwe, attack, debian, vulncheck, greenbone, detection, reports)
  plus `fetch` (shared public-only client, technically core)
- `internal/cverecord` — CVE-ID parsing and vendor/product canonicalization

**Frontend**

- Pages: `DashboardPage`, `CveListPage`, `CveDetailPage`, `VendorPage`,
  `VendorsPage`, `SyncPage`
- Components: `CveTable`, `QueryBar`; `lib/query.ts` (the search query language)

**Tables** (new migrations use the next sequential number — see [../contributing.md](../contributing.md))

- `cve`, `cve_affected`, `kev`, `epss`, `epss_history`, `exploit`,
  `euvd_exploited`, `attack_mapping`, `capec`, `debian_status`, `vulncheck_kev`,
  `detection_rule`, `cwe`, `external_report`, `sync_state`, `sync_run`
- Materialized views: vendor/product stats incl. `product_stats`

## Dependencies

- **Core:** store, config, logger, HTTP server, `sources/fetch`, scheduler.
- **Reads from News:** the CVE detail "articles" endpoint joins `feed_article`
  (owned by News). Kept read-only and additive.

## How to add a feature

- **A new upstream source:** add a package under `internal/sources/`, register
  its task with the syncer scheduler, write rows via `db/enrichment_write.go`
  (or a new writer), and surface it in the CVE/vendor reads. Add a migration in
  a new sequential migration for any new table.
- **A new CVE/vendor query or field:** extend `db/cve_read.go` /
  `vendor_read.go` and the matching `api/*.go` handler; add the field to
  `frontend/src/api/types.ts` (intel section) and render it.
- **A new saved view / query operator:** extend `lib/query.ts` and the backend
  `parseListParams`.

## Gotchas

- Sync is snapshot-safe and incremental; read `ARCHITECTURE.md` §7 before
  changing ingestion. A full corpus is large (≈400k CVEs).
- The API caps list offsets at 10,000; deep pagination is intentionally bounded.
- `product_stats` is a materialized view refreshed by the syncer — it is also
  what the Scanner reads via `TechMatcher`, so do not change its shape without
  updating the scanner contract.
- Severity, scores, and priority are **derived** in places, not always stored;
  check `ARCHITECTURE.md` §6 "Derived, not stored".
