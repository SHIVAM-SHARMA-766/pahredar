# Service: Endpoint Scanner

Assesses a public (or, when enabled, private) endpoint: a details-first recon
profile of everything discoverable, plus optional active checks that probe with
attack patterns. Also hosts an **IP scanner**: give it one IP and it aggregates
reputation and network info from several public databases. Self-contained — the
cleanest module and a good template for new services.

## Owns

**API routes**

- `POST /api/v1/scan` — start a scan job (passive, or active with
  `authorized: true`; optional `templates` filter)
- `GET /api/v1/scan/jobs/{id}` — poll a running job (streams findings)
- `GET /api/v1/scans`, `GET /api/v1/scans/{id}` — stored results
- `GET /api/v1/scan/config` — capabilities (active available, allow private)
- `GET /api/v1/ipscan?ip=` — IP scanner: aggregate one IP's reputation/network/geo
  from public databases (DNS blocklists, Team Cymru, RDAP, ip-api); key-free, no
  storage yet

**Backend**

- `internal/scanner/`: `scanner.go` (module + routes + scan.run handler registration), `handlers.go` (job lifecycle on the durable queue)
- `internal/scan/` (self-contained):
  - `scan.go` — orchestration, scoring, public-only dialer
  - recon: `dns.go`, `tls.go`, `http.go`, `paths.go`, `tech.go`, `recon.go`
    (RDAP registration, ASN/reverse-DNS, CT-log subdomains, favicon mmh3,
    email security)
  - active: `verify.go` (native evidence checks), `active.go` (Nuclei runner),
    `waf.go` (WAF/CDN fingerprint)
  - `ipscan.go` — the IP scanner (DNS blocklists, geo via ip-api, reuses
    `cymruASN`/RDAP/PTR from recon); queries third parties only, never the IP
- `internal/db/scan.go` — `SaveScan`, `GetScan`, `RecentScans`, `MatchTech`

**Frontend**

- Page: `ScanPage` (scan landing + result; an **IP scanner** tab, `?view=ip`)

**Tables** (new migrations use the next sequential number — see [../contributing.md](../contributing.md))

- `scan` (migration 00018; result stored as JSONB)

## Dependencies

- **Core:** store, config, logger, HTTP server.
- **Reads from Intel:** `db.MatchTech` → `scan.TechMatcher` matches fingerprinted
  tech (vendor/product) against intel's `product_stats`/CVE data. This is the
  one cross-service contract; keep it behind the interface.
- **Nuclei:** the binary and templates are bundled in the backend image
  (pinned). Active scanning is gated by `SCAN_ACTIVE_ENABLED`; private targets by
  `SCAN_ALLOW_PRIVATE`.

## How to add a feature

- **A new recon check:** add a `check*` function in a `scan/*.go` file, call it
  from `Scan` (as its own phase or within an existing one), extend the `Report`
  struct and `nilEmpty`, add the field to `frontend/src/api/types.ts`
  (`ScanReport`) and render a card in `ScanPage`.
- **A new native active check:** add to `verify.go` with request/response
  `Evidence`; it streams and shows under "Show evidence". Keep it safe (no
  exploitation/DoS) and cover it in `verify_test.go`.
- **New result data:** always stream findings via the progress callback and
  store the full report as JSONB; the UI leads with details, findings trail.

## Gotchas

- Everything that reaches out uses the scanner's public-only dialer
  (`sc.dial`), which re-resolves and validates the IP on every connection
  (SSRF/DNS-rebinding guard). Private targets are allowed only when
  `SCAN_ALLOW_PRIVATE=true`.
- Nuclei does **not** use the public-only dialer (it has its own client); the
  target URL is validated/allowed before Nuclei is invoked, and template runs
  are filtered to `http,ssl` excluding `dos,fuzz`.
- Path probes use catch-all detection so a single-page app that returns its
  HTML shell for every path does not trip exposure checks — preserve that when
  adding probes.
- Scans run as `scan.run` tasks on the durable queue (`internal/jobs`), so a
  finished scan survives a restart; progress is streamed onto the task row and
  the final report is also persisted to the `scan` table.
