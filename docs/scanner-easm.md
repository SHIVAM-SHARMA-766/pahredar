# Endpoint Scanner → EASM blueprint

Status: **design** (not yet built). This document reframes Pahredar's endpoint
scanner as an **External Attack Surface Management (EASM)** platform and maps a
detailed source spec onto Pahredar's architecture (the modular monolith, the
Phase 4 asset/client model, the durable job queue, and incidents). It is the
blueprint the implementation follows. Source IDs (P\*, A\*, PR\*, R\*) are kept so
the mapping is traceable.

## 1. Purpose and reframe

The current scanner does ad-hoc recon + optional active Nuclei on a single
target. EASM reframes it as **continuous attack-surface discovery and
monitoring** for a tracked asset (a domain or organisation), separating three
concerns that evolve independently:

- **What we collect** (information inventory) — the data, regardless of how it
  was obtained.
- **How we collect it** (collection method) — passive (third-party/public data,
  no contact with the target) vs active (direct requests to the target).
- **What it means** (security assessment) — findings derived from the collected
  intelligence.

The same fact (e.g. an A record) can come passively (passive-DNS dataset) or
actively (a live DNS query); classification is by **source + method**, each
stored separately with its own timestamp and evidence.

Guiding reframe (see memory `project_pahredar_scanner`): **monitor-first** — the
default mode is low-impact passive + light active discovery that runs on a
schedule and raises an incident on change; heavy/intrusive probing is a separate,
authorised, budgeted step.

## 2. Principles

1. **Collection ≠ assessment.** Collectors only gather and normalise; the
   Security Assessment engine reads stored records and produces findings. New
   sources or new checks can be added without touching the other side.
2. **Passive and active are separate** engines, separately scheduled, separately
   stored (method + timestamp on every record). Low-impact discovery never mixes
   with intrusive testing.
3. **Raw evidence is preserved** alongside the parsed record, with source
   attribution and a collection timestamp.
4. **Historical, not overwrite.** Records carry `first_seen`/`last_seen`; a new
   observation updates `last_seen` (and snapshots evidence), it does not erase
   the old one. Change detection diffs scans.
5. **Scope is enforced.** Discovered third-party / CDN / shared-hosting assets
   are *candidates* (`scope: pending`), not auto-scanned. Active probing only
   runs within an asset's authorised scope.
6. **$0 by default.** Only free/no-key sources are used (section 12); paid
   providers are pluggable slots, enabled only if the operator supplies a key.
7. **Data minimisation.** Organisation-level intelligence only; no unnecessary
   personal/employee data, credentials, or sensitive content retained.
8. **Rate limited + budgeted.** Active requests are bounded per scan (a budget),
   honouring robots/politeness and the existing `SCAN_ALLOW_PRIVATE` /
   `SCAN_ACTIVE_ENABLED` gates.

Reference methodologies: OWASP WSTG (Attack Surface Identification), MITRE ATT&CK
(Reconnaissance), NIST SP 800-115.

## 3. How it fits Pahredar

- **Service:** `internal/scanner` is reframed into three engines (section 4),
  still a single `platform.Module` over the shared platform (store, jobs, log).
- **Assets & clients (Phase 4):** every scan targets an **asset** (a domain/org)
  that belongs to a **client**; all EASM records and findings attach to that
  asset and inherit its client, so everything is client-scoped and respects the
  tenancy/RBAC already built. Discovered hostnames/IPs become candidate assets
  under the same client.
- **Jobs:** scans run on the durable job queue (`internal/jobs`) — a passive
  sweep and active probe batches are enqueued tasks, survive restarts, and are
  rate-limited by the worker pool + a per-scan budget.
- **Auth & scope:** passive scanning is public/viewer; active probing is
  operator+ (existing `platform.Guard` + the active-scan authorisation
  confirmation), plus per-asset scope enforcement (principle 5).
- **Monitoring:** change detection feeds the **incidents** engine (Phase 4B) —
  "new subdomain", "expired cert", "newly exposed port" open/raise an incident
  routed by the notification layer (Phase 4C). Scheduled rescans reuse the
  existing asset-rescan loop.

## 4. The three engines

| Engine | Package (proposed) | Responsibility | Method |
|---|---|---|---|
| **Domain Intelligence** | `scanner/passive` | Maximum public information collection | Passive |
| **Active Recon** | `scanner/active` | Verify + discover by contacting the target | Active |
| **Security Assessment** | `scanner/assess` | Turn collected records into findings | Neither (reads records) |

Each engine is a set of **collectors/probes** registered against a shared
**record store**. A scan run = a chosen set of probes (a profile) executed under
a budget, writing records; the assessment engine then evaluates the records.

## 5. Data model

The core new abstraction is an **evidence record**: one observation about an
asset, from one source, at one time. Every record carries the standard metadata
(from the spec's section 6).

Proposed tables (migrations, additive to the Phase 4 schema):

- **`scan_run`** — one scan of an asset: `id, asset_id, client_id, profile
  (passive|active|full), status, started_at, finished_at, budget, stats`.
- **`asset_record`** — the evidence records:
  `id, asset_id, client_id, run_id, category (dns|cert|subdomain|ip|http|tls|
  email|tech|cloud|threat|whois|…), key (the specific item, e.g. the subdomain
  or record), method (passive|active), source (rdap|crtsh|dns_resolve|…),
  data (jsonb, parsed), evidence (jsonb/text, raw), confidence (high|medium|low),
  verification (verified|unverified), scope (in_scope|pending|out_of_scope),
  first_seen, last_seen, scan_timestamp`.
  Uniqueness on `(asset_id, category, key, source)`; a re-observation updates
  `last_seen` + `data`/`evidence`, keeping history via `asset_record_history`
  (or an append-only `observation` row) for the change timeline.
- **`finding`** — Security Assessment output:
  `id, asset_id, client_id, record_id (nullable), kind, severity, title, detail,
  evidence, status (open|confirmed|false_positive|resolved), first_seen,
  last_seen`. Findings feed incidents.

Record JSON shape (per spec §6), example:

```json
{
  "asset": "api.example.com",
  "category": "subdomain",
  "collection": { "method": "active", "source": "dns_resolution", "timestamp": "2026-11-25T10:00:00Z" },
  "data": { "ipv4": ["192.0.2.10"], "ipv6": [], "cname": null },
  "verification": { "status": "verified", "confidence": "high" },
  "scope": "in_scope",
  "first_seen": "2026-10-01T…", "last_seen": "2026-11-25T…",
  "related_assets": []
}
```

Standard metadata fields on every record: Asset ID · Domain · Asset Type ·
Category · Collection Method · Source · First Seen · Last Seen · Scan Timestamp ·
Status · Confidence · Evidence · Verification · Scope Status · Risk Level ·
Related Assets.

## 6. Passive collection modules (Domain Intelligence)

Each maps a spec module to a Pahredar collector writing `asset_record`s. Sources
here are **free** (section 12); paid ones are deferred.

| Spec | Module | Collects | Free source(s) |
|---|---|---|---|
| P01 | Domain registration | registrar, dates, status, nameservers | RDAP (+ WHOIS fallback) |
| P02 | Related domains / portfolio | same-registrant/NS/cert-SAN domains, lookalikes | CT logs, RDAP correlation, permutation (in-house) |
| P03 | DNS intelligence | A/AAAA/NS/MX/TXT/CNAME/SOA/CAA/SRV/… + history | public passive-DNS (free), DNS datasets |
| P04 | Subdomain intelligence | CT-derived + historical subdomains | **crt.sh**, passive-DNS, Wayback |
| P05 | IP & network | reverse DNS, ASN/CIDR, geo, reputation | RDAP/RIR, BGP/ASN free datasets |
| P06 | SSL/TLS certificate | CN/SAN/issuer/validity/chain + history | **crt.sh** / CT logs |
| P07 | Search / web archive | indexed + historical URLs, archived pages | **Wayback**, Common Crawl index |
| P08 | Public repository | org repos, domain/API refs, secret *indicators* | GitHub/GitLab public search (free, metadata only) |
| P09 | Email infrastructure | MX, SPF, DKIM, DMARC, MTA-STS, BIMI | public DNS records |
| P10 | Technology & framework | server/CMS/frameworks/libs/CDN/WAF (from public data) | archived responses, public manifests |
| P11 | Cloud & hosting | AWS/Azure/GCP/S3/CDN hostname references | CT logs, public DNS, public code |
| P12 | Threat intel & reputation | domain/IP reputation, IOC associations | URLhaus, OTX (free), AbuseIPDB free tier, URLScan public |
| P13 | Org & digital footprint | org name, portals, status pages, vendors (public) | company sites, public registries |
| P14 | Historical & temporal | first/last-seen, DNS/IP/cert/content change timelines | Wayback, CT, passive-DNS |

Note: Pahredar already ingests CVE/KEV/EPSS/threat intel (intel + news
services); P10/P12/P14 reuse that store where possible rather than re-fetching.

## 7. Active probing modules (Active Recon)

Operator+ and within the asset's authorised scope. Non-destructive, budgeted.

| Spec | Module | Verifies/Discovers |
|---|---|---|
| A01 | DNS active enumeration | live records, DNSSEC validation, wildcard behaviour, AXFR *config* check |
| A02 | Active subdomain discovery | wordlist + permutation resolution, live vhosts |
| A03 | IP & network discovery | reachable hosts (ICMP/TCP), reverse DNS, traceroute |
| A04 | Port scanning | open TCP (+ limited UDP) ports, service/banner (budgeted) |
| A05 | Service & protocol fingerprinting | HTTP/SSH/SMTP/DNS/FTP/DB versions (safe) |
| A06 | HTTP/HTTPS intelligence | status, headers, redirects, methods, titles |
| A07 | SSL/TLS active assessment | live cert, TLS versions, ciphers, HSTS, OCSP |
| A08 | Web application discovery | root app, login/admin/portal pages, vhosts |
| A09 | URL & endpoint discovery | crawl, sitemap/robots, JS-extracted endpoints |
| A10 | Content & directory discovery | bounded dir discovery, known public files (minimal evidence, no downloads) |
| A11 | JavaScript & frontend | JS inventory, API refs, source-map availability, redacted secret patterns |
| A12 | API intelligence | REST/GraphQL/OpenAPI/Swagger, CORS, rate-limit headers (safe GET/OPTIONS) |
| A13 | Web security configuration | HSTS/CSP/XFO/cookies/CORS/info-disclosure |
| A14 | Email server active | SMTP availability, STARTTLS, EHLO caps, cert (no mailbox/relay abuse) |
| A15 | WebSocket & real-time | WS/WSS endpoints, handshake, origin policy |
| A16 | Virtual host & CDN/WAF | SNI/Host correlation, CDN/WAF/reverse-proxy indicators (CDN IP ≠ origin) |
| A17 | Network path & connectivity | traceroute, latency, route comparison |
| A18 | Vulnerability & misconfig validation | version→CVE correlation + **Nuclei** safe templates, non-destructive |

A18 reuses the existing **Nuclei** integration as one probe (safe templates
only; exploit/DoS/fuzz excluded — already the case). Version→CVE correlation
reuses the intel service's CVE/KEV/EPSS data and the asset_tech → cve_affected
matching already built.

## 8. Probe registry

A central registry maps a probe id → {method, collector fn, module}. A scan
profile is a selected subset. This is the single place that lists every probe
(spec PR01–PR34): passive (PR01–PR09), active (PR10–PR22, PR25–PR32, PR34), and
both (PR23 JS analysis, PR24 API discovery, PR33 tech fingerprinting). Each probe
declares its method, cost (for the budget), and required scope, so a run can be
planned and rate-limited deterministically.

## 9. Security Assessment engine

Reads `asset_record`s and emits `finding`s (which feed incidents). It is
independent of collection, so checks can be added freely. Example checks: expired
/ soon-to-expire certs, weak TLS/ciphers, missing security headers, dangling DNS
(CNAME → unclaimed), exposed admin/DB ports, SPF/DMARC gaps, directory listing,
insecure cookies, version→CVE associations, newly exposed service. Every
suspected issue is **unconfirmed** until validated (false-positive management);
findings carry evidence + remediation. Findings → the Phase 4B incident per
asset, routed by Phase 4C notifications.

## 10. Reporting

Generate structured reports from the records/findings (spec R01–R18): Executive
Summary, Domain Registration, DNS, Subdomains, IP/Network, SSL/TLS, Web/API,
Email Security, Technology, Cloud, Threat Intel, Historical, Exposed Services,
Security Assessment, Asset Relationship, Data Quality (coverage/duplicates/stale),
Scan Comparison (diff), Raw Evidence.

Formats: **JSON, CSV, HTML now**; PDF and SQLite/JSONL export later. Reports are
derived views over the record store, not separate storage.

## 11. Cross-cutting capabilities (mostly reuse)

| Capability | Status in Pahredar |
|---|---|
| Asset correlation (same IP/cert/ASN) | new (relationship graph over `asset_record`) |
| Change detection (new/deleted/modified) | new diff → **incidents** (Phase 4B exists) |
| Scan scheduling | reuse asset-rescan loop (`ASSET_RESCAN_INTERVAL`) |
| Historical database | `asset_record` history + `scan_run` |
| Deduplication | record uniqueness key |
| Confidence engine | `confidence` field + source-reliability table |
| Risk engine | `finding.severity` + existing CVSS/EPSS/KEV prioritisation |
| Source attribution | `source` on every record |
| Coverage engine | Data Quality report (R16) |
| **Alert engine** | reuse **incidents + notifications** (Phase 3/4) |
| API integration | pluggable source adapters |
| Export engine | reporting (section 10) |

## 12. Data sources ($0)

Default **free / no-key** sources only:
- **Certificates / subdomains:** crt.sh (CT logs).
- **Registration:** RDAP (bootstrap registries) + WHOIS fallback.
- **DNS:** public resolvers + free passive-DNS datasets.
- **Web archive:** Wayback Machine, Common Crawl index.
- **Threat intel:** URLhaus, AlienVault OTX (free), AbuseIPDB free tier, URLScan
  public results — several already ingested by the intel/news services.
- **Repos:** GitHub/GitLab public search (metadata only).
- **ASN/IP:** RIR RDAP + free BGP/ASN datasets.

**Pluggable (deferred, operator-supplied key):** VirusTotal, Shodan/Censys,
BuiltWith, reverse-WHOIS providers. These are adapter slots behind a common
interface; no paid service is required or pitched.

## 13. Migration from the current scanner

1. Keep the current passive recon + Nuclei working while the record store is
   introduced (no big-bang rewrite).
2. Introduce `scan_run` + `asset_record` + `finding` tables; write existing scan
   output into records.
3. Reframe handlers around the three engines; the current `/api/v1/scan` passive
   path becomes the Domain Intelligence + light Active Recon profile.
4. Move Nuclei under Active Recon A18; move tech/CVE matching under Security
   Assessment.
5. Retire ad-hoc fields once reports read from records.

(The request-tool has already been removed on `main`, clearing the way.)

## 14. Phased milestones

Mirrors the spec's phases, mapped to Pahredar.

- **S1 — Domain Intelligence (passive).** Record store + `scan_run`; collectors
  for P01 (RDAP/WHOIS), P03 (DNS), P04/P06 (crt.sh subdomains + certs), P05
  (IP/ASN), P09 (email auth), P14 (historical first/last-seen); reports R02–R06,
  R08.
  - **M1 (done):** `scan_run` + `asset_record` store (migration 00034),
    `internal/easm` module with a collector registry, the **crt.sh** (P04/P06)
    and **RDAP** (P01) passive collectors, a queued passive-scan job, and
    `POST /easm/scan` + `GET /easm/assets/{id}/records|runs` (operator triggers,
    viewer reads, client-scoped). Collectors live-verified (crt.sh 55 recs,
    RDAP 3 recs for example.com).
  - **M2 (done):** a light-active collector set (tagged `method: active`, kept
    separate from passive): **DNS** (A/AAAA/NS/MX/TXT/CNAME + `ip` records, P03),
    **email-auth** (SPF + DMARC via TXT, P09), and **IP/ASN enrichment** (RDAP
    IP → network/org/country, P05). The scan now runs passive + light-active and
    enriches discovered IPs. Collectors live-verified (example.com: 77 records
    across cert/subdomain/dns/ip/email/whois/nameserver; SPF + Cloudflare IP org
    resolved).
  - **M3 (done, backend):** a derived **summary report** (R02–R08 condensed:
    registration, counts, subdomains, IP owners, cert count + soonest expiry,
    SPF/DMARC) at `GET /easm/assets/{id}/summary`; a **promote** action
    (`POST /easm/promote`, operator) that turns a discovered hostname into a
    tracked asset under the parent's client (explicit, not auto-created, honoring
    scope enforcement). `buildSummary` unit-tested. *Frontend surface (asset
    detail EASM tab) is a coordinated follow-up with the scanner chat's UI.*
- **S2 — Active Recon.** A01 DNS, A02 subdomain resolution, A06/A07 HTTP+TLS,
  A04/A05 ports+services (budgeted), A13 security headers, A08/A09 web+endpoint
  discovery; scope enforcement + budget; Nuclei folded in (A18, safe).
  - **M1 (done):** an `http_probe` active collector — TLS handshake (A07: cert,
    protocol, cipher), HTTPS request (A06: status/server/title/redirects), and
    security-header read (A13). Scan profiles added (`passive` / `standard` /
    `active`); the `active` profile runs the probe and requires an authorisation
    confirmation (operator + `authorized: true`). Live-verified (example.com:
    TLS 1.3, live cert, HTTP 200, 8 security headers assessed).
  - **M2 (done):** a `port_scan` active collector (A04/A05) — a budgeted
    TCP-connect scan of the domain's resolved IPs (≤4 IPs) on ~25 curated common
    ports, 20-way concurrent with a 2s dial timeout, recording open ports with
    their service name. Part of the `active` profile. Live-verified (example.com:
    80/443/8080/8443 open on the Cloudflare edges). **Nuclei (A18) deferred** to
    the scanner-consolidation step (it lives in `internal/scan`, the scanner
    chat's active area — folding it in now would couple to their work). CDN-vs-
    origin scope refinement (don't treat a CDN edge as the origin) is a later
    enhancement; records carry a `scope` field for it.
- **S3 — Security Assessment.** `finding` engine over records → incidents:
  cert/TLS, email, headers, exposed services, dangling DNS, version→CVE; false-
  positive handling.
  - **M1 (done):** an assessment engine (`buildFindings`) runs after every scan
    — expired / expiring / self-signed cert, deprecated TLS (1.0/1.1), missing
    HSTS/CSP, exposed sensitive ports (MySQL/Postgres/Redis/RDP/Mongo/… — a
    high), and SPF/DMARC gaps. Each finding is written as an **alert row**
    (`type: easm`, deduped per asset+key), so the existing Phase 4 incident loop
    rolls them into the asset's incident and the notification/escalation layer
    delivers them — **no new incident plumbing**. Checks unit-tested. *Later:
    dangling-DNS and version→CVE checks; a `finding` table for false-positive
    status + richer reporting.*
- **S4 — Platform.** Asset relationship graph, change-detection → incidents,
  scheduled EASM scans, scan-comparison + data-quality reports, multi-domain per
  client, HTML/PDF reporting, pluggable paid adapters.
  - **M1 (done):** **scheduled EASM scans** — an `easmScanLoop` enqueues a
    standard scan for every domain/URL asset not scanned within
    `EASM_SCAN_INTERVAL` (opt-in; unset disables it, since it makes external
    lookups). `AssetsDueForEASM` finds them by their latest `scan_run`.
    Change-detection is already emergent: a re-scan re-observes records
    (last_seen) and the assessment's finding dedup means a *new* exposure
    (new open port, newly-missing header) produces a new finding → the asset's
    incident re-surfaces. *Later: explicit change records + scan-comparison
    report.*
  - **Frontend (done):** an `AttackSurface` card on the asset-detail page
    (domain/URL assets) — category counts, registration, email posture
    (SPF/DMARC), certs, IP owners, and subdomains (each promotable to a tracked
    asset); operators trigger a passive (`standard`) or `active` scan (the
    latter behind an authorisation confirm), with live status while it runs.

Each milestone builds + is verified before the next; records and reports are the
stable contract between engines.

### S5 — Software inventory + dependency analysis

Beyond infrastructure recon: an asset (a project) carries a **dependency
inventory** (its manifests' packages + versions), stored as `dependency`
evidence records, and **OSV** (api.osv.dev — free, no key) turns vulnerable
versions into findings → the asset's incident. This covers the app-dependency
side that CPE/CVE matching misses (spec P08/P10, the roadmap's stack matching).

- **M1 (done):** `POST /easm/assets/{id}/dependencies` ingests a component list
  (`{ecosystem, name, version}` — OSV ecosystems Go/npm/PyPI/…) as records;
  `POST /easm/assets/{id}/analyze-deps` queries OSV for each (bounded
  concurrency), writes vulnerable ones as findings (`type: dependency`, deduped
  per `(asset, dep:name:vulnID)`, severity from the advisory) → the asset's
  incident. OSV live-verified (nodemailer@6.6.0 → 23 vulns, x/crypto old → 39
  incl. critical; react@19 clean).
- **Frontend (done):** a `Dependencies` card on the asset-detail page shows the
  inventory grouped by ecosystem (count per ecosystem, name@version), with an
  **Analyze (OSV)** button (operator) that runs the analysis and reports how many
  are vulnerable (findings land on the asset's incident).
- **M2 (done):** analysis handles a **full SBOM** (transitive deps). OSV queries
  use the **batch** endpoint (`/v1/querybatch`, chunked) and fetch each distinct
  vuln's details once, so hundreds of packages are feasible. The analysis is now
  **queued** (`easm.analyze` job) rather than inline, so a large SBOM never hits
  the request timeout. The loader reads `package-lock.json` (`packages` tree) for
  the resolved npm graph and `go.mod` (direct + indirect) for Go.
- Re-analysis is idempotent: an asset's prior dependency findings are cleared first, so a fixed vuln disappears. *Later:* a manifest-upload endpoint (UI-driven ingest).

## 15. Guardrails (finalise before building)

1. Passive vs active results + timestamps stored separately. ✅ (method field)
2. Raw evidence preserved, not just parsed output. ✅ (`evidence`)
3. Source attribution on every finding. ✅ (`source`)
4. Historical tracking; no overwrite. ✅ (first/last-seen + history)
5. False-positive management; nothing auto-confirmed. ✅ (`verification`/`status`)
6. Rate limiting on active requests. ✅ (per-scan budget + worker pool)
7. Scope enforcement; third-party/CDN/shared not auto-scanned. ✅ (`scope`)
8. Data minimisation; no credentials/PII/sensitive content retained. ✅
