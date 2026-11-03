# Pahredar — Architecture

> Status: **v1 complete** (2026-10-28): all seven sources sync, the API serves search, enriched detail, vendor/product stats, and dashboard aggregates, and the web UI (dashboard, CVEs, vendors, sync) runs at `127.0.0.1:3001`. Next are the future phases in §11. See §13. This document is the source of truth for the design and is updated in the same change as any code, schema, or decision it describes.

## 1. Purpose

Pahredar is a personal, self-hosted CVE intelligence application. It keeps a local copy of **every published CVE**, enriches each one with severity, exploitation, and exploit-availability signals from free public sources, keeps that data in sync on a schedule, and presents it through a web UI (dashboard, search, CVE detail, vendor pages).

It is modelled loosely on SOCRadar CVE Radar (https://cve.socradar.io/), but built for a single user, running locally at zero cost.

### Goals (v1)

- Store the full CVE corpus (~300k+ records), including rejected IDs.
- Keep it current automatically: new CVEs within ~1 hour, enrichment within ~1 day.
- Fast search and filtering across the full corpus.
- A detail page that answers "how bad is this, is it being exploited, is there a public exploit, what does it affect".
- Observable sync: every run is logged with counts and errors.

### Non-goals (v1)

- **Tech-stack / watchlist matching** against the user's applications. Planned for a later phase; the schema keeps normalized affected-product data so it can be added without migration pain.
- Alerts / notifications (Telegram, ntfy, email) — later phase.
- Multi-user support and authentication — the app binds to localhost only.
- Cloud deployment — local Docker Compose only for now; OCI VM later.
- A dedicated search engine (Elasticsearch / OpenSearch / Meilisearch). Postgres full-text search is expected to be sufficient; revisit only if it measurably falls short.

## 2. System overview

```
                ┌───────────────────────── external sources ─────────────────────────┐
                │ cvelistV5 (GitHub)  NVD API 2.0  CISA KEV  EPSS  Exploit-DB  MSF  Nuclei │
                └──────────────┬──────────────────────────────────────────────────────┘
                               │ HTTPS pulls (scheduled)
┌──────────────────────────────▼───────────────────────────────┐
│ backend (Go, single binary)                                   │
│                                                               │
│  scheduler ──► sync jobs (one per source) ──► upsert          │
│                                                  │            │
│  HTTP API  (/api/v1/...) ◄──── read queries ─────┤            │
└───────────────▲──────────────────────────────────┼────────────┘
                │ JSON                             │ SQL (pgx)
┌───────────────┴──────────┐            ┌──────────▼───────────┐
│ frontend (React + Vite)  │            │ Postgres             │
│ served by nginx,         │            │ source of truth      │
│ proxies /api → backend   │            │ + full-text search   │
└──────────────────────────┘            └──────────────────────┘
```

One Go binary runs both the scheduler and the HTTP API. Postgres is the only stateful component. The frontend is a static build.

## 3. Repository layout

```
pahredar/
├── README.md               user-facing: what it is, how to run it
├── ARCHITECTURE.md         this file
├── docker-compose.yml      postgres + backend + frontend
├── .env.example            every config variable, documented
├── backend/                Go module (see backend/README.md)
│   ├── cmd/pahredar/       main; subcommands: serve, migrate, sync <source>, healthcheck
│   ├── internal/config/    env parsing and validation
│   ├── internal/cverecord/ parse CVE JSON 5 and NVD records; derive scores, severity, CWEs, refs, affected
│   ├── internal/db/        migrations (embedded SQL) and all queries
│   ├── internal/sources/   one package per upstream feed (fetch + unpack only): cvelist, nvd, kev, epss, exploits; fetch = shared HTTP
│   ├── internal/syncer/    job runner, scheduler, per-source jobs (named syncer to avoid shadowing stdlib sync)
│   └── internal/api/       HTTP handlers, request validation, JSON shapes
└── frontend/               React + Vite + TypeScript SPA (see frontend/README.md)
```

Each important directory gets its own `README.md` once it contains code.

## 4. Technology choices

| Concern | Choice | Reason |
|---|---|---|
| Backend language | Go | Single static binary for API and worker; already in use in the user's other projects. |
| HTTP routing | Go stdlib `net/http` (method + path patterns) | Enough for a small REST API; no framework dependency. |
| DB driver | `pgx/v5` | Native Postgres driver with `COPY` support for bulk loads. |
| Migrations | `goose`, SQL files embedded in the binary | Plain SQL, versioned, runs on startup. |
| Database | Postgres 17 | Transactions, JSONB, `tsvector` full-text search, `pg_trgm` fuzzy matching. |
| Frontend | React + Vite + TypeScript | Rich interactive UI (charts, filters). |
| Frontend data | TanStack Query | Caching, pagination, loading/error states. |
| Routing (UI) | React Router 7 | Standard. Version 8 needs Node ≥ 22.22; the dev machine has Node 20. |
| Styling | Tailwind CSS | Fast iteration, no component-library lock-in. |
| Charts | Recharts | Sufficient for dashboard trends and distributions. |
| Runtime | Docker Compose | One command to run locally; same images move to a VM later. |

## 5. Data sources

All sources are free. Only NVD needs an API key (free, raises rate limit).

| Source | Provides | Format / access | Cadence |
|---|---|---|---|
| **CVEProject/cvelistV5** | Canonical CVE records (CNA data): description, affected products/versions, references, CWE, CNA CVSS, and CISA ADP "Vulnrichment" (CVSS, CWE, affected CPEs, SSVC) | GitHub releases (see §7 for the exact release layout) | Hourly |
| **NVD API 2.0** | NVD analysis: CVSS v2/v3.x/v4 scores, CPE match configurations, CWE, `vulnStatus` | REST, `resultsPerPage` ≤ 2000, `lastModStartDate`/`lastModEndDate` window ≤ 120 days, rate limit 50 req / 30 s with key | Every 2 hours |
| **CISA KEV** | Known-exploited vulnerabilities: date added, due date, required action, ransomware use, forensic triage | `known_exploited_vulnerabilities.json` (~1.8k entries, 1.8 MB) | Every 6 h |
| **EPSS (FIRST / Empirical Security)** | Exploit-prediction score and percentile per CVE | `epss.empiricalsecurity.com/epss_scores-current.csv.gz` (~400k rows, 2.7 MB); first line is `#model_version:…,score_date:<RFC3339>` | Every 6 h (no-op unless the score date changed) |
| **Exploit-DB** | Public exploits mapped to CVE IDs | `files_exploits.csv` on GitLab; CVEs in the `;`-separated `codes` column (~27k of ~47k exploits) | Daily |
| **Metasploit** | Modules referencing CVEs | `db/modules_metadata_base.json` (~7k modules, ~3k with CVEs) | Daily |
| **Nuclei templates** | Detection templates per CVE | `cves.json`, one JSON object per line (~4.5k) | Daily |
| **PoC-in-GitHub** (nomi-sec, CC0) | GitHub proof-of-concept repositories per CVE | The repo's `README.md` (~7 MB): `### CVE-…` headings followed by `- [owner/repo](url)` lines (~27.5k repos for ~11.5k CVEs). Used instead of the ~1 GB repository | Daily |
| **trickest/cve** | Exploit write-ups and PoC links per CVE (Packet Storm, Full Disclosure, blogs) | `references.txt` (~13 MB, `CVE-… - URL` lines); Exploit-DB and GitHub links are skipped as the sources above cover them; ~116k links. Stored as `exploit` rows with source `trickest` | Daily (`EXPLOITS_SYNC_INTERVAL`) |
| **ENISA EUVD** | Actively exploited vulnerabilities per the EU Vulnerability Database, with the date exploitation was seen | `euvdservices.enisa.europa.eu/api/search?exploited=true`, paged 100 at a time (~1,800 entries) | Daily (`CONTEXT_SYNC_INTERVAL`) |
| **VulnCheck KEV** (free Community token, `VULNCHECK_API_TOKEN`) | Known exploited vulnerabilities from VulnCheck's research, a superset of CISA KEV: date added, ransomware use, whether VulnCheck's canaries saw exploitation, the public reports of exploitation, and XDB exploit repositories | `api.vulncheck.com/v3/index/vulncheck-kev`, 2,000 per page with a cursor (~5,750 entries, ~4,000 of them in neither CISA KEV nor EUVD). Skipped when the token is unset | Daily (`CONTEXT_SYNC_INTERVAL`) |
| **CTID KEV → ATT&CK mappings** | For KEV CVEs: the ATT&CK techniques used to exploit them and their primary / secondary impact, with the capability group and an analyst comment | `mappings-explorer` JSON files (Feb 2025 and Jul 2025 KEV snapshots; the newer wins per CVE); ~420 CVEs | Weekly (7 × `CONTEXT_SYNC_INTERVAL`) |
| **MITRE CAPEC** | Attack patterns: description, likelihood, severity, prerequisites, execution flow, indicators, mitigations, related CWEs, ATT&CK techniques | `capec.mitre.org/data/csv/1000.csv.zip` (~560 patterns); a CVE reaches patterns through its CWEs | Weekly |
| **Debian Security Tracker** | Per CVE, source package, and release (bookworm, trixie, forky, sid): status, fixed version, urgency | `security-tracker.debian.org/tracker/data/json` (~90 MB), decoded one package at a time; ~275k rows for ~66k CVEs | Daily (`CONTEXT_SYNC_INTERVAL`) |
| **NVD CVE History API, GitHub commits API** | Per-CVE change log (analysis, score, CPE, reference changes) and the referenced GitHub fix commits (message, author, per-file diff, ≤ 5 commits, ≤ 40 files, ≤ 12 KB diff per file) | Fetched on demand as report sources `history` (cached 1 day) and `commits` (7 days). `NVD_API_KEY` and `GITHUB_TOKEN` are sent when set; GitHub allows 60 requests an hour without one | On demand |
| **OSV.dev, Red Hat Security Data, Ubuntu CVE tracker** | In-depth per-CVE write-ups: OSV advisory records (GitHub Security Advisories, PyPA, Go, RustSec, …) with package-level fixed versions; Red Hat statement, mitigation, Bugzilla summary, and per-product fix status; Ubuntu priority, notes, and per-release package status | Per-CVE JSON APIs, fetched **on demand** when a detail page asks (`/cves/{id}/reports`), not synced. Coverage is strong for open-source and Linux software (e.g. Log4Shell: all three; Heartbleed: Red Hat and Ubuntu) and weak for closed-source products (EternalBlue: Ubuntu notes only) | Cached 7 days (not-found: 1 day) |
| **Microsoft MSRC** (Security Update Guide API) | For Microsoft CVEs: title, severity, impact, exploited / publicly disclosed flags, and per product the KB article, fixed build number, and download link | `api.msrc.microsoft.com/sug/v2.0/…?$filter=cveNumber eq '…'`, on demand; only queried when the assigner or an affected vendor is Microsoft | Cached 7 days |
| **Vendor advisory pages** | Title, summary, site, and date of each vendor-advisory / patch / mitigation / release-notes page the CVE references (up to 8) | On-demand fetch of those URLs, reading Open Graph and meta tags. The URLs come from CVE data, so the fetcher only connects to public unicast IPs (checked after DNS resolution, including redirects), follows ≤ 3 redirects, uses no proxy, reads ≤ 1 MB, and times out after 6 s | Cached 7 days |
| **AlienVault OTX** (`OTX_API_KEY`), **abuse.ch ThreatFox** (`ABUSECH_AUTH_KEY`), **Bluesky** (`BLUESKY_HANDLE` + app password) | OTX: pulses (community campaign reports) naming the CVE, with adversaries, malware, targeted industries and countries, and ATT&CK techniques. ThreatFox: IOCs (malware URLs, C2 servers, hashes) whose reporters tagged them with the CVE ID. Bluesky: posts mentioning the CVE ID | On demand as report sources `otx`, `threatfox`, `bluesky`; a source without its key reports `disabled` and is not cached. OTX returns only the 50 most recently updated pulses; pulses naming more than 10 CVEs (daily KEV digests, scanner feeds) are counted but not shown, and their actors are not attributed to the CVE; cloned pulses with the same name are collapsed. OTX's pulse search returns more pulses but without tags or malware and took ~14 s per 100, so it is not used. ThreatFox tags are free-form, so coverage is mostly recent, widely exploited CVEs. Bluesky search needs a logged-in session (the public AppView answers 403); the session token is reused for 90 minutes. Reddit was dropped: since November 2025 new API access needs Reddit's approval | Cached 1 day |
| **Google News** (RSS search) and **Hacker News** (Algolia search API) | News articles, vendor blogs, research write-ups, and discussions mentioning the exact CVE ID, including for old CVEs | On demand. Google News links redirect through Google to the publisher. Reddit was tried and blocks unauthenticated API use | Cached 1 day |
| **Security feeds** (67 sources, `internal/sources/feeds`) | Vendor advisories: PSIRTs (Cisco, Palo Alto, Fortinet, Ivanti, Juniper, SonicWall, Siemens, Oracle, NVIDIA, Synology, QNAP, ZDI), Linux distributions (Ubuntu USN, Debian DSA, Red Hat RHSA), cloud (AWS, Microsoft MSRC covering Windows / Azure / Office, Google Cloud, GKE), browsers (Chrome), projects (Next.js, React, PHP, Node.js, Ruby, Django, OpenSSL, Kubernetes, GitLab, Jenkins, Grafana, HashiCorp, Drupal core and modules, WordPress), and the whole GitHub Advisory Database (reviewed advisories for npm, PyPI, Maven, Go, Rust, Composer, NuGet, RubyGems, with the affected packages in the title); government advisories from national CERTs (CISA, CISA ICS, CERT/CC, CERT-In India, JVN Japan, Canada CCCS, CERT-EU, CERT-FR advisories and alerts, NCSC-NL, CERT Polska, HKCERT); research blogs (Talos, Unit 42, Tenable, Project Zero, watchTowr, Horizon3, Check Point, ZDI, Rapid7, Wordfence) and the oss-security and Full Disclosure mailing lists (seclists.org), and security news (The Hacker News, BleepingComputer, SecurityWeek, The Record, Help Net Security, Dark Reading, Krebs), with the CVE IDs each item names. News sites rarely put CVE IDs in feed text, so for feeds marked `FetchPage` each new article page is read once (public-IP-only client, ≤ 2 MB, ≤ 150 pages per run). Most sources are RSS / Atom / RDF; Next.js, React, PHP, and the global GitHub Advisory Database are read from the GitHub advisories API (`FormatGitHub`, unauthenticated, 4 requests an hour), NVIDIA from the yearly bulletin table in its PSIRT repository (`FormatNVIDIA`, via the GitHub contents API since NVIDIA publishes bulletins only there), and CERT-In, which has no feed, from its vulnerability note list page (`FormatCERTIn`; each note page holds the CVE IDs). `MaxItems` keeps only the newest items of long feeds (MSRC 300, Siemens 150, SonicWall and Synology 100, Red Hat 60). Not added: ACSC Australia (cyber.gov.au stalls non-browser clients), CERT-Bund Germany (its feed names no CVEs and its pages are a script app), UK NCSC (publishes reports and news, not vulnerability advisories), Apple, Mozilla, Android, Adobe, Intel, AMD, Atlassian, Zyxel, Citrix, and F5 (no official feed; third-party aggregator feeds were not used; their CVEs still arrive through the CVE List, and Canada CCCS republishes many of their bulletins). Only the article's own text counts (`ArticleText`): the largest `<article>` when it holds at least 40% of the page's text, else `<main>`, else `<body>`, minus scripts, `nav` / `aside` / `header` / `footer`, and elements whose class or id token names page furniture (sidebar, related, post-nav, dont-miss, main-secondary, …). Link targets count only when they point to another site (a vendor advisory, NVD); links to the same site are mostly other stories. Reading the whole page attributed sidebar stories' CVEs to every article on Help Net Security, Unit 42, and Rapid7 | Hourly (`FEEDS_SYNC_INTERVAL`) |
| **Detection rules** (`internal/sources/detection`) | Sigma rules from the SigmaHQ repository archive (CVEs from `cve.*` tags, title, and path; deprecated and unsupported rules skipped), Suricata rules from Proofpoint ET Open `emerging-all.rules` (CVEs from `reference:cve`; rules ET ships commented out are kept and marked disabled), and Nmap NSE scripts named after a CVE (from `scripts/script.db`) | Daily (`DETECTION_SYNC_INTERVAL`) |
| **MITRE CWE** | Weakness names | `cwe.mitre.org/data/csv/1000.csv.zip` (research view, ~940 entries) | Weekly |

Exact URLs live as constants in `backend/internal/sources/*` and are verified when each source is implemented (EPSS in particular has changed hosts before).

## 6. Data model

All CVE IDs are stored in canonical upper-case form (`CVE-2024-12345`) and are the join key across every table.

### `cve` — one row per CVE ID

| Column | Type | Notes |
|---|---|---|
| `id` | text PK | `CVE-YYYY-NNNN+` |
| `state` | text | `PUBLISHED` or `REJECTED` |
| `assigner` | text | CNA short name |
| `date_reserved`, `date_published`, `date_updated` | timestamptz | From cvelistV5 |
| `title` | text | CNA title, nullable |
| `description` | text | English description |
| `cwe_ids` | text[] | Union of CNA, CISA ADP, and NVD CWEs (`CWE-n` only; NVD placeholders like `NVD-CWE-noinfo` dropped) |
| `cvss_v4_score`, `cvss_v4_vector` | numeric, text | Effective (see precedence) |
| `cvss_v3_score`, `cvss_v3_vector` | numeric, text | Effective (v3.1 preferred over v3.0) |
| `cvss_v2_score`, `cvss_v2_vector` | numeric, text | Legacy, mostly NVD |
| `severity` | text | `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`NONE`/`UNKNOWN`, derived |
| `severity_source` | text | Which metric/provider `severity` came from |
| `nvd_status` | text | NVD `vulnStatus` (e.g. `Analyzed`, `Awaiting Analysis`) |
| `nvd_last_modified` | timestamptz | Drives incremental NVD sync |
| `refs` | jsonb | `[{url, name, tags[]}]`, merged and de-duplicated. Named `refs` because `references` is a reserved word in SQL |
| `exploit_ref` | boolean | Any reference tagged `exploit` (case-insensitive; CNA uses `exploit`, NVD `Exploit`). Added in migration 00004 |
| `raw_cvelist` | jsonb | Original cvelistV5 record |
| `raw_nvd` | jsonb | Original NVD record, nullable |
| `search` | tsvector | Weighted: id (`simple` config, A) + title (A) + description (B) + vendor/product names (C), `english` config. GIN index. Written by the upsert, not a generated column, because it draws on affected products |
| `created_at`, `updated_at` | timestamptz | Local bookkeeping |

Raw source JSON is kept so derived columns can be recomputed after a logic change without re-downloading (estimated a few GB in total).

**Severity precedence** (first available wins): CNA v4.0 → NVD v4.0 → CNA v3.1 → CNA v3.0 → NVD v3.1 → NVD v3.0 → ADP v4.0 → ADP v3.1 → ADP v3.0 → CNA v2.0 → NVD v2.0. Within NVD, `Primary` (NVD's own analysis) beats `Secondary`. The same order picks the effective `cvss_v4_*`, `cvss_v3_*`, and `cvss_v2_*` columns. A metric's severity is the provider's stated `baseSeverity`, else the standard score band for its version. `severity_source` records the winner as `<provider>:cvss<version>`, e.g. `cna:cvss4.0`. Rejected CVEs are always `UNKNOWN`. Implemented in `internal/cverecord/derive.go`.

**Computed at read time, not stored:** the full per-provider metric list and CISA SSVC decision points (`exploitation`, `automatable`, `technical_impact`) are parsed from the raw records by the detail endpoint, so they always reflect current logic.

### `cve_affected` — affected products (normalized)

| Column | Type | Notes |
|---|---|---|
| `id` | bigserial PK | |
| `cve_id` | text FK → `cve` | |
| `source` | text | `cna`, `adp` (CISA Vulnrichment), or `nvd` (vulnerable `cpeMatch` criteria from NVD configurations, grouped by CPE vendor/product) |
| `vendor`, `product` | text | **Canonical keys** (see below); indexed with `pg_trgm`. Placeholders (`n/a`, `unknown`, …) become `''`; entries with no product are dropped |
| `vendor_label`, `product_label` | text | The spelling as published (CPE underscores as spaces), for display. Added in migration 00007 |
| `cpes` | text[] | CPE 2.3 strings when the provider gives them (migration 00002 replaced the single `cpe` column) |
| `versions` | jsonb | Shape depends on `source`. `cna`/`adp`: CVE JSON 5 version entries (`version`, `lessThan`, `lessThanOrEqual`, `status`, …). `nvd`: NVD `cpeMatch` objects (`criteria`, `versionStartIncluding`, `versionEndExcluding`, …) |

All rows for a CVE are replaced together whenever that CVE is upserted. This table powers vendor/product pages now and stack matching later.

**Canonical names** (`cverecord.CanonicalVendor` / `CanonicalProduct`): lower-case, underscores to spaces, whitespace collapsed; for vendors, trailing legal-entity suffixes are stripped repeatedly (`inc`, `corp`, `corporation`, `co., ltd`, `llc`, `gmbh`, `plc`, …; deliberately not bare two-letter forms like `ag` or `sa`) and a short alias list maps known duplicates (`redhat` → `red hat`, `apache software foundation` → `apache`, `cisco systems` → `cisco`, …). So "Oracle Corporation" (CNA) and "oracle" (CPE) are one vendor, and "Windows Server 2016" and "windows_server_2016" one product. Products with genuinely different names ("Apache Log4j2" vs CPE "log4j") stay separate. The API canonicalises `vendor`/`product` parameters the same way. Display labels are the most common CNA/ADP spelling, else the CPE spelling title-cased when it has no capitals (`db.PrettyLabel`).

### `kev`

`cve_id` (PK), `vendor_project`, `product`, `vulnerability_name`, `short_description`, `required_action`, `date_added`, `due_date`, `known_ransomware_use`, `forensic_triage` (00004), `notes`. Mirrors the feed on each sync: new entries inserted, changed ones updated, removed ones deleted.

### `epss` and `epss_history`

- `epss`: `cve_id` PK, `score`, `percentile`, `score_date`, `score_7d_ago` (latest history score on or before `score_date − 7`, written at load), `delta_7d` (generated `score − score_7d_ago`, indexed). Replaced with `TRUNCATE` + `INSERT` in one transaction when a new score date appears. The 7-day columns (migration 00006) make the dashboard's EPSS movers an index lookup instead of a ~1.7 s lateral scan; they stay NULL until a week of history exists.
- `epss_history`: `(cve_id, score_date)` PK, `score`, `percentile`. A row is written only when a CVE's score changes by ≥ 0.01 from its last history row, keeping growth bounded (a full daily snapshot would be ~100M rows/year).

### `exploit`

`id` PK, `cve_id`, `source` (`exploitdb`/`metasploit`/`nuclei`/`github`), `source_ref`, `title`, `url`, `published_at` (none for `github`), `meta` (jsonb: Metasploit module `type`, `check`, `rport`, `targets`, `post_auth`, `rank`; Nuclei `severity` and `protocol`; null otherwise; migration 00011). Unique on `(source, source_ref, cve_id)` because one exploit or module can cover several CVEs; upserts use that key. `meta` is what the CVE page uses to build scan commands.

### `euvd_exploited`, `attack_mapping`, `capec`, `debian_status` (migration 00012)

- `euvd_exploited`: `cve_id` PK, `euvd_id`, `exploited_since`, `description`.
- `attack_mapping`: `(cve_id, technique_id, mapping_type)` PK, `technique_name`, `capability_group`, `comments`, `refs` text[]. `mapping_type` is `exploitation_technique`, `primary_impact`, `secondary_impact`, or `uncategorized`.
- `capec`: `id` PK (`CAPEC-586`), `name`, `abstraction`, `likelihood`, `severity`, `description`, `prerequisites` / `execution_flow` / `indicators` / `mitigations` (text[]), `cwes` (text[], GIN), `attack` (jsonb `[{id, name}]`). Patterns for a CVE are ranked by how specific the shared CWEs are (each shared CWE adds 1 / the number of patterns linked to it), and patterns reached only through a CWE linked to more than 40 patterns (e.g. CWE-20) are dropped unless nothing better exists.
- `debian_status`: `(cve_id, package, release)` PK, `status` (`resolved`/`open`/`undetermined`), `fixed_version` (`0` = never affected), `urgency`.

Migration 00012 also adds `trickest` to `exploit.source` and `history` / `commits` to `external_report.source`.

### `vulncheck_kev` (migration 00013)

`cve_id` PK, `name`, `vendor`, `product`, `date_added`, `ransomware`, `canary` (VulnCheck's sensors saw exploitation), `reported` (jsonb `[{url, date_added}]`), `xdb` (jsonb `[{id, url, type, repo, date_added}]`, one entry per repository). Snapshot. Migration 00013 also adds `otx`, `threatfox`, `bluesky` to `external_report.source`.

### `detection_rule`

`source` (`sigma`/`suricata`/`nmap`), `rule_id` (Sigma rule UUID, Suricata SID, NSE script name), `title`, `url`, `body` (Sigma YAML, the Suricata rule line, or the script file name), `meta` (jsonb: Sigma `level`, `status`, `logsource`, `attack` technique IDs; Suricata `enabled`, `classtype`, `signature_severity`, `confidence`, dates; Nmap `categories`), `cve_ids` (text[], GIN-indexed). PK `(source, rule_id)`. Snapshot per source. Added in migration 00011.

### `cwe`

`id` PK (`CWE-79`), `name`. Snapshot of MITRE's research view; the detail endpoint resolves a CVE's CWE IDs to names.

### `feed_article`

`id`, `feed` (key from `feeds.All`), `url` (unique), `title`, `summary`, `published_at`, `first_seen_at`, `cve_ids` (text[], GIN-indexed), `page_checked`. One row per feed item; re-reading a feed only adds CVE IDs. CVE IDs here need not exist in `cve`: vendor advisories often name a CVE before the CVE List publishes it, and the UI shows such IDs as "not in the CVE List yet". Articles naming more than 15 CVEs are treated as roundups and excluded from trending. Added in migration 00010.

### `external_report`

`(cve_id, source)` PK, `source` (`osv`/`redhat`/`ubuntu`/`msrc`/`advisories`/`news`/`discussions`, migration 00009; `history`/`commits`, migration 00012; `otx`/`threatfox`/`bluesky`, migration 00013), `status` (`ok`/`not_found`), `fetched_at`, `payload` (Pahredar's normalized JSON, not the raw response). The cache behind `/cves/{id}/reports`; fetch errors are not cached, so a failing source is retried on the next request. Added in migration 00008.

### Foreign keys

Only `cve_affected` references `cve` (with `ON DELETE CASCADE`). The enrichment tables (`kev`, `epss`, `epss_history`, `exploit`) deliberately have **no** foreign key: a source can mention a CVE before the cvelist sync has stored it, and bulk `COPY` loads must not fail on that. Joins to `cve` are plain `LEFT JOIN`s.

### `sync_state` and `sync_run`

- `sync_state`: `source` PK, `cursor` (text; meaning is source-specific, e.g. last delta timestamp or NVD `lastModified`), `last_success_at`.
- `sync_run`: `id`, `source`, `kind` (`bootstrap`/`incremental`), `started_at`, `finished_at`, `status` (`running`/`success`/`failed`), `inserted`, `updated`, `deleted`, `error`.

### Snapshot safety

KEV, EPSS, and each exploit source are full snapshots: a run makes the stored rows equal to the feed. Before replacing, the job refuses (fails the run, keeps the old data) if the feed has fewer than half as many rows as are stored, which catches truncated downloads and silent format changes.

### Vendor and product stats (materialized views, migration 00005)

| View | Key | Contents |
|---|---|---|
| `vendor_stats` | `vendor` | products, distinct CVEs, counts per severity, KEV count, latest publish date. Trigram index for search |
| `product_stats` | `(vendor, product)` | same counts per product |
| `vendor_year_stats` | `(vendor, year)` | distinct published CVEs per year |

Only published CVEs and non-empty vendors count. Vendor totals are distinct CVEs across products, not sums. Computing these live over `cve_affected` takes 0.4–3.4 s; the views make vendor pages ~2–30 ms. They are refreshed `CONCURRENTLY` (~15 s, readers unaffected) by the `stats` sync source, which runs at startup, every `STATS_REFRESH_INTERVAL` (6 h), and is triggered automatically after any cvelist, NVD, or KEV run that changed rows. A product page's per-year chart is computed live (single product, fast enough).

### Derived, not stored

- **Timeline** on the detail endpoint, oldest first: `reserved`, `published`, `kev_added`, `kev_due`, one `exploit_published` per dated exploit, `epss_spike` (score up ≥ 0.1 between consecutive history points), `updated`. Assembled per request in `internal/api/cves.go`.
- **Has public exploit** = `cve.exploit_ref` OR KEV-listed OR EUVD-exploited OR any `exploit` row, including trickest links (`hasExploitExpr` in `internal/db/cve_read.go`).

## 7. Sync design

### Principles

- **Idempotent:** every job is an upsert; re-running a job or replaying a window is safe.
- **Cursor-based:** incremental jobs read their cursor from `sync_state` and only advance it after a successful commit.
- **One job per source, never concurrent with itself:** a Postgres advisory lock keyed on the source name guards each run.
- **Failures are isolated:** a failing source does not block others; the error is recorded in `sync_run` and retried on the next tick with exponential backoff (capped).
- **Bulk loads use `COPY`** into a temp staging table, then a single `INSERT ... ON CONFLICT DO UPDATE`.
- **Serialized CVE writes:** each `cve` batch (1000 records) runs in one transaction that takes a transaction-scoped advisory lock (`pahredar:cve-write`) and `SELECT ... FOR UPDATE`s the existing rows. Every writer derives the full row from *both* raw records (the incoming one plus the stored other one), so the cvelist and NVD jobs can never overwrite each other's contribution with stale data.
- **Newer-only:** a cvelist record is skipped when its `dateUpdated` is not after the stored one. Re-applying a cumulative delta therefore costs a read, not a write. Consequence: after a change to derivation logic, stored rows only pick it up when their upstream record changes or on `pahredar sync cvelist --bootstrap`.
- **Stale runs:** after taking a source's lock, the runner marks any leftover `running` rows for that source as `failed` (the lock proves their process is gone).
- **Retries:** a failed run is retried after 5 min, doubling per consecutive failure, capped at the source's interval.

### Bootstrap (first run, empty DB)

1. **cvelistV5:** take the latest release's `YYYY-MM-DD_all_CVEs_at_midnight.zip.zip` (~615 MB; a zip whose single entry `cves.zip`, ~700 MB, holds one JSON file per CVE). The outer zip is inflated while streaming, so only `cves.zip` is written to `DATA_DIR`, and it is deleted afterwards. Records load in batches of 1000. The cursor is set to `<day> 0000Z`, then the incremental step runs immediately to apply that day's hourly delta.
2. **NVD:** full paginated pull (~160+ pages of 2000) respecting the rate limit; set cursor to the newest `lastModified` seen.
3. **KEV, EPSS, exploits:** normal full runs.
4. Recompute derived columns (`severity`, `search`).

Bootstrap is triggered automatically when `sync_state` has no row for a source, or manually via `pahredar sync <source> --bootstrap`.

### NVD

- **Bootstrap:** no date filter, all ~208 pages of 2000. NVD takes ~3–40 s per page, so 4 pages are fetched concurrently (well under the 50 requests / 30 s keyed limit; requests are also spaced ≥ 700 ms apart, ≥ 6.5 s without a key). Pages are written as they arrive, in any order.
- **Incremental:** `lastModStartDate = cursor − 5 min`, `lastModEndDate = run start`, one page at a time. If the cursor is older than the API's 120-day window, re-bootstrap.
- **Cursor:** the RFC 3339 time the run *started*, so anything modified during a long pull is read again next run.
- **Retries:** network errors, 403 (NVD's throttling response), 429, and 5xx are retried up to 6 times per page with backoff from 10 s, doubling.
- **Skip:** a record whose `lastModified` is not after the stored `nvd_last_modified` is not rewritten.

### Incremental

| Source | Schedule | Mechanism |
|---|---|---|
| cvelist | hourly | See "cvelist release layout" below. If the cursor is more than 14 days old, re-bootstrap instead. |
| nvd | every 2 h | See "NVD" above. |
| kev | every 6 h | Snapshot; cursor is the catalog version. |
| epss | every 6 h | Snapshot when the file's score date differs from the cursor; history rows appended first. `sync_run.updated` = current scores loaded, `inserted` = history rows added. |
| exploitdb / metasploit / nuclei / github | daily | Snapshot per source, keyed `(source, source_ref, cve_id)`; cursor is the run time. |
| cwe | weekly | Snapshot of the CWE name list. |
| euvd / debian | daily | Snapshots into `euvd_exploited` and `debian_status`. |
| vulncheck | daily | Snapshot into `vulncheck_kev`; only scheduled when `VULNCHECK_API_TOKEN` is set. |
| attack / capec | weekly | Snapshots into `attack_mapping` and `capec`. |
| sigma / suricata / nmap | daily | Snapshot per source into `detection_rule`. Sigma downloads the ~10 MB repository archive and reads only `rules*/` YAML files; Suricata streams the ~45 MB ET Open file and keeps lines with a CVE reference (about 7,400 rules covering about 3,000 CVEs). |
| feeds | hourly | Reads all 67 sources concurrently; a failing feed is logged and skipped, and the run fails only if more than half fail. New article pages are read for CVE IDs, at most 150 per run (the rest on later runs). |

Every source also runs once at startup (all concurrently; CVE writes serialize on the `cve-write` lock) and on demand via `POST /api/v1/sync/{source}`. Intervals: `CVELIST_SYNC_INTERVAL`, `NVD_SYNC_INTERVAL`, `KEV_SYNC_INTERVAL`, `EPSS_SYNC_INTERVAL`, `EXPLOITS_SYNC_INTERVAL`, `CWE_SYNC_INTERVAL`, `STATS_REFRESH_INTERVAL`.

### Rederive

Sync jobs only rewrite a CVE when its upstream record changes, so a change to derivation logic (canonical names, severity rules, …) does not reach stored rows by itself. `pahredar rederive` walks every CVE in ID order, rebuilds each row and its affected rows from the stored raw cvelist and NVD JSON (no downloads), then refreshes the stats views. It holds the cvelist and NVD locks while it runs and is logged as source `rederive`. Full corpus: ~10 min.

### Recheck articles

`UpsertArticles` only adds CVE IDs, so a change to page reading does not remove IDs already stored. `pahredar recheck-articles` re-reads every checked page of the `FetchPage` feeds and replaces each article's IDs with those in its title, summary, and article text; an unreadable page keeps its IDs. About 240 pages, under a minute.

### cvelist release layout and cursor

cvelistV5 publishes a release roughly every hour, tagged `cve_YYYY-MM-DD_HHMMZ`. Each carries the day's midnight baseline and `YYYY-MM-DD_delta_CVEs_at_HHMMZ.zip`, which contains **every record changed since 00:00 UTC that day** (cumulative, not just the last hour). Shortly after midnight a `cve_YYYY-MM-DD_at_end_of_day` release adds `..._delta_CVEs_at_end_of_day.zip` covering the whole previous day.

The cursor is `"<day> <hour>"`, for example `2026-10-28 0700Z`, or `2026-10-27 eod` once a day's end-of-day delta is applied. An incremental run:

1. For each day before today that is not yet `eod`: fetch that day's end-of-day release (by tag) and apply it. If it is not published yet, apply the day's newest hourly delta instead and stop; the next run finishes the day.
2. For today: apply the newest hourly delta if its hour is after the cursor's.
3. Advance and save the cursor after each applied archive.

Delta zips are a few MB and are read in memory. GitHub API usage is 1–3 unauthenticated calls per run, well inside the 60/hour anonymous limit.

## 8. HTTP API

JSON over REST under `/api/v1`. Read-only except sync triggers.

| Method & path | Purpose |
|---|---|
| `GET /healthz` | Liveness + DB connectivity |
| `GET /api/v1/cves` | Search/list. Params: `q`, `severity` (comma list), `state`, `vendor` / `product` (comma lists, any of), `cwe`, `published_from`, `published_to` (inclusive, `YYYY-MM-DD`), `kev` / `exploit` / `ransomware` (`true`/`false`; ransomware = KEV known ransomware use), `epss_min` / `epss_max` (0–1), `cvss_min` / `cvss_max` (0–10, best effective score), `sort` (`relevance`, `published`, `updated`, `cvss`, `epss`, `kev_added`), `order` (`asc`/`desc`, default `desc`), `page`, `page_size` (1–250, default 25). Items carry `kev`, `kev_date_added`, `ransomware`, `epss_score`, `epss_percentile`, `has_exploit`, `vendor` (display name: the CNA's first affected vendor as written, else the first normalized vendor), `ssvc_exploitation` (CISA SSVC `none`/`poc`/`active`) |
| `GET /api/v1/cves/{id}` | Detail: core fields, effective CVSS per version, all per-provider metrics, SSVC, `kev` (or null), `epss` with `history`, `exploits` (including GitHub PoCs), `has_exploit`, `assessment` (see below), `advisory` (the CNA's solutions, workarounds, exploit statements, required configurations, credits, CAPEC attack patterns, and CNA timeline), `cwes` (ID + MITRE name), `timeline`, affected products with labels, references |
| `GET /api/v1/cves/{id}/reports` | Third-party material. `sources` (comma list, default all) picks from `osv`, `redhat`, `ubuntu`, `msrc`, `advisories`, `news`, `discussions`, `history` (NVD change log, newest first), `commits` (referenced GitHub commits with diffs), `otx`, `threatfox`, `bluesky`, so the UI loads groups in parallel. Returns `{sources: [{source, status: ok/not_found/error/disabled, fetched_at}], reports: {source: payload}}`. Fresh cache entries are served directly; stale or missing sources are fetched concurrently (10 s timeout each) and cached. A failing source is reported per source, never fails the request |
| `GET /api/v1/cves/{id}/related` | `{groups}` of related CVEs: one group per vendor-advisory/patch URL this CVE cites (up to 6), listing other CVEs citing the same URL (usually fixed in the same release), and one group for the same product published within ±30 days. Each group has `total` and up to 8 items (most severe first), never repeating a CVE across groups. Uses the `refs` GIN index (migration 00009) |
| `GET /api/v1/cves/{id}/attack` | `mappings` (CTID ATT&CK techniques, exploitation first) and `capec` (up to 8 attack patterns for the CVE's CWEs, most relevant first) |
| `GET /api/v1/cves/{id}/detection` | Sigma, Suricata, and Nmap rules naming the CVE (`rules`: source, rule ID, title, URL, body, meta). Nmap first, then Sigma, then Suricata with enabled rules before disabled ones; at most 200 |
| `GET /api/v1/cves/{id}/articles` | Feed articles mentioning the CVE, newest first, with feed name and kind. Works for IDs not yet in the CVE List |
| `GET /api/v1/stats/trending` | CVEs mentioned by the most distinct feeds in the last `days` (default 7), excluding roundups, with the newest headline and the CVE summary (or `cve: null` if not published yet) |
| `GET /api/v1/feeds` | Every configured feed with article counts and its latest item |
| `GET /api/v1/news` | Feed articles for the news page. `kind` (vendor, government, research, news) or `feed` (one key), `q` (substring of title or summary), `days` (default 7; 0 = all time), `cves=1` (only articles naming a CVE), `sort` (`top` or `newest`), `page`, `limit` (≤ 100). Returns `{items, total, cves}`: each item carries `score`, and `cves` maps every CVE the page names to `{severity, score, kev, exploited}`. Top score per article: the best of its CVEs, where exploited (CISA KEV, EUVD, VulnCheck KEV) is 3, critical 2, high 1, plus 1 for each other feed covering that CVE in the window (at most 4); roundups naming more than 15 CVEs score 0. Ties fall back to newest first |
| `GET /api/v1/feeds/advisories` | Newest vendor PSIRT and government items that name CVEs |
| `GET /api/v1/stats/series` | Daily series for the dashboard chart. `metric` = `published` (by severity), `kev_added` (known ransomware use vs other), or `exploits` (Exploit-DB vs Metasploit, by publish date); `from`/`to` (`YYYY-MM-DD`, inclusive, default the last 90 days, at most ~3 years). Returns `{metric, label, keys: [{key, label}], points: [{date, values}]}` with every day present. Bucketing into weeks/months happens in the browser |
| `GET /api/v1/stats/dashboard` | Published counts (today, 7 d, 30 d, total; UTC days), critical in 7 d, KEV total and added in 30 d, severity mix of the last 30 d, `daily` (90 days, every day present, severity mix per day), `epss_movers` (top 10 `delta_7d`). ~240 ms. The dashboard's CVE lists come from `/cves` |
| `GET /api/v1/vendors` | `{items}` of vendor summaries by CVE count. `q` = case-insensitive substring (exact match first), `page_size` 1–100 (default 25) |
| `GET /api/v1/products` | `{items}` of product summaries across all vendors by CVE count. `q` = case-insensitive product substring, `page_size` 1–100 |
| `GET /api/v1/vendors/{vendor}` | Vendor summary, `years` (CVEs per year), `top_products` (top 200 by CVE count). 404 if unknown |
| `GET /api/v1/vendors/{vendor}/products/{product}` | Product summary and `years`. The CVE list itself is `/cves?vendor=&product=`. Names are lower-case and URL-encoded |
| `GET /api/v1/sync/status` | Per-source state and the 20 most recent runs (implemented) |
| `POST /api/v1/sync/{source}` | Queue an immediate run: 202 `{status: queued}`, 404 unknown source, 409 if `SYNC_ENABLED=false`. Repeated triggers while one is pending collapse |

**Assessment.** The detail endpoint adds Pahredar's own triage summary (`assess()` in `internal/api/cves.go`), with the reasons it fired:

| Exploitation | When |
|---|---|
| `active` | in CISA KEV, CISA SSVC exploitation is `active`, listed in ENISA EUVD as exploited, or listed in VulnCheck KEV |
| `poc` | any exploit row (Exploit-DB, Metasploit, Nuclei, GitHub PoC, trickest link), an exploit-tagged reference, or SSVC `poc` |
| `none` | otherwise |

| Priority | When |
|---|---|
| P1 Patch now | exploitation `active` |
| P2 Patch soon | EPSS ≥ 10 %, or exploitation `poc` and best CVSS ≥ 7 |
| P3 Plan to patch | best CVSS ≥ 7, or exploitation `poc` |
| P4 Monitor | otherwise (rejected CVEs get no priority) |

It is a rule of thumb over public signals, not a vendor score; the UI says so.

Search behaviour: if `q` matches a CVE ID pattern (case-insensitive), it becomes an exact ID filter; otherwise it is `websearch_to_tsquery('english', q)` against `search`, and the default sort becomes `relevance` (`ts_rank`, then recency). Without `q`, the default sort is `published`.

Errors are `{"error": "<message>"}` with 400 for invalid parameters, 404 for an unknown CVE, 500 (details only in the server log) otherwise. List responses are `{items, total, page, page_size}`; list items carry a description truncated to 300 characters.

The list query runs in two steps: an inner `SELECT cve.id … ORDER BY … LIMIT` that touches only sort and filter columns, then a fetch of display columns (truncated description, KEV/EPSS, has-exploit) for just that page's IDs via `unnest(ARRAY(…)) WITH ORDINALITY`. Doing both at once made Postgres read every candidate's TOASTed description before the top-N sort. For the selective filters `kev=true`, `ransomware=true`, and `epss_min`, the matching IDs are built first in a `MATERIALIZED` CTE, because the planner otherwise walks the date index hoping to fill a page and scans most of the table (matching CVEs are old).

Measured on the full corpus (415,607 IDs, local, warm cache): default list, `sort=cvss`, `kev=true`, `epss_min=0.9` ~15–40 ms; `sort=epss`, `exploit=true`, full-text with ~20k matches, `vendor=microsoft` ~170–290 ms; `epss_min` with a very low threshold (fence over ~390k rows) ~600 ms; `GET /cves/{id}` ~5 ms. `order=asc` is not index-backed and sorts in memory.

Pagination is offset-based, capped at offset 10,000 (single user; narrow the filters instead of paging deep). Revisit keyset pagination if needed.

## 9. Frontend

Implemented in `frontend/` (details, routes, and conventions in `frontend/README.md`). The shell is a SOCRadar-style collapsible left sidebar: brand, CVE search, sections *Overview* (Dashboard), *Vulnerability intelligence* (CVE explorer, Vendors & products) and *System* (Data sync), and a sync-health card. The theme is dark only: graphite neutrals, a cyan accent, and low-saturation tinted badges.

**Query language.** The CVE explorer is driven by one Kibana-style search bar (`frontend/src/lib/query.ts`): free text plus `field:value` terms such as `is:kev`, `-is:kev`, `has:exploit`, `has:ransomware`, `severity:critical,high`, `epss:>10`, `cvss:>=9`, `vendor:cisco,citrix`, `product:log4j`, `cwe:79`, `age:<30`, `published:>=2024-01-01`, `is:rejected`. The parser runs in the browser and translates the query into `/api/v1/cves` parameters; unknown fields or bad values are reported under the bar and ignored. The URL carries `query` (plus `sort`, `order`, `page`, `page_size`), so saved views are just links with a query. The explorer shows them as tabs above the query bar: *All CVEs*, *Known exploited* (`is:kev`, by KEV date), *Likely exploited* (`epss:>10 -is:kev`, by EPSS), *Ransomware* (`is:kev has:ransomware`), and *Critical · 7 days* (`severity:critical age:<7`); any other query shows as *Custom search*.

| Page | Route | Content |
|---|---|---|
| Dashboard | `/` | Tile strip: hero (critical CVEs in 7 days) plus today, 7 d, 30 d, and KEV added in 30 d, each with the change against the previous period (computed in the browser from the 90-day series) and linking to the matching explorer query; a CloudWatch-style metric widget (`MetricWidget.tsx`): metric picker (published by severity, KEV additions, public exploits), time range 1w/2w/1m/3m/6m/1y/2y or custom dates, period auto/day/week/month (monthly buckets start on the 1st; the current period is labelled "to date"), graph type line/stacked area/stacked bar, crosshair tooltip with totals, drag-to-zoom into a custom range, a legend that toggles series and shows each sum, refresh, and a table view, all kept in the URL (`metric`, `range`, `from`, `to`, `period`, `chart`); 30-day severity mix as a segmented bar plus counts; EPSS movers, or until a week of EPSS history exists, the highest-EPSS CVEs published this week; trending CVEs in security news (7 days, by distinct sources); latest vendor and government advisories; lists of newest critical, recently added to KEV, and highest-EPSS CVEs from the last 90 days not in KEV. Refreshes every 5 min |
| CVE explorer | `/cves` | Query bar with example chips and a syntax panel; compact one-line table (CVE, title, vendor, CISA SSVC, KEV listed, published, EPSS, CVSS, signals) with sortable headers (KEV listed, published, EPSS, CVSS), rows per page (50/100/250) above the table, numbered pagination below it |
| CVE detail | `/cves/:id` | Badges; assessment banner (priority, exploitation, reasons); key-facts strip (CVSS, EPSS, KEV, exploit modules, GitHub PoCs, affected count); then sticky tabs kept in the URL (`?tab=`), each loading its data only when opened. **Overview** (default): nicknames ("Also known as", from Metasploit notes) under the ID, an EUVD-exploited badge when KEV has not listed it (a VulnCheck KEV badge when neither has), a ransomware badge from KEV or VulnCheck, description, **at a glance** (what, affected, exploitation, ATT&CK, detection coverage, fix, news coverage, each opening its tab), timeline, CWE, KEV, ENISA EUVD, VulnCheck KEV (ransomware, canaries, XDB count, the reports of exploitation), EPSS, SSVC, record. **Detection**: the detection card (Debian packages feed its version checks). **ATT&CK**: CTID technique mappings (or techniques via CAPEC) and CAPEC patterns with how it works, prerequisites, indicators, mitigations. **Remediation**: fixes, Debian per-release status, fix-commit diffs, vendor advisories. **History**: NVD change log, consecutive same-day bulk edits folded. **Exploits**. **Reports & news**: threat intelligence (actors, malware, industries, countries, and ATT&CK techniques across OTX pulses and ThreatFox; focused OTX pulses; ThreatFox IOC table with copy-all), reports, news (with a Bluesky tab), related CVEs. **CVSS & affected**: CVSS, affected products, CNA advisory details. **References**. In detail: **detection** with a target box and five tabs: *Am I affected?* (installed-version commands per package ecosystem from OSV / Ubuntu / Red Hat, direct CVE lookups with `pro fix`, `dnf updateinfo`, OSV-Scanner, Trivy, Grype, `Get-HotFix` per MSRC KB, and `nmap -sV --script vulners` for network-exploitable CVEs), *Active scan* (Nuclei templates, Nmap NSE scripts, Metasploit modules with a `check` method or auxiliary scanners), *Network IDS* (ET Open Suricata rules, deploy / enable / hunt-in-eve.json commands), *Logs / SIEM* (Sigma rules with log source, ATT&CK techniques, YAML, download and sigma-cli convert commands), *What to look for* (hunting hints per CWE, CISA forensic triage, CNA exploitation statements); commands are built in the browser (`lib/detection.ts`); remediation with **fixed versions per product** (the `lessThan` bound / `unaffected` versions from the CVE record, `versionEndExcluding` from NVD); vendor advisories (MSRC table of KB, fixed build, and download for Microsoft CVEs; preview cards for every referenced vendor advisory or patch page); in-depth reports with a tab per available source (OSV, Red Hat, Ubuntu); related vulnerabilities (same advisory, same product ±30 days); news & research (articles from Pahredar's own feeds tagged vendor / government / research / news, Google News, Hacker News); a CVE ID not yet in the CVE List shows the feed articles that already mention it instead of a 404; each of these loads separately so the page never waits on a third party; remediation (CNA solutions and workarounds, CISA required action, patch/advisory references); CVSS per version with vector breakdown and every provider's score; affected products with affected ranges and a fixed-in column; exploits, GitHub PoCs (with an unvetted-code warning), VulnCheck XDB exploit repositories not already listed as GitHub PoCs, and trickest exploit write-up links; CNA advisory details (configurations, CAPEC, credits, CNA timeline); references grouped by kind; other CVEs for the same product; CWE names; KEV block; EPSS chart; SSVC; timeline; record metadata |
| Vendors & products | `/vendors` | Tabs for vendors and products (`?tab=products`), each with substring search, CVE count, severity mix, critical and KEV counts, latest CVE |
| Vendor | `/vendors/:vendor` | Severity counts, CVEs per year chart, top products table |
| Product | `/vendors/:vendor/products/:product` | Severity counts, CVEs per year, the CVE list fixed to the product |
| Security news | `/news` | Filters kept in the URL: kind (All, News, Research, Vendor advisories, Government), time range (24 h, 7 days, 30 days, all time), sort (Top, Newest), search, only articles naming a CVE, and a source chip. Each article: title, kind, source (click to filter), age, two-line summary, and CVE chips with CVSS, KEV or Exploited, exploited CVEs first (roundups show the count and six chips). Sidebar: trending CVEs for the window (30 days for all time) and every source with its article count. Paged 30 at a time; refreshes every 10 min |
| Sync | `/sync` | Each source's last success, latest run, cursor, "Run now"; recent runs with counts and errors |

Filter state lives in the URL query string using the API's parameter names, so every view is linkable. The header search box jumps straight to a CVE when given an ID.

**Chart colour.** Severity in charts uses *emphasis*: the two levels that drive action carry hue — critical `#d13d43`, high `#b98d2e` — and medium, low, and unscored are graded grays (`#7c818b`, `#4b4f57`, `#2f3237`), so the eye lands on what matters and critical sits on the baseline of stacked bars. The critical/high pair passes the dataviz validator's categorical checks (lightness band, chroma, colour-vision separation, normal-vision floor, contrast) against the graphite card surface `#151619`; the grays pass its ordinal checks. Earlier versions used a single-hue red ramp, which made critical the palest bar and the levels hard to tell apart. Single-series charts (CVEs per year, EPSS history) use the cyan accent `#1aa6bb` (validated against the red and amber series it shares charts with). Colours are CSS variables in `frontend/src/index.css`. Text badges keep conventional hues because they always carry a label.

## 10. Runtime and configuration

Docker Compose services:

| Service | Image | Port (host) | Notes |
|---|---|---|---|
| `postgres` | `postgres:17` | `127.0.0.1:${POSTGRES_HOST_PORT:-5433}` | Named volume `pgdata`; published on localhost so the backend can also run outside Docker. 5433 avoids clashing with a host Postgres |
| `backend` | built from `backend/` (distroless, non-root) | `127.0.0.1:${BACKEND_HOST_PORT:-8080}` | Applies migrations, then serves the API and runs the sync scheduler. Named volume `workdir` at `/var/lib/pahredar` (`DATA_DIR`) holds download scratch. Container health check runs `/pahredar healthcheck` |
| `frontend` | built from `frontend/` (Node 22 build, `nginx:1.29-alpine` runtime) | `127.0.0.1:${FRONTEND_HOST_PORT:-3001}` | Serves the static build with SPA fallback, proxies `/api/` and `/healthz` to the backend. Default 3001 because 3000 is commonly taken on the dev machine |

All host ports bind to `127.0.0.1` because there is no authentication. For development, the frontend can run with `npm run dev` (Vite proxy to the backend) instead of the container.

Configuration is environment-only, documented in `.env.example`. Secrets (`NVD_API_KEY`, optional `GITHUB_TOKEN`) are copied from the user's local credential store into the gitignored `.env`; they are never committed.

## 11. Future phases

1. **Stack matching:** a watchlist of vendor/product/version and package manifests (`package-lock.json`, `go.mod`, `requirements.txt`) matched against `cve_affected` (CPE + version ranges) and OSV/GitHub Advisory data; "affects me" view ranked KEV → EPSS → CVSS.
2. **Alerts:** notify on new matches, KEV additions, EPSS spikes (Telegram / ntfy / email).
3. **Deployment:** move to the OCI free-tier VM with HTTPS, authentication, and backups.
4. **Search engine:** only if Postgres FTS proves insufficient.

## 12. Decision log

| Date | Decision |
|---|---|
| 2026-10-28 | Project named **Pahredar**. |
| 2026-10-28 | Store the full CVE corpus, not a recent subset. |
| 2026-10-28 | v1 is the CVE application only; stack matching deferred. |
| 2026-10-28 | Postgres as sole datastore; Elasticsearch rejected for now (heavier, not a source of truth, Postgres FTS sufficient at ~300k records). |
| 2026-10-28 | Go backend, React + Vite frontend, local Docker Compose. |
| 2026-10-28 | No foreign keys from enrichment tables to `cve` (sources can lead the cvelist sync). |
| 2026-10-28 | Repository is personal (GitHub `SHIVAM-SHARMA-766`), not office. |
| 2026-10-28 | cvelist sync uses GitHub release archives (baseline + cumulative daily deltas + end-of-day), not per-file raw fetches or a git clone. |
| 2026-10-28 | CISA ADP affected products are stored (`source = 'adp'`); `cve_affected.cpe` became `cpes text[]`. |
| 2026-10-28 | Per-provider metrics and SSVC are derived from raw JSON at read time rather than stored. |
| 2026-10-28 | Sort indexes declared `DESC NULLS LAST, id DESC` to match the API; plain `DESC` indexes went unused (300 ms → 11 ms). |
| 2026-10-28 | NVD bootstrap fetches 4 pages concurrently (~14 min for 208 pages with a key, vs ~2 h sequential). |
| 2026-10-28 | KEV/EPSS/exploit snapshots refuse feeds under half the stored size rather than mirroring a broken download. |
| 2026-10-28 | Each exploit index is its own sync source (isolated failures) sharing one interval. |
| 2026-10-28 | Vendor/product aggregates are materialized views refreshed by a `stats` source after data changes, not live queries (seconds → milliseconds). |
| 2026-10-28 | UI routes lazy-load chart pages (initial JS 327 KB instead of 762 KB). |
| 2026-10-28 | Severity in charts is an ordinal one-hue ramp, validated per colour scheme; badges keep conventional colours. |
| 2026-11-02 | More per-CVE context from free, keyless sources: ENISA EUVD (exploitation evidence beyond KEV), CTID ATT&CK mappings and CAPEC (where the CVE fits in an attack), the Debian tracker (per-release fix status), trickest/cve (exploit write-ups), and on demand NVD change history and GitHub fix-commit diffs. Bulk sets are synced; per-CVE APIs are fetched on demand and cached. |
| 2026-11-02 | Snapshot writes `ANALYZE` their temp stage table: without statistics the planner chose a nested-loop anti-join for the stale-row delete, and the first 116k-row trickest snapshot ran for minutes instead of 12 s. |
| 2026-11-03 | Feeds grew to 67 with disclosure lists (oss-security, Full Disclosure), the whole GitHub Advisory Database, and Juniper, SonicWall, Synology, QNAP, NVIDIA, Drupal, and WordPress. Only official sources are used; vendors without a feed are left to the CVE List rather than read through third-party aggregators. |
| 2026-11-03 | Feeds grew from 26 to 56: cloud and framework vendors (AWS, Microsoft, Google Cloud, Next.js, React, PHP, Node.js, …) and national CERTs beyond the US (India, Japan, Canada, EU, France, Netherlands, Poland, Hong Kong), so an advisory published first outside the US or by a project is not missed. Every source was checked live before adding. `<form>` is no longer skipped when reading pages, since CERT-In wraps whole pages in one. |
| 2026-11-03 | A news page over the ingested feeds, ranked by the CVEs a story covers rather than by recency alone, so exploited and widely covered vulnerabilities lead. |
| 2026-11-03 | Article pages are read for their article text only, not the whole page: sidebars and related-story lists had put other stories' CVE IDs on unrelated articles (72 of 235 checked articles changed on recheck), which would have skewed the news ranking and trending. |
| 2026-11-03 | Free-signup sources: VulnCheck KEV is synced (it adds ~4,000 exploited CVEs beyond CISA KEV and EUVD, so it counts as active exploitation); OTX, ThreatFox, and Bluesky are on-demand report sources. Every key is optional and a missing one disables only its source. Mastodon, Reddit, and Cisco openVuln were left out: infosec.exchange needs manual approval to sign up, Reddit closed self-service API access, and Cisco CVEs already arrive through the CVE List and NVD. |
| 2026-11-02 | The CVE page is split into tabs: Overview carries the basics and each area has its own tab, so the first view stays short and third-party data loads only for the tab being read. |
| 2026-11-02 | Detection content comes from free, bulk, CVE-tagged sources (SigmaHQ, ET Open, Nmap script index) synced daily; scan and version-check commands are generated from data already stored (exploit `meta`, OSV / Ubuntu / Red Hat / MSRC reports, CWE) instead of a curated command database, so every CVE with package or module data gets commands without manual upkeep. |
| 2026-11-02 | Security news, research, PSIRT, and government feeds are ingested hourly (rather than searched per CVE) so Pahredar can rank trending CVEs and surface advisories before the CVE record exists. |
| 2026-11-02 | DB pool raised to 32 connections: with a dozen sync jobs each holding a lock connection, pgx's default (CPU count) starved them at startup. |
| 2026-11-02 | CVE pages gain vendor advisories (MSRC, advisory page previews), news (Google News, Hacker News), fixed versions, and related CVEs (same advisory / same product), all on demand. Advisory previews fetch untrusted URLs, hence the public-IP-only client. |
| 2026-11-02 | Dashboard chart rebuilt as a CloudWatch-style metric widget backed by `/stats/series` (user request). |
| 2026-11-02 | Detailed per-CVE reports come from OSV, Red Hat, and Ubuntu on demand with a 7-day cache, rather than bulk-syncing those datasets: one CVE page needs three small requests, while the bulk data is large and mostly never viewed. |
| 2026-11-02 | Chart severity switched to emphasis colouring (critical red, high amber, the rest gray) after user feedback that the dashboard was hard to read; dashboard gets period deltas, a 30/90-day toggle, and a non-empty EPSS card. |
| 2026-10-28 | EPSS 7-day change is precomputed at load (`score_7d_ago`, `delta_7d`): dashboard 3 s → 0.24 s. |
| 2026-10-28 | UI moved to a left sidebar and a dark-only theme (user request, SOCRadar as reference); light mode dropped. |
| 2026-10-28 | Vendor/product names are canonicalised (suffix stripping + aliases) with separate display labels; existing data rewritten with the new `rederive` command. |
| 2026-10-28 | GitHub PoCs come from the PoC-in-GitHub README index, not the 1 GB repo; no stars or descriptions, links only. |
| 2026-10-28 | Social-media mentions, news, threat-actor and dark-web data (as on SOCRadar) are out of scope: no free, reliable source. |
| 2026-10-28 | Explorer filters replaced by a Kibana-style query bar parsed client-side; table redesigned to one line per CVE. Palette moved to graphite + cyan with muted severity colours (user found the bright red childish). |

### Corpus after first full sync (2026-10-28)

415,607 CVE IDs (396,936 published, 18,671 rejected). Severity: 38,577 critical, 154,937 high, 182,315 medium, 16,348 low, 110 none, 23,320 unknown (the rejected IDs plus ~4.6k new CVEs NVD has not analysed). Severity source: NVD 212k, CNA 180k. 1.59M affected rows (NVD 953k, CNA 516k, ADP 126k). KEV 1,760; EPSS 396,257; exploit rows: Exploit-DB 30,392, Nuclei 4,541, Metasploit 3,536. Database ~4.5 GB.

## 13. Implementation milestones

| # | Milestone | Status |
|---|---|---|
| 1 | Repo skeleton, Compose (Postgres + backend), schema migration, `/healthz` | ✅ Done 2026-10-28 |
| 2 | cvelistV5 bootstrap + incremental sync, scheduler, advisory locks, `sync_run` logging, CVE list/detail + sync status API | ✅ Done 2026-10-28 |
| 3 | NVD, KEV, EPSS, Exploit-DB, Metasploit, Nuclei; NVD CPE affected rows; `kev`/`exploit`/`epss` filters and `sort=epss`; enriched detail + timeline; `POST /sync/{source}` | ✅ Done 2026-10-28 |
| 4 | Frontend: list, detail, vendor, product, sync pages; `frontend` Compose service; vendor API and stats views | ✅ Done 2026-10-28 |
| 5 | Dashboard (`/api/v1/stats/dashboard` + `/` page); chart polish (validated palette, mark specs, mobile layout) | ✅ Done 2026-10-28 |
