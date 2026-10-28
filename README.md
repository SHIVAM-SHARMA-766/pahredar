# Pahredar

A personal, self-hosted CVE tracker. Pahredar keeps a local copy of every published CVE, enriches it with CVSS, CISA KEV, EPSS, and public-exploit data, syncs on a schedule, and shows it in a web UI.

> **Status:** milestone 2 of 5. The full CVE corpus imports and syncs hourly from cvelistV5, and the search/detail API works. NVD/KEV/EPSS/exploit enrichment and the UI are next. See [ARCHITECTURE.md](ARCHITECTURE.md) for the design and milestone list.

## Features (v1, planned)

- Full CVE corpus from the official CVE List (cvelistV5), kept current hourly
- Enrichment from NVD, CISA KEV, EPSS, Exploit-DB, Metasploit, and Nuclei templates
- Dashboard with new, critical, actively exploited, and high-EPSS CVEs
- Full-text search and filters (severity, KEV, exploit available, vendor, product, CWE, dates, EPSS)
- CVE detail page with CVSS breakdown, EPSS history, KEV info, affected products, references, exploits, and a timeline
- Vendor and product pages
- Sync status page with per-source run history

Matching CVEs against your own tech stack and alerting come in later phases.

## Stack

Go backend (API and sync worker in one binary), Postgres, React + Vite frontend, all run with Docker Compose.

## Running locally

```bash
cp .env.example .env        # set POSTGRES_PASSWORD; NVD_API_KEY needed from milestone 3
docker compose up -d --build
curl http://127.0.0.1:8080/healthz
```

The first start downloads the full CVE corpus (~615 MB) and imports it in the background; the API answers meanwhile. Follow it with `docker compose logs -f backend` or `curl 127.0.0.1:8080/api/v1/sync/status`. After that, new and changed CVEs arrive hourly.

```bash
curl '127.0.0.1:8080/api/v1/cves?q=remote+code+execution&severity=CRITICAL&page_size=5'
curl  127.0.0.1:8080/api/v1/cves/CVE-2021-44228
```

All ports bind to `127.0.0.1` only; there is no authentication. The UI (milestone 4) will be at `http://127.0.0.1:3001`.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): design, data model, sync, API, decision log, milestones
- [backend/README.md](backend/README.md): Go module layout, subcommands, configuration, migrations
