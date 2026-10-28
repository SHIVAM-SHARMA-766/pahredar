# Pahredar

A personal, self-hosted CVE tracker. Pahredar keeps a local copy of every published CVE, enriches it with CVSS, CISA KEV, EPSS, and public-exploit data, syncs on a schedule, and shows it in a web UI.

> **Status:** milestone 1 of 5. The Compose stack, database schema, and backend health endpoint run; CVE sync, API, and UI are in progress. See [ARCHITECTURE.md](ARCHITECTURE.md) for the design and milestone list.

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

All ports bind to `127.0.0.1` only; there is no authentication.

Once sync and the UI land, the first start will run a full import of all CVEs (this takes a while) and the UI will be at `http://127.0.0.1:3001`.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): design, data model, sync, API, decision log, milestones
- [backend/README.md](backend/README.md): Go module layout, subcommands, configuration, migrations
