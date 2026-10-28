# backend

Go module for the Pahredar backend: one binary that applies database migrations, serves the HTTP API, and (from milestone 3) runs the sync scheduler. See [../ARCHITECTURE.md](../ARCHITECTURE.md) for the overall design.

## Layout

| Path | Role |
|---|---|
| `cmd/pahredar/` | Entry point and subcommand dispatch (`serve`, `migrate`, `healthcheck`). Owns process lifecycle: signal handling, HTTP server timeouts, graceful shutdown (10 s). |
| `internal/config/` | Reads all configuration from environment variables. `DATABASE_URL` is required; everything else has a default or is optional. |
| `internal/db/` | `Open` (pgx connection pool + ping) and `Migrate` (goose, SQL files embedded with `go:embed`). |
| `internal/db/migrations/` | Versioned SQL migrations, `NNNNN_name.sql`, each with `-- +goose Up` and `-- +goose Down` sections. |
| `internal/api/` | HTTP handlers on the stdlib `ServeMux`. Currently only `GET /healthz`. |

Planned: `internal/sources/` (one package per upstream feed) and `internal/sync/` (scheduler, run logging, advisory locks).

## Subcommands

| Command | Behaviour |
|---|---|
| `pahredar serve` | Applies pending migrations, opens the pool, listens on `HTTP_ADDR` (default `:8080`). Exits cleanly on SIGINT/SIGTERM. |
| `pahredar migrate` | Applies pending migrations and exits. |
| `pahredar healthcheck` | GETs `http://127.0.0.1:8080/healthz`; exit 0 on HTTP 200. Used by the Compose health check because the distroless image has no curl. Assumes the default port. |

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `DATABASE_URL` | yes | none | Postgres connection string |
| `HTTP_ADDR` | no | `:8080` | Listen address |
| `LOG_LEVEL` | no | `info` | `debug` / `info` / `warn` / `error` |
| `NVD_API_KEY` | no (needed from milestone 3) | none | NVD API key |
| `GITHUB_TOKEN` | no | none | Higher GitHub rate limit for cvelistV5 downloads |

## Endpoints

| Method & path | Response |
|---|---|
| `GET /healthz` | `200 {"status":"ok","database":"ok"}`, or `503` if Postgres does not answer a ping within 2 s |

## Migrations

- Applied automatically by `serve`; tracked in the `goose_db_version` table.
- Never edit a migration that has been applied; add a new file with the next number.
- `00001_init.sql` creates the full v1 schema (see ARCHITECTURE.md §6).

## Development

```bash
# Postgres from Compose, backend on the host
docker compose up -d postgres
export DATABASE_URL='postgres://pahredar:<password>@127.0.0.1:5433/pahredar?sslmode=disable'
go run ./cmd/pahredar serve

go vet ./... && gofmt -l .
```

## Image

Multi-stage `Dockerfile`: builds a static binary (`CGO_ENABLED=0`) on `golang:1.26-alpine` and runs it on `gcr.io/distroless/static-debian12:nonroot`.
