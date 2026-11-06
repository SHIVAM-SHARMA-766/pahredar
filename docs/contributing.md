# Working on Pahredar (incl. in parallel)

Conventions that let several changes — or several chats — proceed at once
without stepping on each other. The architecture is in
[foundation.md](foundation.md); each service is documented under
`docs/services/`.

## Rule 1 — Declare your service

Every change belongs to one service (**intel**, **news**, **scanner**) or to
**core**. State which at the start, and touch only that service's files plus its
doc. A change that needs core is a coordination point — see Rule 3.

Service ownership is listed in each `docs/services/<name>.md` (its routes,
backend files, frontend files, and tables).

## Rule 2 — Migrations are plain sequential

Migrations are `backend/internal/db/migrations/NNNNN_name.sql`, applied by goose
in numeric order. Keep them a single sequence: to add one, `ls
backend/internal/db/migrations/` → take the next number after the highest
existing (e.g. after `00018` comes `00019`).

Work is usually sequential (one change finished and committed before the next),
so numbers don't collide. If two parallel changes ever grab the same number,
the later one to merge renames its file to the next free number — a trivial fix,
since nothing is applied to a shared database until merged.

Never edit a migration that may already be applied — always add a new one.

## Rule 3 — The shared core is a coordination zone

These files are used by every service. Changing them in two places at once
causes conflicts, so keep edits minimal and say when you touch them:

- `backend/internal/api/api.go` — route registration and the server struct
- `backend/internal/db/{db,store}.go` — pool, migration runner, store wiring
- `backend/cmd/pahredar/main.go` — process wiring
- `frontend/src/api/{client,types}.ts` — shared API client and types
- `frontend/src/components/Layout.tsx` — navigation
- `docker-compose.yml`, the Dockerfiles

Until the P1 module pattern (see foundation.md) lands, these are edited
directly; keep additions grouped by service (see Rule 4) to shrink the conflict
surface.

## Rule 4 — Add, don't weave

- **Backend routes:** put handlers in your service's `api/<service>.go`; in
  `api.go` add the `mux.HandleFunc` lines in your service's block, not scattered.
- **Backend data access:** add to your service's `db/*.go` files; do not reach
  into another service's queries — go through a documented interface (e.g. the
  scanner uses `scan.TechMatcher` to read intel's data, never intel's db
  functions directly).
- **Frontend types:** append to `api/types.ts` in your service's section; keep
  the `api/client.ts` methods grouped by service.
- **Nav:** add your entry to the correct section in `Layout.tsx`.

## Rule 5 — Cross-service contracts are explicit

A service may read another's data only through a named interface, so boundaries
stay enforceable:

- **Scanner → Intel:** `scan.TechMatcher` (tech → CVE matching).
- **News → Intel:** CVE badges/summaries for trending.

If you need a new cross-service dependency, add it as an interface and note it in
both services' docs.

## Rule 6 — Leave a trail

At the end of a change, note which **core** files (Rule 3) you touched, so a
parallel change knows. Add a line to the decision log in `ARCHITECTURE.md` for
anything architectural.

## Checks before done

- Backend: `gofmt`, `go vet ./...`, `go build ./...`, `go test ./...`.
- Frontend: `npx tsc --noEmit`.
- Migrations apply cleanly from an empty database.
