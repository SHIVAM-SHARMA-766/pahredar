# Pahredar docs

Deeper documentation than the top-level `README.md`. For how the system is
built today, see `../ARCHITECTURE.md`.

- **[foundation.md](foundation.md)** — the platform shape (modular monolith) and
  the foundational pillars (module pattern, durable jobs, asset model, events,
  auth, observability, CI). Read before adding a service or touching core.
- **[roadmap.md](roadmap.md)** — phased plan from tools to platform, future
  services, and current known gaps/limitations.
- **[contributing.md](contributing.md)** — conventions for working in parallel:
  service ownership, migration numbering, the core coordination zone.
- **services/** — one spec per product service:
  - [intel.md](services/intel.md) — Vulnerability Intelligence
  - [news.md](services/news.md) — Security News
  - [scanner.md](services/scanner.md) — Endpoint Scanner

A fresh contributor (or chat) working on one service should read that service's
spec plus `contributing.md`, and only reach into `foundation.md`/core when a
change needs the shared platform.
