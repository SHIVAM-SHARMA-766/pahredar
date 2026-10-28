# frontend

React single-page app for Pahredar: CVE search and detail, vendor and product pages, and sync status. It is a static build that talks only to the backend's JSON API. See [../ARCHITECTURE.md](../ARCHITECTURE.md) §8 (API) and §9 (pages).

## Stack

React 19, TypeScript 5.9, Vite 8, Tailwind CSS 4 (via `@tailwindcss/vite`, no config file), TanStack Query 5 (fetching and caching), React Router 7 (library mode, `createBrowserRouter`), Recharts 3, lucide-react icons. Versions are pinned exactly in `package.json`; new dependencies use a release at least two weeks old.

React Router 8 needs Node ≥ 22.22 and the dev machine has Node 20, so the app stays on 7.x. Use npm 11 (`npx npm@11 install`): npm 10's resolver crashes on Vite 8's optional peer dependencies.

## Layout

| Path | Role |
|---|---|
| `src/main.tsx` | Router, query client defaults (60 s stale time, no retry on 400/404), lazy loading of chart-heavy pages. |
| `src/api/types.ts` | TypeScript mirror of the backend's JSON responses. Update together with the Go structs. |
| `src/api/client.ts` | `api.*` fetch functions; non-2xx responses throw `ApiError` with the backend's `error` message. |
| `src/lib/` | Pure helpers: date/number/EPSS formatting (`format.ts`), severity colours and labels (`severity.ts`), CVSS vector breakdown for v2/v3.x/v4.0 (`cvss.ts`), affected-version range strings for CNA and NVD shapes (`versions.ts`). |
| `src/components/ui.tsx` | Small shared pieces: page header, severity badge, KEV/exploit tags, card, stats, severity bar, pagination, loading and error states. |
| `src/components/CveFilters.tsx` | Filter sidebar and sort control. |
| `src/components/CveTable.tsx` | CVE result table. |
| `src/components/charts.tsx` | Daily stacked volume chart (with legend and table view), year bar chart, EPSS history line chart, shared tooltip and tick formatting. |
| `src/components/Layout.tsx` | App shell: collapsible left sidebar (brand, search box that jumps to a CVE when given an ID, sectioned navigation, sync-health card), mobile top bar with a slide-in drawer, and the page frame. |
| `src/pages/` | One component per route (below). |

## Routes

| Path | Page |
|---|---|
| `/` | Dashboard: headline counts, 90-day volume chart, severity mix, EPSS movers, and three CVE lists (`pages/DashboardPage.tsx`) |
| `/cves` | Filterable, sortable CVE list. The sidebar's "Known exploited" (`?kev=true&sort=kev_added`) and "Likely exploited" (`?kev=false&sort=epss&epss_min=0.1`) are presets of this page; the header and highlighted nav item follow the active preset |
| `/cves/:id` | CVE detail: CVSS breakdown per version and provider, affected products, exploits, references, KEV, EPSS chart, SSVC, timeline |
| `/vendors` | Vendor search, ranked by CVE count |
| `/vendors/:vendor` | Vendor stats, CVEs per year, top 200 products |
| `/vendors/:vendor/products/:product` | Product stats, CVEs per year, and the CVE list fixed to that product |
| `/sync` | Per-source status with "Run now", and recent runs (polls every 5 s) |

## Conventions

- **Filter state lives in the URL** using the API's own parameter names (`severity`, `kev`, `epss_min`, `sort`, `page`, …), so every view is linkable and `api.listCves` passes the query string straight through. Changing any filter resets `page`.
- Text filters commit on Enter or blur, not on every keystroke.
- EPSS is shown as a percentage, truncated rather than rounded (0.99999 → 99.99%).
- Vendor and product names are URL-encoded in paths (`vendorPath`, `productPath` in `format.ts`); they can contain spaces and slashes.
- Charts have animation disabled: it adds nothing here and Recharts' animation does not progress in headless screenshot runs.
- **Chart colours are CSS variables** in `src/index.css` (`--sev-*`, `--surface`, `--grid`, `--axis-text`, `--track`), with values for the navy card surface. Severity uses an ordinal one-hue red ramp validated with the dataviz skill's `validate_palette.js --mode dark --ordinal --surface "#161a24"`; change the values only together with a re-validation. `severityFill` / `chartSeries` in `src/lib/severity.ts` reference the variables. Badges (`severityBadge`) keep conventional colours because they carry text.
- **Mark specs:** solid hairline grid, bars ≤ 24px with a 4px rounded top and square baseline, a 2px gap between stacked segments (custom bar shape in `charts.tsx`), 2px lines, values in text colours with a swatch for identity, a legend plus a table view for multi-series charts.
- Each chart sits in an `overflow-hidden` box and every `Card` is `min-w-0`, so wide content can never widen a card on narrow screens.
- **Open issue (unverified on a real phone):** in 390px headless-Chromium screenshots the page lays out at 390px but Recharts measures ~419px for chart width (it measures 500 − 81, the same as at a 500px window), so the right edge of charts is clipped. The likely cause is headless Chromium starting at its 500px minimum window width and the ResizeObserver update not running under `--virtual-time-budget`, but this has not been confirmed; check charts in a real browser's device mode or on a phone.
- **Theme: dark only.** `<html class="dark">` plus `@custom-variant dark` in `index.css` keep every `dark:` class active, so the light classes still present in components are inert. The `zinc` scale is redefined in `@theme` as cool navy grays (950 page, 900 cards and sidebar, 800 borders), which re-themes every `zinc-*` class at once. The accent is Tailwind `rose`. To restyle, change the `@theme` block rather than individual components.
- **Navigation:** the sidebar is defined by `SECTIONS` in `Layout.tsx`; each item has its own `active(location)` test because presets share the `/cves` route. Collapsed state is remembered in `localStorage` (`pahredar.sidebar.collapsed`, read defensively). Below `lg` the sidebar becomes a drawer that closes on navigation.

## Development

```bash
docker compose up -d postgres backend     # API on 127.0.0.1:8080
cd frontend
npx npm@11 install
npm run dev                               # http://127.0.0.1:5173, proxies /api to the backend
npm run typecheck
npm run build                             # dist/
```

Set `PAHREDAR_API` to point the dev proxy at a different backend.

## Production image

`Dockerfile`: builds with Node 22 and npm 11, then serves `dist/` from `nginx:1.29-alpine` using `nginx.conf`, which proxies `/api/` and `/healthz` to `backend:8080`, serves `index.html` for every client-side route (`no-cache`), and caches fingerprinted `/assets/` for a year. Compose publishes it on `127.0.0.1:${FRONTEND_HOST_PORT:-3001}`.
