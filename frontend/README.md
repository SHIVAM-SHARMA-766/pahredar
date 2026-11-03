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
| `src/lib/` | Pure helpers: fixed-version extraction (`fixedVersions` in `versions.ts`), the explorer query language (`query.ts`: `parseQuery`, `FIELDS`, `EXAMPLES`, `explorerLink`), date/number/EPSS formatting (`format.ts`), severity colours and labels (`severity.ts`), CVSS vector breakdown for v2/v3.x/v4.0 (`cvss.ts`), detection commands and per-CWE hunting hints (`detection.ts`: package version checks per ecosystem, CVE lookups, Windows KB checks, Nuclei / Nmap / Metasploit commands, Suricata and sigma-cli commands), affected-version range strings for CNA and NVD shapes (`versions.ts`). |
| `src/lib/origin.ts` | `useOrigin(label)` records the current list page (dashboard, explorer, news, vendors, vendor, product) with its query string in `sessionStorage`; `readOrigin()` gives CVE pages their first breadcrumb |
| `src/components/ui.tsx` | Small shared pieces: page header, severity badge, KEV/exploit tags, card, stats, severity bar, pagination, loading and error states. |
| `src/components/QueryBar.tsx` | Explorer search bar: applies on Enter, example chips, error line, syntax panel. |
| `src/components/CveTable.tsx` | Compact CVE table with sortable headers (`SortKey`: published, kev_added, epss, cvss). |
| `src/components/MetricWidget.tsx` | CloudWatch-style dashboard chart: metric, time range, period, graph type, legend toggles with sums, crosshair, drag-to-zoom, table. State in the URL. Buckets daily points from `/stats/series` into weeks or calendar months in the browser |
| `src/components/CveContextCards.tsx` | `AttackCard` (CTID ATT&CK techniques, CAPEC patterns), `HistoryCard` (NVD change log), `CommitsCard` (fix-commit diffs), `DebianCard` (per-release status table) |
| `src/components/DetectionCard.tsx` | CVE page Detection card: coverage line and *Start here* step, target box (remembered in `localStorage`), tabs (Am I affected?, Active scan (Nuclei, Nmap, Metasploit, and Greenbone tests via `GreenboneTests`), Network IDS (Suricata, Snort 3), Logs / SIEM (Sigma, Splunk, Elastic; rules cited only in references are tagged related), Files (YARA, one file built by `yaraFile` in `lib/detection.ts` with imports and helper rules once each), What to look for). *Am I affected?* shows the verdict scripts from `lib/affected.ts` (copy, download, fleet commands) and a version box per library |
| `src/lib/affected.ts` | Verdict logic: `compareVersions` and `osvVerdict` (OSV range events) for libraries; `distroPackages` + `debianScript` (dpkg source versions vs the Debian tracker and Ubuntu), `rhelScript` (dnf updateinfo), `windowsBuilds` + `windowsScript` (build and UBR vs MSRC fixed builds), `fleetCommands`. Values reaching a script pass strict allowlists |
| `src/components/FeedCards.tsx` | Feed-backed pieces: `TrendingCard` (dashboard and news page; `days`, `limit`) and `LatestAdvisoriesCard` (dashboard), `FeedArticleList` and `NotYetPublished` (CVE page; the latter replaces the 404 for IDs not yet in the CVE List), `KindTag` |
| `src/components/ThreatIntelCard.tsx` | Threat intelligence on the Reports & news tab: actors, malware, targeting, and ATT&CK across AlienVault OTX and ThreatFox; focused OTX pulses; ThreatFox IOC table with copy-all. Shows which `.env` key to set when a source is disabled |
| `src/components/CveIntelCards.tsx` | CVE page cards loaded on demand: `VendorAdvisoriesCard` (MSRC KB/fixed-build table, advisory page previews), `NewsCard` (Pahredar feeds, Google News, Hacker News, Bluesky, Mastodon), `RelatedCard` (same advisory, same product ±30 days) |
| `src/components/ReportsCard.tsx` | In-depth reports on the CVE page: one tab per source that has a record (OSV, Red Hat, Ubuntu); advisory text is shown as plain text, never as HTML |
| `src/components/charts.tsx` | Year bar chart and EPSS history line chart. |
| `src/components/Layout.tsx` | App shell: collapsible left sidebar (brand, sectioned navigation, sync-health card), mobile top bar with a slide-in drawer, and the page frame. |
| `src/pages/` | One component per route (below). |

## Routes

| Path | Page |
|---|---|
| `/` | Dashboard: tile strip with period deltas, metric widget (`?metric=&range=&period=&chart=&from=&to=`), severity mix, EPSS movers (or highest EPSS this week until history exists), and three CVE lists (`pages/DashboardPage.tsx`) |
| `/cves` | CVE explorer: `?query=` in the query language, plus `sort`, `order`, `page`, `page_size`. Saved views are tabs above the query bar (`VIEWS` in `CveListPage.tsx`: All CVEs, Known exploited, Likely exploited, Ransomware, Critical · 7 days); a tab is active while the URL's `query` equals its own, otherwise the page shows "Custom search" |
| `/cves/:id` | CVE detail: breadcrumb (`lib/origin.ts`: the last list page visited, with its filters), header, assessment banner, key facts, then tabs in `?tab=` (`CveTabs` in `pages/CveDetailPage.tsx`): Overview (default: nicknames, description, at a glance, timeline, CWE, KEV, ENISA EUVD, VulnCheck KEV, EPSS, SSVC, record), `detection`, `attack` (ATT&CK, CAPEC), `remediation` (fixes, Debian, fix commits, vendor advisories), `exploits`, `intel` (threat intelligence, reports, news, related), `technical` (CVSS, affected products, CNA advisory details), `history` (NVD changes), `references`. A tab's cards mount, and fetch, only when it is open. Once the header scrolls away the pinned tab bar adds a row naming the CVE (`StuckIdentity`) |
| `/vendors` | Vendors and products tabs (`?tab=products`) with search (`?q=`), ranked by CVE count. Names show the display label; links use the canonical key |
| `/vendors/:vendor` | Vendor stats, CVEs per year, top 200 products |
| `/vendors/:vendor/products/:product` | Product stats, CVEs per year, and the CVE list fixed to that product |
| `/news` | Security news (`pages/NewsPage.tsx`): `?kind=&feed=&q=&days=&cves=1&saved=1&sort=newest&page=`; defaults are all kinds, 7 days, top first; each article has a bookmark button (`PUT /api/v1/news/bookmark`), and `saved=1` lists bookmarked articles whatever their date |
| `/scan` | Endpoint scanner (`pages/ScanPage.tsx`): `?target=`. Posts to `/api/v1/scan`, renders the report (grade, findings, TLS/headers/DNS/tech/paths/related cards); a hero with a Passive/Active mode toggle. An active-checks toggle (with an authorisation confirmation) appears when the server enables it (`/api/v1/scan/config`); it is in its own Offensive nav section |
| `/sync` | Per-source status with "Run now", and recent runs (polls every 5 s) |

## Conventions

- **Explorer state lives in the URL**: `query` (the query language) and the view parameters `sort`, `order`, `page`, `page_size`. `parseQuery` turns the query into API filter parameters in the browser; `CveResults` adds the view parameters. Build links with `explorerLink(query, sort?)`. A new query or sort resets `page`.
- The query applies on Enter or when an example chip is clicked, not on every keystroke. Unknown fields and bad values are listed under the bar and ignored, never sent.
- Pagination: the rows-per-page control sits above the table and the numbered pager (`Pager` in `CveListPage.tsx`: first, last, and two pages either side of the current one) below it.
- Adding a query field: extend `FIELDS` (it drives the help panel) and the `switch` in `parseQuery`; add the API parameter in `backend/internal/api/cves.go` if it needs one.
- EPSS is shown as a percentage, truncated rather than rounded (0.99999 → 99.99%).
- Vendor and product names are URL-encoded in paths (`vendorPath`, `productPath` in `format.ts`); they can contain spaces and slashes.
- Charts have animation disabled: it adds nothing here and Recharts' animation does not progress in headless screenshot runs.
- **Chart colours are CSS variables** in `src/index.css` (`--sev-*`, `--chart-accent`, `--surface`, `--grid`, `--axis-text`, `--track`), with values for the graphite card surface. Severity uses emphasis: critical and high are hues validated with the dataviz skill's `validate_palette.js "#d13d43,#b98d2e" --mode dark --surface "#151619"`, medium/low/unscored are grays validated with `--ordinal`; change the values only together with a re-validation. `severityFill` / `chartSeries` in `src/lib/severity.ts` reference the variables. Badges (`severityBadge`) keep conventional colours because they carry text.
- **Mark specs:** solid hairline grid, bars ≤ 24px with a 4px rounded top and square baseline, a 2px gap between stacked segments (custom bar shape in `charts.tsx`), 2px lines, values in text colours with a swatch for identity, a legend plus a table view for multi-series charts.
- Each chart sits in an `overflow-hidden` box and every `Card` is `min-w-0`, so wide content can never widen a card on narrow screens.
- **Open issue (unverified on a real phone):** in 390px headless-Chromium screenshots the page lays out at 390px but Recharts measures ~419px for chart width (it measures 500 − 81, the same as at a 500px window), so the right edge of charts is clipped. The likely cause is headless Chromium starting at its 500px minimum window width and the ResizeObserver update not running under `--virtual-time-budget`, but this has not been confirmed; check charts in a real browser's device mode or on a phone.
- **Theme: dark only.** `<html class="dark">` plus `@custom-variant dark` in `index.css` keep every `dark:` class active, so the light classes still present in components are inert. The `zinc` scale is redefined in `@theme` as near-neutral graphite (950 page, 900 cards and sidebar, 800 borders), which re-themes every `zinc-*` class at once. The accent is Tailwind `cyan` (links, CVE IDs, active nav, focus rings). Status colours are low-saturation tints (`bg-<hue>-500/10 text-<hue>-300 ring-<hue>-400/25`); avoid solid saturated fills. To restyle, change the `@theme` block rather than individual components.
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

## Phone layout

Every page is checked at 390 px wide; none may scroll sideways. Patterns used:

- Lists that are tables on desktop become cards below `md` (`CveTable`: `CveCards` / `CveRows`).
- Tab strips scroll sideways in one row with the `no-scrollbar` utility (`index.css`) and `overflow-y-hidden`, instead of wrapping onto several lines.
- Wide tables sit in an `overflow-x-auto` wrapper and carry a `min-w-[…]` so columns scroll rather than squeeze.
- Label / value grids stack below `sm` (CVE page "At a glance").
