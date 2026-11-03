import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router'
import { api } from '../api/client'
import { CveTable, type SortKey } from '../components/CveTable'
import { QueryBar } from '../components/QueryBar'
import { Card, ErrorBox, PageHeader, Spinner } from '../components/ui'
import { fmtNumber } from '../lib/format'
import { severityFill } from '../lib/severity'
import { useOrigin } from '../lib/origin'
import { parseQuery } from '../lib/query'

// URL parameters of the explorer: `query` (the query language), plus `sort`,
// `order`, `page`, and `page_size`, which pass through to the API.
const PAGE_SIZES = [50, 100, 250]
const DEFAULT_PAGE_SIZE = 50

// Saved views: tabs that set a query and sort. A view is active while the
// URL's query equals its own; editing the query in the bar makes it a
// custom search.
export const VIEWS = [
  { key: 'all', label: 'All CVEs', query: '', sort: null, hint: 'Every CVE in the CVE List, newest first.' },
  { key: 'kev', label: 'Known exploited', query: 'is:kev', sort: 'kev_added', hint: 'In the CISA Known Exploited Vulnerabilities catalog: attackers are using these now. Sorted by date added.' },
  { key: 'likely', label: 'Likely exploited', query: 'epss:>10 -is:kev', sort: 'epss', hint: 'Not yet in KEV but EPSS above 10%: likely to see exploitation in the next 30 days.' },
  { key: 'ransomware', label: 'Ransomware', query: 'is:kev has:ransomware', sort: 'kev_added', hint: 'KEV entries CISA links to ransomware campaigns.' },
  { key: 'critical', label: 'Critical · 7 days', query: 'severity:critical age:<7', sort: null, hint: 'Critical CVEs published in the last week.' },
] as const

export function CveListPage() {
  const [params, setParams] = useSearchParams()
  useOrigin('CVE explorer')
  const query = params.get('query') ?? ''
  const parsed = parseQuery(query)
  const view = VIEWS.find((v) => v.query === query)

  const pickView = (v: (typeof VIEWS)[number]) => {
    const next = new URLSearchParams()
    if (v.query) next.set('query', v.query)
    if (v.sort) next.set('sort', v.sort)
    const size = params.get('page_size')
    if (size) next.set('page_size', size)
    setParams(next)
  }

  const submit = (q: string) => {
    const next = new URLSearchParams(params)
    if (q) next.set('query', q)
    else next.delete('query')
    next.delete('page')
    setParams(next)
  }

  return (
    <>
      <PageHeader title="CVE explorer" subtitle="Search every CVE in the CVE List, enriched with NVD, CISA KEV, EPSS, and public exploits." />
      <div className="no-scrollbar mb-4 flex items-end gap-1 overflow-x-auto overflow-y-hidden border-b border-zinc-800" role="tablist" aria-label="Saved views">
        {VIEWS.map((v) => (
          <button
            key={v.key}
            role="tab"
            aria-selected={view?.key === v.key}
            onClick={() => pickView(v)}
            className={`-mb-px shrink-0 border-b-2 px-3.5 py-2 text-sm font-medium whitespace-nowrap transition-colors ${view?.key === v.key ? 'border-cyan-400 text-white' : 'border-transparent text-zinc-400 hover:border-zinc-600 hover:text-zinc-200'}`}
          >
            {v.label}
          </button>
        ))}
        {!view && <span className="-mb-px shrink-0 border-b-2 border-cyan-400/60 px-3.5 py-2 text-sm font-medium whitespace-nowrap text-zinc-200">Custom search</span>}
      </div>
      {view && <p className="-mt-2 mb-3 text-xs text-zinc-500">{view.hint}</p>}
      <div className="space-y-4">
        <QueryBar value={query} onSubmit={submit} errors={parsed.errors} />
        <CveFacetBar filters={parsed.api} />
        <CveResults filters={parsed.api} view={params} onView={setParams} defaultSort={parsed.text ? 'relevance' : 'published'} />
      </div>
    </>
  )
}

// CveResults is the paginated, sortable table for a set of API filters. The
// view params (sort, order, page, page_size) live in the page URL; the
// product page reuses this with vendor/product filters.
export function CveResults({ filters, view, onView, defaultSort = 'published', title }: {
  filters: URLSearchParams
  view: URLSearchParams
  onView: (next: URLSearchParams) => void
  defaultSort?: string
  title?: string
}) {
  const page = Math.max(1, Number(view.get('page') ?? '1') || 1)
  const pageSize = PAGE_SIZES.includes(Number(view.get('page_size'))) ? Number(view.get('page_size')) : DEFAULT_PAGE_SIZE
  const sort = view.get('sort') ?? defaultSort
  const desc = view.get('order') !== 'asc'

  const apiParams = new URLSearchParams(filters)
  apiParams.set('sort', sort)
  if (!desc) apiParams.set('order', 'asc')
  apiParams.set('page', String(page))
  apiParams.set('page_size', String(pageSize))

  const result = useQuery({
    queryKey: ['cves', apiParams.toString()],
    queryFn: () => api.listCves(apiParams),
    placeholderData: keepPreviousData,
  })

  const update = (changes: Record<string, string | null>, resetPage = true) => {
    const next = new URLSearchParams(view)
    for (const [k, v] of Object.entries(changes)) {
      if (v == null) next.delete(k)
      else next.set(k, v)
    }
    if (resetPage) next.delete('page')
    onView(next)
  }
  const onSort = (k: SortKey) =>
    k === sort ? update({ order: desc ? 'asc' : null }) : update({ sort: k, order: null })
  const goto = (p: number) => {
    update({ page: p > 1 ? String(p) : null }, false)
    window.scrollTo({ top: 0 })
  }

  const total = result.data?.total ?? 0
  // The API caps offsets at 10,000.
  const lastPage = Math.max(1, Math.min(Math.ceil(total / pageSize), Math.floor(10000 / pageSize) + 1))

  return (
    <Card>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div className="text-sm text-zinc-400">
          {title && <span className="mr-2 font-medium text-zinc-200">{title}</span>}
          {result.data && (
            <>
              <span className="font-medium text-zinc-200">{fmtNumber(total)}</span> CVE{total === 1 ? '' : 's'} · page {fmtNumber(page)} of {fmtNumber(lastPage)}
            </>
          )}
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-semibold tracking-wider text-zinc-500 uppercase">Rows</span>
            <div className="flex rounded-md border border-zinc-800 p-0.5">
              {PAGE_SIZES.map((n) => (
                <button
                  key={n}
                  onClick={() => update({ page_size: n === DEFAULT_PAGE_SIZE ? null : String(n) })}
                  className={`rounded px-2.5 py-0.5 text-xs tabular-nums ${n === pageSize ? 'bg-zinc-800 text-white' : 'text-zinc-400 hover:text-zinc-200'}`}
                >
                  {n}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
      {result.isPending ? (
        <Spinner />
      ) : result.isError ? (
        <ErrorBox error={result.error} />
      ) : (
        <div className={result.isPlaceholderData ? 'opacity-60' : ''}>
          <CveTable items={result.data.items} sort={{ sort, desc, onSort }} />
          {lastPage > 1 && <Pager page={page} lastPage={lastPage} onPage={goto} />}
        </div>
      )}
    </Card>
  )
}

// Page numbers around the current page, with the first and last always shown.
function pageWindow(page: number, last: number): (number | '…')[] {
  const pages = new Set([1, last, page - 2, page - 1, page, page + 1, page + 2])
  const sorted = [...pages].filter((p) => p >= 1 && p <= last).sort((a, b) => a - b)
  const out: (number | '…')[] = []
  sorted.forEach((p, i) => {
    if (i > 0 && p - sorted[i - 1] > 1) out.push('…')
    out.push(p)
  })
  return out
}

function Pager({ page, lastPage, onPage }: { page: number; lastPage: number; onPage: (p: number) => void }) {
  const btn = 'min-w-8 rounded-md border px-2.5 py-1 text-xs tabular-nums disabled:opacity-40'
  const idle = 'border-zinc-800 text-zinc-300 hover:bg-zinc-800'
  return (
    <nav className="mt-4 flex flex-wrap items-center justify-center gap-1.5" aria-label="Pagination">
      <button className={`${btn} ${idle}`} disabled={page <= 1} onClick={() => onPage(page - 1)}>← Previous</button>
      {pageWindow(page, lastPage).map((p, i) =>
        p === '…' ? (
          <span key={`gap-${i}`} className="px-1 text-xs text-zinc-600">…</span>
        ) : (
          <button
            key={p}
            onClick={() => onPage(p)}
            aria-current={p === page ? 'page' : undefined}
            className={`${btn} ${p === page ? 'border-cyan-400/40 bg-cyan-500/10 text-cyan-200' : idle}`}
          >
            {p.toLocaleString()}
          </button>
        ),
      )}
      <button className={`${btn} ${idle}`} disabled={page >= lastPage} onClick={() => onPage(page + 1)}>Next →</button>
    </nav>
  )
}


// SEVERITY_SEGMENTS drives the explorer's overview bar: the severity order and
// the fill each slice uses.
const SEVERITY_SEGMENTS: { key: string; label: string; fill: string }[] = [
  { key: 'CRITICAL', label: 'Critical', fill: severityFill.CRITICAL },
  { key: 'HIGH', label: 'High', fill: severityFill.HIGH },
  { key: 'MEDIUM', label: 'Medium', fill: severityFill.MEDIUM },
  { key: 'LOW', label: 'Low', fill: severityFill.LOW },
  { key: 'OTHER', label: 'Unscored', fill: 'var(--sev-other)' },
]

// CveFacetBar is the graphical summary above the results table: the severity
// composition and KEV count of everything matching the current query (not
// just the visible page). It is keyed on the filters alone, so paging and
// re-sorting do not refetch it.
function CveFacetBar({ filters }: { filters: URLSearchParams }) {
  const key = filters.toString()
  const q = useQuery({
    queryKey: ['cve-facets', key],
    queryFn: () => api.cveFacets(filters),
    placeholderData: keepPreviousData,
    staleTime: 60_000,
  })
  const f = q.data
  if (q.isError) return null
  const total = f?.total ?? 0
  const segments = f ? SEVERITY_SEGMENTS.map((s) => ({ ...s, n: f.severity[s.key] ?? 0 })).filter((s) => s.n > 0) : []
  const kevPct = total ? Math.round((f!.kev / total) * 100) : 0

  return (
    <div className={`rounded-xl border border-zinc-800 bg-gradient-to-br from-zinc-900 to-zinc-950 p-4 ${q.isPlaceholderData ? 'opacity-60' : ''}`}>
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center">
        <div className="shrink-0">
          <div className="font-mono text-2xl font-bold text-white tabular-nums">{fmtNumber(total)}</div>
          <div className="text-[11px] tracking-wider text-zinc-500 uppercase">matching CVEs</div>
        </div>

        <div className="min-w-0 flex-1 lg:border-l lg:border-zinc-800 lg:pl-4">
          {total > 0 ? (
            <>
              <div className="flex h-2.5 overflow-hidden rounded-full bg-zinc-800">
                {segments.map((s) => (
                  <div key={s.key} className="h-full border-r-2 border-zinc-950 last:border-r-0" style={{ width: `${(s.n / total) * 100}%`, background: s.fill }} title={`${s.label}: ${fmtNumber(s.n)}`} />
                ))}
              </div>
              <ul className="mt-2.5 flex flex-wrap gap-x-4 gap-y-1">
                {segments.map((s) => (
                  <li key={s.key} className="flex items-center gap-1.5 text-xs text-zinc-400">
                    <span className="h-2 w-2 shrink-0 rounded-sm" style={{ background: s.fill }} />
                    <span>{s.label}</span>
                    <span className="font-medium text-zinc-200 tabular-nums">{fmtNumber(s.n)}</span>
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <p className="text-sm text-zinc-500">{q.isPending ? 'Summarising…' : 'No CVEs match this query.'}</p>
          )}
        </div>

        <div className="flex shrink-0 gap-2 lg:flex-col lg:items-end">
          <div className="rounded-lg border border-red-400/20 bg-red-500/[0.07] px-3 py-1.5 text-center">
            <div className="font-mono text-base font-semibold text-red-300 tabular-nums">{fmtNumber(f?.kev ?? 0)}</div>
            <div className="text-[10px] tracking-wider text-red-300/70 uppercase">In CISA KEV{total > 0 ? ` · ${kevPct}%` : ''}</div>
          </div>
        </div>
      </div>
    </div>
  )
}
