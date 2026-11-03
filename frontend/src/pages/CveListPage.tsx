import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router'
import { api } from '../api/client'
import { CveTable, type SortKey } from '../components/CveTable'
import { QueryBar } from '../components/QueryBar'
import { Card, ErrorBox, PageHeader, Spinner } from '../components/ui'
import { fmtNumber } from '../lib/format'
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
      <div className="mb-4 flex flex-wrap items-end gap-1 border-b border-zinc-800" role="tablist" aria-label="Saved views">
        {VIEWS.map((v) => (
          <button
            key={v.key}
            role="tab"
            aria-selected={view?.key === v.key}
            onClick={() => pickView(v)}
            className={`-mb-px border-b-2 px-3.5 py-2 text-sm font-medium transition-colors ${view?.key === v.key ? 'border-cyan-400 text-white' : 'border-transparent text-zinc-400 hover:border-zinc-600 hover:text-zinc-200'}`}
          >
            {v.label}
          </button>
        ))}
        {!view && <span className="-mb-px border-b-2 border-cyan-400/60 px-3.5 py-2 text-sm font-medium text-zinc-200">Custom search</span>}
      </div>
      {view && <p className="-mt-2 mb-3 text-xs text-zinc-500">{view.hint}</p>}
      <div className="space-y-4">
        <QueryBar value={query} onSubmit={submit} errors={parsed.errors} />
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
