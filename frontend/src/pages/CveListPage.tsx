import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router'
import { api } from '../api/client'
import { CveTable, type SortKey } from '../components/CveTable'
import { QueryBar } from '../components/QueryBar'
import { Card, ErrorBox, PageHeader, Spinner } from '../components/ui'
import { fmtNumber } from '../lib/format'
import { parseQuery } from '../lib/query'

// URL parameters of the explorer: `query` (the query language), plus `sort`,
// `order`, `page`, and `page_size`, which pass through to the API.
const PAGE_SIZES = [50, 100, 250]
const DEFAULT_PAGE_SIZE = 50

// The sidebar's saved views are queries; name the page after the one in use
// so the header matches the highlighted nav item.
function viewTitle(query: string): [string, string] {
  if (query === 'is:kev') {
    return ['Known exploited', 'CVEs in the CISA Known Exploited Vulnerabilities catalog — attackers are using these now.']
  }
  if (query === 'epss:>10 -is:kev') {
    return ['Likely exploited', 'Not yet in KEV, ranked by EPSS: the probability of exploitation activity in the next 30 days.']
  }
  return ['CVE explorer', 'Search every CVE in the CVE List, enriched with NVD, CISA KEV, EPSS, and public exploits.']
}

export function CveListPage() {
  const [params, setParams] = useSearchParams()
  const query = params.get('query') ?? ''
  const parsed = parseQuery(query)
  const [title, subtitle] = viewTitle(query)

  const submit = (q: string) => {
    const next = new URLSearchParams(params)
    if (q) next.set('query', q)
    else next.delete('query')
    next.delete('page')
    setParams(next)
  }

  return (
    <>
      <PageHeader title={title} subtitle={subtitle} />
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
  const btn = 'rounded-md border border-zinc-800 px-2.5 py-1 text-xs text-zinc-300 hover:bg-zinc-800 disabled:opacity-40 disabled:hover:bg-transparent'

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
          <div className="flex gap-1.5">
            <button className={btn} disabled={page <= 1} onClick={() => goto(page - 1)}>Previous</button>
            <button className={btn} disabled={page >= lastPage} onClick={() => goto(page + 1)}>Next</button>
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
        </div>
      )}
    </Card>
  )
}
