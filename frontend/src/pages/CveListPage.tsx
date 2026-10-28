import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router'
import { api } from '../api/client'
import { CveFilters, SortControl } from '../components/CveFilters'
import { CveTable } from '../components/CveTable'
import { Card, ErrorBox, Pagination, Spinner } from '../components/ui'

export function CveListPage() {
  const [params, setParams] = useSearchParams()
  return (
    <div className="grid gap-6 lg:grid-cols-[16rem_1fr]">
      <aside>
        <Card title="Filters" actions={params.size > 0 && <button className="text-xs text-blue-700 hover:underline dark:text-blue-400" onClick={() => setParams({})}>Clear</button>}>
          <CveFilters params={params} onChange={setParams} />
        </Card>
      </aside>
      <CveResults params={params} onChange={setParams} />
    </div>
  )
}

// CveResults is the sortable, paginated table for a filter set; the product
// page reuses it with vendor/product fixed.
export function CveResults({ params, onChange, title = 'CVEs' }: { params: URLSearchParams; onChange: (p: URLSearchParams) => void; title?: string }) {
  const query = useQuery({
    queryKey: ['cves', params.toString()],
    queryFn: () => api.listCves(params),
    placeholderData: keepPreviousData,
  })
  const page = Number(params.get('page') ?? '1')
  const setPage = (p: number) => {
    const next = new URLSearchParams(params)
    next.set('page', String(p))
    onChange(next)
    window.scrollTo({ top: 0 })
  }

  return (
    <Card title={title} actions={<SortControl params={params} onChange={onChange} />}>
      {query.isPending ? (
        <Spinner />
      ) : query.isError ? (
        <ErrorBox error={query.error} />
      ) : (
        <div className={`space-y-4 ${query.isPlaceholderData ? 'opacity-60' : ''}`}>
          <Pagination page={page} pageSize={query.data.page_size} total={query.data.total} onPage={setPage} />
          <CveTable items={query.data.items} />
          {query.data.total > query.data.page_size && (
            <Pagination page={page} pageSize={query.data.page_size} total={query.data.total} onPage={setPage} />
          )}
        </div>
      )}
    </Card>
  )
}
