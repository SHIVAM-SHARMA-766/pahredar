import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useDeferredValue } from 'react'
import { Link, useSearchParams } from 'react-router'
import { api } from '../api/client'
import { Card, ErrorBox, PageHeader, SeverityBar, Spinner } from '../components/ui'
import { fmtDate, fmtNumber, vendorPath } from '../lib/format'

export function VendorsPage() {
  const [params, setParams] = useSearchParams()
  const q = params.get('q') ?? ''
  const deferred = useDeferredValue(q)
  const query = useQuery({
    queryKey: ['vendors', deferred],
    queryFn: () => api.listVendors(deferred, 100),
    placeholderData: keepPreviousData,
  })

  return (
    <>
    <PageHeader title="Vendors & products" subtitle="Who ships the most vulnerabilities, and how severe they are. Names come from CNA records and NVD CPEs, so one vendor can appear under two spellings." />
    <Card
      title={deferred ? `Vendors matching “${deferred}”` : 'Vendors by CVE count'}
      actions={
        <input
          value={q}
          onChange={(e) => setParams(e.target.value ? { q: e.target.value } : {}, { replace: true })}
          placeholder="Search vendors…"
          className="w-64 rounded border border-zinc-300 bg-white px-2 py-1 text-sm dark:border-zinc-700 dark:bg-zinc-950"
        />
      }
    >
      {query.isPending ? (
        <Spinner />
      ) : query.isError ? (
        <ErrorBox error={query.error} />
      ) : query.data.items.length === 0 ? (
        <p className="py-8 text-center text-sm text-zinc-500">No vendors match.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-200 text-left text-xs text-zinc-500 uppercase dark:border-zinc-800">
                <th className="py-2 pr-3 font-medium">Vendor</th>
                <th className="py-2 pr-3 text-right font-medium">CVEs</th>
                <th className="w-48 py-2 pr-3 font-medium">Severity mix</th>
                <th className="py-2 pr-3 text-right font-medium">KEV</th>
                <th className="py-2 pr-3 text-right font-medium">Products</th>
                <th className="py-2 font-medium">Latest</th>
              </tr>
            </thead>
            <tbody>
              {query.data.items.map((v) => (
                <tr key={v.vendor} className="border-b border-zinc-100 hover:bg-zinc-50 dark:border-zinc-800/60 dark:hover:bg-zinc-900">
                  <td className="py-1.5 pr-3">
                    <Link className="text-cyan-300 hover:text-cyan-200" to={vendorPath(v.vendor)}>{v.vendor}</Link>
                  </td>
                  <td className="py-1.5 pr-3 text-right tabular-nums">{fmtNumber(v.cves)}</td>
                  <td className="py-1.5 pr-3"><SeverityBar counts={v} /></td>
                  <td className="py-1.5 pr-3 text-right tabular-nums">{v.kev > 0 ? <span className="text-red-300">{v.kev}</span> : '—'}</td>
                  <td className="py-1.5 pr-3 text-right tabular-nums">{fmtNumber(v.products)}</td>
                  <td className="py-1.5 text-zinc-500">{fmtDate(v.latest_published)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
    </>
  )
}
