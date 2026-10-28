import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router'
import { api } from '../api/client'
import { YearChart } from '../components/charts'
import { Card, ErrorBox, SeverityBar, SeverityStats, Spinner } from '../components/ui'
import { fmtDate, fmtNumber, productPath, vendorPath } from '../lib/format'
import { explorerLink } from '../lib/query'
import { CveResults } from './CveListPage'

export function VendorPage() {
  const { vendor = '' } = useParams()
  const query = useQuery({ queryKey: ['vendor', vendor], queryFn: () => api.getVendor(vendor) })
  const [filter, setFilter] = useState('')

  if (query.isPending) return <Spinner />
  if (query.isError) return <ErrorBox error={query.error} />
  const v = query.data
  const products = v.top_products.filter((p) => p.product.includes(filter.toLowerCase()))

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">{v.vendor}</h1>
        <p className="text-sm text-zinc-500">
          {fmtNumber(v.products)} products · latest CVE {fmtDate(v.latest_published)} ·{' '}
          <Link className="text-cyan-300 hover:text-cyan-200" to={explorerLink(`vendor:"${v.vendor}"`)}>browse all CVEs</Link>
        </p>
      </div>
      <Card>
        <SeverityStats counts={v} />
        <SeverityBar counts={v} className="mt-4 h-3" />
      </Card>
      <Card title="Published CVEs per year">
        <YearChart years={v.years} />
      </Card>
      <Card
        title={v.products > v.top_products.length ? `Top ${v.top_products.length} of ${fmtNumber(v.products)} products` : `Products (${v.products})`}
        actions={
          <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter products…"
            className="w-56 rounded border border-zinc-300 bg-white px-2 py-1 text-sm dark:border-zinc-700 dark:bg-zinc-950" />
        }
      >
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-200 text-left text-xs text-zinc-500 uppercase dark:border-zinc-800">
                <th className="py-2 pr-3 font-medium">Product</th>
                <th className="py-2 pr-3 text-right font-medium">CVEs</th>
                <th className="w-48 py-2 pr-3 font-medium">Severity mix</th>
                <th className="py-2 pr-3 text-right font-medium">KEV</th>
                <th className="py-2 font-medium">Latest</th>
              </tr>
            </thead>
            <tbody>
              {products.map((p) => (
                <tr key={p.product} className="border-b border-zinc-100 hover:bg-zinc-50 dark:border-zinc-800/60 dark:hover:bg-zinc-900">
                  <td className="py-1.5 pr-3">
                    <Link className="text-cyan-300 hover:text-cyan-200" to={productPath(v.vendor, p.product)}>{p.product}</Link>
                  </td>
                  <td className="py-1.5 pr-3 text-right tabular-nums">{fmtNumber(p.cves)}</td>
                  <td className="py-1.5 pr-3"><SeverityBar counts={p} /></td>
                  <td className="py-1.5 pr-3 text-right tabular-nums">{p.kev > 0 ? <span className="text-red-300">{p.kev}</span> : '—'}</td>
                  <td className="py-1.5 text-zinc-500">{fmtDate(p.latest_published)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}

export function ProductPage() {
  const { vendor = '', product = '' } = useParams()
  const query = useQuery({ queryKey: ['product', vendor, product], queryFn: () => api.getProduct(vendor, product) })
  const [view, setView] = useSearchParams()

  // The CVE list is fixed to this product; sort and paging live in the URL.
  const filters = new URLSearchParams({ vendor, product })

  if (query.isPending) return <Spinner />
  if (query.isError) return <ErrorBox error={query.error} />
  const p = query.data

  return (
    <div className="space-y-6">
      <div>
        <p className="text-sm">
          <Link className="text-cyan-300 hover:text-cyan-200" to={vendorPath(p.vendor)}>{p.vendor}</Link>
        </p>
        <h1 className="text-2xl font-bold">{p.product}</h1>
        <p className="text-sm text-zinc-500">Latest CVE {fmtDate(p.latest_published)}</p>
      </div>
      <Card>
        <SeverityStats counts={p} />
        <SeverityBar counts={p} className="mt-4 h-3" />
      </Card>
      <Card title="Published CVEs per year">
        <YearChart years={p.years} />
      </Card>
      <CveResults filters={filters} view={view} onView={setView} title={`CVEs affecting ${p.product}`} />
    </div>
  )
}
