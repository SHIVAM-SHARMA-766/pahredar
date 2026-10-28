import { useQuery } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import { useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router'
import { api } from '../api/client'
import { YearChart } from '../components/charts'
import { Card, ErrorBox, PageHeader, SeverityBar, SeverityStats, Spinner } from '../components/ui'
import { fmtDate, fmtNumber, vendorPath } from '../lib/format'
import { explorerLink } from '../lib/query'
import { CveResults } from './CveListPage'
import { ProductTable } from './VendorsPage'

const link = 'text-cyan-300 hover:text-cyan-200'

export function VendorPage() {
  const { vendor = '' } = useParams()
  const query = useQuery({ queryKey: ['vendor', vendor], queryFn: () => api.getVendor(vendor) })
  const [filter, setFilter] = useState('')

  if (query.isPending) return <Spinner />
  if (query.isError) return <ErrorBox error={query.error} />
  const v = query.data
  const f = filter.trim().toLowerCase()
  const products = v.top_products.filter((p) => !f || p.product.includes(f) || p.label.toLowerCase().includes(f))

  return (
    <div className="space-y-6">
      <div>
        <Link to="/vendors" className="text-xs text-zinc-500 hover:text-zinc-300">← Vendors & products</Link>
        <PageHeader
          title={v.label}
          subtitle={<>{fmtNumber(v.products)} products · latest CVE {fmtDate(v.latest_published)}</>}
          actions={
            <div className="flex gap-2">
              <Link className="rounded-md border border-zinc-800 px-3 py-1.5 text-sm text-zinc-200 hover:bg-zinc-800" to={explorerLink(`vendor:"${v.vendor}"`)}>All CVEs</Link>
              <Link className="rounded-md border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-sm text-cyan-200 hover:bg-cyan-500/15" to={explorerLink(`vendor:"${v.vendor}" is:kev`, 'kev_added')}>Known exploited</Link>
            </div>
          }
        />
      </div>
      <Card>
        <SeverityStats counts={v} />
        <SeverityBar counts={v} className="mt-4 h-2.5" />
      </Card>
      <Card title="Published CVEs per year">
        <YearChart years={v.years} />
      </Card>
      <Card
        title={v.products > v.top_products.length ? `Top ${v.top_products.length} of ${fmtNumber(v.products)} products` : `Products (${v.products})`}
        actions={
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
            <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter products…"
              className="w-56 rounded-md border border-zinc-800 bg-zinc-950 py-1.5 pr-2 pl-8 text-sm placeholder:text-zinc-500 focus:border-cyan-400/40 focus:outline-none" />
          </div>
        }
      >
        {products.length === 0 ? <p className="py-6 text-center text-sm text-zinc-500">No products match.</p> : <ProductTable items={products} />}
      </Card>
    </div>
  )
}

export function ProductPage() {
  const { vendor = '', product = '' } = useParams()
  const query = useQuery({ queryKey: ['product', vendor, product], queryFn: () => api.getProduct(vendor, product) })
  const [view, setView] = useSearchParams()

  if (query.isPending) return <Spinner />
  if (query.isError) return <ErrorBox error={query.error} />
  const p = query.data
  // The CVE list is fixed to this product; sort and paging live in the URL.
  const filters = new URLSearchParams({ vendor: p.vendor, product: p.product })

  return (
    <div className="space-y-6">
      <div>
        <Link to={vendorPath(p.vendor)} className={`text-sm ${link}`}>← {p.vendor_label}</Link>
        <PageHeader title={p.label} subtitle={<>Latest CVE {fmtDate(p.latest_published)}</>} />
      </div>
      <Card>
        <SeverityStats counts={p} />
        <SeverityBar counts={p} className="mt-4 h-2.5" />
      </Card>
      <Card title="Published CVEs per year">
        <YearChart years={p.years} />
      </Card>
      <CveResults filters={filters} view={view} onView={setView} title={`CVEs affecting ${p.label}`} />
    </div>
  )
}
