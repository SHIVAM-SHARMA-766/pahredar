import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import { useDeferredValue } from 'react'
import { Link, useSearchParams } from 'react-router'
import { api } from '../api/client'
import type { ProductSummary, VendorSummary } from '../api/types'
import { Card, ErrorBox, PageHeader, SeverityBar, Spinner } from '../components/ui'
import { fmtDate, fmtNumber, productPath, vendorPath } from '../lib/format'

const link = 'text-cyan-300 hover:text-cyan-200'
const th = 'py-2.5 pr-3 text-[11px] font-semibold tracking-wider text-zinc-500 uppercase'

// One page, two tabs: `?tab=products` switches from vendors to products;
// `?q=` filters either by substring.
export function VendorsPage() {
  const [params, setParams] = useSearchParams()
  const tab = params.get('tab') === 'products' ? 'products' : 'vendors'
  const q = params.get('q') ?? ''
  const deferred = useDeferredValue(q.trim().toLowerCase())

  const set = (changes: Record<string, string>) => {
    const next = new URLSearchParams(params)
    for (const [k, v] of Object.entries(changes)) {
      if (v) next.set(k, v)
      else next.delete(k)
    }
    setParams(next, { replace: true })
  }

  return (
    <>
      <PageHeader
        title="Vendors & products"
        subtitle="Who ships the most vulnerabilities, and how severe they are. Spellings from CVE records and NVD CPEs are merged, so “Oracle Corporation” and “oracle” are one vendor."
      />
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="flex rounded-lg border border-zinc-800 bg-zinc-900 p-0.5">
          {(['vendors', 'products'] as const).map((t) => (
            <button
              key={t}
              onClick={() => set({ tab: t === 'vendors' ? '' : t })}
              className={`rounded-md px-4 py-1.5 text-sm font-medium capitalize ${tab === t ? 'bg-zinc-800 text-white' : 'text-zinc-400 hover:text-zinc-200'}`}
            >
              {t}
            </button>
          ))}
        </div>
        <div className="relative min-w-64 flex-1">
          <Search className="pointer-events-none absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-zinc-500" />
          <input
            value={q}
            onChange={(e) => set({ q: e.target.value })}
            placeholder={tab === 'vendors' ? 'Search vendors, e.g. fortinet' : 'Search products, e.g. log4j, exchange server'}
            className="w-full rounded-lg border border-zinc-800 bg-zinc-950 py-2 pr-3 pl-9 text-sm placeholder:text-zinc-500 focus:border-cyan-400/40 focus:ring-1 focus:ring-cyan-400/20 focus:outline-none"
          />
        </div>
      </div>
      {tab === 'vendors' ? <VendorList q={deferred} /> : <ProductList q={deferred} />}
    </>
  )
}

function VendorList({ q }: { q: string }) {
  const query = useQuery({ queryKey: ['vendors', q], queryFn: () => api.listVendors(q, 100), placeholderData: keepPreviousData })
  return (
    <Card title={q ? `Vendors matching “${q}”` : 'Top 100 vendors by CVE count'}>
      {query.isPending ? <Spinner /> : query.isError ? <ErrorBox error={query.error} /> : query.data.items.length === 0 ? (
        <p className="py-8 text-center text-sm text-zinc-500">No vendors match.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-sm">
            <thead>
              <tr className="border-b border-zinc-800 text-left">
                <th className={th}>Vendor</th>
                <th className={`${th} text-right`}>CVEs</th>
                <th className={`${th} w-52`}>Severity mix</th>
                <th className={`${th} text-right`}>Critical</th>
                <th className={`${th} text-right`}>KEV</th>
                <th className={`${th} text-right`}>Products</th>
                <th className={th}>Latest CVE</th>
              </tr>
            </thead>
            <tbody>{query.data.items.map((v) => <VendorRow key={v.vendor} v={v} />)}</tbody>
          </table>
        </div>
      )}
    </Card>
  )
}

function VendorRow({ v }: { v: VendorSummary }) {
  return (
    <tr className="border-b border-zinc-800/60 hover:bg-white/[0.02]">
      <td className="py-2 pr-3"><Link className={`font-medium ${link}`} to={vendorPath(v.vendor)}>{v.label}</Link></td>
      <td className="py-2 pr-3 text-right tabular-nums">{fmtNumber(v.cves)}</td>
      <td className="py-2 pr-3"><SeverityBar counts={v} /></td>
      <td className="py-2 pr-3 text-right tabular-nums text-zinc-300">{fmtNumber(v.critical)}</td>
      <td className="py-2 pr-3 text-right tabular-nums">{v.kev > 0 ? <span className="text-red-300">{fmtNumber(v.kev)}</span> : <span className="text-zinc-600">—</span>}</td>
      <td className="py-2 pr-3 text-right tabular-nums text-zinc-300">{fmtNumber(v.products)}</td>
      <td className="py-2 text-zinc-500 tabular-nums">{fmtDate(v.latest_published)}</td>
    </tr>
  )
}

function ProductList({ q }: { q: string }) {
  const query = useQuery({ queryKey: ['products', q], queryFn: () => api.listProducts(q, 100), placeholderData: keepPreviousData })
  return (
    <Card title={q ? `Products matching “${q}”` : 'Top 100 products by CVE count'}>
      {query.isPending ? <Spinner /> : query.isError ? <ErrorBox error={query.error} /> : query.data.items.length === 0 ? (
        <p className="py-8 text-center text-sm text-zinc-500">No products match.</p>
      ) : (
        <ProductTable items={query.data.items} showVendor />
      )}
    </Card>
  )
}

export function ProductTable({ items, showVendor = false }: { items: ProductSummary[]; showVendor?: boolean }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[720px] text-sm">
        <thead>
          <tr className="border-b border-zinc-800 text-left">
            <th className={th}>Product</th>
            {showVendor && <th className={th}>Vendor</th>}
            <th className={`${th} text-right`}>CVEs</th>
            <th className={`${th} w-52`}>Severity mix</th>
            <th className={`${th} text-right`}>Critical</th>
            <th className={`${th} text-right`}>KEV</th>
            <th className={th}>Latest CVE</th>
          </tr>
        </thead>
        <tbody>
          {items.map((p) => (
            <tr key={p.vendor + '/' + p.product} className="border-b border-zinc-800/60 hover:bg-white/[0.02]">
              <td className="py-2 pr-3"><Link className={`font-medium ${link}`} to={productPath(p.vendor, p.product)}>{p.label}</Link></td>
              {showVendor && <td className="py-2 pr-3"><Link className="text-zinc-300 hover:text-white" to={vendorPath(p.vendor)}>{p.vendor_label}</Link></td>}
              <td className="py-2 pr-3 text-right tabular-nums">{fmtNumber(p.cves)}</td>
              <td className="py-2 pr-3"><SeverityBar counts={p} /></td>
              <td className="py-2 pr-3 text-right tabular-nums text-zinc-300">{fmtNumber(p.critical)}</td>
              <td className="py-2 pr-3 text-right tabular-nums">{p.kev > 0 ? <span className="text-red-300">{fmtNumber(p.kev)}</span> : <span className="text-zinc-600">—</span>}</td>
              <td className="py-2 text-zinc-500 tabular-nums">{fmtDate(p.latest_published)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
