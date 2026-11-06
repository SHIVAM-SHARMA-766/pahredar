import type {
  Asset,
  AttackMapping,
  CapecPattern,
  CveDetail,
  CveFacets,
  CveList,
  CveReports,
  DetectionRule,
  FeedArticle,
  FeedInfo,
  NewsPage,
  NewsQuery,
  ScanConfig,
  ScanRequestResult,
  ScanRequestSpec,
  ScanJob,
  ScanReport,
  ScanSummary,
  Dashboard,
  ProductDetail,
  ProductSummary,
  RelatedGroup,
  Series,
  TrendingItem,
  SyncStatus,
  VendorDetail,
  VendorSummary,
} from './types'

export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { ...init, headers: { Accept: 'application/json', ...init?.headers } })
  const body = await res.json().catch(() => null)
  if (!res.ok) {
    throw new ApiError(res.status, body?.error ?? res.statusText)
  }
  return body as T
}

const enc = encodeURIComponent

export const api = {
  dashboard: () => request<Dashboard>('/api/v1/stats/dashboard'),
  listCves: (params: URLSearchParams) => request<CveList>(`/api/v1/cves?${params}`),
  cveFacets: (params: URLSearchParams) => request<CveFacets>(`/api/v1/cves/facets?${params}`),
  getCve: (id: string) => request<CveDetail>(`/api/v1/cves/${enc(id)}`),
  getCveReports: (id: string, sources: string[]) =>
    request<CveReports>(`/api/v1/cves/${enc(id)}/reports?${new URLSearchParams({ sources: sources.join(',') })}`),
  getAttack: (id: string) => request<{ mappings: AttackMapping[]; capec: CapecPattern[] }>(`/api/v1/cves/${enc(id)}/attack`),
  getDetection: (id: string) => request<{ rules: DetectionRule[] }>(`/api/v1/cves/${enc(id)}/detection`),
  getArticles: (id: string) => request<{ items: FeedArticle[] }>(`/api/v1/cves/${enc(id)}/articles`),
  trending: (days = 7, limit = 10) =>
    request<{ days: number; items: TrendingItem[] }>(`/api/v1/stats/trending?${new URLSearchParams({ days: String(days), limit: String(limit) })}`),
  latestAdvisories: (limit = 10) => request<{ items: FeedArticle[] }>(`/api/v1/feeds/advisories?limit=${limit}`),
  feeds: () => request<{ items: FeedInfo[] }>('/api/v1/feeds'),
  news: (q: NewsQuery) => {
    const p = new URLSearchParams()
    for (const [k, v] of Object.entries(q)) {
      if (v === undefined || v === '' || v === false) continue
      p.set(k, v === true ? '1' : String(v))
    }
    return request<NewsPage>(`/api/v1/news?${p}`)
  },
  scan: (target: string, opts: { fresh?: boolean; active?: boolean; authorized?: boolean; templates?: { tags?: string[]; severity?: string[]; ids?: string[] } } = {}) =>
    request<{ id: number }>('/api/v1/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, ...opts }),
    }),
  scanJob: (id: number) => request<ScanJob>(`/api/v1/scan/jobs/${id}`),
  scanConfig: () => request<ScanConfig>('/api/v1/scan/config'),
  assets: () => request<{ items: Asset[] }>('/api/v1/assets'),
  getAsset: (id: number) => request<Asset>(`/api/v1/assets/${id}`),
  createAsset: (body: { kind: string; value: string; label?: string; tags?: string[] }) =>
    request<{ id: number }>('/api/v1/assets', { method: 'POST', body: JSON.stringify(body) }),
  deleteAsset: (id: number) => request<{ deleted: number }>(`/api/v1/assets/${id}`, { method: 'DELETE' }),
  scanAsset: (id: number) => request<{ job_id: number }>(`/api/v1/assets/${id}/scan`, { method: 'POST' }),
  assetScans: (id: number) => request<{ items: ScanSummary[] }>(`/api/v1/assets/${id}/scans`),
  scanRequest: (spec: ScanRequestSpec) => request<ScanRequestResult>('/api/v1/scan/request', { method: 'POST', body: JSON.stringify(spec) }),
  recentScans: () => request<{ items: ScanSummary[] }>('/api/v1/scans'),
  getScan: (id: number) => request<ScanReport>(`/api/v1/scans/${id}`),
  setBookmark: (url: string, bookmarked: boolean) =>
    request<{ url: string; bookmarked: boolean }>('/api/v1/news/bookmark', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, bookmarked }),
    }),
  getRelated: (id: string) => request<{ groups: RelatedGroup[] }>(`/api/v1/cves/${enc(id)}/related`),
  series: (metric: string, from: string, to: string) =>
    request<Series>(`/api/v1/stats/series?${new URLSearchParams({ metric, from, to })}`),
  listVendors: (q: string, pageSize = 50) =>
    request<{ items: VendorSummary[] }>(`/api/v1/vendors?${new URLSearchParams({ q, page_size: String(pageSize) })}`),
  listProducts: (q: string, pageSize = 50) =>
    request<{ items: ProductSummary[] }>(`/api/v1/products?${new URLSearchParams({ q, page_size: String(pageSize) })}`),
  getVendor: (vendor: string) => request<VendorDetail>(`/api/v1/vendors/${enc(vendor)}`),
  getProduct: (vendor: string, product: string) =>
    request<ProductDetail>(`/api/v1/vendors/${enc(vendor)}/products/${enc(product)}`),
  syncStatus: () => request<SyncStatus>('/api/v1/sync/status'),
  triggerSync: (source: string) =>
    request<{ status: string; source: string }>(`/api/v1/sync/${enc(source)}`, { method: 'POST' }),
}
