import type {
  CveDetail,
  CveList,
  Dashboard,
  ProductDetail,
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
  getCve: (id: string) => request<CveDetail>(`/api/v1/cves/${enc(id)}`),
  listVendors: (q: string, pageSize = 50) =>
    request<{ items: VendorSummary[] }>(`/api/v1/vendors?${new URLSearchParams({ q, page_size: String(pageSize) })}`),
  getVendor: (vendor: string) => request<VendorDetail>(`/api/v1/vendors/${enc(vendor)}`),
  getProduct: (vendor: string, product: string) =>
    request<ProductDetail>(`/api/v1/vendors/${enc(vendor)}/products/${enc(product)}`),
  syncStatus: () => request<SyncStatus>('/api/v1/sync/status'),
  triggerSync: (source: string) =>
    request<{ status: string; source: string }>(`/api/v1/sync/${enc(source)}`, { method: 'POST' }),
}
