import type {
  Alert,
  Asset,
  AssetCVE,
  AttackMapping,
  CapecPattern,
  Channel,
  Client,
  CveDetail,
  EscalationPolicy,
  EscalationStep,
  EasmSummary,
  EasmRecord,
  EasmRun,
  EasmChangeSet,
  CveFacets,
  CveList,
  CveReports,
  DetectionRule,
  FeedArticle,
  FeedInfo,
  Incident,
  Me,
  NewsPage,
  OnCallSchedule,
  OnCallShift,
  NewsQuery,
  IPScanReport,
  ScanConfig,
  ScanJob,
  ScanReport,
  ScanSummary,
  Dashboard,
  ProductDetail,
  ProductSummary,
  RelatedGroup,
  Series,
  TrendingItem,
  Suppression,
  SyncStatus,
  User,
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

import { requireAuth } from '../lib/auth'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json', ...(init?.headers as Record<string, string>) }
  // Send the session cookie; the SPA authenticates by account, not API key.
  const res = await fetch(path, { ...init, headers, credentials: 'include' })
  const body = await res.json().catch(() => null)
  if (res.status === 401) {
    requireAuth()
    throw new ApiError(401, body?.error ?? 'unauthorized')
  }
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
  ipScan: (ip: string) => request<IPScanReport>(`/api/v1/ipscan?ip=${encodeURIComponent(ip)}`),
  assets: () => request<{ items: Asset[] }>('/api/v1/assets'),
  getAsset: (id: number) => request<Asset>(`/api/v1/assets/${id}`),
  createAsset: (body: { client_id: number; kind: string; value: string; label?: string; tags?: string[] }) =>
    request<{ id: number }>('/api/v1/assets', { method: 'POST', body: JSON.stringify(body) }),
  deleteAsset: (id: number) => request<{ deleted: number }>(`/api/v1/assets/${id}`, { method: 'DELETE' }),
  scanAsset: (id: number) => request<{ job_id: number }>(`/api/v1/assets/${id}/scan`, { method: 'POST' }),
  assetScans: (id: number) => request<{ items: ScanSummary[] }>(`/api/v1/assets/${id}/scans`),
  assetCves: (id: number) => request<{ items: AssetCVE[] }>(`/api/v1/assets/${id}/cves`),

  // Incidents (per-asset rollups).
  incidents: () => request<{ items: Incident[] }>('/api/v1/incidents'),
  incidentsUnread: () => request<{ unread: number }>('/api/v1/incidents/unread-count'),
  getIncident: (id: number) => request<Incident>(`/api/v1/incidents/${id}`),
  incidentItems: (id: number) => request<{ items: Alert[] }>(`/api/v1/incidents/${id}/items`),
  markIncidentRead: (id: number) => request<{ ok: boolean }>(`/api/v1/incidents/${id}/read`, { method: 'PUT' }),
  markAllIncidentsRead: () => request<{ ok: boolean }>('/api/v1/incidents/read-all', { method: 'PUT' }),
  acknowledgeIncident: (id: number) => request<{ ok: boolean }>(`/api/v1/incidents/${id}/acknowledge`, { method: 'PUT' }),
  resolveIncident: (id: number) => request<{ ok: boolean }>(`/api/v1/incidents/${id}/resolve`, { method: 'PUT' }),
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

  // Auth + accounts.
  me: () => request<Me>('/api/v1/auth/me'),
  login: (email: string, password: string) =>
    request<{ user: User }>('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    }),
  logout: () => request<{ ok: boolean }>('/api/v1/auth/logout', { method: 'POST' }),
  users: () => request<{ items: User[] }>('/api/v1/users'),
  createUser: (body: { email: string; password: string; role: string }) =>
    request<User>('/api/v1/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  updateUser: (id: number, body: { role?: string; disabled?: boolean }) =>
    request<User>(`/api/v1/users/${id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  resetUserPassword: (id: number, password: string) =>
    request<{ ok: boolean }>(`/api/v1/users/${id}/password`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }) }),
  deleteUser: (id: number) => request<{ deleted: number }>(`/api/v1/users/${id}`, { method: 'DELETE' }),

  // Clients (tenants).
  clients: () => request<{ items: Client[] }>('/api/v1/clients'),
  createClient: (body: { name: string; slug?: string; notes?: string }) =>
    request<Client>('/api/v1/clients', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  updateClient: (id: number, body: { name: string; notes?: string }) =>
    request<Client>(`/api/v1/clients/${id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  deleteClient: (id: number) => request<{ deleted: number }>(`/api/v1/clients/${id}`, { method: 'DELETE' }),
  userClients: (id: number) => request<{ items: Client[] }>(`/api/v1/users/${id}/clients`),
  setUserClients: (id: number, clientIds: number[]) =>
    request<{ ok: boolean }>(`/api/v1/users/${id}/clients`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ client_ids: clientIds }) }),

  // Notification channels.
  channels: () => request<{ items: Channel[] }>('/api/v1/channels'),
  createChannel: (body: { client_id?: number | null; type: string; name: string; target: string }) =>
    request<Channel>('/api/v1/channels', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  updateChannel: (id: number, body: { name?: string; target?: string; enabled?: boolean }) =>
    request<Channel>(`/api/v1/channels/${id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  deleteChannel: (id: number) => request<{ deleted: number }>(`/api/v1/channels/${id}`, { method: 'DELETE' }),

  // Escalation policies.
  escalationPolicies: () => request<{ items: EscalationPolicy[] }>('/api/v1/escalation-policies'),
  createEscalationPolicy: (body: { client_id?: number | null; name: string; is_default?: boolean; steps?: EscalationStep[] }) =>
    request<EscalationPolicy>('/api/v1/escalation-policies', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  updateEscalationPolicy: (id: number, body: { name?: string; is_default?: boolean }) =>
    request<EscalationPolicy>(`/api/v1/escalation-policies/${id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  setPolicySteps: (id: number, steps: EscalationStep[]) =>
    request<{ ok: boolean }>(`/api/v1/escalation-policies/${id}/steps`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ steps }) }),
  deleteEscalationPolicy: (id: number) => request<{ deleted: number }>(`/api/v1/escalation-policies/${id}`, { method: 'DELETE' }),

  // On-call schedules.
  oncallSchedules: () => request<{ items: OnCallSchedule[] }>('/api/v1/oncall-schedules'),
  createOncallSchedule: (body: { client_id?: number | null; name: string }) =>
    request<OnCallSchedule>('/api/v1/oncall-schedules', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  deleteOncallSchedule: (id: number) => request<{ deleted: number }>(`/api/v1/oncall-schedules/${id}`, { method: 'DELETE' }),
  addOncallShift: (id: number, body: { user_id: number; starts_at: string; ends_at: string }) =>
    request<OnCallShift>(`/api/v1/oncall-schedules/${id}/shifts`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  deleteOncallShift: (id: number) => request<{ deleted: number }>(`/api/v1/oncall-shifts/${id}`, { method: 'DELETE' }),

  // Suppression windows.
  suppressions: () => request<{ items: Suppression[] }>('/api/v1/suppressions'),
  createSuppression: (body: { client_id?: number | null; asset_id?: number | null; reason?: string; starts_at: string; ends_at: string }) =>
    request<Suppression>('/api/v1/suppressions', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  deleteSuppression: (id: number) => request<{ deleted: number }>(`/api/v1/suppressions/${id}`, { method: 'DELETE' }),

  // EASM (attack surface).
  easmScan: (assetId: number, profile: string, authorized = false) =>
    request<{ job_id: number }>('/api/v1/easm/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ asset_id: assetId, profile, authorized }) }),
  easmSummary: (assetId: number) => request<EasmSummary>(`/api/v1/easm/assets/${assetId}/summary`),
  easmRecords: (assetId: number, category?: string) =>
    request<{ items: EasmRecord[] }>(`/api/v1/easm/assets/${assetId}/records${category ? `?category=${encodeURIComponent(category)}` : ''}`),
  easmRuns: (assetId: number) => request<{ items: EasmRun[] }>(`/api/v1/easm/assets/${assetId}/runs`),
  easmPromote: (parentAssetId: number, value: string) =>
    request<{ id: number }>('/api/v1/easm/promote', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ parent_asset_id: parentAssetId, value }) }),
  easmAnalyzeDeps: (assetId: number) =>
    request<{ job_id: number; dependencies: number }>(`/api/v1/easm/assets/${assetId}/analyze-deps`, { method: 'POST' }),
  easmChanges: (assetId: number, since?: number) =>
    request<EasmChangeSet>(`/api/v1/easm/assets/${assetId}/changes${since ? `?since=${since}` : ''}`),
  // Report export is a browser file download (cookie-authenticated, same origin).
  easmReportUrl: (assetId: number, format: 'csv' | 'html') =>
    `/api/v1/easm/assets/${assetId}/report?format=${format}`,
}
