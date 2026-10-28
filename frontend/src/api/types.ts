// Response shapes of the backend API (backend/internal/api, ARCHITECTURE.md §8).
// Keep in sync with the Go structs' JSON tags.

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' | 'UNKNOWN'
export type Provider = 'cna' | 'adp' | 'nvd'

export interface CveSummary {
  id: string
  state: 'PUBLISHED' | 'REJECTED'
  assigner: string | null
  title: string | null
  description: string | null
  severity: Severity
  severity_source: string | null
  cvss_v4_score: number | null
  cvss_v3_score: number | null
  cvss_v2_score: number | null
  date_published: string | null
  date_updated: string | null
  kev: boolean
  kev_date_added: string | null
  ransomware: boolean
  epss_score: number | null
  epss_percentile: number | null
  has_exploit: boolean
  vendor: string | null
  ssvc_exploitation: string | null
}

export interface CveList {
  items: CveSummary[]
  total: number
  page: number
  page_size: number
}

export interface Metric {
  provider: Provider
  provider_name?: string
  version: string
  score: number
  vector: string
  severity: Severity
}

export interface Ssvc {
  exploitation?: string
  automatable?: string
  technical_impact?: string
}

export interface Kev {
  vendor_project: string | null
  product: string | null
  vulnerability_name: string | null
  short_description: string | null
  required_action: string | null
  date_added: string
  due_date: string | null
  known_ransomware_use: string | null
  forensic_triage: string | null
  notes: string | null
}

export interface EpssPoint {
  score_date: string
  score: number
  percentile: number
}

export interface Epss extends EpssPoint {
  history: EpssPoint[]
}

export interface Exploit {
  source: 'exploitdb' | 'metasploit' | 'nuclei'
  source_ref: string
  title: string | null
  url: string | null
  published_at: string | null
}

export interface TimelineEvent {
  date: string
  type: string
  detail?: string
}

export interface Reference {
  url: string
  name?: string
  tags?: string[]
}

// CNA/ADP version entries (CVE JSON 5).
export interface CnaVersion {
  version?: string
  status?: string
  lessThan?: string
  lessThanOrEqual?: string
  versionType?: string
}

// NVD cpeMatch entries.
export interface CpeMatch {
  vulnerable: boolean
  criteria: string
  versionStartIncluding?: string
  versionStartExcluding?: string
  versionEndIncluding?: string
  versionEndExcluding?: string
}

export interface Affected {
  source: Provider
  vendor: string
  product: string
  cpes: string[]
  versions: CnaVersion[] | CpeMatch[]
}

export interface CveDetail {
  id: string
  state: 'PUBLISHED' | 'REJECTED'
  assigner: string | null
  date_reserved: string | null
  date_published: string | null
  date_updated: string | null
  title: string | null
  description: string | null
  cwe_ids: string[]
  severity: Severity
  severity_source: string | null
  cvss: { v4: Metric | null; v3: Metric | null; v2: Metric | null }
  metrics: Metric[]
  ssvc: Ssvc | null
  nvd_status: string | null
  nvd_last_modified: string | null
  has_exploit: boolean
  kev: Kev | null
  epss: Epss | null
  exploits: Exploit[]
  timeline: TimelineEvent[]
  references: Reference[]
  affected: Affected[]
}

export interface SeverityCounts {
  cves: number
  critical: number
  high: number
  medium: number
  low: number
  kev: number
  latest_published: string | null
}

export interface VendorSummary extends SeverityCounts {
  vendor: string
  products: number
}

export interface ProductSummary extends SeverityCounts {
  vendor: string
  product: string
}

export interface YearCount {
  year: number
  cves: number
}

export interface VendorDetail extends VendorSummary {
  years: YearCount[]
  top_products: ProductSummary[]
}

export interface ProductDetail extends ProductSummary {
  years: YearCount[]
}

export interface SyncState {
  source: string
  cursor: string | null
  last_success_at: string | null
}

export interface SyncRun {
  id: number
  source: string
  kind: 'bootstrap' | 'incremental'
  status: 'running' | 'success' | 'failed'
  started_at: string
  finished_at: string | null
  inserted: number
  updated: number
  deleted: number
  error: string | null
}

export interface SyncStatus {
  scheduler_enabled: boolean
  sources: SyncState[]
  recent_runs: SyncRun[]
}

export interface SeverityMix {
  critical: number
  high: number
  medium: number
  low: number
  // NONE plus UNKNOWN (not yet scored).
  other: number
}

export interface DailyCount extends SeverityMix {
  date: string
}

export interface EpssMover {
  id: string
  title: string | null
  severity: Severity
  kev: boolean
  from: number
  to: number
  score_date: string
}

export interface Dashboard {
  generated_at: string
  published_today: number
  published_7d: number
  published_30d: number
  critical_7d: number
  total_published: number
  kev_total: number
  kev_added_30d: number
  severity_30d: SeverityMix
  daily: DailyCount[]
  epss_movers: EpssMover[]
}
