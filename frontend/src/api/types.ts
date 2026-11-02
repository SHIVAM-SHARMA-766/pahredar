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
  source: 'exploitdb' | 'metasploit' | 'nuclei' | 'github'
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
  // Canonical keys (URLs, filters) and published spellings (display).
  vendor: string
  product: string
  vendor_label: string
  product_label: string
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
  cwes: { id: string; name: string | null }[]
  severity: Severity
  severity_source: string | null
  cvss: { v4: Metric | null; v3: Metric | null; v2: Metric | null }
  metrics: Metric[]
  ssvc: Ssvc | null
  nvd_status: string | null
  nvd_last_modified: string | null
  has_exploit: boolean
  assessment: Assessment
  advisory: Advisory
  kev: Kev | null
  epss: Epss | null
  exploits: Exploit[]
  timeline: TimelineEvent[]
  references: Reference[]
  affected: Affected[]
}

export interface Assessment {
  exploitation: 'active' | 'poc' | 'none'
  // P1 patch now … P4 monitor; empty for rejected CVEs.
  priority: 'P1' | 'P2' | 'P3' | 'P4' | ''
  reasons: string[]
}

export interface Advisory {
  solutions: string[]
  workarounds: string[]
  exploit_statements: string[]
  configurations: string[]
  credits: { name: string; type?: string }[]
  capec: { id: string; description: string }[]
  timeline: { date: string; value: string }[]
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
  label: string
  products: number
}

export interface ProductSummary extends SeverityCounts {
  vendor: string
  vendor_label: string
  product: string
  label: string
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

export interface Series {
  metric: string
  label: string
  // Stacking order, bottom first.
  keys: { key: string; label: string }[]
  // One point per UTC day, every key present.
  points: { date: string; values: Record<string, number> }[]
}

export interface ReportStatus {
  source: 'osv' | 'redhat' | 'ubuntu'
  status: 'ok' | 'not_found' | 'error'
  fetched_at: string | null
  error?: string
}

export interface OsvAdvisory {
  id: string
  summary?: string
  details?: string
  published?: string
  modified?: string
  affected: { ecosystem: string; package: string; introduced: string[]; fixed: string[]; last_affected: string[] }[]
  references: { type?: string; url: string }[]
  url: string
}

export interface RedHatReport {
  threat_severity?: string
  public_date?: string
  statement?: string
  mitigation?: string
  summary?: string
  bugzilla_url?: string
  details: string[]
  cvss3_score?: string
  cvss3_vector?: string
  cwe?: string
  fixed_in: { product: string; package?: string; advisory?: string; release_date?: string }[]
  states: { product: string; package: string; fix_state: string }[]
  url: string
}

export interface UbuntuReport {
  priority?: string
  description?: string
  ubuntu_description?: string
  mitigation?: string
  notes: { author: string; note: string }[]
  packages: { name: string; statuses: { release: string; status: string; description?: string }[] }[]
  url: string
}

export interface CveReports {
  sources: ReportStatus[]
  reports: { osv?: OsvAdvisory[]; redhat?: RedHatReport; ubuntu?: UbuntuReport }
}
