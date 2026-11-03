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

// Severity breakdown + KEV count for a filter set (GET /api/v1/cves/facets),
// used by the explorer's graphical overview strip.
export interface CveFacets {
  total: number
  severity: Record<string, number>
  kev: number
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
  source: 'exploitdb' | 'metasploit' | 'nuclei' | 'github' | 'trickest'
  source_ref: string
  title: string | null
  url: string | null
  published_at: string | null
  // Metasploit: module type, non-destructive check, default port, targets.
  // Nuclei: severity and protocol (top-level template folder). Else null.
  meta: { type?: string; check?: boolean; rport?: string | number; targets?: string[]; post_auth?: boolean; aka?: string[]; severity?: string; protocol?: string } | null
}

export interface DetectionRule {
  source: 'sigma' | 'suricata' | 'nmap' | 'splunk' | 'elastic' | 'snort' | 'yara' | 'greenbone'
  rule_id: string
  title: string
  url: string | null
  // Sigma: the rule YAML. Suricata / Snort: the rule line. Nmap: the script
  // file name. Splunk: the SPL search. Elastic: the query. YARA: the rule.
  body: string
  meta: {
    // Sigma
    level?: string
    status?: string
    author?: string
    date?: string
    logsource?: { product?: string; service?: string; category?: string }
    attack?: string[]
    // Suricata
    enabled?: boolean
    classtype?: string
    signature_severity?: string
    confidence?: string
    created_at?: string
    updated_at?: string
    // Nmap
    categories?: string[]
    // Splunk, Elastic, Snort, YARA
    license?: string
    // The CVE is cited only in the rule's references: a behaviour rule
    // that also catches this CVE rather than one written for it.
    related?: boolean
    description?: string
    type?: string
    data_source?: string[]
    how_to_implement?: string
    language?: string
    severity?: string
    risk_score?: number
    index?: string[]
    name?: string
    score?: string
    file?: string
    reference?: string
    // YARA: modules the rule uses, and the texts of the file's other rules
    // its condition needs (dependencies first).
    imports?: string[]
    requires?: string[]
    // Greenbone: test family, how it checks (remote: over the network;
    // authenticated: needs SSH / SMB credentials), quality-of-detection type.
    family?: string
    check?: 'remote' | 'authenticated'
    qod_type?: string
    solution_type?: string
    cvss_vector?: string
    modified?: string
  }
  cve_ids: string[]
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
  // Nicknames such as "Log4Shell".
  aliases: string[]
  // ENISA EUVD's exploited list.
  euvd: { euvd_id: string; exploited_since: string | null } | null
  // VulnCheck KEV (only when VULNCHECK_API_TOKEN is set).
  vulncheck: VulnCheckKev | null
  debian: DebianStatus[]
}

export interface VulnCheckKev {
  name: string | null
  date_added: string | null
  ransomware: boolean
  // VulnCheck's own canaries saw exploitation.
  canary: boolean
  reported: { url: string; date_added?: string }[]
  xdb: { id: string; url: string; type?: string; repo?: string; date_added?: string }[]
}

export interface DebianStatus {
  package: string
  release: string
  status: 'resolved' | 'open' | 'undetermined' | string
  // "0" means the release was never affected.
  fixed_version: string | null
  urgency: string | null
}

export interface AttackMapping {
  technique_id: string
  mapping_type: 'exploitation_technique' | 'primary_impact' | 'secondary_impact' | 'uncategorized' | string
  technique_name: string
  capability_group: string | null
  comments: string | null
  refs: string[]
}

export interface CapecPattern {
  id: string
  name: string
  abstraction: string | null
  likelihood: string | null
  severity: string | null
  description: string | null
  prerequisites: string[]
  execution_flow: string[]
  indicators: string[]
  mitigations: string[]
  cwes: string[]
  attack: { id: string; name: string }[]
}

export interface HistoryChange {
  event: string
  created: string
  source?: string
  details: { action: string; type: string; old?: string; new?: string }[]
}

export interface Commit {
  repo: string
  sha: string
  url: string
  message: string
  author?: string
  date?: string
  additions: number
  deletions: number
  files: { name: string; status: string; additions: number; deletions: number; patch?: string; truncated?: boolean }[]
  more_files?: number
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

export type ReportSource = 'osv' | 'redhat' | 'ubuntu' | 'msrc' | 'advisories' | 'news' | 'discussions' | 'history' | 'commits' | 'otx' | 'threatfox' | 'bluesky' | 'mastodon'

export interface ReportStatus {
  source: ReportSource
  // disabled: the source's key is not set in .env.
  status: 'ok' | 'not_found' | 'error' | 'disabled'
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
  reports: {
    osv?: OsvAdvisory[]
    redhat?: RedHatReport
    ubuntu?: UbuntuReport
    msrc?: MsrcReport
    advisories?: AdvisoryPreview[]
    news?: NewsItem[]
    discussions?: NewsItem[]
    history?: HistoryChange[]
    commits?: Commit[]
    otx?: OtxReport
    threatfox?: ThreatFoxReport
    bluesky?: NewsItem[]
    mastodon?: NewsItem[]
  }
}

export interface OtxReport {
  pulse_count: number
  // Pulses naming more than 10 CVEs (daily digests, scanner lists); not shown.
  bulk_pulses: number
  pulses: OtxPulse[]
  adversaries: string[]
  malware: string[]
  industries: string[]
  countries: string[]
  techniques: { id: string; name: string }[]
  url: string
}

export interface OtxPulse {
  id: string
  name: string
  url: string
  created: string
  modified: string
  author: string
  adversary?: string
  malware: string[]
  industries: string[]
  countries: string[]
  techniques: string[]
  tags: string[]
  indicators: number
  references: string[]
}

export interface ThreatFoxReport {
  iocs: { ioc: string; type: string; threat_type: string; malware: string; confidence: number; first_seen: string; last_seen?: string; reporter?: string; reference?: string; tags: string[]; url: string }[]
  malware: { name: string; malpedia?: string; iocs: number }[]
  url: string
}

export interface MsrcReport {
  title: string
  release_date?: string
  severity?: string
  impact?: string
  exploited?: string
  publicly_disclosed?: string
  products: {
    family?: string
    product: string
    severity?: string
    action_required: boolean
    kb: { article: string; url?: string; fixed_build?: string; download_url?: string; download?: string }[]
  }[]
  url: string
}

export interface AdvisoryPreview {
  url: string
  host: string
  title?: string
  description?: string
  site_name?: string
  published?: string
  error?: string
}

export interface NewsItem {
  title: string
  url: string
  source?: string
  published?: string
  discussion_url?: string
  points?: number
  comments?: number
}

export interface RelatedGroup {
  kind: 'advisory' | 'product'
  label: string
  url?: string
  vendor?: string
  product?: string
  total: number
  items: CveSummary[]
}

export type FeedKind = 'vendor' | 'government' | 'research' | 'news'

export interface FeedArticle {
  feed: string
  feed_name: string
  feed_kind: FeedKind | ''
  url: string
  title: string
  summary: string | null
  published: string
  cve_ids: string[]
}

// GET /api/v1/news: feed articles with a top-story score and a badge per
// CVE they name.
export interface NewsArticle extends FeedArticle {
  // Best of the article's CVEs: exploited 3, critical 2, high 1, plus 1 per
  // other feed covering it in the window (≤ 4). Roundups score 0.
  score: number
  // Bookmarked articles are kept past their kind's retention.
  bookmarked: boolean
}

export interface CveBadge {
  severity: Severity
  score: number | null
  kev: boolean
  // CISA KEV, ENISA EUVD, or VulnCheck KEV.
  exploited: boolean
}

export interface NewsPage {
  items: NewsArticle[]
  total: number
  cves: Record<string, CveBadge>
}

export interface NewsQuery {
  kind?: FeedKind
  feed?: string
  q?: string
  days?: number
  cves?: boolean
  bookmarked?: boolean
  sort?: 'top' | 'newest'
  page?: number
  limit?: number
}

export interface TrendingItem {
  id: string
  sources: number
  articles: number
  latest: string
  headline: string
  url: string
  // Null when the CVE is not in the CVE List yet.
  cve: CveSummary | null
}

export interface FeedInfo {
  key: string
  name: string
  kind: FeedKind
  url: string
  articles: number
  with_cve: number
  latest: string | null
}

// --- Endpoint scanner (POST /api/v1/scan) ------------------------------------

export type ScanSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'good'

export interface ScanEvidence {
  request: string
  response: string
  snippet?: string
}

export interface ScanFinding {
  severity: ScanSeverity
  category: string
  title: string
  detail?: string
  // Present on Pahredar's own active checks: the request sent and the
  // response that proves the finding.
  evidence?: ScanEvidence
}

export interface ScanTechCve {
  id: string
  severity: string
  kev: boolean
}

export interface ScanTech {
  name: string
  version?: string
  from: string
  cves?: {
    vendor: string
    product: string
    total: number
    kev: number
    critical: number
    examples: ScanTechCve[]
  }
}

export interface ScanReport {
  target: string
  url: string
  host: string
  ip: string
  scanned_at: string
  duration: string
  grade: string
  score: number
  findings: ScanFinding[]
  dns: {
    a: string[]
    aaaa: string[]
    mx: string[]
    ns: string[]
    txt: string[]
    spf: string
    dmarc: string
  } | null
  tls: {
    supported: boolean
    version: string
    min_observed: string
    cipher: string
    issuer: string
    subject: string
    sans: string[]
    not_before: string
    not_after: string
    days_left: number
    key_type: string
    self_signed: boolean
    host_match: boolean
  } | null
  http: {
    final_url: string
    status: number
    server: string
    powered_by: string
    https_redirect: boolean
    methods: string[]
  } | null
  headers: { name: string; present: boolean; value?: string }[]
  cookies: { name: string; secure: boolean; http_only: boolean; same_site: string }[]
  tech: ScanTech[]
  paths: { path: string; status: number; exposed: boolean }[]
  related: {
    security_txt: boolean
    contacts: string[]
    subdomains: string[]
    assets: string[]
    disallowed: string[]
  } | null
  active: {
    ran: boolean
    engine: string
    duration: string
    note?: string
    findings: {
      template_id: string
      name: string
      severity: string
      tags: string[]
      cves: string[]
      matched_at: string
      reference?: string[]
      count: number
    }[]
  } | null
  errors: string[]
}

export interface ScanCategory {
  key: string
  count: number
}

export interface ScanConfig {
  active_available: boolean
  allow_private: boolean
  // Nuclei template categories the active scan covers, largest first.
  active_catalog?: ScanCategory[]
  active_total?: number
}

export interface ScanPhase {
  name: string
  status: 'pending' | 'running' | 'done'
}

export interface ScanProgress {
  phases: ScanPhase[]
  active?: {
    templates: number
    requests: number
    total: number
    percent: number
    matched: number
  }
  // Findings recorded so far, sorted by severity — streamed as each check
  // completes so the UI can show results before the scan finishes.
  findings?: ScanFinding[]
}

export interface ScanJob {
  id: number
  target: string
  host: string
  active: boolean
  status: 'queued' | 'running' | 'done' | 'error'
  progress: ScanProgress
  report?: ScanReport
  stored_id?: number
  error?: string
  cached: boolean
}

export interface ScanSummary {
  id: number
  target: string
  host: string
  grade: string
  score: number
  created_at: string
}
