import { useMutation, useQuery } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, ChevronDown, ChevronRight, Circle, Download, Fingerprint, Info, Loader2, Lock, Search, ShieldCheck, Zap } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { Link, useSearchParams } from 'react-router'
import { api, ApiError } from '../api/client'
import type { ScanEvidence, ScanFinding, ScanJob, ScanReport, ScanSeverity, ScanTech } from '../api/types'
import { Card, ErrorBox, Tag } from '../components/ui'
import { Gauge } from '../components/Gauge'
import { relativeTime } from '../lib/format'
import { useOrigin } from '../lib/origin'

const link = 'text-cyan-300 hover:text-cyan-200'

const sevStyle: Record<ScanSeverity, { tag: string; label: string }> = {
  critical: { tag: 'bg-red-500/15 text-red-300 ring-red-400/30', label: 'Critical' },
  high: { tag: 'bg-orange-500/15 text-orange-300 ring-orange-400/30', label: 'High' },
  medium: { tag: 'bg-amber-500/15 text-amber-200 ring-amber-400/30', label: 'Medium' },
  low: { tag: 'bg-sky-500/10 text-sky-300 ring-sky-400/25', label: 'Low' },
  info: { tag: 'bg-zinc-700/40 text-zinc-300 ring-zinc-600/40', label: 'Info' },
  good: { tag: 'bg-emerald-500/10 text-emerald-300 ring-emerald-400/25', label: 'Good' },
}

const gradeColor: Record<string, string> = {
  A: 'text-emerald-300 ring-emerald-400/30 bg-emerald-500/10',
  B: 'text-cyan-300 ring-cyan-400/30 bg-cyan-500/10',
  C: 'text-amber-200 ring-amber-400/30 bg-amber-500/10',
  D: 'text-orange-300 ring-orange-400/30 bg-orange-500/10',
  F: 'text-red-300 ring-red-400/30 bg-red-500/10',
}

export function ScanPage() {
  useOrigin('Endpoint scan')
  const [params, setParams] = useSearchParams()
  const [input, setInput] = useState(params.get('target') ?? '')
  const [active, setActive] = useState(false)
  const [authorized, setAuthorized] = useState(false)
  const [jobId, setJobId] = useState<number | null>(() => {
    const j = Number(params.get('job'))
    return Number.isInteger(j) && j > 0 ? j : null
  })
  const config = useQuery({ queryKey: ['scan-config'], queryFn: api.scanConfig, staleTime: 5 * 60_000 })

  const start = useMutation({
    mutationFn: (v: { target: string; fresh?: boolean; active?: boolean; authorized?: boolean }) => api.scan(v.target, { fresh: v.fresh, active: v.active, authorized: v.authorized }),
    onSuccess: (res, v) => {
      setJobId(res.id)
      const next = new URLSearchParams(params)
      next.set('target', v.target)
      next.set('job', String(res.id))
      setParams(next, { replace: true })
    },
  })
  // Poll the job while it runs; the scan keeps going on the server even if
  // this page is closed, so returning with ?job= resumes it.
  const job = useQuery({
    queryKey: ['scan-job', jobId],
    queryFn: () => api.scanJob(jobId as number),
    enabled: jobId != null,
    refetchInterval: (q) => {
      const st = q.state.data?.status
      return st === 'done' || st === 'error' ? false : 1000
    },
  })

  const canActive = config.data?.active_available ?? false
  const runActive = active && canActive
  const jobData = jobId != null ? job.data : undefined
  const status = jobData?.status
  const scanning = start.isPending || status === 'queued' || status === 'running'
  const report = jobData?.report
  const errMsg = start.isError
    ? start.error instanceof ApiError ? start.error.message : String(start.error)
    : status === 'error' ? jobData?.error ?? 'Scan failed'
    : jobId != null && job.isError ? 'This scan job expired. Start a new scan.'
    : null

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const t = input.trim()
    if (t && (!runActive || authorized)) start.mutate({ target: t, active: runActive, authorized })
  }
  const rescan = () => report && start.mutate({ target: report.target, fresh: true, active: runActive, authorized })
  const newScan = () => {
    setJobId(null)
    const next = new URLSearchParams(params)
    next.delete('job')
    setParams(next, { replace: true })
  }

  // Once a scan is started, the landing is replaced by the result view.
  if (jobId != null) {
    return (
      <ScanResult
        host={jobData?.host ?? report?.host ?? input.trim()}
        active={jobData?.active ?? runActive}
        scanning={scanning}
        job={jobData}
        report={report}
        cached={jobData?.cached ?? false}
        errMsg={errMsg}
        onNew={newScan}
        onRescan={rescan}
      />
    )
  }

  return (
    <div>
      {/* Hero */}
      <div className="relative overflow-hidden rounded-2xl border border-zinc-800 bg-gradient-to-b from-zinc-900/80 to-zinc-950 px-5 py-10 text-center sm:px-8 sm:py-14">
        <pre aria-hidden className="pointer-events-none absolute inset-0 -z-10 overflow-hidden p-4 text-left font-mono text-[11px] leading-5 whitespace-pre-wrap text-zinc-500/10 select-none">
{`$ curl -sI https://target.example/   Server: nginx  X-Powered-By: PHP/8.2.27
$ nmap -sV target.example            443/tcp open  ssl/http  TLS 1.3
$ dig target.example TXT             v=spf1 ... ~all   _dmarc p=reject
GET /.git/HEAD  404     GET /.env  404     /.well-known/security.txt 200
[INF] templates loaded: 10679   matched: 0   requests: 19739`}
        </pre>
        <h1 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">Endpoint Scanner</h1>
        <p className="mt-2 text-base text-zinc-300 sm:text-lg">How exposed is your endpoint, from the outside?</p>
        <p className="mx-auto mt-3 max-w-xl text-sm text-zinc-500">
          Enter a domain. We fingerprint its TLS, DNS, HTTP headers and tech stack, match it against Pahredar's CVE data, and probe for exposed paths — in seconds. No signup, no agent.
        </p>

        <div className="mt-6 inline-flex rounded-full border border-zinc-800 bg-zinc-900 p-1 text-sm">
          <button type="button" onClick={() => setActive(false)} className={`rounded-full px-4 py-1.5 font-medium transition-colors ${!active ? 'bg-cyan-500/20 text-cyan-100 ring-1 ring-cyan-400/30' : 'text-zinc-400 hover:text-zinc-200'}`}>
            Passive check
          </button>
          <button type="button" disabled={!canActive} onClick={() => setActive(true)} title={canActive ? 'Runs intrusive vulnerability checks' : 'Enable SCAN_ACTIVE_ENABLED on the server to use active scanning'} className={`inline-flex items-center gap-1 rounded-full px-4 py-1.5 font-medium transition-colors disabled:opacity-40 ${active ? 'bg-rose-500/20 text-rose-100 ring-1 ring-rose-400/30' : 'text-zinc-400 hover:text-zinc-200'}`}>
            Active scan <Lock className="h-3.5 w-3.5" />
          </button>
        </div>

        <form onSubmit={submit} className={`mx-auto mt-5 flex max-w-xl items-center gap-2 rounded-full border bg-zinc-950 py-1.5 pr-1.5 pl-4 ${active ? 'border-rose-400/30' : 'border-zinc-800 focus-within:border-cyan-400/40'}`}>
          <Search className="h-4 w-4 shrink-0 text-zinc-500" />
          <input value={input} onChange={(e) => setInput(e.target.value)} placeholder="example.com" autoFocus className="min-w-0 flex-1 bg-transparent py-1.5 text-sm text-zinc-100 placeholder:text-zinc-500 focus:outline-none" />
          <button type="submit" disabled={!input.trim() || (runActive && !authorized)} className={`inline-flex shrink-0 items-center gap-1.5 rounded-full px-4 py-2 text-sm font-medium text-white disabled:opacity-50 ${active ? 'bg-rose-500 hover:bg-rose-400' : 'bg-cyan-500 hover:bg-cyan-400'}`}>
            {active ? 'Run active scan' : 'Check exposure'} <span aria-hidden>→</span>
          </button>
        </form>

        {runActive && (
          <label className="mx-auto mt-3 flex max-w-xl cursor-pointer items-center justify-center gap-2 text-xs text-amber-200/90">
            <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} className="accent-amber-400" />
            I am authorised to actively test this target.
          </label>
        )}
        <p className="mx-auto mt-3 flex max-w-xl items-center justify-center gap-1.5 text-xs text-zinc-600">
          <AlertTriangle className="h-3.5 w-3.5" /> Only scan endpoints you own or are authorised to assess. Scans are logged.
        </p>
      </div>

      <div className="mt-6 grid gap-4 sm:grid-cols-3">
        <Feature icon={Fingerprint} tone="violet" title="Fingerprint & CVE match" text="Reads TLS, headers, cookies and the tech stack, then matches each product against Pahredar's CVE data, flagging KEV-listed ones." />
        <Feature icon={ShieldCheck} tone="cyan" title="Posture & exposure" text="Grades security headers, certificate health and SPF/DMARC, and probes a safe list of commonly exposed paths (.git, .env, actuator…)." />
        <Feature icon={active ? Zap : AlertTriangle} tone="rose" title="Optional active verification" text="With authorisation, runs Nuclei's vulnerability templates to actually verify issues. No denial-of-service, no exploitation." />
      </div>

      {active && <div className="mt-6"><ActiveCoverage /></div>}

      <div className="mt-8 space-y-6">
        <ScanIntro />
      </div>
    </div>
  )
}

// gradeAccent is the left-border colour of the result header.
const gradeAccent: Record<string, string> = {
  A: 'border-l-emerald-400', B: 'border-l-cyan-400', C: 'border-l-amber-400', D: 'border-l-orange-400', F: 'border-l-red-400',
}
const gradeRisk: Record<string, string> = { A: 'Low risk', B: 'Low risk', C: 'Medium risk', D: 'High risk', F: 'High risk' }

function ScanResult({ host, active, scanning, job, report, cached, errMsg, onNew, onRescan }: {
  host: string; active: boolean; scanning: boolean; job?: ScanJob; report?: ScanReport; cached: boolean; errMsg: string | null; onNew: () => void; onRescan: () => void
}) {
  const grade = report?.grade ?? '?'
  const [copied, setCopied] = useState(false)
  // Findings stream in via job.progress while the scan runs; the final report
  // supersedes them when it arrives.
  const live = report?.findings ?? job?.progress.findings ?? []
  const liveCount = live.filter((f) => f.severity !== 'good').length
  const copyLink = () => {
    navigator.clipboard?.writeText(window.location.href).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1200) }).catch(() => {})
  }
  return (
    <div>
      <div className="mb-3 flex items-center gap-1 text-sm text-zinc-500">
        <button onClick={onNew} className="hover:text-cyan-200">Scanner</button>
        <ChevronRight className="h-3.5 w-3.5 text-zinc-600" />
        <span className="font-mono text-zinc-300">{host}</span>
      </div>

      {/* Header */}
      <div className={`overflow-hidden rounded-xl border border-zinc-800 border-l-4 bg-zinc-900/40 ${report ? gradeAccent[grade] ?? 'border-l-zinc-600' : 'border-l-cyan-400'}`}>
        <div className="p-5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <Tag tone="zinc">Endpoint</Tag>
                {report && <span className={`rounded px-2 py-0.5 font-semibold ring-1 ring-inset ${gradeColor[grade] ?? gradeColor.F}`}>Grade {grade} · {report.score}/100</span>}
                {active && <Tag tone="red">Active</Tag>}
                {cached && <Tag>cached</Tag>}
              </div>
              <h1 className="mt-2 font-mono text-2xl font-bold break-all text-white">{host}</h1>
              <p className="mt-1 flex flex-wrap items-center gap-1 text-sm text-zinc-500">
                <Info className="h-3.5 w-3.5" /> The grade is heuristic — verify before acting on results.
                {report && <> · scanned {relativeTime(report.scanned_at)}</>}
              </p>
            </div>
            <div className="flex shrink-0 gap-2">
              {report && <button onClick={onRescan} className="rounded-lg border border-zinc-800 px-3 py-1.5 text-sm text-zinc-300 hover:bg-zinc-800">Re-scan</button>}
              <button onClick={onNew} className="rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-sm text-cyan-200 hover:bg-cyan-500/20">New scan</button>
            </div>
          </div>
        </div>
        <div className="grid grid-cols-2 divide-x divide-zinc-800 border-t border-zinc-800 sm:grid-cols-4">
          <Stat label="Scanned" value={report ? relativeTime(report.scanned_at) : scanning ? 'running…' : '—'} />
          <Stat label="Duration" value={report?.duration ?? '—'} />
          <Stat label="Findings" value={report ? String(report.findings.filter((f) => f.severity !== 'good').length) : liveCount ? String(liveCount) : scanning ? '…' : '—'} />
          <Stat label="Score" value={report ? `${report.score}/100` : '—'} />
        </div>
      </div>

      {/* Body */}
      {scanning ? (
        <div className="mt-6 grid gap-6 lg:grid-cols-[1fr_340px]">
          <div className="min-w-0 space-y-6">
            <ProgressCard job={job} active={active} target={host} />
            {live.length > 0 && <FindingsCard findings={live} live />}
          </div>
          {active && <div className="min-w-0"><ActiveCoverage /></div>}
        </div>
      ) : errMsg ? (
        <div className="mt-6"><ErrorBox error={errMsg} /></div>
      ) : report ? (
        <div className="mt-6 grid gap-6 lg:grid-cols-[1fr_340px]">
          <div className="min-w-0 space-y-6">
            <FindingsCard findings={report.findings} />
            {report.active?.ran && <ActiveCard active={report.active} />}
            <div className="grid gap-6 xl:grid-cols-2">
              {report.tech.length > 0 && <TechCard tech={report.tech} />}
              {report.tls && <TlsCard tls={report.tls} />}
              <HeadersCard report={report} />
              {report.dns && <DnsCard dns={report.dns} />}
              {report.paths.some((p) => p.exposed) && <PathsCard report={report} />}
              {report.related && <RelatedCard related={report.related} />}
            </div>
            {report.errors.length > 0 && (
              <Card title="Scan notes"><ul className="space-y-1 text-xs text-zinc-500">{report.errors.map((e, i) => <li key={i}>{e}</li>)}</ul></Card>
            )}
          </div>

          <div className="min-w-0 space-y-6">
            <Card title="Score">
              <ScoreGauge score={report.score} grade={grade} />
            </Card>
            {active && <ActiveCoverage />}
            <Card title="Target">
              <dl>
                <Row label="IP">{report.ip}</Row>
                {report.http && <Row label="Final URL"><a href={report.http.final_url} target="_blank" rel="noreferrer" className={link}>{report.http.final_url}</a></Row>}
                {report.http?.server && <Row label="Server">{report.http.server}</Row>}
                {report.http?.powered_by && <Row label="Powered by">{report.http.powered_by}</Row>}
                {report.http && <Row label="https redirect">{report.http.https_redirect ? 'yes' : 'no'}</Row>}
                {report.http && report.http.methods.length > 0 && <Row label="Methods">{report.http.methods.join(', ')}</Row>}
              </dl>
            </Card>
            <Card title="Export">
              <button onClick={() => downloadJSON(report)} className="flex w-full items-center justify-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-950 py-2 text-sm text-zinc-200 hover:bg-zinc-800">
                <Download className="h-4 w-4" /> Download report (JSON)
              </button>
              <div className="mt-3 text-xs text-zinc-500">Permalink</div>
              <div className="mt-1 flex items-center gap-2">
                <input readOnly value={window.location.href} className="min-w-0 flex-1 truncate rounded border border-zinc-800 bg-zinc-950 px-2 py-1 font-mono text-xs text-zinc-400" />
                <button onClick={copyLink} className="shrink-0 rounded border border-zinc-800 px-2 py-1 text-xs text-zinc-300 hover:bg-zinc-800">{copied ? 'Copied' : 'Copy'}</button>
              </div>
            </Card>
          </div>
        </div>
      ) : null}
    </div>
  )
}

// CATEGORY_META maps Nuclei's folder keys to a label and a one-line
// description of what that group of checks looks for.
const CATEGORY_META: Record<string, { label: string; desc: string }> = {
  cves: { label: 'Known CVEs', desc: 'Published vulnerabilities probed on the live target' },
  'exposed-panels': { label: 'Exposed panels', desc: 'Admin, login and management interfaces reachable from outside' },
  technologies: { label: 'Technology detection', desc: 'Frameworks, servers and products in use' },
  osint: { label: 'OSINT & info leaks', desc: 'Public info and data unintentionally exposed' },
  misconfiguration: { label: 'Misconfigurations', desc: 'Unsafe defaults, debug modes, open settings' },
  vulnerabilities: { label: 'Generic vulnerabilities', desc: 'XSS, SSRF, LFI, injection and similar classes' },
  exposures: { label: 'Exposed files & secrets', desc: 'Config, backups, logs, tokens left reachable' },
  'default-logins': { label: 'Default credentials', desc: 'Products still using shipped default passwords' },
  'token-spray': { label: 'API token checks', desc: 'Leaked API keys validated against their service' },
  takeovers: { label: 'Subdomain takeover', desc: 'Dangling DNS pointing at claimable services' },
  iot: { label: 'IoT & devices', desc: 'Routers, cameras and embedded device issues' },
  miscellaneous: { label: 'Miscellaneous', desc: 'Checks that do not fit another group' },
  cnvd: { label: 'CNVD advisories', desc: 'Vulnerabilities from the Chinese CNVD database' },
  ssl: { label: 'TLS / SSL', desc: 'Certificate and protocol weaknesses' },
  'credential-stuffing': { label: 'Credential stuffing', desc: 'Known breached-credential checks' },
}

// ActiveCoverage shows what the active (Nuclei) scan actually covers, broken
// down by category with counts, so the total is not just an opaque number.
function ActiveCoverage() {
  const config = useQuery({ queryKey: ['scan-config'], queryFn: api.scanConfig, staleTime: 5 * 60_000 })
  const cats = config.data?.active_catalog ?? []
  const total = config.data?.active_total ?? 0
  if (cats.length === 0) return null
  const max = Math.max(...cats.map((c) => c.count))
  return (
    <Card title="Active scan coverage" actions={<span className="text-xs text-zinc-500 tabular-nums">{total.toLocaleString()} checks · {cats.length} categories</span>}>
      <p className="mb-3 text-xs text-zinc-500">Nuclei community templates, grouped. The active scan runs these against the target to verify issues — no denial-of-service or exploitation.</p>
      <ul className="space-y-2.5">
        {cats.map((c) => {
          const meta = CATEGORY_META[c.key] ?? { label: c.key, desc: '' }
          return (
            <li key={c.key}>
              <div className="flex items-baseline justify-between gap-3">
                <span className="text-sm font-medium text-zinc-200">{meta.label}</span>
                <span className="shrink-0 font-mono text-xs text-zinc-400 tabular-nums">{c.count.toLocaleString()}</span>
              </div>
              <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-zinc-800">
                <div className="h-full rounded-full bg-rose-400/70" style={{ width: `${Math.max(3, Math.round((c.count / max) * 100))}%` }} />
              </div>
              {meta.desc && <p className="mt-0.5 text-xs text-zinc-600">{meta.desc}</p>}
            </li>
          )
        })}
      </ul>
    </Card>
  )
}

// FindingsCard shows a severity-count row and the findings list. With `live`
// it reflects results still streaming in from a running scan.
function FindingsCard({ findings, live = false }: { findings: ScanFinding[]; live?: boolean }) {
  const counts = findings.reduce<Record<string, number>>((a, f) => ((a[f.severity] = (a[f.severity] ?? 0) + 1), a), {})
  return (
    <Card title={live ? 'Findings so far' : 'Findings'} actions={live ? <span className="inline-flex items-center gap-1.5 text-xs text-cyan-300"><Loader2 className="h-3.5 w-3.5 animate-spin" /> live</span> : undefined}>
      <div className="mb-3 flex flex-wrap gap-1.5">
        {(['critical', 'high', 'medium', 'low', 'info', 'good'] as ScanSeverity[]).filter((s) => counts[s]).map((s) => (
          <span key={s} className={`rounded px-1.5 py-0.5 text-xs font-medium ring-1 ring-inset ${sevStyle[s].tag}`}>{counts[s]} {sevStyle[s].label.toLowerCase()}</span>
        ))}
      </div>
      {findings.length === 0 ? (
        <p className="text-sm text-zinc-500">{live ? 'Checking…' : 'No findings.'}</p>
      ) : (
        <ul className="space-y-2">{findings.map((f, i) => <FindingRow key={`${f.category}-${f.title}-${i}`} f={f} />)}</ul>
      )}
    </Card>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="px-4 py-3 text-center">
      <div className="font-mono text-lg font-semibold text-zinc-100">{value}</div>
      <div className="text-xs tracking-wider text-zinc-500 uppercase">{label}</div>
    </div>
  )
}

const gaugeStroke: Record<string, string> = { A: '#34d399', B: '#22d3ee', C: '#fbbf24', D: '#fb923c', F: '#f87171' }

function ScoreGauge({ score, grade }: { score: number; grade: string }) {
  return <Gauge value={score} max={100} display={String(score)} caption="score" color={gaugeStroke[grade] ?? '#f87171'} risk={`Grade ${grade} · ${gradeRisk[grade] ?? 'Unknown'}`} />
}

function ActiveCard({ active }: { active: NonNullable<ScanReport['active']> }) {
  return (
    <Card title="Active checks (Nuclei)">
      <p className="mb-2 text-xs text-zinc-500">
        {active.engine} · {active.duration} · {active.findings.length} template{active.findings.length === 1 ? '' : 's'} matched. These verify issues by probing the target; results also appear in Findings.
        {active.note && <span className="text-amber-300/80"> · {active.note}</span>}
      </p>
      {active.findings.length === 0 ? (
        <p className="text-sm text-zinc-500">No vulnerability template matched.</p>
      ) : (
        <ul className="space-y-1.5">
          {active.findings.map((f) => (
            <li key={f.template_id} className="flex flex-wrap items-baseline gap-x-2 text-sm">
              <span className={`inline-flex h-5 items-center rounded px-1.5 text-xs font-medium ring-1 ring-inset ${sevStyle[(f.severity as ScanSeverity) in sevStyle ? (f.severity as ScanSeverity) : 'info'].tag}`}>{f.severity}</span>
              <span className="text-zinc-200">{f.name}</span>
              {f.count > 1 && <span className="text-xs text-zinc-500">×{f.count}</span>}
              {f.cves.map((c) => <Link key={c} to={`/cves/${c}`} className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-xs text-cyan-300 hover:bg-zinc-700">{c}</Link>)}
              <span className="font-mono text-xs text-zinc-600">{f.template_id}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}

function downloadJSON(report: ScanReport) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `scan-${report.host}.json`
  a.click()
  URL.revokeObjectURL(url)
}

function ProgressCard({ job, active, target }: { job?: ScanJob; active: boolean; target: string }) {
  const phases = job?.progress.phases ?? []
  const ap = job?.progress.active
  return (
    <Card>
      <div className="flex items-center gap-2 text-sm text-zinc-200">
        <Loader2 className="h-4 w-4 animate-spin text-cyan-300" />
        Scanning <span className="font-mono">{target}</span>…
        {job?.status === 'queued' && <span className="text-xs text-zinc-500">(queued)</span>}
      </div>
      <ul className="mt-3 space-y-1.5">
        {phases.map((ph) => (
          <li key={ph.name} className="flex items-center gap-2 text-sm">
            {ph.status === 'done' ? <CheckCircle2 className="h-4 w-4 text-emerald-400" /> : ph.status === 'running' ? <Loader2 className="h-4 w-4 animate-spin text-cyan-300" /> : <Circle className="h-4 w-4 text-zinc-700" />}
            <span className={ph.status === 'pending' ? 'text-zinc-600' : 'text-zinc-200'}>{ph.name}</span>
          </li>
        ))}
      </ul>
      {active && ap && (ap.total > 0 || ap.templates > 0) && (
        <div className="mt-4">
          <div className="flex justify-between text-xs text-zinc-500">
            <span>Nuclei · {ap.requests.toLocaleString()} / {ap.total.toLocaleString()} requests</span>
            <span>{ap.matched} matched</span>
          </div>
          <div className="mt-1 h-2 overflow-hidden rounded bg-zinc-800">
            <div className="h-2 rounded bg-rose-400 transition-all" style={{ width: `${Math.min(ap.percent, 100)}%` }} />
          </div>
          <p className="mt-1 text-xs text-zinc-600">Active scans run many requests and can take a few minutes. You can leave this page — the scan keeps running.</p>
        </div>
      )}
    </Card>
  )
}

const WHAT_WE_CHECK: { title: string; items: string[] }[] = [
  { title: 'TLS & certificate', items: ['Protocol versions (flags TLS 1.0/1.1)', 'Certificate expiry, issuer, hostname match', 'Self-signed and weak keys'] },
  { title: 'HTTP headers & cookies', items: ['HSTS, CSP, X-Frame-Options, nosniff', 'Referrer- and Permissions-Policy', 'Cookie Secure / HttpOnly / SameSite'] },
  { title: 'DNS & email', items: ['A / AAAA / MX / NS records', 'SPF and DMARC policy', 'Spoofing exposure'] },
  { title: 'Technology & CVEs', items: ['Server, framework and JS library versions', 'Match against Pahredar\'s per-product CVEs', 'KEV-listed vulnerabilities flagged'] },
  { title: 'Exposed paths', items: ['.git, .env, actuator, server-status…', 'security.txt and robots.txt', 'Safe GET probes, no payloads'] },
  { title: 'Active (optional)', items: ['Nuclei vulnerability templates', 'Verifies issues by probing', 'No DoS, no exploitation'] },
]

const FAQ: { q: string; a: string }[] = [
  { q: 'Is this intrusive?', a: 'The passive check only sends the requests a browser or crawler would. The optional active scan runs Nuclei\'s vulnerability templates, which actively probe the target to verify issues — enable it only for targets you are authorised to test.' },
  { q: 'How are CVEs matched?', a: 'The detected product and version are matched against Pahredar\'s per-product CVE data. It is product-level (not matched to the exact version), so treat the CVE counts as "worth checking" and confirm the running version.' },
  { q: 'Can I scan internal hosts?', a: 'Only when the server has SCAN_ALLOW_PRIVATE enabled. From the container, use host.docker.internal or a LAN IP to reach services on your network.' },
  { q: 'What happens if I close the page?', a: 'Nothing is lost. The scan runs on the server; progress is polled from a job. Reopening the scanner with the same link resumes it, and finished scans are kept for a while.' },
]

function ScanIntro() {
  return (
    <>
      <Card title="What this checks">
        <div className="grid gap-x-8 gap-y-5 sm:grid-cols-2 lg:grid-cols-3">
          {WHAT_WE_CHECK.map((g) => (
            <div key={g.title}>
              <h4 className="text-sm font-semibold text-zinc-200">{g.title}</h4>
              <ul className="mt-1 space-y-0.5 text-xs text-zinc-500">
                {g.items.map((it) => <li key={it} className="flex gap-1.5"><span className="text-cyan-500/70">·</span>{it}</li>)}
              </ul>
            </div>
          ))}
        </div>
      </Card>
      <Card title="FAQ">
        <div className="divide-y divide-zinc-800/70">
          {FAQ.map((f) => (
            <details key={f.q} className="py-2">
              <summary className="cursor-pointer list-none text-sm font-medium text-zinc-200 marker:content-none">{f.q}</summary>
              <p className="mt-1.5 text-sm text-zinc-500">{f.a}</p>
            </details>
          ))}
        </div>
      </Card>
    </>
  )
}



const featureTone: Record<string, string> = {
  violet: 'bg-violet-500/15 text-violet-300',
  cyan: 'bg-cyan-500/15 text-cyan-300',
  rose: 'bg-rose-500/15 text-rose-300',
}

function Feature({ icon: Icon, tone, title, text }: { icon: typeof Search; tone: string; title: string; text: string }) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4">
      <span className={`inline-flex h-9 w-9 items-center justify-center rounded-lg ${featureTone[tone]}`}><Icon className="h-5 w-5" /></span>
      <h3 className="mt-3 text-sm font-semibold text-zinc-100">{title}</h3>
      <p className="mt-1 text-xs text-zinc-500">{text}</p>
    </div>
  )
}


function FindingRow({ f }: { f: ScanFinding }) {
  const Icon = f.severity === 'good' ? ShieldCheck : AlertTriangle
  const [open, setOpen] = useState(false)
  return (
    <li className="flex gap-3">
      <span className={`mt-0.5 inline-flex h-5 shrink-0 items-center gap-1 rounded px-1.5 text-xs font-medium ring-1 ring-inset ${sevStyle[f.severity].tag}`}>
        <Icon className="h-3 w-3" />{sevStyle[f.severity].label}
      </span>
      <div className="min-w-0 flex-1">
        <div className="text-sm text-zinc-200">
          {f.title}{' '}
          {f.category === 'active' ? <span className="rounded bg-rose-500/15 px-1 text-[10px] font-medium text-rose-300 ring-1 ring-rose-400/30">verified · nuclei</span>
            : f.category === 'verify' ? <span className="rounded bg-cyan-500/15 px-1 text-[10px] font-medium text-cyan-300 ring-1 ring-cyan-400/30">verified · evidence</span>
            : <span className="text-xs text-zinc-600">· {f.category}</span>}
        </div>
        {f.detail && <p className="text-xs text-zinc-500">{f.detail}</p>}
        {f.evidence && (
          <div className="mt-1.5">
            <button onClick={() => setOpen((v) => !v)} className="inline-flex items-center gap-1 text-xs text-cyan-300 hover:text-cyan-200">
              {open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />} {open ? 'Hide' : 'Show'} evidence
            </button>
            {open && <EvidenceBlock e={f.evidence} />}
          </div>
        )}
      </div>
    </li>
  )
}

function EvidenceBlock({ e }: { e: ScanEvidence }) {
  return (
    <div className="mt-1.5 space-y-2 rounded-lg border border-zinc-800 bg-zinc-950 p-3">
      <div>
        <div className="mb-1 text-[10px] font-semibold tracking-wider text-zinc-500 uppercase">Request sent</div>
        <pre className="overflow-x-auto font-mono text-xs break-all whitespace-pre-wrap text-emerald-300/90">{e.request}</pre>
      </div>
      <div>
        <div className="mb-1 text-[10px] font-semibold tracking-wider text-zinc-500 uppercase">Response</div>
        <pre className="overflow-x-auto font-mono text-xs break-all whitespace-pre-wrap text-cyan-200/90">{e.response}</pre>
      </div>
      {e.snippet && (
        <div>
          <div className="mb-1 text-[10px] font-semibold tracking-wider text-zinc-500 uppercase">Body evidence</div>
          <pre className="overflow-x-auto font-mono text-xs break-all whitespace-pre-wrap text-amber-200/80">{e.snippet}</pre>
        </div>
      )}
    </div>
  )
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[8rem_1fr] gap-2 py-1 text-sm">
      <dt className="text-zinc-500">{label}</dt>
      <dd className="min-w-0 break-words text-zinc-200">{children}</dd>
    </div>
  )
}

function TechCard({ tech }: { tech: ScanTech[] }) {
  return (
    <Card title="Technology & known CVEs">
      <p className="mb-2 text-xs text-zinc-500">CVE counts are for the product overall, not matched to the exact version. Check the running version against them.</p>
      <ul className="space-y-3">
        {tech.map((t) => (
          <li key={t.name}>
            <div className="flex flex-wrap items-baseline gap-2">
              <span className="font-medium text-zinc-100">{t.name}</span>
              {t.version && <span className="font-mono text-xs text-zinc-400">{t.version}</span>}
              <span className="text-xs text-zinc-600">{t.from}</span>
            </div>
            {t.cves && (
              <div className="mt-1 flex flex-wrap items-center gap-2 text-xs">
                <Link to={`/vendors/${t.cves.vendor}/products/${t.cves.product}`} className={link}>{t.cves.total} CVEs for {t.cves.product}</Link>
                {t.cves.kev > 0 && <Tag tone="red">{t.cves.kev} in KEV</Tag>}
                {t.cves.critical > 0 && <span className="text-zinc-500">{t.cves.critical} critical</span>}
                <span className="flex flex-wrap gap-1">
                  {t.cves.examples.slice(0, 4).map((e) => (
                    <Link key={e.id} to={`/cves/${e.id}`} className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-cyan-300 hover:bg-zinc-700">{e.id}{e.kev ? ' ⚠' : ''}</Link>
                  ))}
                </span>
              </div>
            )}
          </li>
        ))}
      </ul>
    </Card>
  )
}

function TlsCard({ tls }: { tls: NonNullable<ScanReport['tls']> }) {
  return (
    <Card title="TLS / certificate">
      <dl>
        <Row label="Protocol">{tls.version}{tls.min_observed && tls.min_observed !== tls.version && <span className="text-zinc-500"> (accepts down to {tls.min_observed})</span>}</Row>
        <Row label="Cipher">{tls.cipher}</Row>
        <Row label="Issuer">{tls.issuer || '—'}</Row>
        <Row label="Expires">{tls.not_after} <span className={tls.days_left < 30 ? 'text-amber-300' : 'text-zinc-500'}>({tls.days_left} days)</span></Row>
        <Row label="Key">{tls.key_type}</Row>
        <Row label="Hostname match">{tls.host_match ? 'yes' : 'no'}{tls.self_signed && ' · self-signed'}</Row>
        {tls.sans.length > 0 && <Row label="SANs">{tls.sans.slice(0, 8).join(', ')}{tls.sans.length > 8 && ` +${tls.sans.length - 8}`}</Row>}
      </dl>
    </Card>
  )
}

function HeadersCard({ report }: { report: ScanReport }) {
  return (
    <Card title="HTTP headers & cookies">
      <ul className="space-y-1 text-sm">
        {report.headers.map((h) => (
          <li key={h.name} className="flex items-center gap-2">
            <span className={h.present ? 'text-emerald-400' : 'text-red-400'}>{h.present ? '✓' : '✗'}</span>
            <span className="text-zinc-300">{h.name}</span>
            {h.value && <span className="min-w-0 truncate font-mono text-xs text-zinc-600" title={h.value}>{h.value}</span>}
          </li>
        ))}
      </ul>
      {report.http && (
        <div className="mt-3 border-t border-zinc-800 pt-2 text-xs text-zinc-500">
          Status {report.http.status}{report.http.server && ` · Server: ${report.http.server}`}{report.http.methods.length > 0 && ` · Methods: ${report.http.methods.join(', ')}`}
        </div>
      )}
      {report.cookies.length > 0 && (
        <div className="mt-2 text-xs text-zinc-500">
          Cookies: {report.cookies.map((c) => `${c.name} (${[c.secure && 'Secure', c.http_only && 'HttpOnly', c.same_site && `SameSite=${c.same_site}`].filter(Boolean).join(', ') || 'no flags'})`).join('; ')}
        </div>
      )}
    </Card>
  )
}

function DnsCard({ dns }: { dns: NonNullable<ScanReport['dns']> }) {
  return (
    <Card title="DNS & email">
      <dl>
        {dns.a.length > 0 && <Row label="A">{dns.a.join(', ')}</Row>}
        {dns.aaaa.length > 0 && <Row label="AAAA">{dns.aaaa.slice(0, 3).join(', ')}</Row>}
        {dns.mx.length > 0 && <Row label="MX">{dns.mx.slice(0, 4).join(', ')}</Row>}
        {dns.ns.length > 0 && <Row label="NS">{dns.ns.slice(0, 4).join(', ')}</Row>}
        <Row label="SPF">{dns.spf ? <span className="font-mono text-xs">{dns.spf}</span> : <span className="text-red-400">missing</span>}</Row>
        <Row label="DMARC">{dns.dmarc ? <span className="font-mono text-xs">{dns.dmarc}</span> : <span className="text-red-400">missing</span>}</Row>
      </dl>
    </Card>
  )
}

function PathsCard({ report }: { report: ScanReport }) {
  return (
    <Card title="Exposed paths">
      <ul className="space-y-1 text-sm">
        {report.paths.filter((p) => p.exposed).map((p) => (
          <li key={p.path} className="flex items-center gap-2">
            <span className="text-amber-400">●</span>
            <span className="font-mono text-xs text-zinc-200">{p.path}</span>
            <span className="text-xs text-zinc-600">{p.status}</span>
          </li>
        ))}
      </ul>
    </Card>
  )
}

function RelatedCard({ related }: { related: NonNullable<ScanReport['related']> }) {
  return (
    <Card title="Related resources">
      <dl>
        <Row label="security.txt">{related.security_txt ? (related.contacts.join(', ') || 'present') : <span className="text-zinc-500">not published</span>}</Row>
        {related.subdomains.length > 0 && <Row label="Cert names">{related.subdomains.slice(0, 8).map((s) => <a key={s} href={`?target=${s}`} className={`mr-2 ${link}`}>{s}</a>)}</Row>}
        {related.assets.length > 0 && <Row label="External assets">{related.assets.slice(0, 8).join(', ')}</Row>}
        {related.disallowed.length > 0 && <Row label="robots.txt">{related.disallowed.length} disallowed paths <span className="font-mono text-xs text-zinc-500">{related.disallowed.slice(0, 5).join(' ')}</span></Row>}
      </dl>
      {related.contacts.length === 0 && !related.subdomains.length && !related.assets.length && !related.disallowed.length && !related.security_txt && (
        <p className="text-sm text-zinc-500">Nothing notable.</p>
      )}
    </Card>
  )
}
