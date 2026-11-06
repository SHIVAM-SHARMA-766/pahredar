import { useMutation, useQuery } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, ChevronDown, ChevronRight, Circle, Download, Fingerprint, Info, Loader2, Lock, Search, Send, ShieldCheck, Terminal, Zap } from 'lucide-react'
import { useEffect, useState, type ReactNode } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router'
import { api, ApiError } from '../api/client'
import type { ScanEvidence, ScanFinding, ScanJob, ScanReport, ScanRequestResult, ScanRequestSpec, ScanSeverity, ScanTech } from '../api/types'
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
  // Optional active-scan template filters (run a chosen subset, not all 19k).
  const [tmplTags, setTmplTags] = useState('')
  const [tmplIds, setTmplIds] = useState('')
  const [tmplSev, setTmplSev] = useState<string[]>([])
  const [showFilters, setShowFilters] = useState(false)
  const [jobId, setJobId] = useState<number | null>(() => {
    const j = Number(params.get('job'))
    return Number.isInteger(j) && j > 0 ? j : null
  })
  const config = useQuery({ queryKey: ['scan-config'], queryFn: api.scanConfig, staleTime: 5 * 60_000 })

  const start = useMutation({
    mutationFn: (v: { target: string; fresh?: boolean; active?: boolean; authorized?: boolean; templates?: { tags?: string[]; severity?: string[]; ids?: string[] } }) => api.scan(v.target, { fresh: v.fresh, active: v.active, authorized: v.authorized, templates: v.templates }),
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
    if (t && (!runActive || authorized)) start.mutate({ target: t, active: runActive, authorized, templates: runActive ? buildTemplates() : undefined })
  }
  const buildTemplates = () => {
    const tags = tmplTags.split(',').map((s) => s.trim()).filter(Boolean)
    const ids = tmplIds.split(',').map((s) => s.trim()).filter(Boolean)
    if (!tags.length && !ids.length && !tmplSev.length) return undefined
    return { tags, severity: tmplSev, ids }
  }
  const rescan = () => report && start.mutate({ target: report.target, fresh: true, active: runActive, authorized, templates: runActive ? buildTemplates() : undefined })
  const newScan = () => {
    setJobId(null)
    const next = new URLSearchParams(params)
    next.delete('job')
    setParams(next, { replace: true })
  }

  // The scanner has two tools: the scan (passive/active) and the request tool.
  const view = params.get('view') === 'request' ? 'request' : 'scan'
  const setView = (v: 'scan' | 'request') => {
    const next = new URLSearchParams(params)
    if (v === 'request') next.set('view', 'request')
    else next.delete('view')
    setParams(next, { replace: true })
  }

  if (view === 'request') {
    return (
      <div>
        <ToolTabs view={view} onView={setView} />
        <div className="mt-5"><RequestTool allowPrivate={config.data?.allow_private ?? false} /></div>
      </div>
    )
  }

  // Once a scan is started, the landing is replaced by the result view.
  if (jobId != null) {
    return (
      <div>
        <ToolTabs view={view} onView={setView} />
        <div className="mt-5">
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
        </div>
      </div>
    )
  }

  return (
    <div>
      <ToolTabs view={view} onView={setView} />
      <div className="mt-5" />
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
        {runActive && (
          <div className="mx-auto mt-3 max-w-xl text-left">
            <button type="button" onClick={() => setShowFilters((v) => !v)} className="mx-auto flex items-center gap-1 text-xs text-zinc-400 hover:text-zinc-200">
              {showFilters ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />} Template filters (optional) — run a chosen subset, not all
            </button>
            {showFilters && (
              <div className="mt-2 space-y-2 rounded-lg border border-zinc-800 bg-zinc-950/60 p-3">
                <div>
                  <label className="mb-1 block text-[11px] text-zinc-500">Severity</label>
                  <div className="flex flex-wrap gap-1.5">
                    {['critical', 'high', 'medium', 'low', 'info'].map((sv) => {
                      const on = tmplSev.includes(sv)
                      return <button key={sv} type="button" onClick={() => setTmplSev((p) => on ? p.filter((x) => x !== sv) : [...p, sv])} className={`rounded px-2 py-0.5 text-xs ring-1 ring-inset ${on ? 'bg-rose-500/15 text-rose-200 ring-rose-400/30' : 'text-zinc-400 ring-zinc-700 hover:text-zinc-200'}`}>{sv}</button>
                    })}
                  </div>
                </div>
                <div>
                  <label className="mb-1 block text-[11px] text-zinc-500">Tags (comma-separated, e.g. cve,rce,exposure,wordpress)</label>
                  <input value={tmplTags} onChange={(e) => setTmplTags(e.target.value)} placeholder="cve,exposure,misconfig" className="w-full rounded border border-zinc-800 bg-zinc-950 px-2 py-1 font-mono text-xs text-zinc-200 placeholder:text-zinc-600 focus:border-rose-400/40 focus:outline-none" />
                </div>
                <div>
                  <label className="mb-1 block text-[11px] text-zinc-500">Template IDs (comma-separated)</label>
                  <input value={tmplIds} onChange={(e) => setTmplIds(e.target.value)} placeholder="CVE-2021-44228,git-config" className="w-full rounded border border-zinc-800 bg-zinc-950 px-2 py-1 font-mono text-xs text-zinc-200 placeholder:text-zinc-600 focus:border-rose-400/40 focus:outline-none" />
                </div>
                <p className="text-[11px] text-zinc-600">Leave empty to run the full set. Filters narrow Nuclei to matching templates — far faster for a focused test.</p>
              </div>
            )}
          </div>
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
        <div className="mt-6 space-y-6">
          <ProgressCard job={job} active={active} target={host} />
          {live.length > 0 && <FindingsCard findings={live} live baseUrl={report?.http?.final_url ?? report?.url} />}
        </div>
      ) : errMsg ? (
        <div className="mt-6"><ErrorBox error={errMsg} /></div>
      ) : report ? (
        <div className="mt-6 grid gap-6 lg:grid-cols-[1fr_340px]">
          {/* Details first: a recon profile of the endpoint, section by section. */}
          <div className="min-w-0 space-y-6">
            <HostCard report={report} />
            {report.domain && <DomainCard domain={report.domain} />}
            {report.dns && <DnsCard dns={report.dns} />}
            {report.tls && <TlsCard tls={report.tls} />}
            <div className="grid gap-6 xl:grid-cols-2">
              {report.tech.length > 0 && <TechCard tech={report.tech} />}
              {report.ports.length > 0 && <PortsCard ports={report.ports} />}
            </div>
            {report.subdomains.length > 0 && <SubdomainsCard subdomains={report.subdomains} />}
            <HeadersCard report={report} />
            {report.cookies.length > 0 && <CookiesCard cookies={report.cookies} />}
            {report.paths.some((p) => p.exposed) && <PathsCard report={report} />}
            {report.related && <RelatedCard related={report.related} />}
            {/* Security issues, derived from the details above. */}
            <div id="issues"><FindingsCard findings={report.findings} baseUrl={report.http?.final_url ?? report.url} /></div>
            {report.active?.ran && <ActiveCard active={report.active} />}
            {report.errors.length > 0 && (
              <Card title="Scan notes"><ul className="space-y-1 text-xs text-zinc-500">{report.errors.map((e, i) => <li key={i}>{e}</li>)}</ul></Card>
            )}
          </div>

          <div className="min-w-0 space-y-6">
            <Card title="Security score">
              <ScoreGauge score={report.score} grade={grade} />
              <IssuesSummary findings={report.findings} />
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

// FindingsCard shows a severity-count row and the findings list. With `live`
// it reflects results still streaming in from a running scan.
function FindingsCard({ findings, live = false, baseUrl }: { findings: ScanFinding[]; live?: boolean; baseUrl?: string }) {
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
        <ul className="space-y-2">{findings.map((f, i) => <FindingRow key={`${f.category}-${f.title}-${i}`} f={f} baseUrl={baseUrl} />)}</ul>
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


function FindingRow({ f, baseUrl }: { f: ScanFinding; baseUrl?: string }) {
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
            {open && <EvidenceBlock e={f.evidence} baseUrl={baseUrl} />}
          </div>
        )}
      </div>
    </li>
  )
}

function EvidenceBlock({ e, baseUrl }: { e: ScanEvidence; baseUrl?: string }) {
  const navigate = useNavigate()
  const replay = () => {
    const spec = rawToSpec(e.request, baseUrl)
    if (!spec) return
    try { sessionStorage.setItem('pahredar-replay', JSON.stringify(spec)) } catch { /* ignore */ }
    navigate('?view=request')
  }
  return (
    <div className="mt-1.5 space-y-2 rounded-lg border border-zinc-800 bg-zinc-950 p-3">
      <div>
        <div className="mb-1 flex items-center justify-between">
          <span className="text-[10px] font-semibold tracking-wider text-zinc-500 uppercase">Request sent</span>
          {e.request && <button onClick={replay} className="inline-flex items-center gap-1 text-[11px] text-cyan-300 hover:text-cyan-200"><Terminal className="h-3 w-3" /> Edit & replay</button>}
        </div>
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

// HostCard is the top of the recon profile: the resolved IP, its network
// (reverse DNS, ASN, hosting org), and the live HTTP response.
function HostCard({ report }: { report: ScanReport }) {
  const n = report.net
  return (
    <Card title="Host & network">
      <dl>
        <Row label="IP address">{report.ip}</Row>
        {n?.ptr && <Row label="Reverse DNS">{n.ptr}</Row>}
        {n?.asn && <Row label="ASN">{n.asn}{n.as_org && <span className="text-zinc-400"> · {n.as_org}</span>}</Row>}
        {n?.org && <Row label="Network org">{n.org}</Row>}
        {n?.net_name && <Row label="Net name">{n.net_name}{n.net_range && <span className="text-zinc-500"> · {n.net_range}</span>}</Row>}
        {n?.country && <Row label="Country">{n.country}</Row>}
        {report.http && <Row label="Final URL"><a href={report.http.final_url} target="_blank" rel="noreferrer" className={`break-all ${link}`}>{report.http.final_url}</a></Row>}
        {report.http && <Row label="Status">{report.http.status}</Row>}
        {report.http?.server && <Row label="Server">{report.http.server}</Row>}
        {report.waf && <Row label="WAF / CDN"><span className="rounded bg-violet-500/15 px-1.5 py-0.5 text-xs text-violet-300 ring-1 ring-inset ring-violet-400/30">{report.waf}</span></Row>}
        {report.http?.powered_by && <Row label="Powered by">{report.http.powered_by}</Row>}
        {report.http && <Row label="https redirect">{report.http.https_redirect ? 'yes' : 'no'}</Row>}
        {report.http && report.http.methods.length > 0 && <Row label="Methods">{report.http.methods.join(', ')}</Row>}
      </dl>
    </Card>
  )
}

// DomainCard shows the registration record (RDAP / WHOIS).
function DomainCard({ domain }: { domain: NonNullable<ScanReport['domain']> }) {
  const soon = domain.expires && new Date(domain.expires).getTime() - Date.now() < 30 * 864e5
  return (
    <Card title="Domain registration">
      <dl>
        <Row label="Domain">{domain.domain}</Row>
        {domain.registrar && <Row label="Registrar">{domain.registrar}</Row>}
        {domain.registrant_org && <Row label="Registrant">{domain.registrant_org}</Row>}
        {domain.created && <Row label="Created">{domain.created}</Row>}
        {domain.updated && <Row label="Updated">{domain.updated}</Row>}
        {domain.expires && <Row label="Expires"><span className={soon ? 'text-amber-300' : undefined}>{domain.expires}</span></Row>}
        <Row label="DNSSEC">{domain.dnssec ? <span className="text-emerald-300">enabled</span> : <span className="text-zinc-400">not enabled</span>}</Row>
        {domain.nameservers.length > 0 && <Row label="Nameservers">{domain.nameservers.join(', ')}</Row>}
        {domain.statuses.length > 0 && <Row label="Status"><span className="text-xs text-zinc-400">{domain.statuses.join(', ')}</span></Row>}
      </dl>
      <p className="mt-2 text-[11px] text-zinc-600">Source: RDAP (registry data). Some fields may be redacted by the registrar.</p>
    </Card>
  )
}

function DnsCard({ dns }: { dns: NonNullable<ScanReport['dns']> }) {
  return (
    <Card title="DNS records & email">
      <dl>
        {dns.a.length > 0 && <Row label="A">{dns.a.join(', ')}</Row>}
        {dns.aaaa.length > 0 && <Row label="AAAA">{dns.aaaa.join(', ')}</Row>}
        {dns.mx.length > 0 && <Row label="MX">{dns.mx.join(', ')}</Row>}
        {dns.ns.length > 0 && <Row label="NS">{dns.ns.join(', ')}</Row>}
        {dns.caa.length > 0 && <Row label="CAA">{dns.caa.join(', ')}</Row>}
        <Row label="SPF">{dns.spf ? <span className="font-mono text-xs break-all">{dns.spf}</span> : <span className="text-red-400">missing</span>}</Row>
        <Row label="DMARC">{dns.dmarc ? <span className="font-mono text-xs break-all">{dns.dmarc}</span> : <span className="text-red-400">missing</span>}</Row>
        <Row label="DKIM">{dns.dkim.length > 0 ? dns.dkim.join(', ') : <span className="text-zinc-500">no common selector found</span>}</Row>
        {dns.txt.length > 0 && <Row label="TXT"><div className="space-y-0.5">{dns.txt.map((t, i) => <div key={i} className="font-mono text-xs break-all text-zinc-400">{t}</div>)}</div></Row>}
      </dl>
    </Card>
  )
}

// HeadersCard shows the graded security headers and the full raw header set.
function HeadersCard({ report }: { report: ScanReport }) {
  const [showAll, setShowAll] = useState(false)
  return (
    <Card title="HTTP response headers">
      <div className="mb-1 text-[11px] font-semibold tracking-wider text-zinc-500 uppercase">Security headers</div>
      <ul className="space-y-1 text-sm">
        {report.headers.map((h) => (
          <li key={h.name} className="flex items-center gap-2">
            <span className={h.present ? 'text-emerald-400' : 'text-red-400'}>{h.present ? '✓' : '✗'}</span>
            <span className="text-zinc-300">{h.name}</span>
            {h.value && <span className="min-w-0 truncate font-mono text-xs text-zinc-600" title={h.value}>{h.value}</span>}
          </li>
        ))}
      </ul>
      {report.all_headers.length > 0 && (
        <div className="mt-3 border-t border-zinc-800 pt-2">
          <button onClick={() => setShowAll((v) => !v)} className="inline-flex items-center gap-1 text-xs text-cyan-300 hover:text-cyan-200">
            {showAll ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />} {showAll ? 'Hide' : 'Show'} all {report.all_headers.length} response headers
          </button>
          {showAll && (
            <dl className="mt-2 space-y-1">
              {report.all_headers.map((h, i) => (
                <div key={i} className="grid grid-cols-[10rem_1fr] gap-2 text-xs">
                  <dt className="truncate font-mono text-zinc-400" title={h.name}>{h.name}</dt>
                  <dd className="min-w-0 font-mono break-all text-zinc-300">{h.value}</dd>
                </div>
              ))}
            </dl>
          )}
        </div>
      )}
    </Card>
  )
}

// CookiesCard lists every Set-Cookie and its flags.
function CookiesCard({ cookies }: { cookies: ScanReport['cookies'] }) {
  return (
    <Card title={`Cookies (${cookies.length})`}>
      <ul className="space-y-1.5 text-sm">
        {cookies.map((c) => (
          <li key={c.name} className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-zinc-200">{c.name}</span>
            <span className={`rounded px-1.5 text-[10px] ring-1 ring-inset ${c.secure ? 'text-emerald-300 ring-emerald-400/30' : 'text-red-300 ring-red-400/30'}`}>{c.secure ? 'Secure' : 'no Secure'}</span>
            <span className={`rounded px-1.5 text-[10px] ring-1 ring-inset ${c.http_only ? 'text-emerald-300 ring-emerald-400/30' : 'text-red-300 ring-red-400/30'}`}>{c.http_only ? 'HttpOnly' : 'no HttpOnly'}</span>
            <span className="rounded px-1.5 text-[10px] text-zinc-400 ring-1 ring-inset ring-zinc-700">SameSite={c.same_site || 'none'}</span>
          </li>
        ))}
      </ul>
    </Card>
  )
}

// SubdomainsCard lists subdomains discovered from certificates and CT logs.
function SubdomainsCard({ subdomains }: { subdomains: string[] }) {
  const [showAll, setShowAll] = useState(false)
  const shown = showAll ? subdomains : subdomains.slice(0, 30)
  return (
    <Card title={`Subdomains (${subdomains.length})`} actions={<span className="text-xs text-zinc-500">cert SANs + CT logs</span>}>
      <div className="flex flex-wrap gap-1.5">
        {shown.map((s) => (
          <a key={s} href={`?target=${encodeURIComponent(s)}`} className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-xs text-cyan-300 hover:bg-zinc-700">{s}</a>
        ))}
      </div>
      {subdomains.length > 30 && (
        <button onClick={() => setShowAll((v) => !v)} className="mt-2 text-xs text-cyan-300 hover:text-cyan-200">{showAll ? 'Show fewer' : `Show all ${subdomains.length}`}</button>
      )}
    </Card>
  )
}

// PortsCard lists open TCP ports found by the active scan.
function PortsCard({ ports }: { ports: NonNullable<ScanReport['ports']> }) {
  return (
    <Card title={`Open ports (${ports.length})`}>
      <ul className="space-y-1 text-sm">
        {ports.map((p) => (
          <li key={p.port} className="flex items-center gap-2">
            <span className="text-emerald-400">●</span>
            <span className="font-mono text-zinc-200">{p.port}/tcp</span>
            <span className="text-xs text-zinc-500">{p.service}</span>
          </li>
        ))}
      </ul>
    </Card>
  )
}

// IssuesSummary is the sidebar count of security findings by severity, linking
// to the issues section (the details lead the page; issues are derived).
function IssuesSummary({ findings }: { findings: ScanFinding[] }) {
  const counts = findings.reduce<Record<string, number>>((a, f) => ((a[f.severity] = (a[f.severity] ?? 0) + 1), a), {})
  const total = findings.filter((f) => f.severity !== 'good').length
  return (
    <a href="#issues" className="mt-4 block border-t border-zinc-800 pt-3">
      <div className="flex items-baseline justify-between">
        <span className="text-sm text-zinc-300">Security issues</span>
        <span className="font-mono text-sm font-semibold text-zinc-100">{total}</span>
      </div>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {(['critical', 'high', 'medium', 'low', 'info', 'good'] as ScanSeverity[]).filter((s) => counts[s]).map((s) => (
          <span key={s} className={`rounded px-1.5 py-0.5 text-xs font-medium ring-1 ring-inset ${sevStyle[s].tag}`}>{counts[s]} {sevStyle[s].label.toLowerCase()}</span>
        ))}
      </div>
    </a>
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
        {related.assets.length > 0 && <Row label="External assets">{related.assets.slice(0, 10).join(', ')}</Row>}
        {related.disallowed.length > 0 && <Row label="robots.txt">{related.disallowed.length} disallowed paths <span className="font-mono text-xs text-zinc-500">{related.disallowed.slice(0, 5).join(' ')}</span></Row>}
      </dl>
      {related.contacts.length === 0 && !related.subdomains.length && !related.assets.length && !related.disallowed.length && !related.security_txt && (
        <p className="text-sm text-zinc-500">Nothing notable.</p>
      )}
    </Card>
  )
}

// ToolTabs switches between the scanner and the request tool.
function ToolTabs({ view, onView }: { view: 'scan' | 'request'; onView: (v: 'scan' | 'request') => void }) {
  const tab = (v: 'scan' | 'request', icon: typeof Search, label: string) => {
    const Icon = icon
    const on = view === v
    return (
      <button onClick={() => onView(v)} className={`inline-flex items-center gap-2 border-b-2 px-4 py-2.5 text-sm font-medium transition-colors ${on ? 'border-cyan-400 text-white' : 'border-transparent text-zinc-400 hover:border-zinc-600 hover:text-zinc-200'}`}>
        <Icon className="h-4 w-4" /> {label}
      </button>
    )
  }
  return (
    <div className="flex items-end gap-1 border-b border-zinc-800">
      {tab('scan', Search, 'Endpoint scan')}
      {tab('request', Terminal, 'Request tool')}
    </div>
  )
}

const REQUEST_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']

// RequestTool is a transparent HTTP client (a Repeater): craft a request,
// send it through the scanner's public-only client, and inspect the raw
// request and response. The request bodies of scan findings can be replayed
// here to probe further.
function RequestTool({ allowPrivate }: { allowPrivate: boolean }) {
  const [method, setMethod] = useState('GET')
  const [url, setUrl] = useState('')
  const [headersText, setHeadersText] = useState('')
  const [body, setBody] = useState('')
  const [follow, setFollow] = useState(false)
  // Prefill from a finding's "Edit & replay".
  useEffect(() => {
    let raw: string | null = null
    try { raw = sessionStorage.getItem('pahredar-replay'); sessionStorage.removeItem('pahredar-replay') } catch { /* ignore */ }
    if (!raw) return
    try {
      const s = JSON.parse(raw) as ScanRequestSpec
      setMethod(s.method || 'GET')
      setUrl(s.url || '')
      setHeadersText((s.headers || []).map((h) => `${h.name}: ${h.value}`).join('\n'))
      setBody(s.body || '')
      setFollow(!!s.follow_redirects)
    } catch { /* ignore */ }
  }, [])
  const send = useMutation({
    mutationFn: () => api.scanRequest({ method, url: url.trim(), headers: parseHeaderLines(headersText), body, follow_redirects: follow }),
  })
  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    if (url.trim()) send.mutate()
  }
  const res = send.data

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <form onSubmit={submit} className="space-y-3">
        <Card title="Request">
          <div className="flex gap-2">
            <select value={method} onChange={(e) => setMethod(e.target.value)} className="shrink-0 rounded-lg border border-zinc-800 bg-zinc-950 px-2 py-2 text-sm text-zinc-100 focus:border-cyan-400/40 focus:outline-none">
              {REQUEST_METHODS.map((m) => <option key={m}>{m}</option>)}
            </select>
            <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com/api/path?query=1" autoFocus
              className="min-w-0 flex-1 rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 font-mono text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-cyan-400/40 focus:outline-none" />
            <button type="submit" disabled={!url.trim() || send.isPending} className="inline-flex shrink-0 items-center gap-1.5 rounded-lg bg-cyan-500 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-400 disabled:opacity-50">
              {send.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />} Send
            </button>
          </div>
          <div className="mt-3">
            <label className="mb-1 block text-[11px] font-semibold tracking-wider text-zinc-500 uppercase">Headers (one per line, Name: value)</label>
            <textarea value={headersText} onChange={(e) => setHeadersText(e.target.value)} rows={4} spellCheck={false}
              placeholder={'Authorization: Bearer …\nContent-Type: application/json'}
              className="w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 font-mono text-xs text-zinc-200 placeholder:text-zinc-600 focus:border-cyan-400/40 focus:outline-none" />
          </div>
          <div className="mt-3">
            <label className="mb-1 block text-[11px] font-semibold tracking-wider text-zinc-500 uppercase">Body</label>
            <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={5} spellCheck={false}
              placeholder={'{ "key": "value" }'}
              className="w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 font-mono text-xs text-zinc-200 placeholder:text-zinc-600 focus:border-cyan-400/40 focus:outline-none" />
          </div>
          <label className="mt-3 flex cursor-pointer items-center gap-2 text-sm text-zinc-300">
            <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} className="accent-cyan-400" /> Follow redirects
          </label>
          <p className="mt-2 text-xs text-zinc-600">Sends exactly what you specify, through the scanner's {allowPrivate ? 'client (public and private targets allowed on this server)' : 'public-only client'}. Only test endpoints you are authorised to.</p>
          {send.isError && <p className="mt-2 text-sm text-red-300">{send.error instanceof ApiError ? send.error.message : String(send.error)}</p>}
        </Card>
        {res && (
          <Card title="Request sent">
            <pre className="max-h-64 overflow-auto font-mono text-xs break-all whitespace-pre-wrap text-emerald-300/90">{res.request}</pre>
          </Card>
        )}
      </form>

      <div className="space-y-3">
        {send.isPending ? (
          <Card><div className="flex items-center gap-2 text-sm text-zinc-400"><Loader2 className="h-4 w-4 animate-spin text-cyan-300" /> Sending…</div></Card>
        ) : res ? (
          <ResponseView res={res} />
        ) : (
          <Card><p className="py-8 text-center text-sm text-zinc-500">The response will appear here. Craft a request and press Send.</p></Card>
        )}
      </div>
    </div>
  )
}

function ResponseView({ res }: { res: ScanRequestResult }) {
  const [tab, setTab] = useState<'body' | 'headers'>('body')
  const statusTone = res.status >= 500 ? 'text-red-300' : res.status >= 400 ? 'text-amber-300' : res.status >= 300 ? 'text-sky-300' : 'text-emerald-300'
  return (
    <Card title="Response">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className={`font-mono font-semibold ${statusTone}`}>{res.status} {res.status_text}</span>
        <span className="text-xs text-zinc-500">{res.proto}</span>
        <span className="text-xs text-zinc-500">· {res.time_ms} ms</span>
        <span className="text-xs text-zinc-500">· {fmtBytes(res.body_size)}</span>
        {res.remote_ip && <span className="text-xs text-zinc-500">· {res.remote_ip}</span>}
        {res.waf && <span className="rounded bg-violet-500/15 px-1.5 py-0.5 text-[10px] font-medium text-violet-300 ring-1 ring-inset ring-violet-400/30">WAF: {res.waf}</span>}
        {res.blocked && <span className="rounded bg-red-500/15 px-1.5 py-0.5 text-[10px] font-medium text-red-300 ring-1 ring-inset ring-red-400/30">looks blocked</span>}
      </div>
      <div className="mt-3 flex gap-1 border-b border-zinc-800">
        {(['body', 'headers'] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)} className={`-mb-px border-b-2 px-3 py-1.5 text-xs font-medium ${tab === t ? 'border-cyan-400 text-white' : 'border-transparent text-zinc-400 hover:text-zinc-200'}`}>
            {t === 'body' ? 'Body' : `Headers (${res.headers.length})`}
          </button>
        ))}
      </div>
      {tab === 'body' ? (
        <pre className="mt-2 max-h-[32rem] overflow-auto font-mono text-xs break-all whitespace-pre-wrap text-zinc-300">{res.body || <span className="text-zinc-600">(empty body)</span>}</pre>
      ) : (
        <dl className="mt-2 max-h-[32rem] space-y-1 overflow-auto">
          {res.headers.map((h, i) => (
            <div key={i} className="grid grid-cols-[10rem_1fr] gap-2 text-xs">
              <dt className="truncate font-mono text-zinc-400" title={h.name}>{h.name}</dt>
              <dd className="min-w-0 font-mono break-all text-zinc-300">{h.value}</dd>
            </div>
          ))}
        </dl>
      )}
    </Card>
  )
}

// parseHeaderLines turns "Name: value" lines into header pairs.
function parseHeaderLines(text: string): { name: string; value: string }[] {
  const out: { name: string; value: string }[] = []
  for (const line of text.split('\n')) {
    const i = line.indexOf(':')
    if (i <= 0) continue
    const name = line.slice(0, i).trim()
    const value = line.slice(i + 1).trim()
    if (name) out.push({ name, value })
  }
  return out
}

function fmtBytes(n: number): string {
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MB`
  if (n >= 1 << 10) return `${(n / (1 << 10)).toFixed(1)} KB`
  return `${n} B`
}

// rawToSpec parses a raw HTTP request (as captured in evidence) into a request
// spec the request tool can send. baseUrl supplies the scheme/host when the
// request line has only a path.
function rawToSpec(raw: string, baseUrl?: string): ScanRequestSpec | null {
  if (!raw) return null
  const lines = raw.replace(/\r/g, '').split('\n')
  const m = lines[0].trim().match(/^([A-Z]+)\s+(\S+)(?:\s+HTTP\/[\d.]+)?$/)
  if (!m) return null
  const method = m[1]
  let path = m[2]
  const headers: { name: string; value: string }[] = []
  let host = ''
  let bodyStart = -1
  for (let i = 1; i < lines.length; i++) {
    if (lines[i].trim() === '') { bodyStart = i + 1; break }
    const idx = lines[i].indexOf(':')
    if (idx <= 0) continue
    const name = lines[i].slice(0, idx).trim()
    const value = lines[i].slice(idx + 1).trim()
    if (name.toLowerCase() === 'host') { host = value; continue }
    headers.push({ name, value })
  }
  const body = bodyStart >= 0 ? lines.slice(bodyStart).join('\n') : ''
  let scheme = 'https'
  let baseHost = host
  try { const b = baseUrl ? new URL(baseUrl) : null; if (b) { scheme = b.protocol.replace(':', ''); if (!baseHost) baseHost = b.host } } catch { /* ignore */ }
  const url = /^https?:\/\//.test(path) ? path : `${scheme}://${baseHost}${path.startsWith('/') ? '' : '/'}${path}`
  return { method, url, headers, body, follow_redirects: false }
}
