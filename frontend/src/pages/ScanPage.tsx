import { useMutation, useQuery } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, Circle, Fingerprint, Loader2, Lock, Search, ShieldCheck, Zap } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { Link, useSearchParams } from 'react-router'
import { api, ApiError } from '../api/client'
import type { ScanFinding, ScanJob, ScanReport, ScanSeverity, ScanTech } from '../api/types'
import { Card, ErrorBox, Tag } from '../components/ui'
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

  return (
    <div className="mx-auto max-w-3xl">
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
          <button type="submit" disabled={scanning || !input.trim() || (runActive && !authorized)} className={`inline-flex shrink-0 items-center gap-1.5 rounded-full px-4 py-2 text-sm font-medium text-white disabled:opacity-50 ${active ? 'bg-rose-500 hover:bg-rose-400' : 'bg-cyan-500 hover:bg-cyan-400'}`}>
            {scanning ? 'Scanning…' : active ? 'Run active scan' : 'Check exposure'} <span aria-hidden>→</span>
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

      <div className="mt-8 space-y-6">
        {scanning && <ProgressCard job={jobData} active={runActive} target={jobData?.target ?? input.trim()} />}
        {errMsg && !scanning && <ErrorBox error={errMsg} />}
        {report && !scanning && (
          <>
            <div className="flex items-center justify-end">
              <button type="button" onClick={rescan} className="rounded-lg border border-zinc-800 px-3 py-1.5 text-sm text-zinc-300 hover:bg-zinc-800">Re-scan</button>
            </div>
            <ReportView report={report} cached={jobData?.cached ?? false} />
          </>
        )}
        {!report && !scanning && !errMsg && <ScanIntro />}
      </div>
    </div>
  )
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
        <div className="grid gap-x-6 gap-y-4 sm:grid-cols-2">
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


function GradeChip({ grade, small }: { grade: string; small?: boolean }) {
  return (
    <span className={`inline-flex items-center justify-center rounded font-bold ring-1 ring-inset ${gradeColor[grade] ?? gradeColor.F} ${small ? 'h-6 w-6 text-sm' : 'h-16 w-16 text-4xl'}`}>
      {grade}
    </span>
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

function ReportView({ report, cached }: { report: ScanReport; cached: boolean }) {
  const counts = report.findings.reduce<Record<string, number>>((a, f) => ((a[f.severity] = (a[f.severity] ?? 0) + 1), a), {})
  return (
    <>
      <Card>
        <div className="flex flex-wrap items-center gap-4">
          <GradeChip grade={report.grade} />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-baseline gap-2">
              <h2 className="font-mono text-lg font-semibold text-white">{report.host}</h2>
              <span className="text-sm text-zinc-500">{report.ip}</span>
            </div>
            <div className="mt-1 flex flex-wrap gap-1.5">
              {(['critical', 'high', 'medium', 'low', 'info', 'good'] as ScanSeverity[]).filter((s) => counts[s]).map((s) => (
                <span key={s} className={`rounded px-1.5 py-0.5 text-xs font-medium ring-1 ring-inset ${sevStyle[s].tag}`}>{counts[s]} {sevStyle[s].label.toLowerCase()}</span>
              ))}
            </div>
            <p className="mt-1.5 text-xs text-zinc-500">
              Score {report.score}/100 · scanned in {report.duration} · {relativeTime(report.scanned_at)}
              {cached && ' · cached'}{report.http && <> · <a href={report.http.final_url} target="_blank" rel="noreferrer" className={link}>{report.http.final_url}</a></>}
            </p>
          </div>
        </div>
      </Card>

      <Card title="Findings">
        {report.findings.length === 0 ? <p className="text-sm text-zinc-500">No findings.</p> : (
          <ul className="space-y-2">
            {report.findings.map((f, i) => <FindingRow key={i} f={f} />)}
          </ul>
        )}
      </Card>

      {report.active?.ran && (
        <Card title="Active checks (Nuclei)">
          <p className="mb-2 text-xs text-zinc-500">
            {report.active.engine} · {report.active.duration} · {report.active.findings.length} template{report.active.findings.length === 1 ? '' : 's'} matched. These verify issues by probing the target; results also appear in Findings above.
            {report.active.note && <span className="text-amber-300/80"> · {report.active.note}</span>}
          </p>
          {report.active.findings.length === 0 ? (
            <p className="text-sm text-zinc-500">No vulnerability template matched.</p>
          ) : (
            <ul className="space-y-1.5">
              {report.active.findings.map((f) => (
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
      )}

      <div className="grid gap-6 md:grid-cols-2">
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
    </>
  )
}

function FindingRow({ f }: { f: ScanFinding }) {
  const Icon = f.severity === 'good' ? ShieldCheck : AlertTriangle
  return (
    <li className="flex gap-3">
      <span className={`mt-0.5 inline-flex h-5 shrink-0 items-center gap-1 rounded px-1.5 text-xs font-medium ring-1 ring-inset ${sevStyle[f.severity].tag}`}>
        <Icon className="h-3 w-3" />{sevStyle[f.severity].label}
      </span>
      <div className="min-w-0">
        <div className="text-sm text-zinc-200">{f.title} {f.category === 'active' ? <span className="rounded bg-rose-500/15 px-1 text-[10px] font-medium text-rose-300 ring-1 ring-rose-400/30">verified</span> : <span className="text-xs text-zinc-600">· {f.category}</span>}</div>
        {f.detail && <p className="text-xs text-zinc-500">{f.detail}</p>}
      </div>
    </li>
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
