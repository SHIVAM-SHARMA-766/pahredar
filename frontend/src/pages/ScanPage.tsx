import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Search, ShieldCheck } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { Link, useSearchParams } from 'react-router'
import { api, ApiError } from '../api/client'
import type { ScanFinding, ScanReport, ScanSeverity, ScanTech } from '../api/types'
import { Card, ErrorBox, PageHeader, Spinner, Tag } from '../components/ui'
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
  const qc = useQueryClient()

  const scan = useMutation({
    mutationFn: ({ target, fresh }: { target: string; fresh: boolean }) => api.scan(target, fresh),
    onSuccess: (_, v) => {
      setParams({ target: v.target }, { replace: true })
      qc.invalidateQueries({ queryKey: ['recent-scans'] })
    },
  })
  const recent = useQuery({ queryKey: ['recent-scans'], queryFn: api.recentScans, staleTime: 30_000 })

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const t = input.trim()
    if (t) scan.mutate({ target: t, fresh: false })
  }
  const report = scan.data?.report

  return (
    <>
      <PageHeader
        title="Endpoint scanner"
        subtitle="A non-intrusive external security check of a public endpoint: TLS, DNS, HTTP security headers, technology and its known CVEs, exposed paths, and related resources. It only sends the requests a browser would — no exploitation."
      />

      <div className="mb-4 flex items-start gap-2 rounded-lg border border-amber-400/20 bg-amber-500/[0.06] px-3 py-2 text-xs text-amber-200/90">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
        <span>Only scan endpoints you own or are explicitly authorised to assess. Scans are logged.</span>
      </div>

      <form onSubmit={submit} className="mb-6 flex flex-wrap gap-2">
        <div className="relative min-w-64 flex-1">
          <Search className="pointer-events-none absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-zinc-500" />
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="example.com or https://example.com"
            autoFocus
            className="w-full rounded-lg border border-zinc-800 bg-zinc-950 py-2.5 pr-3 pl-9 text-sm placeholder:text-zinc-500 focus:border-cyan-400/40 focus:ring-1 focus:ring-cyan-400/20 focus:outline-none"
          />
        </div>
        <button
          type="submit"
          disabled={scan.isPending || !input.trim()}
          className="rounded-lg bg-cyan-500/15 px-5 py-2.5 text-sm font-medium text-cyan-100 ring-1 ring-cyan-400/30 hover:bg-cyan-500/25 disabled:opacity-50"
        >
          {scan.isPending ? 'Scanning…' : 'Scan'}
        </button>
        {report && !scan.isPending && (
          <button type="button" onClick={() => scan.mutate({ target: report.target, fresh: true })} className="rounded-lg border border-zinc-800 px-3 py-2.5 text-sm text-zinc-300 hover:bg-zinc-800">
            Re-scan
          </button>
        )}
      </form>

      <div className="grid gap-6 lg:grid-cols-[1fr_18rem]">
        <div className="min-w-0 space-y-6">
          {scan.isPending && (
            <Card><Spinner label={`Scanning ${input.trim()}… this takes a few seconds`} /></Card>
          )}
          {scan.isError && !scan.isPending && (
            <ErrorBox error={scan.error instanceof ApiError ? scan.error.message : String(scan.error)} />
          )}
          {report && !scan.isPending && <ReportView report={report} cached={scan.data?.cached ?? false} />}
          {!report && !scan.isPending && !scan.isError && (
            <Card><p className="py-8 text-center text-sm text-zinc-500">Enter a public endpoint above to run a scan.</p></Card>
          )}
        </div>

        <div className="min-w-0">
          <Card title="Recent scans">
            {recent.isPending ? <Spinner /> : !recent.data?.items.length ? (
              <p className="text-sm text-zinc-500">No scans yet.</p>
            ) : (
              <ul className="divide-y divide-zinc-800/70">
                {recent.data.items.map((s) => (
                  <li key={s.id}>
                    <button
                      onClick={() => { setInput(s.target); scan.mutate({ target: s.target, fresh: false }) }}
                      className="flex w-full items-center gap-2 py-2 text-left hover:text-cyan-200"
                    >
                      <GradeChip grade={s.grade} small />
                      <span className="min-w-0 flex-1 truncate text-sm text-zinc-300">{s.host}</span>
                      <span className="shrink-0 text-xs text-zinc-500">{relativeTime(s.created_at)}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      </div>
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
        <div className="text-sm text-zinc-200">{f.title} <span className="text-xs text-zinc-600">· {f.category}</span></div>
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
