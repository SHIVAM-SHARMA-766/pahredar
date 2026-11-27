import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, FileText, GitCompareArrows, Loader2, Radar, ShieldCheck } from 'lucide-react'
import { api } from '../api/client'
import type { EasmSummary } from '../api/types'
import { Card, ErrorBox, Spinner, Tag } from './ui'
import { relativeTime } from '../lib/format'

// AttackSurface shows an asset's EASM evidence (registration, DNS/subdomain/IP,
// certs, email posture) and lets an operator run a passive or active scan.
// Findings flow into the asset's incident; this surfaces the raw intelligence.

const catLabel: Record<string, string> = {
  subdomain: 'subdomains', ip: 'IPs', dns: 'DNS', cert: 'certs', port: 'ports',
  http_security: 'headers', nameserver: 'nameservers', email: 'email', whois: 'whois', http: 'http', tls: 'tls',
  url: 'archived URLs', dependency: 'dependencies', related_domain: 'related domains', well_known: 'well-known files',
}

export function AttackSurface({ assetId, canEdit }: { assetId: number; canEdit: boolean }) {
  const qc = useQueryClient()
  const summary = useQuery({
    queryKey: ['easm-summary', assetId],
    queryFn: () => api.easmSummary(assetId),
    refetchInterval: (q) => (q.state.data?.last_run?.status === 'running' ? 3000 : false),
  })
  const scan = useMutation({
    mutationFn: (v: { profile: string; authorized?: boolean }) => api.easmScan(assetId, v.profile, v.authorized),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['easm-summary', assetId] }),
  })

  const runStandard = () => scan.mutate({ profile: 'standard' })
  const runActive = () => {
    if (window.confirm('Active scan contacts the target directly (HTTP/TLS requests, a port scan). Confirm you are authorised to test it.')) {
      scan.mutate({ profile: 'active', authorized: true })
    }
  }

  const s = summary.data
  const running = s?.last_run?.status === 'running' || scan.isPending

  const scanned = !!s?.last_run
  const actions = (
    <div className="flex flex-wrap gap-1.5">
      {scanned && (
        <>
          <a href={api.easmReportUrl(assetId, 'html')} target="_blank" rel="noreferrer" title="Open a printable report (use the browser’s Save as PDF)" className="inline-flex items-center gap-1 rounded-lg border border-zinc-600/40 bg-zinc-700/30 px-2.5 py-1 text-xs text-zinc-300 hover:bg-zinc-700/50">
            <FileText className="h-3.5 w-3.5" /> Report
          </a>
          <a href={api.easmReportUrl(assetId, 'csv')} title="Download the record inventory as CSV" className="inline-flex items-center gap-1 rounded-lg border border-zinc-600/40 bg-zinc-700/30 px-2.5 py-1 text-xs text-zinc-300 hover:bg-zinc-700/50">
            <Download className="h-3.5 w-3.5" /> CSV
          </a>
        </>
      )}
      {canEdit && (
        <>
          <button onClick={runStandard} disabled={running} className="inline-flex items-center gap-1 rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-2.5 py-1 text-xs text-cyan-200 hover:bg-cyan-500/20 disabled:opacity-50">
            {running ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Radar className="h-3.5 w-3.5" />} Scan
          </button>
          <button onClick={runActive} disabled={running} className="inline-flex items-center gap-1 rounded-lg border border-rose-400/30 bg-rose-500/10 px-2.5 py-1 text-xs text-rose-200 hover:bg-rose-500/20 disabled:opacity-50">
            Active
          </button>
        </>
      )}
    </div>
  )

  return (
    <Card title="Attack surface" actions={actions}>
      {summary.isPending ? <Spinner /> : summary.isError ? <ErrorBox error={summary.error} /> : !s?.last_run ? (
        <p className="py-4 text-sm text-zinc-500">
          Not scanned yet. {canEdit ? 'Run a passive scan to map this domain’s attack surface (subdomains, DNS, certs, email posture) from public sources.' : 'Ask an operator to run a scan.'}
        </p>
      ) : (
        <Body s={s} assetId={assetId} canEdit={canEdit} running={running} />
      )}
    </Card>
  )
}

function Body({ s, assetId, canEdit, running }: { s: EasmSummary; assetId: number; canEdit: boolean; running: boolean }) {
  const qc = useQueryClient()
  const reg = (s.registration ?? {}) as Record<string, string>
  const promote = useMutation({
    mutationFn: (value: string) => api.easmPromote(assetId, value),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets'] }),
  })

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 text-xs text-zinc-500">
        <span>last scan {relativeTime(s.last_run!.started_at)}</span>
        <Tag tone={s.last_run!.status === 'failed' ? 'red' : s.last_run!.status === 'running' ? 'amber' : 'zinc'}>{running ? 'scanning…' : s.last_run!.status}</Tag>
        <span>·</span>
        <span>{s.last_run!.record_count} records</span>
      </div>

      {/* Category counts */}
      <div className="flex flex-wrap gap-1.5">
        {Object.entries(s.counts).sort().map(([cat, n]) => (
          <span key={cat} className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-300">{n} {catLabel[cat] ?? cat}</span>
        ))}
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        {/* Registration */}
        {reg.registrar && (
          <Field label="Registration">
            <div className="text-zinc-300">{reg.registrar}</div>
            {reg.expires && <div className="text-xs text-zinc-500">expires {reg.expires.slice(0, 10)}</div>}
          </Field>
        )}
        {/* Email posture */}
        <Field label="Email authentication">
          <div className="flex gap-1.5">
            <Tag tone={s.email.spf ? 'zinc' : 'red'}>SPF {s.email.spf ? 'present' : 'missing'}</Tag>
            <Tag tone={s.email.dmarc ? 'zinc' : 'red'}>DMARC {s.email.dmarc ? (s.email.dmarc_policy || 'present') : 'missing'}</Tag>
          </div>
        </Field>
        {/* Certs */}
        {s.certs.count > 0 && (
          <Field label="Certificates">
            <div className="text-zinc-300">{s.certs.count} seen in CT</div>
            {s.certs.soonest_not_after && <div className="text-xs text-zinc-500">earliest expiry {s.certs.soonest_not_after.slice(0, 10)}</div>}
          </Field>
        )}
        {/* IPs */}
        {s.ips.length > 0 && (
          <Field label={`IP addresses (${s.ips.length})`}>
            <ul className="space-y-0.5">
              {s.ips.slice(0, 5).map((ip) => (
                <li key={ip.ip} className="truncate text-xs text-zinc-400"><span className="font-mono text-zinc-300">{ip.ip}</span>{ip.org && <> · {ip.org}</>}</li>
              ))}
            </ul>
          </Field>
        )}
      </div>

      {/* Subdomains with promote */}
      {s.subdomains.length > 0 && (
        <Field label={`Subdomains (${s.subdomains.length})`}>
          <div className="flex flex-wrap gap-1.5">
            {s.subdomains.slice(0, 40).map((sd) => (
              <span key={sd} className="inline-flex items-center gap-1 rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-xs text-zinc-300">
                {sd}
                {canEdit && (
                  <button onClick={() => promote.mutate(sd)} disabled={running} title="Track as an asset" className="text-cyan-400 hover:text-cyan-200 disabled:opacity-50">+</button>
                )}
              </span>
            ))}
          </div>
        </Field>
      )}

      <Changes assetId={assetId} />
    </div>
  )
}

// Changes shows what appeared or dropped off since the previous scan — a derived
// diff over the record timestamps. Hidden until there are at least two scans.
function Changes({ assetId }: { assetId: number }) {
  const changes = useQuery({ queryKey: ['easm-changes', assetId], queryFn: () => api.easmChanges(assetId) })
  const c = changes.data
  if (!c || !c.since_run || (c.added.length === 0 && c.removed.length === 0)) return null
  return (
    <Field label="Changes since last scan">
      <div className="flex flex-wrap gap-1.5">
        <Tag tone={c.added.length ? 'cyan' : 'zinc'}><GitCompareArrows className="mr-1 inline h-3 w-3" />{c.added.length} new</Tag>
        <Tag tone={c.removed.length ? 'amber' : 'zinc'}>{c.removed.length} gone</Tag>
      </div>
      {c.added.length > 0 && (
        <div className="mt-2">
          <div className="text-[11px] tracking-wide text-emerald-400/80 uppercase">Appeared</div>
          <ul className="mt-1 space-y-0.5">
            {c.added.slice(0, 12).map((r) => (
              <li key={`a-${r.category}-${r.key}`} className="text-xs text-zinc-400"><span className="text-zinc-500">{r.category}</span> <span className="font-mono text-zinc-300">{r.key}</span></li>
            ))}
          </ul>
        </div>
      )}
      {c.removed.length > 0 && (
        <div className="mt-2">
          <div className="text-[11px] tracking-wide text-amber-400/80 uppercase">Not re-observed</div>
          <ul className="mt-1 space-y-0.5">
            {c.removed.slice(0, 12).map((r) => (
              <li key={`r-${r.category}-${r.key}`} className="text-xs text-zinc-400"><span className="text-zinc-500">{r.category}</span> <span className="font-mono text-zinc-300">{r.key}</span></li>
            ))}
          </ul>
          {c.note && <p className="mt-1 text-[11px] text-zinc-600">{c.note}</p>}
        </div>
      )}
    </Field>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-1 flex items-center gap-1 text-[11px] tracking-wider text-zinc-500 uppercase"><ShieldCheck className="h-3 w-3" />{label}</div>
      <div className="text-sm">{children}</div>
    </div>
  )
}
