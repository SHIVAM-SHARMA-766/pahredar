import { useQuery } from '@tanstack/react-query'
import { ExternalLink } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { api } from '../api/client'
import type { OsvAdvisory, RedHatReport, ReportStatus, UbuntuReport } from '../api/types'
import { Card, Spinner, Tag } from './ui'

// Third-party write-ups fetched on demand by the backend (GET
// /cves/{id}/reports) and cached for a week. Coverage is best for
// open-source and Linux software.

const SOURCE_LABEL: Partial<Record<ReportStatus['source'], string>> = {
  osv: 'OSV / GitHub advisories',
  redhat: 'Red Hat',
  ubuntu: 'Ubuntu',
}

const link = 'text-cyan-300 hover:text-cyan-200'

export function ReportsCard({ id }: { id: string }) {
  const query = useQuery({ queryKey: ['reports', id, 'writeups'], queryFn: () => api.getCveReports(id, ['osv', 'redhat', 'ubuntu']), staleTime: 10 * 60_000 })
  const [picked, setPicked] = useState<ReportStatus['source'] | null>(null)

  if (query.isPending) {
    return (
      <Card title="In-depth reports">
        <Spinner label="Fetching OSV, Red Hat, and Ubuntu reports…" />
      </Card>
    )
  }
  if (query.isError) {
    return <Card title="In-depth reports"><p className="text-sm text-zinc-500">Reports are unavailable right now.</p></Card>
  }

  const { sources, reports } = query.data
  const available = sources.filter((s) => s.status === 'ok').map((s) => s.source)
  const tab = picked && available.includes(picked) ? picked : available[0]

  return (
    <Card title="In-depth reports">
      <div className="mb-4 flex flex-wrap items-center gap-2 text-xs">
        {sources.map((s) =>
          s.status === 'ok' ? (
            <button
              key={s.source}
              onClick={() => setPicked(s.source)}
              className={`rounded-md border px-3 py-1.5 text-sm ${tab === s.source ? 'border-cyan-400/40 bg-cyan-500/10 text-cyan-100' : 'border-zinc-700 text-zinc-300 hover:bg-zinc-800'}`}
            >
              {SOURCE_LABEL[s.source]}
            </button>
          ) : (
            <span key={s.source} className="rounded-md border border-dashed border-zinc-800 px-3 py-1.5 text-zinc-500" title={s.error}>
              {SOURCE_LABEL[s.source]}: {s.status === 'not_found' ? 'no record' : 'unavailable, retry later'}
            </span>
          ),
        )}
      </div>

      {!tab ? (
        <p className="text-sm text-zinc-500">
          None of these sources covers this CVE. They focus on open-source and Linux software; for closed-source products, the vendor advisory under References is the detailed source.
        </p>
      ) : tab === 'osv' ? (
        <OsvReport advisories={reports.osv ?? []} />
      ) : tab === 'redhat' ? (
        <RedHat r={reports.redhat!} />
      ) : (
        <Ubuntu r={reports.ubuntu!} />
      )}
    </Card>
  )
}

function Section({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <div className="mb-1 text-xs font-semibold tracking-wider text-zinc-500 uppercase">{label}</div>
      {children}
    </div>
  )
}

function Prose({ text }: { text: string }) {
  // Advisory text is Markdown-ish; show it as plain text, turning "## Heading"
  // lines into bold headings. Nothing is rendered as HTML.
  return (
    <div className="space-y-2 text-sm leading-relaxed text-zinc-200">
      {text.split(/\n{2,}/).map((block, i) => {
        const heading = block.match(/^#{1,6}\s+(.*)$/)
        return heading ? (
          <p key={i} className="pt-1 font-semibold text-zinc-100">{heading[1]}</p>
        ) : (
          <p key={i} className="whitespace-pre-line">{block.replace(/^#{1,6}\s+/gm, '')}</p>
        )
      })}
    </div>
  )
}

function Source({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noreferrer" className={`inline-flex items-center gap-1 text-xs ${link}`}>
      {children} <ExternalLink className="h-3 w-3" />
    </a>
  )
}

const th = 'py-1.5 pr-3 text-left text-[11px] font-semibold tracking-wider text-zinc-500 uppercase'

function OsvReport({ advisories }: { advisories: OsvAdvisory[] }) {
  return (
    <div className="space-y-6">
      {advisories.map((a) => (
        <article key={a.id} className="space-y-3">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <div>
              <span className="font-mono text-sm font-semibold text-zinc-100">{a.id}</span>
              {a.summary && <span className="ml-2 text-zinc-300">{a.summary}</span>}
            </div>
            <Source href={a.url}>osv.dev</Source>
          </div>
          {a.details && <Prose text={a.details} />}
          {a.affected.length > 0 && (
            <Section label="Affected packages">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead><tr className="border-b border-zinc-800"><th className={th}>Ecosystem</th><th className={th}>Package</th><th className={th}>Introduced</th><th className={th}>Fixed in</th></tr></thead>
                  <tbody>
                    {a.affected.map((p, i) => (
                      <tr key={i} className="border-b border-zinc-800/60 align-top">
                        <td className="py-1.5 pr-3 text-zinc-400">{p.ecosystem}</td>
                        <td className="py-1.5 pr-3 font-mono text-xs break-all text-zinc-200">{p.package}</td>
                        <td className="py-1.5 pr-3 font-mono text-xs text-zinc-400">{p.introduced.join(', ') || 'all'}</td>
                        <td className="py-1.5 font-mono text-xs text-emerald-300">{p.fixed.join(', ') || (p.last_affected.length ? `≤ ${p.last_affected.join(', ')} (no fix)` : 'no fix listed')}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Section>
          )}
        </article>
      ))}
    </div>
  )
}

function RedHat({ r }: { r: RedHatReport }) {
  const [all, setAll] = useState(false)
  const fixed = all ? r.fixed_in : r.fixed_in.slice(0, 8)
  return (
    <div className="space-y-4 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        {r.threat_severity && <Tag>Red Hat severity: {r.threat_severity}</Tag>}
        {r.cvss3_score && <Tag>CVSS {r.cvss3_score}</Tag>}
        {r.cwe && <Tag>{r.cwe}</Tag>}
        {r.public_date && <span className="text-xs text-zinc-500">public {r.public_date.slice(0, 10)}</span>}
        <span className="ml-auto flex gap-3">
          {r.bugzilla_url && <Source href={r.bugzilla_url}>Bugzilla</Source>}
          <Source href={r.url}>access.redhat.com</Source>
        </span>
      </div>
      {r.summary && <p className="font-medium text-zinc-100">{r.summary}</p>}
      {r.details.length > 0 && <Section label="Analysis"><Prose text={r.details.join('\n\n')} /></Section>}
      {r.statement && <Section label="Red Hat statement"><Prose text={r.statement} /></Section>}
      {r.mitigation && <Section label="Mitigation"><Prose text={r.mitigation} /></Section>}
      {r.fixed_in.length > 0 && (
        <Section label={`Fixed in (${r.fixed_in.length})`}>
          <table className="w-full text-sm">
            <thead><tr className="border-b border-zinc-800"><th className={th}>Product</th><th className={th}>Package</th><th className={th}>Advisory</th><th className={th}>Date</th></tr></thead>
            <tbody>
              {fixed.map((f, i) => (
                <tr key={i} className="border-b border-zinc-800/60 align-top">
                  <td className="py-1.5 pr-3 text-zinc-300">{f.product}</td>
                  <td className="py-1.5 pr-3 font-mono text-xs break-all text-zinc-400">{f.package ?? '—'}</td>
                  <td className="py-1.5 pr-3">{f.advisory ? <a className={`font-mono text-xs ${link}`} href={`https://access.redhat.com/errata/${f.advisory}`} target="_blank" rel="noreferrer">{f.advisory}</a> : '—'}</td>
                  <td className="py-1.5 text-xs text-zinc-500 tabular-nums">{f.release_date?.slice(0, 10) ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {r.fixed_in.length > fixed.length && <button className={`mt-2 text-sm ${link}`} onClick={() => setAll(true)}>Show all {r.fixed_in.length}</button>}
        </Section>
      )}
      {r.states.length > 0 && (
        <Section label="Other products">
          <ul className="space-y-0.5">
            {r.states.map((s, i) => (
              <li key={i} className="text-zinc-400"><span className="text-zinc-300">{s.product}</span> · <span className="font-mono text-xs">{s.package}</span> · {s.fix_state}</li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  )
}

const ubuntuTone = (status: string) =>
  status === 'released' ? 'text-emerald-300' : status === 'not-affected' ? 'text-zinc-500' : status === 'needed' || status === 'needs-triage' ? 'text-amber-200' : 'text-zinc-300'

function Ubuntu({ r }: { r: UbuntuReport }) {
  return (
    <div className="space-y-4 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        {r.priority && <Tag>Ubuntu priority: {r.priority}</Tag>}
        <span className="ml-auto"><Source href={r.url}>ubuntu.com/security</Source></span>
      </div>
      {r.ubuntu_description && <Section label="Ubuntu description"><Prose text={r.ubuntu_description} /></Section>}
      {r.notes.length > 0 && (
        <Section label="Security team notes">
          <ul className="space-y-2">
            {r.notes.map((n, i) => <li key={i}><span className="text-xs text-zinc-500">{n.author}</span><Prose text={n.note} /></li>)}
          </ul>
        </Section>
      )}
      {r.mitigation && <Section label="Mitigation"><Prose text={r.mitigation} /></Section>}
      {r.packages.length > 0 && (
        <Section label="Package status by release">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b border-zinc-800"><th className={th}>Package</th><th className={th}>Release</th><th className={th}>Status</th><th className={th}>Detail</th></tr></thead>
              <tbody>
                {r.packages.flatMap((p) =>
                  p.statuses.map((s, i) => (
                    <tr key={p.name + s.release} className="border-b border-zinc-800/60">
                      <td className="py-1 pr-3 font-mono text-xs text-zinc-300">{i === 0 ? p.name : ''}</td>
                      <td className="py-1 pr-3 text-zinc-400">{s.release}</td>
                      <td className={`py-1 pr-3 ${ubuntuTone(s.status)}`}>{s.status}</td>
                      <td className="py-1 font-mono text-xs text-zinc-500">{s.description}</td>
                    </tr>
                  )),
                )}
              </tbody>
            </table>
          </div>
        </Section>
      )}
    </div>
  )
}
