import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useParams } from 'react-router'
import { api } from '../api/client'
import type { Affected, CveDetail, Metric, Reference } from '../api/types'
import { EpssChart } from '../components/charts'
import { Card, ErrorBox, ExploitTag, KevTag, SeverityBadge, Spinner, Tag } from '../components/ui'
import { parseVector } from '../lib/cvss'
import { fmtDate, fmtEpss, fmtPercentile, productPath, vendorPath } from '../lib/format'
import { describeVersions } from '../lib/versions'

export function CveDetailPage() {
  const { id = '' } = useParams()
  const query = useQuery({ queryKey: ['cve', id], queryFn: () => api.getCve(id) })

  if (query.isPending) return <Spinner />
  if (query.isError) return <ErrorBox error={query.error} />
  const c = query.data

  return (
    <div className="space-y-6">
      <Header c={c} />
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Card title="Description">
            <p className="leading-relaxed whitespace-pre-line">{c.description ?? 'No description.'}</p>
            {c.cwe_ids.length > 0 && (
              <div className="mt-3 flex flex-wrap gap-1">
                {c.cwe_ids.map((cwe) => (
                  <a key={cwe} href={`https://cwe.mitre.org/data/definitions/${cwe.slice(4)}.html`} target="_blank" rel="noreferrer">
                    <Tag>{cwe}</Tag>
                  </a>
                ))}
              </div>
            )}
          </Card>
          <CvssCard c={c} />
          <AffectedCard affected={c.affected} />
          {c.exploits.length > 0 && <ExploitsCard c={c} />}
          <ReferencesCard refs={c.references} />
        </div>
        <div className="space-y-6">
          {c.kev && <KevCard c={c} />}
          <EpssCard c={c} />
          {c.ssvc && (
            <Card title="CISA SSVC">
              <dl className="grid grid-cols-2 gap-y-1 text-sm">
                <dt className="text-zinc-500">Exploitation</dt>
                <dd className="font-medium capitalize">{c.ssvc.exploitation ?? '—'}</dd>
                <dt className="text-zinc-500">Automatable</dt>
                <dd className="font-medium capitalize">{c.ssvc.automatable ?? '—'}</dd>
                <dt className="text-zinc-500">Technical impact</dt>
                <dd className="font-medium capitalize">{c.ssvc.technical_impact ?? '—'}</dd>
              </dl>
            </Card>
          )}
          <TimelineCard c={c} />
          <Card title="Record">
            <dl className="grid grid-cols-2 gap-y-1 text-sm">
              <dt className="text-zinc-500">Assigner</dt>
              <dd>{c.assigner ?? '—'}</dd>
              <dt className="text-zinc-500">NVD status</dt>
              <dd>{c.nvd_status ?? 'not in NVD'}</dd>
              <dt className="text-zinc-500">Severity from</dt>
              <dd className="font-mono text-xs">{c.severity_source ?? '—'}</dd>
            </dl>
            <div className="mt-3 flex gap-3 text-sm">
              <a className="text-cyan-300 hover:text-cyan-200" href={`https://www.cve.org/CVERecord?id=${c.id}`} target="_blank" rel="noreferrer">cve.org</a>
              <a className="text-cyan-300 hover:text-cyan-200" href={`https://nvd.nist.gov/vuln/detail/${c.id}`} target="_blank" rel="noreferrer">NVD</a>
            </div>
          </Card>
        </div>
      </div>
    </div>
  )
}

function Header({ c }: { c: CveDetail }) {
  const best = c.cvss.v4 ?? c.cvss.v3 ?? c.cvss.v2
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="font-mono text-2xl font-bold">{c.id}</h1>
        {c.state === 'REJECTED' ? <Tag>Rejected</Tag> : <SeverityBadge severity={c.severity} score={best?.score} />}
        {c.kev && <KevTag />}
        {c.has_exploit && <ExploitTag />}
        {c.epss && <Tag title={fmtPercentile(c.epss.percentile)}>EPSS {fmtEpss(c.epss.score)}</Tag>}
      </div>
      {c.title && <p className="mt-1 text-lg">{c.title}</p>}
      <p className="mt-1 text-sm text-zinc-500">
        Published {fmtDate(c.date_published)} · Updated {fmtDate(c.date_updated)}
      </p>
    </div>
  )
}

const providerLabel = { cna: 'CNA', adp: 'CISA ADP', nvd: 'NVD' }

function CvssCard({ c }: { c: CveDetail }) {
  const effective = [c.cvss.v4, c.cvss.v3, c.cvss.v2].filter((m): m is Metric => m != null)
  const [selected, setSelected] = useState(0)
  if (c.metrics.length === 0) {
    return <Card title="CVSS"><p className="text-sm text-zinc-500">No CVSS scores from any provider yet.</p></Card>
  }
  const m = effective[selected] ?? effective[0]
  return (
    <Card title="CVSS">
      <div className="mb-3 flex flex-wrap gap-2">
        {effective.map((e, i) => (
          <button key={e.version} onClick={() => setSelected(i)}
            className={`rounded border px-2 py-1 text-sm ${i === selected ? 'border-zinc-800 dark:border-zinc-200' : 'border-zinc-300 text-zinc-500 dark:border-zinc-700'}`}>
            v{e.version} · <span className="font-semibold">{e.score.toFixed(1)}</span> · {providerLabel[e.provider]}
          </button>
        ))}
      </div>
      {m && (
        <>
          <div className="mb-2 font-mono text-xs break-all text-zinc-500">{m.vector}</div>
          <dl className="grid grid-cols-1 gap-x-6 gap-y-1 text-sm sm:grid-cols-2">
            {parseVector(m.version, m.vector).map((p) => (
              <div key={p.key} className="flex justify-between gap-2 border-b border-zinc-100 py-0.5 dark:border-zinc-800">
                <dt className="text-zinc-500">{p.name}</dt>
                <dd className="font-medium">{p.label}</dd>
              </div>
            ))}
          </dl>
        </>
      )}
      {c.metrics.length > 1 && (
        <details className="mt-4 text-sm">
          <summary className="cursor-pointer text-zinc-500">All {c.metrics.length} scores by provider</summary>
          <table className="mt-2 w-full">
            <tbody>
              {c.metrics.map((x, i) => (
                <tr key={i} className="border-b border-zinc-100 dark:border-zinc-800">
                  <td className="py-1 pr-2">{providerLabel[x.provider]}</td>
                  <td className="py-1 pr-2 text-zinc-500">{x.provider_name}</td>
                  <td className="py-1 pr-2">v{x.version}</td>
                  <td className="py-1 pr-2"><SeverityBadge severity={x.severity} score={x.score} /></td>
                  <td className="py-1 font-mono text-xs break-all text-zinc-500">{x.vector}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
    </Card>
  )
}

function AffectedCard({ affected }: { affected: Affected[] }) {
  const [showAll, setShowAll] = useState(false)
  if (affected.length === 0) {
    return <Card title="Affected products"><p className="text-sm text-zinc-500">No affected products listed.</p></Card>
  }
  const shown = showAll ? affected : affected.slice(0, 15)
  return (
    <Card title={`Affected products (${affected.length})`}>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-200 text-left text-xs text-zinc-500 uppercase dark:border-zinc-800">
              <th className="py-1 pr-3 font-medium">Source</th>
              <th className="py-1 pr-3 font-medium">Vendor</th>
              <th className="py-1 pr-3 font-medium">Product</th>
              <th className="py-1 font-medium">Versions</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((a, i) => {
              const versions = describeVersions(a)
              return (
                <tr key={i} className="border-b border-zinc-100 align-top dark:border-zinc-800">
                  <td className="py-1 pr-3 text-zinc-500">{providerLabel[a.source]}</td>
                  <td className="py-1 pr-3">
                    {a.vendor ? <Link className="text-cyan-300 hover:text-cyan-200" to={vendorPath(a.vendor)}>{a.vendor}</Link> : '—'}
                  </td>
                  <td className="py-1 pr-3">
                    {a.vendor ? <Link className="text-cyan-300 hover:text-cyan-200" to={productPath(a.vendor, a.product)}>{a.product}</Link> : a.product}
                  </td>
                  <td className="py-1 font-mono text-xs">
                    {versions.slice(0, 6).join(', ') || '—'}
                    {versions.length > 6 && <span className="text-zinc-500"> +{versions.length - 6} more</span>}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {affected.length > shown.length && (
        <button className="mt-2 text-sm text-cyan-300 hover:text-cyan-200" onClick={() => setShowAll(true)}>
          Show all {affected.length}
        </button>
      )}
    </Card>
  )
}

const exploitSource = { exploitdb: 'Exploit-DB', metasploit: 'Metasploit', nuclei: 'Nuclei' }

function ExploitsCard({ c }: { c: CveDetail }) {
  return (
    <Card title={`Public exploits (${c.exploits.length})`}>
      <ul className="space-y-1 text-sm">
        {c.exploits.map((e) => (
          <li key={e.source + e.source_ref} className="flex gap-2">
            <span className="w-24 shrink-0 text-zinc-500">{exploitSource[e.source]}</span>
            <a href={e.url ?? undefined} target="_blank" rel="noreferrer" className="text-cyan-300 hover:text-cyan-200">
              {e.title ?? e.source_ref}
            </a>
            {e.published_at && <span className="ml-auto shrink-0 text-zinc-500">{fmtDate(e.published_at)}</span>}
          </li>
        ))}
      </ul>
    </Card>
  )
}

function ReferencesCard({ refs }: { refs: Reference[] }) {
  if (refs.length === 0) return null
  return (
    <Card title={`References (${refs.length})`}>
      <ul className="space-y-1 text-sm">
        {refs.map((r) => (
          <li key={r.url} className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <a href={r.url} target="_blank" rel="noreferrer" className="break-all text-cyan-300 hover:text-cyan-200">
              {r.name && r.name !== r.url ? r.name : r.url}
            </a>
            {(r.tags ?? []).map((t) => (
              <Tag key={t}>{t.toLowerCase()}</Tag>
            ))}
          </li>
        ))}
      </ul>
    </Card>
  )
}

function KevCard({ c }: { c: CveDetail }) {
  const k = c.kev!
  return (
    <Card title="CISA KEV">
      <div className="space-y-2 text-sm">
        {k.vulnerability_name && <p className="font-medium">{k.vulnerability_name}</p>}
        <dl className="grid grid-cols-2 gap-y-1">
          <dt className="text-zinc-500">Added</dt>
          <dd>{fmtDate(k.date_added)}</dd>
          <dt className="text-zinc-500">Due</dt>
          <dd>{fmtDate(k.due_date)}</dd>
          <dt className="text-zinc-500">Ransomware use</dt>
          <dd className={k.known_ransomware_use === 'Known' ? 'font-semibold text-red-300' : ''}>{k.known_ransomware_use ?? '—'}</dd>
        </dl>
        {k.required_action && <p className="text-zinc-600 dark:text-zinc-400">{k.required_action}</p>}
      </div>
    </Card>
  )
}

function EpssCard({ c }: { c: CveDetail }) {
  return (
    <Card title="EPSS">
      {c.epss ? (
        <div className="space-y-3">
          <div className="flex items-baseline gap-3">
            <span className="text-3xl font-semibold tabular-nums">{fmtEpss(c.epss.score)}</span>
            <span className="text-sm text-zinc-500">{fmtPercentile(c.epss.percentile)} · {fmtDate(c.epss.score_date)}</span>
          </div>
          <p className="text-xs text-zinc-500">Probability of exploitation activity in the next 30 days.</p>
          <EpssChart history={c.epss.history} />
        </div>
      ) : (
        <p className="text-sm text-zinc-500">Not scored by EPSS.</p>
      )}
    </Card>
  )
}

const eventLabel: Record<string, string> = {
  reserved: 'ID reserved',
  published: 'Published',
  kev_added: 'Added to KEV',
  kev_due: 'KEV due date',
  exploit_published: 'Exploit published',
  epss_spike: 'EPSS spike',
  updated: 'Last updated',
}

function TimelineCard({ c }: { c: CveDetail }) {
  return (
    <Card title="Timeline">
      <ol className="relative space-y-3 border-l border-zinc-200 pl-4 text-sm dark:border-zinc-800">
        {c.timeline.map((e, i) => (
          <li key={i}>
            <span className={`absolute -left-1.5 mt-1.5 h-3 w-3 rounded-full ${e.type.startsWith('kev') ? 'bg-red-400' : e.type === 'exploit_published' ? 'bg-violet-400' : 'bg-zinc-400'}`} />
            <div className="text-xs text-zinc-500">{fmtDate(e.date)}</div>
            <div className="font-medium">{eventLabel[e.type] ?? e.type}</div>
            {e.detail && e.type !== 'kev_added' && e.type !== 'kev_due' && e.type !== 'updated' && (
              <div className="text-zinc-600 dark:text-zinc-400">{e.detail}</div>
            )}
          </li>
        ))}
      </ol>
    </Card>
  )
}
