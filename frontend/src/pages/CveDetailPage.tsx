import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, ExternalLink, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router'
import { api } from '../api/client'
import type { Affected, CveDetail, Metric, Reference } from '../api/types'
import { EpssChart } from '../components/charts'
import { ReportsCard } from '../components/ReportsCard'
import { Card, ErrorBox, ExploitTag, KevTag, RansomwareTag, SeverityBadge, Spinner, Tag } from '../components/ui'
import { parseVector } from '../lib/cvss'
import { fmtDate, fmtEpss, fmtPercentile, productPath, vendorPath } from '../lib/format'
import { bestScore, severityText } from '../lib/severity'
import { describeVersions } from '../lib/versions'

const link = 'text-cyan-300 hover:text-cyan-200'

export function CveDetailPage() {
  const { id = '' } = useParams()
  const query = useQuery({ queryKey: ['cve', id], queryFn: () => api.getCve(id) })

  if (query.isPending) return <Spinner />
  if (query.isError) return <ErrorBox error={query.error} />
  const c = query.data

  return (
    <div className="space-y-6">
      <Header c={c} />
      {c.state !== 'REJECTED' && <AssessmentBanner c={c} />}
      <KeyFacts c={c} />
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="min-w-0 space-y-6 lg:col-span-2">
          <Card title="Description">
            <p className="leading-relaxed whitespace-pre-line text-zinc-200">{c.description ?? 'No description.'}</p>
          </Card>
          <ReportsCard id={c.id} />
          <RemediationCard c={c} />
          <CvssCard c={c} />
          <AffectedCard affected={c.affected} />
          <ExploitsCard c={c} />
          <AdvisoryCard c={c} />
          <ReferencesCard refs={c.references} />
          <RelatedCard c={c} />
        </div>
        <div className="min-w-0 space-y-6">
          <WeaknessCard c={c} />
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
              <dt className="text-zinc-500">Assigner (CNA)</dt>
              <dd>{c.assigner ?? '—'}</dd>
              <dt className="text-zinc-500">Reserved</dt>
              <dd>{fmtDate(c.date_reserved)}</dd>
              <dt className="text-zinc-500">NVD status</dt>
              <dd>{c.nvd_status ?? 'not in NVD'}</dd>
              <dt className="text-zinc-500">NVD modified</dt>
              <dd>{fmtDate(c.nvd_last_modified)}</dd>
              <dt className="text-zinc-500">Severity from</dt>
              <dd className="font-mono text-xs">{c.severity_source ?? '—'}</dd>
            </dl>
            <div className="mt-3 flex flex-wrap gap-3 text-sm">
              <ExtLink href={`https://www.cve.org/CVERecord?id=${c.id}`}>cve.org</ExtLink>
              <ExtLink href={`https://nvd.nist.gov/vuln/detail/${c.id}`}>NVD</ExtLink>
              <ExtLink href={`https://github.com/search?q=${c.id}&type=repositories`}>GitHub search</ExtLink>
            </div>
          </Card>
        </div>
      </div>
    </div>
  )
}

function ExtLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noreferrer" className={`inline-flex items-center gap-1 ${link}`}>
      {children}
      <ExternalLink className="h-3 w-3" />
    </a>
  )
}

function Header({ c }: { c: CveDetail }) {
  const best = c.cvss.v4 ?? c.cvss.v3 ?? c.cvss.v2
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="font-mono text-2xl font-bold text-white">{c.id}</h1>
        {c.state === 'REJECTED' ? <Tag>Rejected</Tag> : <SeverityBadge severity={c.severity} score={best?.score} />}
        {c.kev && <KevTag />}
        {c.kev?.known_ransomware_use === 'Known' && <RansomwareTag />}
        {c.has_exploit && <ExploitTag />}
      </div>
      {c.title && <p className="mt-1 text-lg text-zinc-100">{c.title}</p>}
      <p className="mt-1 text-sm text-zinc-500">
        Published {fmtDate(c.date_published)} · Updated {fmtDate(c.date_updated)}
        {c.assigner && <> · CNA {c.assigner}</>}
      </p>
    </div>
  )
}

const priorityInfo = {
  P1: { label: 'Patch now', tone: 'border-red-400/30 bg-red-500/[0.07]', text: 'text-red-200', Icon: ShieldAlert },
  P2: { label: 'Patch soon', tone: 'border-orange-400/30 bg-orange-500/[0.07]', text: 'text-orange-200', Icon: AlertTriangle },
  P3: { label: 'Plan to patch', tone: 'border-amber-400/25 bg-amber-500/[0.05]', text: 'text-amber-100', Icon: ShieldQuestion },
  P4: { label: 'Monitor', tone: 'border-zinc-700 bg-zinc-900', text: 'text-zinc-200', Icon: ShieldCheck },
}

const exploitationLabel = {
  active: 'Exploited in the wild',
  poc: 'Public exploit code',
  none: 'No known exploitation',
}

// Pahredar's heuristic priority (backend internal/api/cves.go assess()).
function AssessmentBanner({ c }: { c: CveDetail }) {
  const p = c.assessment.priority
  if (!p) return null
  const info = priorityInfo[p]
  return (
    <div className={`flex flex-wrap items-start gap-4 rounded-lg border p-4 ${info.tone}`}>
      <info.Icon className={`mt-0.5 h-6 w-6 shrink-0 ${info.text}`} />
      <div className="min-w-0 flex-1">
        <div className={`flex flex-wrap items-baseline gap-x-3 text-base font-semibold ${info.text}`}>
          <span>{p} · {info.label}</span>
          <span className="text-sm font-normal text-zinc-400">{exploitationLabel[c.assessment.exploitation]}</span>
        </div>
        <ul className="mt-1 flex flex-wrap gap-x-4 gap-y-0.5 text-sm text-zinc-300">
          {c.assessment.reasons.map((r) => <li key={r}>• {r}</li>)}
        </ul>
      </div>
      <span className="text-xs text-zinc-500" title="P1: in KEV or SSVC active. P2: EPSS ≥ 10%, or public exploit with CVSS ≥ 7. P3: CVSS ≥ 7 or public exploit. P4: otherwise.">
        How is this decided?
      </span>
    </div>
  )
}

function KeyFacts({ c }: { c: CveDetail }) {
  const best = c.cvss.v4 ?? c.cvss.v3 ?? c.cvss.v2
  const pocs = c.exploits.filter((e) => e.source === 'github').length
  const modules = c.exploits.length - pocs
  const facts: [string, ReactNode][] = [
    ['CVSS', best ? <span className={severityText[c.severity]}>{best.score.toFixed(1)} <span className="text-xs text-zinc-500">v{best.version}</span></span> : '—'],
    ['EPSS', c.epss ? <>{fmtEpss(c.epss.score)} <span className="text-xs text-zinc-500">{fmtPercentile(c.epss.percentile)}</span></> : '—'],
    ['CISA KEV', c.kev ? <>since {fmtDate(c.kev.date_added)}</> : 'not listed'],
    ['Exploit modules', modules || '—'],
    ['GitHub PoCs', pocs || '—'],
    ['Affected products', c.affected.length || '—'],
  ]
  return (
    <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-zinc-800 bg-zinc-800 sm:grid-cols-3 lg:grid-cols-6">
      {facts.map(([label, value]) => (
        <div key={label} className="bg-zinc-900 px-4 py-3">
          <div className="text-[11px] font-semibold tracking-wider text-zinc-500 uppercase">{label}</div>
          <div className="mt-1 text-lg font-semibold text-zinc-100">{value}</div>
        </div>
      ))}
    </div>
  )
}

// References whose tags mark them as fixes or official guidance.
const REMEDIATION_TAGS = ['patch', 'vendor-advisory', 'vendor advisory', 'mitigation', 'release-notes', 'release notes']
const isRemediation = (r: Reference) => (r.tags ?? []).some((t) => REMEDIATION_TAGS.includes(t.toLowerCase()))

function RemediationCard({ c }: { c: CveDetail }) {
  const refs = c.references.filter(isRemediation)
  const { solutions, workarounds } = c.advisory
  if (!solutions.length && !workarounds.length && !refs.length && !c.kev?.required_action) {
    return (
      <Card title="Remediation">
        <p className="text-sm text-zinc-500">No fix, workaround, or vendor advisory has been published in the CVE record or NVD references.</p>
      </Card>
    )
  }
  return (
    <Card title="Remediation">
      <div className="space-y-4 text-sm">
        {solutions.length > 0 && <TextBlock label="Solution (from the CNA)" items={solutions} />}
        {workarounds.length > 0 && <TextBlock label="Workaround" items={workarounds} />}
        {c.kev?.required_action && <TextBlock label="CISA required action" items={[c.kev.required_action]} />}
        {refs.length > 0 && (
          <div>
            <div className="mb-1 text-xs font-semibold tracking-wider text-zinc-500 uppercase">Patches and advisories</div>
            <ul className="space-y-1">
              {refs.map((r) => (
                <li key={r.url} className="flex flex-wrap items-baseline gap-2">
                  <a href={r.url} target="_blank" rel="noreferrer" className={`break-all ${link}`}>{r.name && r.name !== r.url ? r.name : r.url}</a>
                  {(r.tags ?? []).filter((t) => REMEDIATION_TAGS.includes(t.toLowerCase())).map((t) => <Tag key={t} tone="cyan">{t.toLowerCase()}</Tag>)}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </Card>
  )
}

function TextBlock({ label, items }: { label: string; items: string[] }) {
  return (
    <div>
      <div className="mb-1 text-xs font-semibold tracking-wider text-zinc-500 uppercase">{label}</div>
      {items.map((t, i) => <p key={i} className="leading-relaxed whitespace-pre-line text-zinc-200">{t}</p>)}
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
            className={`rounded-md border px-2.5 py-1 text-sm ${i === selected ? 'border-cyan-400/40 bg-cyan-500/10 text-cyan-100' : 'border-zinc-800 text-zinc-400 hover:text-zinc-200'}`}>
            v{e.version} · <span className="font-semibold">{e.score.toFixed(1)}</span> · {providerLabel[e.provider]}
          </button>
        ))}
      </div>
      {m && (
        <>
          <div className="mb-2 font-mono text-xs break-all text-zinc-500">{m.vector}</div>
          <dl className="grid grid-cols-1 gap-x-6 gap-y-1 text-sm sm:grid-cols-2">
            {parseVector(m.version, m.vector).map((p) => (
              <div key={p.key} className="flex justify-between gap-2 border-b border-zinc-800 py-0.5">
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
                <tr key={i} className="border-b border-zinc-800">
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
            <tr className="border-b border-zinc-800 text-left text-[11px] font-semibold tracking-wider text-zinc-500 uppercase">
              <th className="py-1.5 pr-3">Source</th>
              <th className="py-1.5 pr-3">Vendor</th>
              <th className="py-1.5 pr-3">Product</th>
              <th className="py-1.5">Versions</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((a, i) => {
              const versions = describeVersions(a)
              return (
                <tr key={i} className="border-b border-zinc-800/60 align-top">
                  <td className="py-1.5 pr-3 text-zinc-500">{providerLabel[a.source]}</td>
                  <td className="py-1.5 pr-3">
                    {a.vendor ? <Link className={link} to={vendorPath(a.vendor)}>{a.vendor_label || a.vendor}</Link> : '—'}
                  </td>
                  <td className="py-1.5 pr-3">
                    {a.vendor ? <Link className={link} to={productPath(a.vendor, a.product)}>{a.product_label || a.product}</Link> : a.product_label || a.product}
                  </td>
                  <td className="py-1.5 font-mono text-xs text-zinc-300">
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
        <button className={`mt-2 text-sm ${link}`} onClick={() => setShowAll(true)}>Show all {affected.length}</button>
      )}
    </Card>
  )
}

const exploitSource = { exploitdb: 'Exploit-DB', metasploit: 'Metasploit', nuclei: 'Nuclei', github: 'GitHub' }

function ExploitsCard({ c }: { c: CveDetail }) {
  const [showAllPocs, setShowAllPocs] = useState(false)
  const modules = c.exploits.filter((e) => e.source !== 'github')
  const pocs = c.exploits.filter((e) => e.source === 'github')
  const statements = c.advisory.exploit_statements
  if (!modules.length && !pocs.length && !statements.length) {
    return (
      <Card title="Exploits and proofs of concept">
        <p className="text-sm text-zinc-500">No public exploit, Metasploit module, Nuclei template, or GitHub proof of concept is indexed for this CVE.</p>
      </Card>
    )
  }
  const shownPocs = showAllPocs ? pocs : pocs.slice(0, 10)
  return (
    <Card title="Exploits and proofs of concept">
      <div className="space-y-4 text-sm">
        {statements.length > 0 && <TextBlock label="Exploitation status (from the CNA)" items={statements} />}
        {modules.length > 0 && (
          <div>
            <div className="mb-1 text-xs font-semibold tracking-wider text-zinc-500 uppercase">Exploits and modules ({modules.length})</div>
            <ul className="space-y-1">
              {modules.map((e) => (
                <li key={e.source + e.source_ref} className="flex gap-3">
                  <span className="w-24 shrink-0 text-zinc-500">{exploitSource[e.source]}</span>
                  <a href={e.url ?? undefined} target="_blank" rel="noreferrer" className={`min-w-0 ${link}`}>{e.title ?? e.source_ref}</a>
                  {e.published_at && <span className="ml-auto shrink-0 text-zinc-500 tabular-nums">{fmtDate(e.published_at)}</span>}
                </li>
              ))}
            </ul>
          </div>
        )}
        {pocs.length > 0 && (
          <div>
            <div className="mb-1 text-xs font-semibold tracking-wider text-zinc-500 uppercase">GitHub proof-of-concept repositories ({pocs.length})</div>
            <p className="mb-2 text-xs text-zinc-500">Community repositories indexed by PoC-in-GitHub. Unvetted: some are scanners or patches, some are fake or malicious. Review code before running it.</p>
            <ul className="grid gap-x-6 gap-y-1 sm:grid-cols-2">
              {shownPocs.map((e) => (
                <li key={e.source_ref} className="truncate">
                  <a href={e.url ?? undefined} target="_blank" rel="noreferrer" className={`font-mono text-xs ${link}`} title={e.source_ref}>{e.source_ref}</a>
                </li>
              ))}
            </ul>
            {pocs.length > shownPocs.length && (
              <button className={`mt-2 text-sm ${link}`} onClick={() => setShowAllPocs(true)}>Show all {pocs.length}</button>
            )}
          </div>
        )}
      </div>
    </Card>
  )
}

// The rest of what the CNA published: affected configurations, attack
// patterns, credits, and its own timeline.
function AdvisoryCard({ c }: { c: CveDetail }) {
  const a = c.advisory
  if (!a.configurations.length && !a.capec.length && !a.credits.length && !a.timeline.length) return null
  return (
    <Card title="Advisory details">
      <div className="space-y-4 text-sm">
        {a.configurations.length > 0 && <TextBlock label="Required configuration" items={a.configurations} />}
        {a.capec.length > 0 && (
          <div>
            <div className="mb-1 text-xs font-semibold tracking-wider text-zinc-500 uppercase">Attack patterns (CAPEC)</div>
            <ul className="space-y-1">
              {a.capec.map((p) => (
                <li key={p.id}>
                  <a href={`https://capec.mitre.org/data/definitions/${p.id.replace(/^CAPEC-/i, '')}.html`} target="_blank" rel="noreferrer" className={link}>{p.id}</a>
                  <span className="text-zinc-400"> {p.description.replace(new RegExp(`^${p.id}\\s*`, 'i'), '')}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
        {a.credits.length > 0 && (
          <div>
            <div className="mb-1 text-xs font-semibold tracking-wider text-zinc-500 uppercase">Credits</div>
            <ul className="flex flex-wrap gap-1.5">
              {a.credits.map((cr, i) => (
                <li key={i}><Tag>{cr.name}{cr.type && <span className="ml-1 text-zinc-500">· {cr.type.replace(/_/g, ' ')}</span>}</Tag></li>
              ))}
            </ul>
          </div>
        )}
        {a.timeline.length > 0 && (
          <div>
            <div className="mb-1 text-xs font-semibold tracking-wider text-zinc-500 uppercase">CNA timeline</div>
            <ul className="space-y-0.5">
              {a.timeline.map((t, i) => <li key={i}><span className="text-zinc-500 tabular-nums">{t.date}</span> <span className="text-zinc-300">{t.value}</span></li>)}
            </ul>
          </div>
        )}
      </div>
    </Card>
  )
}

// Group references by what they are, not by URL.
function refGroup(r: Reference): string {
  const tags = (r.tags ?? []).map((t) => t.toLowerCase())
  if (tags.some((t) => REMEDIATION_TAGS.includes(t))) return 'Fixes and advisories'
  if (tags.includes('exploit')) return 'Exploits'
  if (tags.some((t) => t.includes('third-party') || t.includes('third party') || t === 'technical-description')) return 'Third-party analysis'
  if (tags.some((t) => t.includes('mailing') || t.includes('issue'))) return 'Mailing lists and issue trackers'
  return 'Other'
}

function ReferencesCard({ refs }: { refs: Reference[] }) {
  if (refs.length === 0) return null
  const order = ['Fixes and advisories', 'Exploits', 'Third-party analysis', 'Mailing lists and issue trackers', 'Other']
  const groups = new Map<string, Reference[]>()
  for (const r of refs) groups.set(refGroup(r), [...(groups.get(refGroup(r)) ?? []), r])
  return (
    <Card title={`References (${refs.length})`}>
      <div className="space-y-4 text-sm">
        {order.filter((g) => groups.has(g)).map((g) => (
          <details key={g} open={g !== 'Other' || groups.size === 1}>
            <summary className="mb-1 cursor-pointer text-xs font-semibold tracking-wider text-zinc-500 uppercase">{g} ({groups.get(g)!.length})</summary>
            <ul className="space-y-1">
              {groups.get(g)!.map((r) => (
                <li key={r.url} className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                  <a href={r.url} target="_blank" rel="noreferrer" className={`break-all ${link}`}>{r.name && r.name !== r.url ? r.name : r.url}</a>
                  {(r.tags ?? []).map((t) => <Tag key={t}>{t.toLowerCase()}</Tag>)}
                </li>
              ))}
            </ul>
          </details>
        ))}
      </div>
    </Card>
  )
}

// Other CVEs for the first affected product (CNA data preferred).
function RelatedCard({ c }: { c: CveDetail }) {
  const target = c.affected.find((a) => a.vendor && a.source !== 'nvd') ?? c.affected.find((a) => a.vendor)
  const params = new URLSearchParams({ page_size: '7' })
  if (target) {
    params.set('vendor', target.vendor)
    params.set('product', target.product)
  }
  const query = useQuery({ queryKey: ['cves', params.toString()], queryFn: () => api.listCves(params), enabled: !!target })
  if (!target) return null
  const items = (query.data?.items ?? []).filter((x) => x.id !== c.id).slice(0, 6)
  return (
    <Card
      title={`Other CVEs in ${target.product_label || target.product}`}
      actions={<Link to={productPath(target.vendor, target.product)} className={`text-xs ${link}`}>All for this product →</Link>}
    >
      {query.isPending ? <Spinner /> : items.length === 0 ? (
        <p className="text-sm text-zinc-500">No other CVEs for this product.</p>
      ) : (
        <ul className="divide-y divide-zinc-800 text-sm">
          {items.map((x) => (
            <li key={x.id} className="flex items-center gap-3 py-1.5">
              <Link to={`/cves/${x.id}`} className={`font-mono text-[13px] font-semibold whitespace-nowrap ${link}`}>{x.id}</Link>
              <span className="min-w-0 flex-1 truncate text-zinc-300">{x.title ?? x.description}</span>
              {x.kev && <KevTag />}
              <span className={`w-8 text-right font-semibold tabular-nums ${severityText[x.severity]}`}>{bestScore(x)?.toFixed(1) ?? '—'}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}

function WeaknessCard({ c }: { c: CveDetail }) {
  if (c.cwes.length === 0) return null
  return (
    <Card title="Weaknesses (CWE)">
      <ul className="space-y-2 text-sm">
        {c.cwes.map((w) => (
          <li key={w.id}>
            <a href={`https://cwe.mitre.org/data/definitions/${w.id.slice(4)}.html`} target="_blank" rel="noreferrer" className={`font-mono text-xs ${link}`}>{w.id}</a>
            <div className="text-zinc-300">{w.name ?? <span className="text-zinc-500">name not in MITRE's research view</span>}</div>
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
        {k.vulnerability_name && <p className="font-medium text-zinc-100">{k.vulnerability_name}</p>}
        <dl className="grid grid-cols-2 gap-y-1">
          <dt className="text-zinc-500">Added</dt>
          <dd>{fmtDate(k.date_added)}</dd>
          <dt className="text-zinc-500">Due</dt>
          <dd>{fmtDate(k.due_date)}</dd>
          <dt className="text-zinc-500">Ransomware use</dt>
          <dd className={k.known_ransomware_use === 'Known' ? 'font-semibold text-red-300' : ''}>{k.known_ransomware_use ?? '—'}</dd>
          {k.forensic_triage && (
            <>
              <dt className="text-zinc-500">Forensic triage</dt>
              <dd>{k.forensic_triage}</dd>
            </>
          )}
        </dl>
        {k.short_description && <p className="text-zinc-400">{k.short_description}</p>}
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
            <span className="text-3xl font-semibold">{fmtEpss(c.epss.score)}</span>
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
      <ol className="relative space-y-3 border-l border-zinc-800 pl-4 text-sm">
        {c.timeline.map((e, i) => (
          <li key={i}>
            <span className={`absolute -left-1.5 mt-1.5 h-3 w-3 rounded-full ${e.type.startsWith('kev') ? 'bg-red-400' : e.type === 'exploit_published' ? 'bg-violet-400' : 'bg-zinc-500'}`} />
            <div className="text-xs text-zinc-500">{fmtDate(e.date)}</div>
            <div className="font-medium">{eventLabel[e.type] ?? e.type}</div>
            {e.detail && e.type !== 'kev_added' && e.type !== 'kev_due' && e.type !== 'updated' && (
              <div className="text-zinc-400">{e.detail}</div>
            )}
          </li>
        ))}
      </ol>
    </Card>
  )
}
