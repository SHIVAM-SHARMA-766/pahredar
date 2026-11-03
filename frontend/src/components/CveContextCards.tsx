// CVE page cards for attack context (ATT&CK, CAPEC), NVD change history,
// fix commits, and Debian status.
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { api } from '../api/client'
import type { CapecPattern, CveDetail, DebianStatus, HistoryChange } from '../api/types'
import { fmtDate } from '../lib/format'
import { Card, Spinner, Tag } from './ui'

const link = 'text-cyan-300 hover:text-cyan-200'
const label = 'mb-1 text-xs font-semibold tracking-wider text-zinc-500 uppercase'

export function useAttack(id: string) {
  return useQuery({ queryKey: ['attack', id], queryFn: () => api.getAttack(id), staleTime: 10 * 60_000 })
}

const techniqueUrl = (id: string) => `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`

const mappingLabel: Record<string, string> = {
  exploitation_technique: 'How it is exploited',
  primary_impact: 'Primary impact',
  secondary_impact: 'Secondary impact',
  uncategorized: 'Other',
}

export function AttackCard({ c }: { c: CveDetail }) {
  const q = useAttack(c.id)
  if (q.isPending) return <Card title="MITRE ATT&CK"><Spinner /></Card>
  if (q.isError) return <Card title="MITRE ATT&CK"><p className="text-sm text-zinc-500">Could not load attack mappings.</p></Card>
  const { mappings, capec } = q.data
  const groups = Object.keys(mappingLabel).map((k) => [k, mappings.filter((m) => m.mapping_type === k)] as const).filter(([, l]) => l.length)
  // Techniques reached through CAPEC, for CVEs without a CTID mapping.
  const viaCapec = new Map<string, string>()
  for (const p of capec) for (const t of p.attack) viaCapec.set(t.id, t.name)
  const capability = mappings.find((m) => m.capability_group)?.capability_group
  // CTID often repeats one comment across a CVE's techniques; show each once.
  const firstWithComment = new Map<string, string>()
  for (const m of mappings) if (m.comments && !firstWithComment.has(m.comments)) firstWithComment.set(m.comments, m.technique_id + m.mapping_type)

  return (
    <div className="space-y-6">
      <Card title="MITRE ATT&CK">
        {mappings.length > 0 ? (
          <div className="space-y-4 text-sm">
            <p className="text-xs text-zinc-500">
              Mapped by the Center for Threat-Informed Defense (KEV mappings).{capability && <> Capability: <span className="text-zinc-300">{capability}</span>.</>}
            </p>
            {groups.map(([k, list]) => (
              <div key={k}>
                <div className={label}>{mappingLabel[k]}</div>
                <ul className="space-y-2">
                  {list.map((m) => (
                    <li key={m.technique_id + m.mapping_type}>
                      <a href={techniqueUrl(m.technique_id)} target="_blank" rel="noreferrer" className={`font-mono text-xs ${link}`}>{m.technique_id}</a>
                      <span className="ml-2 text-zinc-200">{m.technique_name}</span>
                      {m.comments && firstWithComment.get(m.comments) === m.technique_id + m.mapping_type && <p className="mt-0.5 text-zinc-400">{m.comments}</p>}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        ) : viaCapec.size > 0 ? (
          <div className="text-sm">
            <p className="mb-2 text-xs text-zinc-500">No CTID mapping for this CVE (those cover CISA KEV entries). Techniques linked to its weakness through CAPEC:</p>
            <ul className="flex flex-wrap gap-1.5">
              {[...viaCapec].map(([id, name]) => (
                <li key={id}><a href={techniqueUrl(id)} target="_blank" rel="noreferrer"><Tag tone="cyan">{id} · {name}</Tag></a></li>
              ))}
            </ul>
          </div>
        ) : (
          <p className="text-sm text-zinc-500">No ATT&CK mapping for this CVE or its weakness.</p>
        )}
      </Card>
      <Card title={`Attack patterns (CAPEC)${capec.length ? ` · ${capec.length}` : ''}`}>
        {capec.length ? (
          <>
            <p className="mb-3 text-xs text-zinc-500">MITRE CAPEC patterns for this CVE's weaknesses ({c.cwes.map((w) => w.id).join(', ')}), most specific first. How the attack generally works, what it needs, how to spot it, and how to stop it.</p>
            <ul className="space-y-2">{capec.map((p) => <CapecItem key={p.id} p={p} />)}</ul>
          </>
        ) : (
          <p className="text-sm text-zinc-500">{c.cwes.length ? 'No CAPEC pattern is linked to this CVE\'s weaknesses.' : 'The CVE has no CWE, so no attack pattern can be linked.'}</p>
        )}
      </Card>
    </div>
  )
}

function CapecItem({ p }: { p: CapecPattern }) {
  const sections: [string, string[]][] = [
    ['How it works', p.execution_flow],
    ['Prerequisites', p.prerequisites],
    ['Indicators', p.indicators],
    ['Mitigations', p.mitigations],
  ]
  return (
    <li className="rounded-md border border-zinc-800 px-3 py-2 text-sm">
      <details>
        <summary className="cursor-pointer list-none">
          <div className="flex flex-wrap items-baseline gap-2">
            <a href={`https://capec.mitre.org/data/definitions/${p.id.slice(6)}.html`} target="_blank" rel="noreferrer" className={`font-mono text-xs ${link}`} onClick={(e) => e.stopPropagation()}>{p.id}</a>
            <span className="font-medium text-zinc-100">{p.name}</span>
            {p.likelihood && <Tag>likelihood {p.likelihood.toLowerCase()}</Tag>}
            {p.severity && <Tag>severity {p.severity.toLowerCase()}</Tag>}
          </div>
          {p.attack.length > 0 && <div className="mt-0.5 text-xs text-zinc-500">ATT&CK: {p.attack.map((t) => `${t.id} ${t.name}`).join(' · ')}</div>}
        </summary>
        <div className="mt-3 space-y-3">
          {p.description && <p className="leading-relaxed text-zinc-300">{p.description}</p>}
          {sections.filter(([, items]) => items.length).map(([title, items]) => (
            <div key={title}>
              <div className={label}>{title}</div>
              <ul className="list-disc space-y-0.5 pl-5 text-zinc-400">{items.map((x, i) => <li key={i}>{x}</li>)}</ul>
            </div>
          ))}
        </div>
      </details>
    </li>
  )
}

function useReport(id: string, source: 'history' | 'commits') {
  return useQuery({ queryKey: ['reports', id, source], queryFn: () => api.getCveReports(id, [source]), staleTime: 10 * 60_000 })
}

export function HistoryCard({ id }: { id: string }) {
  const q = useReport(id, 'history')
  const [all, setAll] = useState(false)
  if (q.isPending) return <Card title="Change history (NVD)"><Spinner label="Loading NVD change history…" /></Card>
  const status = q.data?.sources[0]
  const changes = q.data?.reports.history ?? []
  if (!changes.length) {
    return (
      <Card title="Change history (NVD)">
        <p className="text-sm text-zinc-500">{status?.status === 'error' ? 'NVD is unavailable right now; try again later.' : 'NVD has no recorded changes for this CVE.'}</p>
      </Card>
    )
  }
  // NVD logs bulk edits (e.g. a CPE rename) as one change per item; fold
  // consecutive changes with the same event, source, and day into one.
  const groups: { first: HistoryChange; count: number; details: HistoryChange['details'] }[] = []
  for (const ch of changes) {
    const last = groups[groups.length - 1]
    if (last && last.first.event === ch.event && last.first.source === ch.source && last.first.created.slice(0, 10) === ch.created.slice(0, 10)) {
      last.count++
      last.details.push(...ch.details)
    } else {
      groups.push({ first: ch, count: 1, details: [...ch.details] })
    }
  }
  const shown = all ? groups : groups.slice(0, 15)
  return (
    <Card title={`Change history (NVD) · ${changes.length}`}>
      <p className="mb-3 text-xs text-zinc-500">Every change NVD recorded, newest first: analysis, score and CPE changes, references, KEV updates.</p>
      <ol className="relative space-y-4 border-l border-zinc-800 pl-4 text-sm">
        {shown.map(({ first: ch, count, details }, i) => (
          <li key={i}>
            <span className="absolute -left-1.5 mt-1.5 h-3 w-3 rounded-full bg-zinc-600" />
            <div className="flex flex-wrap items-baseline gap-x-2">
              <span className="font-medium text-zinc-100">{ch.event}</span>
              {count > 1 && <span className="text-xs text-zinc-500">× {count}</span>}
              <span className="text-xs text-zinc-500 tabular-nums">{fmtDate(ch.created)}</span>
              {ch.source && <span className="text-xs text-zinc-600">{ch.source}</span>}
            </div>
            {details.length > 0 && (
              <ul className="mt-1 space-y-1">
                {details.slice(0, count > 1 ? 4 : 12).map((d, j) => (
                  <li key={j} className="text-xs">
                    <span className={d.action === 'Removed' ? 'text-zinc-500' : d.action === 'Added' ? 'text-emerald-300/90' : 'text-amber-200/90'}>{d.action}</span>
                    <span className="text-zinc-400"> {d.type}</span>
                    {d.old && <div className="font-mono break-all text-zinc-500 line-through decoration-zinc-600">{d.old}</div>}
                    {d.new && <div className="font-mono break-all whitespace-pre-wrap text-zinc-300">{d.new}</div>}
                  </li>
                ))}
                {details.length > (count > 1 ? 4 : 12) && <li className="text-xs text-zinc-500">+ {details.length - (count > 1 ? 4 : 12)} more changes</li>}
              </ul>
            )}
          </li>
        ))}
      </ol>
      {groups.length > shown.length && <button className={`mt-3 text-sm ${link}`} onClick={() => setAll(true)}>Show all {groups.length}</button>}
    </Card>
  )
}

function DiffLine({ line }: { line: string }) {
  const tone = line.startsWith('+') ? 'bg-emerald-500/10 text-emerald-200' : line.startsWith('-') ? 'bg-red-500/10 text-red-200' : line.startsWith('@@') ? 'text-cyan-300/80' : 'text-zinc-400'
  return <div className={`px-3 ${tone}`}>{line || ' '}</div>
}

export function CommitsCard({ id }: { id: string }) {
  const q = useReport(id, 'commits')
  if (q.isPending) return <Card title="Fix commits"><Spinner label="Loading commits from GitHub…" /></Card>
  const status = q.data?.sources[0]
  const commits = q.data?.reports.commits ?? []
  if (!commits.length) {
    return (
      <Card title="Fix commits">
        <p className="text-sm text-zinc-500">
          {status?.status === 'error' ? 'GitHub is unavailable or rate-limited right now (60 requests an hour without a token); try again later.' : 'The CVE references no GitHub commit.'}
        </p>
      </Card>
    )
  }
  return (
    <Card title={`Fix commits · ${commits.length}`}>
      <p className="mb-3 text-xs text-zinc-500">GitHub commits the CVE references, usually the fix. The diff shows exactly what changed; open a file to see it.</p>
      <div className="space-y-4">
        {commits.map((cm) => (
          <div key={cm.sha} className="rounded-md border border-zinc-800">
            <div className="border-b border-zinc-800 px-3 py-2">
              <div className="flex flex-wrap items-baseline gap-x-2 text-sm">
                <a href={cm.url} target="_blank" rel="noreferrer" className={`font-mono text-xs ${link}`}>{cm.repo}@{cm.sha.slice(0, 10)}</a>
                <span className="text-xs text-zinc-500">{cm.author}{cm.date && <> · {fmtDate(cm.date)}</>}</span>
                <span className="ml-auto font-mono text-xs"><span className="text-emerald-300">+{cm.additions}</span> <span className="text-red-300">−{cm.deletions}</span></span>
              </div>
              <p className="mt-1 text-sm whitespace-pre-line text-zinc-200">{cm.message}</p>
            </div>
            <ul className="divide-y divide-zinc-800/70">
              {cm.files.map((f) => (
                <li key={f.name}>
                  <details>
                    <summary className="flex cursor-pointer list-none items-baseline gap-2 px-3 py-1.5 text-xs hover:bg-zinc-800/40">
                      <span className="min-w-0 flex-1 truncate font-mono text-zinc-300">{f.name}</span>
                      {f.status !== 'modified' && <Tag>{f.status}</Tag>}
                      <span className="font-mono"><span className="text-emerald-300">+{f.additions}</span> <span className="text-red-300">−{f.deletions}</span></span>
                    </summary>
                    {f.patch ? (
                      <pre className="max-h-[32rem] overflow-auto bg-zinc-950 py-2 font-mono text-xs leading-relaxed">
                        {f.patch.split('\n').map((l, i) => <DiffLine key={i} line={l} />)}
                        {f.truncated && <div className="px-3 text-zinc-500">… diff truncated; open the commit for the rest.</div>}
                      </pre>
                    ) : (
                      <p className="bg-zinc-950 px-3 py-2 text-xs text-zinc-500">No text diff (binary or too large).</p>
                    )}
                  </details>
                </li>
              ))}
              {cm.more_files ? <li className="px-3 py-1.5 text-xs text-zinc-500">+ {cm.more_files} more files on GitHub</li> : null}
            </ul>
          </div>
        ))}
      </div>
    </Card>
  )
}

const debianTone: Record<string, string> = { resolved: 'text-emerald-300', open: 'text-amber-200', undetermined: 'text-zinc-400' }

function debianCell(s: DebianStatus | undefined) {
  if (!s) return <span className="text-zinc-700">—</span>
  if (s.status === 'resolved' && s.fixed_version === '0') return <span className="text-zinc-500" title="This release never had the vulnerable code">not affected</span>
  if (s.status === 'resolved') return <span className={`font-mono ${debianTone.resolved}`} title="Fixed in this version">{s.fixed_version}</span>
  return <span className={debianTone[s.status] ?? 'text-zinc-300'}>{s.status === 'open' ? 'vulnerable' : s.status}</span>
}

export function DebianCard({ c }: { c: CveDetail }) {
  if (!c.debian.length) return null
  const releases = [...new Set(c.debian.map((d) => d.release))]
  const packages = [...new Set(c.debian.map((d) => d.package))]
  const at = (pkg: string, rel: string) => c.debian.find((d) => d.package === pkg && d.release === rel)
  return (
    <Card title="Debian" actions={<a href={`https://security-tracker.debian.org/tracker/${c.id}`} target="_blank" rel="noreferrer" className={`text-xs ${link}`}>Security tracker</a>}>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[520px] text-sm">
          <thead>
            <tr className="border-b border-zinc-800 text-left text-[11px] font-semibold tracking-wider text-zinc-500 uppercase">
              <th className="py-1.5 pr-3">Source package</th>
              {releases.map((r) => <th key={r} className="py-1.5 pr-3">{r}</th>)}
              <th className="py-1.5">Urgency</th>
            </tr>
          </thead>
          <tbody>
            {packages.map((p) => (
              <tr key={p} className="border-b border-zinc-800/60">
                <td className="py-1.5 pr-3 font-mono text-xs text-zinc-200">{p}</td>
                {releases.map((r) => <td key={r} className="py-1.5 pr-3 text-xs">{debianCell(at(p, r))}</td>)}
                <td className="py-1.5 text-xs text-zinc-500">{[...new Set(c.debian.filter((d) => d.package === p).map((d) => d.urgency).filter(Boolean))].join(', ') || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-2 text-xs text-zinc-500">A version means the release is fixed from that version on. Compare with <code className="text-zinc-400">dpkg-query -W PACKAGE</code>.</p>
    </Card>
  )
}
