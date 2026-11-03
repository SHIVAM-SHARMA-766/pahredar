import { useQuery } from '@tanstack/react-query'
import { useState, type ReactNode } from 'react'
import { api } from '../api/client'
import type { OtxReport, ReportStatus, ThreatFoxReport } from '../api/types'
import { fmtDate, fmtNumber } from '../lib/format'
import { CopyButton } from './DetectionCard'
import { Card, Spinner, Tag } from './ui'

// Threat intelligence from free-key sources, fetched on demand and cached
// for a day: AlienVault OTX pulses (who uses the CVE, against whom, how)
// and abuse.ch ThreatFox IOCs tagged with the CVE ID.

const link = 'text-cyan-300 hover:text-cyan-200'
const th = 'py-1.5 pr-3 text-left text-[11px] font-semibold tracking-wider text-zinc-500 uppercase'

const KEY_HINT: Record<'otx' | 'threatfox', string> = {
  otx: 'Set OTX_API_KEY in .env to load AlienVault OTX pulses.',
  threatfox: 'Set ABUSECH_AUTH_KEY in .env to load ThreatFox IOCs.',
}

function Label({ children }: { children: ReactNode }) {
  return <div className="mb-1.5 text-xs font-semibold tracking-wider text-zinc-500 uppercase">{children}</div>
}

function statusText(s: ReportStatus | undefined, source: 'otx' | 'threatfox', none: string) {
  if (!s || s.status === 'disabled') return KEY_HINT[source]
  return s.status === 'error' ? 'Unavailable right now; try again later.' : none
}

export function ThreatIntelCard({ id }: { id: string }) {
  const q = useQuery({ queryKey: ['reports', id, 'threat'], queryFn: () => api.getCveReports(id, ['otx', 'threatfox']), staleTime: 10 * 60_000 })
  if (q.isPending) return <Card title="Threat intelligence"><Spinner label="Asking AlienVault OTX and ThreatFox…" /></Card>
  if (q.isError) return <Card title="Threat intelligence"><p className="text-sm text-zinc-500">Threat intelligence is unavailable right now.</p></Card>
  const st = (s: string) => q.data.sources.find((x) => x.source === s)
  const { otx, threatfox } = q.data.reports
  return (
    <Card title="Threat intelligence">
      <div className="space-y-6">
        <Actors otx={otx} tf={threatfox} />
        <section>
          <div className="mb-2 flex items-baseline justify-between gap-3">
            <Label>AlienVault OTX pulses</Label>
            {otx && <a href={otx.url} target="_blank" rel="noreferrer" className={`text-xs ${link}`}>All {fmtNumber(otx.pulse_count)} on OTX →</a>}
          </div>
          {otx ? <Pulses r={otx} /> : <p className="text-sm text-zinc-500">{statusText(st('otx'), 'otx', 'No OTX pulse mentions this CVE.')}</p>}
        </section>
        <section>
          <div className="mb-2 flex items-baseline justify-between gap-3">
            <Label>ThreatFox IOCs</Label>
            {threatfox && <a href={threatfox.url} target="_blank" rel="noreferrer" className={`text-xs ${link}`}>ThreatFox →</a>}
          </div>
          {threatfox ? <Iocs r={threatfox} /> : <p className="text-sm text-zinc-500">{statusText(st('threatfox'), 'threatfox', 'No ThreatFox IOC is tagged with this CVE ID. Tags are added by reporters, so coverage is mostly recent, widely exploited CVEs.')}</p>}
        </section>
      </div>
    </Card>
  )
}

// Actors summarizes who exploits the CVE across both sources.
function Actors({ otx, tf }: { otx?: OtxReport; tf?: ThreatFoxReport }) {
  const malware = [...new Set([...(otx?.malware ?? []), ...(tf?.malware.map((m) => m.name) ?? [])])]
  const rows: [string, string[]][] = [
    ['Threat actors', otx?.adversaries ?? []],
    ['Malware', malware],
    ['Targeted industries', otx?.industries ?? []],
    ['Targeted countries', otx?.countries ?? []],
  ]
  const techniques = otx?.techniques ?? []
  if (!rows.some(([, v]) => v.length) && !techniques.length) return null
  return (
    <dl className="grid gap-x-4 gap-y-2 text-sm sm:grid-cols-[10rem_1fr]">
      {rows.filter(([, v]) => v.length).map(([label, v]) => (
        <div key={label} className="contents">
          <dt className="text-zinc-500">{label}</dt>
          <dd className="flex flex-wrap gap-1.5">{v.map((x) => <Tag key={x} tone={label === 'Threat actors' ? 'red' : label === 'Malware' ? 'violet' : 'zinc'}>{x}</Tag>)}</dd>
        </div>
      ))}
      {techniques.length > 0 && (
        <>
          <dt className="text-zinc-500">ATT&CK in campaigns</dt>
          <dd><Techniques list={techniques} /></dd>
        </>
      )}
    </dl>
  )
}

function Techniques({ list }: { list: { id: string; name: string }[] }) {
  const [all, setAll] = useState(false)
  const shown = all ? list : list.slice(0, 12)
  return (
    <div className="flex flex-wrap gap-1.5">
      {shown.map((t) => (
        <a key={t.id} href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`} target="_blank" rel="noreferrer" title={t.name}>
          <Tag tone="cyan">{t.id} {t.name}</Tag>
        </a>
      ))}
      {list.length > shown.length && <button className={`text-xs ${link}`} onClick={() => setAll(true)}>+{list.length - shown.length} more</button>}
    </div>
  )
}

function Pulses({ r }: { r: OtxReport }) {
  const [all, setAll] = useState(false)
  const shown = all ? r.pulses : r.pulses.slice(0, 8)
  return (
    <>
      {r.pulses.length === 0 ? (
        <p className="text-sm text-zinc-500">Only bulk lists mention this CVE among the recent pulses.</p>
      ) : (
        <ul className="divide-y divide-zinc-800">
          {shown.map((p) => (
            <li key={p.id} className="py-2 text-sm">
              <div className="flex items-baseline gap-3">
                <span className="w-24 shrink-0 text-xs text-zinc-500 tabular-nums">{fmtDate(p.modified)}</span>
                <a href={p.url} target="_blank" rel="noreferrer" className={`min-w-0 flex-1 ${link}`}>{p.name}</a>
                <span className="shrink-0 text-xs text-zinc-500">{fmtNumber(p.indicators)} IOCs</span>
              </div>
              {(p.adversary || p.malware.length > 0 || p.industries.length > 0) && (
                <div className="mt-1 ml-27 flex flex-wrap gap-1.5">
                  {p.adversary && <Tag tone="red">{p.adversary}</Tag>}
                  {p.malware.map((m) => <Tag key={m} tone="violet">{m}</Tag>)}
                  {p.industries.slice(0, 4).map((i) => <Tag key={i}>{i}</Tag>)}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      {r.pulses.length > shown.length && <button className={`mt-2 text-sm ${link}`} onClick={() => setAll(true)}>Show all {r.pulses.length}</button>}
      <p className="mt-2 text-xs text-zinc-500">
        Community reports of campaigns using this CVE, newest first. OTX returns the 50 most recently updated pulses
        {r.bulk_pulses > 0 && <>; {r.bulk_pulses} of them are bulk lists naming more than 10 CVEs (daily KEV digests, scanner feeds) and are left out, along with their actors and malware</>}.
      </p>
    </>
  )
}

function Iocs({ r }: { r: ThreatFoxReport }) {
  const [all, setAll] = useState(false)
  const shown = all ? r.iocs : r.iocs.slice(0, 15)
  return (
    <>
      <div className="mb-2 flex items-center gap-2 text-xs text-zinc-400">
        <span>{r.iocs.length} indicator{r.iocs.length === 1 ? '' : 's'}</span>
        <span className="text-zinc-600">·</span>
        <span>Copy all for a blocklist or hunt</span>
        <CopyButton text={r.iocs.map((i) => i.ioc).join('\n')} />
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[600px] text-sm">
          <thead>
            <tr className="border-b border-zinc-800">
              <th className={th}>IOC</th>
              <th className={th}>Type</th>
              <th className={th}>Malware</th>
              <th className={th}>Confidence</th>
              <th className={th}>First seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/70">
            {shown.map((i) => (
              <tr key={i.url}>
                <td className="max-w-[22rem] py-1.5 pr-3">
                  <a href={i.url} target="_blank" rel="noreferrer" className={`block truncate font-mono text-xs ${link}`} title={i.ioc}>{i.ioc}</a>
                </td>
                <td className="py-1.5 pr-3 text-xs whitespace-nowrap text-zinc-400" title={i.threat_type}>{i.type}</td>
                <td className="py-1.5 pr-3 text-xs whitespace-nowrap">{i.malware}</td>
                <td className="py-1.5 pr-3 text-xs text-zinc-400 tabular-nums">{i.confidence}%</td>
                <td className="py-1.5 pr-3 text-xs whitespace-nowrap text-zinc-400 tabular-nums">{fmtDate(i.first_seen.replace(' UTC', 'Z').replace(' ', 'T'))}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {r.iocs.length > shown.length && <button className={`mt-2 text-sm ${link}`} onClick={() => setAll(true)}>Show all {r.iocs.length}</button>}
      <p className="mt-2 text-xs text-zinc-500">
        Indicators (malware download URLs, C2 servers, hashes) that abuse.ch reporters tagged with this CVE ID. Defang before sharing; do not open them.
      </p>
    </>
  )
}
