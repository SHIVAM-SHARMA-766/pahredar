import { useQuery } from '@tanstack/react-query'
import { Check, Copy, ExternalLink } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { api } from '../api/client'
import type { CveDetail, DetectionRule } from '../api/types'
import {
  activeScans, cveLookups, packageChecks, sigmaCommands, suricataCommands, weaknessHints, windowsChecks, type Command,
} from '../lib/detection'
import { Card, Tag } from './ui'

const link = 'text-cyan-300 hover:text-cyan-200'

export function useDetection(id: string) {
  return useQuery({ queryKey: ['detection', id], queryFn: () => api.getDetection(id), staleTime: 10 * 60_000 })
}

// The same query keys as ReportsCard and VendorAdvisoriesCard, so the
// reports are fetched once per page.
function useReports(id: string) {
  const writeups = useQuery({ queryKey: ['reports', id, 'writeups'], queryFn: () => api.getCveReports(id, ['osv', 'redhat', 'ubuntu']), staleTime: 10 * 60_000 })
  const vendor = useQuery({ queryKey: ['reports', id, 'vendor'], queryFn: () => api.getCveReports(id, ['msrc', 'advisories']), staleTime: 10 * 60_000 })
  return { reports: { ...writeups.data?.reports, ...vendor.data?.reports }, pending: writeups.isPending || vendor.isPending }
}

export function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false)
  return (
    <button
      type="button"
      title="Copy"
      className="shrink-0 rounded p-1 text-zinc-500 hover:bg-zinc-800 hover:text-zinc-200"
      onClick={() => {
        navigator.clipboard?.writeText(text).then(() => {
          setDone(true)
          setTimeout(() => setDone(false), 1200)
        }).catch(() => {})
      }}
    >
      {done ? <Check className="h-3.5 w-3.5 text-emerald-300" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  )
}

function CommandRow({ c }: { c: Command }) {
  return (
    <li>
      <div className="text-xs text-zinc-400">{c.label}</div>
      <div className="mt-0.5 flex items-start gap-1 rounded-md border border-zinc-800 bg-zinc-950 px-2.5 py-1.5">
        <code className="min-w-0 flex-1 font-mono text-xs whitespace-pre-wrap text-zinc-200 [overflow-wrap:anywhere]">{c.cmd}</code>
        <CopyButton text={c.cmd} />
      </div>
      {c.note && <div className="mt-0.5 text-xs text-zinc-500">{c.note}</div>}
    </li>
  )
}

function Commands({ items }: { items: Command[] }) {
  return <ul className="space-y-2.5">{items.map((c, i) => <CommandRow key={i} c={c} />)}</ul>
}

function Section({ title, hint, children }: { title: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <div>
      <div className="mb-1.5 text-xs font-semibold tracking-wider text-zinc-500 uppercase">{title}</div>
      {hint && <p className="mb-2 text-xs text-zinc-500">{hint}</p>}
      {children}
    </div>
  )
}

function CodeBlock({ text }: { text: string }) {
  return (
    <div className="relative mt-2 rounded-md border border-zinc-800 bg-zinc-950">
      <div className="absolute top-1 right-1"><CopyButton text={text} /></div>
      <pre className="max-h-96 overflow-auto p-3 pr-9 font-mono text-xs leading-relaxed whitespace-pre-wrap text-zinc-300">{text}</pre>
    </div>
  )
}

const levelTone = { critical: 'red', high: 'amber', medium: 'zinc', low: 'zinc', informational: 'zinc' } as const

function SigmaRule({ r }: { r: DetectionRule }) {
  const ls = r.meta.logsource
  return (
    <li className="rounded-md border border-zinc-800 px-3 py-2">
      <details>
        <summary className="cursor-pointer list-none">
          <div className="flex flex-wrap items-baseline gap-2">
            <span className="font-medium text-zinc-100">{r.title}</span>
            {r.meta.level && <Tag tone={levelTone[r.meta.level as keyof typeof levelTone] ?? 'zinc'}>{r.meta.level}</Tag>}
            {r.meta.status && r.meta.status !== 'stable' && <Tag>{r.meta.status}</Tag>}
          </div>
          <div className="mt-0.5 flex flex-wrap gap-x-3 text-xs text-zinc-500">
            {ls && <span>Log source: {[ls.product, ls.service, ls.category].filter(Boolean).join(' / ')}</span>}
            {r.meta.attack?.length ? (
              <span>ATT&CK: {r.meta.attack.map((t, i) => (
                <a key={t} href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`} target="_blank" rel="noreferrer" className={link} onClick={(e) => e.stopPropagation()}>{i > 0 && ', '}{t}</a>
              ))}</span>
            ) : null}
            <span className="text-cyan-300/80">Show rule and commands</span>
          </div>
        </summary>
        <div className="mt-3 space-y-3">
          <Commands items={sigmaCommands(r)} />
          <CodeBlock text={r.body} />
          {r.url && <a href={r.url} target="_blank" rel="noreferrer" className={`inline-flex items-center gap-1 text-xs ${link}`}>View on GitHub <ExternalLink className="h-3 w-3" /></a>}
        </div>
      </details>
    </li>
  )
}

function SuricataRule({ r }: { r: DetectionRule }) {
  return (
    <li className="border-b border-zinc-800/60 py-1.5 last:border-0">
      <details>
        <summary className="flex cursor-pointer list-none flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <span className="font-mono text-xs text-zinc-500 tabular-nums">{r.rule_id}</span>
          <span className="min-w-0 flex-1 text-zinc-200">{r.title}</span>
          {r.meta.enabled === false && <Tag tone="amber" title="Shipped commented out in ET Open; enable it in enable.conf">disabled by default</Tag>}
          {r.meta.classtype && <span className="text-xs text-zinc-500">{r.meta.classtype}</span>}
        </summary>
        <CodeBlock text={r.body} />
      </details>
    </li>
  )
}

type Tab = 'exposure' | 'scan' | 'network' | 'logs' | 'hunt'

export function DetectionCard({ c }: { c: CveDetail }) {
  const det = useDetection(c.id)
  const { reports, pending } = useReports(c.id)
  const [target, setTarget] = useState('TARGET')
  const rules = det.data?.rules ?? []

  const checks = packageChecks(reports, c.debian)
  const lookups = cveLookups(c.id, reports, checks)
  const kbs = windowsChecks(reports)
  const scans = activeScans(c.id, c.exploits, rules, target || 'TARGET')
  const suricata = rules.filter((r) => r.source === 'suricata')
  const sigma = rules.filter((r) => r.source === 'sigma')
  const hints = weaknessHints(c.cwes.map((w) => w.id))
  const vector = (c.cvss.v4 ?? c.cvss.v3 ?? c.cvss.v2)?.vector ?? ''
  const network = /AV:N/.test(vector)

  const tabs: { key: Tab; label: string; count?: number }[] = [
    { key: 'exposure', label: 'Am I affected?', count: checks.length + kbs.length || undefined },
    { key: 'scan', label: 'Active scan', count: scans.length },
    { key: 'network', label: 'Network IDS', count: suricata.length },
    { key: 'logs', label: 'Logs / SIEM', count: sigma.length },
    { key: 'hunt', label: 'What to look for', count: hints.length || undefined },
  ]
  const firstWithData = tabs.find((t) => t.key !== 'exposure' && t.key !== 'hunt' && t.count)?.key
  const [tab, setTab] = useState<Tab | null>(null)
  const [allChecks, setAllChecks] = useState(false)
  const [allSuricata, setAllSuricata] = useState(false)
  const current = tab ?? (checks.length || kbs.length ? 'exposure' : firstWithData ?? 'exposure')

  return (
    <Card
      title="Detection"
      actions={
        <label className="flex items-center gap-2 text-xs text-zinc-500">
          Target
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value.replace(/[^A-Za-z0-9.:/_\-[\]]/g, ''))}
            className="w-48 rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs text-zinc-200 focus:border-cyan-500 focus:outline-none"
            placeholder="host, IP, or URL"
          />
        </label>
      }
    >
      <div className="no-scrollbar mb-4 flex gap-1 overflow-x-auto overflow-y-hidden border-b border-zinc-800">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`-mb-px shrink-0 border-b-2 px-3 py-1.5 text-sm whitespace-nowrap ${current === t.key ? 'border-cyan-400 text-zinc-100' : 'border-transparent text-zinc-500 hover:text-zinc-300'}`}
          >
            {t.label}
            {t.count !== undefined && <span className={`ml-1.5 text-xs ${t.count ? 'text-zinc-400' : 'text-zinc-600'}`}>{t.count}</span>}
          </button>
        ))}
      </div>

      <div className="space-y-5 text-sm">
        {current === 'exposure' && (
          <>
            {pending && <p className="text-xs text-zinc-500">Loading package data from OSV, Ubuntu, Red Hat, and MSRC…</p>}
            {checks.length > 0 && (
              <Section title="Installed version" hint="Compare the output with the fixed versions. Anything older is affected.">
                <ul className="space-y-2.5">
                  {checks.slice(0, allChecks ? undefined : 6).map((p) => (
                    <CommandRow key={p.ecosystem + p.pkg} c={{ label: `${p.ecosystem} · ${p.pkg}`, cmd: p.cmd, note: p.fixed.length ? `Fixed in ${p.fixed.slice(0, 6).join(', ')}${p.fixed.length > 6 ? ` +${p.fixed.length - 6}` : ''}` : undefined }} />
                  ))}
                </ul>
                {!allChecks && checks.length > 6 && <button className={`mt-2 text-sm ${link}`} onClick={() => setAllChecks(true)}>Show all {checks.length} packages</button>}
              </Section>
            )}
            {lookups.length > 0 && <Section title="Look the CVE up directly"><Commands items={lookups} /></Section>}
            {kbs.length > 0 && (
              <Section title="Windows updates" hint="If Get-HotFix returns nothing, the update is missing (or superseded by a later cumulative update; check the build number).">
                <Commands items={kbs} />
              </Section>
            )}
            {network && (
              <Section title="Network fingerprint" hint="Finds the service and version listening on the target and lists CVEs known for that version (Nmap's vulners script).">
                <Commands items={[{ label: 'Service version and known CVEs', cmd: `nmap -sV --script vulners ${target.replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, '') || 'TARGET'}` }]} />
              </Section>
            )}
            {!pending && !checks.length && !lookups.length && !kbs.length && (
              <p className="text-zinc-500">No package-level data for this CVE. Check the product version against <strong className="font-medium text-zinc-300">Affected products</strong> and the vendor advisory.</p>
            )}
          </>
        )}

        {current === 'scan' && (
          scans.length > 0 ? (
            <Section title="Active checks" hint="Run these only against systems you own or are authorised to test. Set the target above.">
              <Commands items={scans} />
            </Section>
          ) : (
            <p className="text-zinc-500">No Nuclei template, Nmap script, or Metasploit check module exists for this CVE. Use the version check under <em>Am I affected?</em></p>
          )
        )}

        {current === 'network' && (
          suricata.length > 0 ? (
            <>
              <Section title="Deploy and hunt"><Commands items={suricataCommands(rules)} /></Section>
              <Section title={`Suricata rules · ET Open (${suricata.length})`} hint="Proofpoint Emerging Threats Open ruleset. Click a rule to see it.">
                <ul>{suricata.slice(0, allSuricata ? undefined : 15).map((r) => <SuricataRule key={r.rule_id} r={r} />)}</ul>
                {!allSuricata && suricata.length > 15 && <button className={`mt-2 text-sm ${link}`} onClick={() => setAllSuricata(true)}>Show all {suricata.length} rules</button>}
              </Section>
            </>
          ) : (
            <p className="text-zinc-500">No ET Open Suricata rule references this CVE.</p>
          )
        )}

        {current === 'logs' && (
          sigma.length > 0 ? (
            <Section title={`Sigma rules (${sigma.length})`} hint="Vendor-neutral detections from SigmaHQ. Convert them to your SIEM's query language with sigma-cli (pip install sigma-cli).">
              <ul className="space-y-2">{sigma.map((r) => <SigmaRule key={r.rule_id} r={r} />)}</ul>
            </Section>
          ) : (
            <p className="text-zinc-500">No SigmaHQ rule names this CVE. See <em>What to look for</em> for the weakness class.</p>
          )
        )}

        {current === 'hunt' && (
          <>
            {hints.length > 0 ? (
              <Section title="Indicators by weakness" hint="What exploitation of this kind of flaw usually leaves in logs and process trees. Use these when no rule exists.">
                <div className="space-y-3">
                  {hints.map((h) => (
                    <div key={h.cwe}>
                      <div className="text-zinc-300">{h.cwe} <span className="text-zinc-500">{c.cwes.find((w) => w.id === h.cwe)?.name}</span></div>
                      <ul className="mt-1 list-disc space-y-0.5 pl-5 text-zinc-400">{h.hints.map((x) => <li key={x}>{x}</li>)}</ul>
                    </div>
                  ))}
                </div>
              </Section>
            ) : (
              <p className="text-zinc-500">No hunting hints for this CVE's weakness class{c.cwes.length ? ` (${c.cwes.map((w) => w.id).join(', ')})` : ''}.</p>
            )}
            {c.kev?.forensic_triage && c.kev.forensic_triage !== 'No' && (
              <Section title="CISA forensic triage"><p className="text-zinc-300">{c.kev.forensic_triage}</p></Section>
            )}
            {c.advisory.exploit_statements.length > 0 && (
              <Section title="Exploitation status (from the CNA)">
                {c.advisory.exploit_statements.map((s, i) => <p key={i} className="whitespace-pre-line text-zinc-300">{s}</p>)}
              </Section>
            )}
          </>
        )}
      </div>
    </Card>
  )
}
