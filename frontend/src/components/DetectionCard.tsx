import { useQuery } from '@tanstack/react-query'
import { Check, Copy, Download, ExternalLink } from 'lucide-react'
import { useEffect, useState, type ReactNode } from 'react'
import { api } from '../api/client'
import type { CveDetail, DetectionRule } from '../api/types'
import {
  debianScript, distroPackages, fleetCommands, libraryPackages, osvVerdict, rhelScript, windowsBuilds, windowsScript,
  type DistroPackage, type LibraryPackage,
} from '../lib/affected'
import {
  activeScans, cveLookups, sigmaCommands, suricataCommands, versionCommand, weaknessHints, windowsChecks, type Command,
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

// ScriptBlock shows a generated script with copy and download buttons.
function ScriptBlock({ file, text }: { file: string; text: string }) {
  const download = () => {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
    const a = document.createElement('a')
    a.href = url
    a.download = file
    a.click()
    URL.revokeObjectURL(url)
  }
  return (
    <div className="rounded-md border border-zinc-800 bg-zinc-950">
      <div className="flex items-center gap-2 border-b border-zinc-800 px-2.5 py-1.5 text-xs text-zinc-400">
        <span className="min-w-0 flex-1 truncate font-mono">{file}</span>
        <button type="button" onClick={download} className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 hover:bg-zinc-800 hover:text-zinc-200" title="Download the script">
          <Download className="h-3.5 w-3.5" /> Download
        </button>
        <CopyButton text={text} />
      </div>
      <details>
        <summary className="cursor-pointer px-2.5 py-1.5 text-xs text-cyan-300/80 hover:text-cyan-200">Show script</summary>
        <pre className="max-h-80 overflow-auto px-3 pb-3 font-mono text-xs leading-relaxed whitespace-pre text-zinc-300">{text}</pre>
      </details>
    </div>
  )
}

const needLabel = (n: string) => (n === 'none' ? 'no fix yet' : n === '?' ? 'not triaged' : n)

// One line per release that needs something: the fixed version, "no fix
// yet", or "not triaged"; releases not affected are left out.
function ReleaseChips({ distro, needs }: { distro: string; needs: Map<string, string> }) {
  const shown = [...needs.entries()].filter(([, n]) => n !== '-')
  if (!shown.length) return null
  return (
    <div className="flex flex-wrap items-baseline gap-1.5 text-xs">
      <span className="w-14 shrink-0 text-zinc-500">{distro}</span>
      {shown.map(([rel, n]) => (
        <span key={rel} className={`rounded px-1.5 py-0.5 ring-1 ring-inset ${n === 'none' ? 'bg-red-500/10 text-red-300 ring-red-400/25' : n === '?' ? 'bg-amber-500/10 text-amber-200 ring-amber-400/25' : 'bg-zinc-800 text-zinc-300 ring-zinc-700'}`}>
          {rel} <span className="font-mono">{needLabel(n)}</span>
        </span>
      ))}
    </div>
  )
}

function DistroSection({ id, packages, hidden }: { id: string; packages: DistroPackage[]; hidden: number }) {
  const [all, setAll] = useState(false)
  const file = `pahredar-${id}-debian.sh`
  const shown = all ? packages : packages.slice(0, 5)
  return (
    <Section
      title="Debian / Ubuntu servers"
      hint={<>Run the script on a server: it reads the release from /etc/os-release and prints <b className="font-medium text-zinc-300">AFFECTED</b>, <b className="font-medium text-zinc-300">PATCHED</b>, or <b className="font-medium text-zinc-300">NOT AFFECTED</b> per source package, comparing the installed source version with dpkg's own rules.</>}
    >
      <ul className="mb-3 space-y-2">
        {shown.map((p) => (
          <li key={p.pkg} className="space-y-1">
            <div className="font-mono text-xs text-zinc-200">{p.pkg}</div>
            <ReleaseChips distro="Debian" needs={p.debian} />
            <ReleaseChips distro="Ubuntu" needs={p.ubuntu} />
          </li>
        ))}
      </ul>
      {packages.length > shown.length && <button className={`mb-3 text-sm ${link}`} onClick={() => setAll(true)}>Show all {packages.length} packages</button>}
      {hidden > 0 && <p className="mb-3 text-xs text-zinc-500">{hidden} more package{hidden > 1 ? 's are' : ' is'} not affected in any release and left out.</p>}
      <ScriptBlock file={file} text={debianScript(id, packages)} />
      <div className="mt-3"><Commands items={fleetCommands(file)} /></div>
    </Section>
  )
}

function RhelSection({ id, fixedIn }: { id: string; fixedIn: { product: string; package?: string; advisory?: string }[] }) {
  const file = `pahredar-${id}-rhel.sh`
  const shown = fixedIn.filter((f) => f.package).slice(0, 5)
  return (
    <Section title="RHEL / Alma / Rocky servers" hint="dnf knows which advisory fixes the CVE and whether it is installed, so the script asks it directly (dnf 4: RHEL 8 to 10).">
      {shown.length > 0 && (
        <ul className="mb-3 space-y-0.5 text-xs text-zinc-400">
          {shown.map((f, i) => <li key={i}><span className="text-zinc-300">{f.product}</span> · <span className="font-mono">{f.package}</span>{f.advisory && <> · {f.advisory}</>}</li>)}
          {fixedIn.length > shown.length && <li className="text-zinc-500">+{fixedIn.length - shown.length} more fixed packages</li>}
        </ul>
      )}
      <ScriptBlock file={file} text={rhelScript(id)} />
      <div className="mt-3"><Commands items={fleetCommands(file)} /></div>
    </Section>
  )
}

function WindowsSection({ id, builds, kbs }: { id: string; builds: { build: string; fixed: string; products: string[] }[]; kbs: Command[] }) {
  return (
    <Section title="Windows" hint="The script compares the running build (including the update revision) with the fixed build for that Windows version. Unlike Get-HotFix, it is not fooled by a later cumulative update that replaced the KB.">
      <div className="mb-3 overflow-x-auto">
        <table className="w-full min-w-[480px] text-xs">
          <thead><tr className="text-left text-zinc-500"><th className="py-1 pr-3 font-medium">Build</th><th className="py-1 pr-3 font-medium">Fixed in</th><th className="py-1 font-medium">Products</th></tr></thead>
          <tbody>
            {builds.map((b) => (
              <tr key={b.build} className="border-t border-zinc-800/70">
                <td className="py-1 pr-3 font-mono text-zinc-300">{b.build}</td>
                <td className="py-1 pr-3 font-mono text-zinc-200">{b.fixed}</td>
                <td className="py-1 text-zinc-400">{b.products.slice(0, 2).join(', ')}{b.products.length > 2 && ` +${b.products.length - 2}`}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <ScriptBlock file={`pahredar-${id}-windows.ps1`} text={windowsScript(id, builds)} />
      {kbs.length > 0 && (
        <details className="mt-3">
          <summary className="cursor-pointer text-xs text-cyan-300/80 hover:text-cyan-200">KB articles ({kbs.length})</summary>
          <div className="mt-2"><Commands items={kbs} /></div>
        </details>
      )}
    </Section>
  )
}

// LibraryRow checks a version the user types against the OSV ranges.
function LibraryRow({ p }: { p: LibraryPackage }) {
  const [version, setVersion] = useState('')
  const v = version.trim()
  const verdict = v ? (p.ranges.some((r) => osvVerdict(v, r) === 'affected') ? 'affected' : 'not-affected') : null
  const cmd = versionCommand(p.ecosystem, p.pkg)
  return (
    <li className="space-y-1.5 rounded-md border border-zinc-800 px-3 py-2">
      <div className="flex flex-wrap items-baseline gap-x-2">
        <span className="text-xs text-zinc-500">{p.ecosystem}</span>
        <span className="font-mono text-xs text-zinc-200">{p.pkg}</span>
        {p.fixed.length > 0 && <span className="text-xs text-zinc-500">fixed in {p.fixed.slice(0, 5).join(', ')}{p.fixed.length > 5 && ` +${p.fixed.length - 5}`}</span>}
      </div>
      {cmd && (
        <div className="flex items-start gap-1 rounded-md border border-zinc-800 bg-zinc-950 px-2.5 py-1.5">
          <code className="min-w-0 flex-1 font-mono text-xs whitespace-pre-wrap text-zinc-200 [overflow-wrap:anywhere]">{cmd}</code>
          <CopyButton text={cmd} />
        </div>
      )}
      <label className="flex flex-wrap items-center gap-2 text-xs text-zinc-400">
        Your version
        <input
          value={version}
          onChange={(e) => setVersion(e.target.value.slice(0, 40))}
          placeholder="e.g. 1.2.0"
          className="w-28 rounded border border-zinc-700 bg-zinc-950 px-1.5 py-0.5 font-mono text-xs text-zinc-200 focus:border-cyan-500 focus:outline-none"
        />
        {verdict === 'affected' && <Tag tone="red">Affected</Tag>}
        {verdict === 'not-affected' && <Tag tone="cyan">Not affected</Tag>}
      </label>
    </li>
  )
}

function LibrarySection({ packages }: { packages: LibraryPackage[] }) {
  const [all, setAll] = useState(false)
  const shown = all ? packages : packages.slice(0, 5)
  return (
    <Section title="Libraries and applications" hint="Affected ranges from OSV (GitHub, PyPI, Go, npm, Bitnami, … advisories). Type the version you run to see whether it falls in one.">
      <ul className="space-y-2">{shown.map((p) => <LibraryRow key={p.ecosystem + p.pkg} p={p} />)}</ul>
      {packages.length > shown.length && <button className={`mt-2 text-sm ${link}`} onClick={() => setAll(true)}>Show all {packages.length} packages</button>}
    </Section>
  )
}

const TARGET_KEY = 'pahredar.detection.target'

function readTarget(): string {
  try {
    return localStorage.getItem(TARGET_KEY) ?? ''
  } catch {
    return ''
  }
}

export function DetectionCard({ c }: { c: CveDetail }) {
  const det = useDetection(c.id)
  const { reports, pending } = useReports(c.id)
  const [target, setTarget] = useState(readTarget)
  useEffect(() => {
    try {
      localStorage.setItem(TARGET_KEY, target)
    } catch {
      // Not remembered; harmless.
    }
  }, [target])
  const host = target || 'TARGET'
  const rules = det.data?.rules ?? []

  const distro = distroPackages(c.debian, reports.ubuntu)
  const libraries = libraryPackages(reports.osv)
  // Red Hat often has a page saying every product is not affected; only a
  // fix or an affected product makes the RHEL check worth showing.
  const redhat = reports.redhat && (reports.redhat.fixed_in.length > 0 || reports.redhat.states.some((s) => s.fix_state !== 'Not affected')) ? reports.redhat : undefined
  const builds = windowsBuilds(reports.msrc)
  const kbs = windowsChecks(reports)
  const ecosystems = new Set([
    ...libraries.map((l) => l.ecosystem.split(':')[0]),
    ...(distro.packages.some((p) => p.debian.size) ? ['Debian'] : []),
    ...(distro.packages.some((p) => p.ubuntu.size) ? ['Ubuntu'] : []),
    ...(redhat ? ['Red Hat'] : []),
  ])
  const lookups = cveLookups(c.id, ecosystems)
  const scans = activeScans(c.id, c.exploits, rules, host)
  const suricata = rules.filter((r) => r.source === 'suricata')
  const sigma = rules.filter((r) => r.source === 'sigma')
  const hints = weaknessHints(c.cwes.map((w) => w.id))
  const vector = (c.cvss.v4 ?? c.cvss.v3 ?? c.cvss.v2)?.vector ?? ''
  const network = /AV:N/.test(vector)

  const versionChecks = [
    distro.packages.length > 0 && 'Debian / Ubuntu',
    redhat && 'RHEL',
    // Builds come from Windows products only; KBs alone can be .NET, Office, …
    builds.length > 0 ? 'Windows build' : kbs.length > 0 && 'Microsoft KBs',
    libraries.length > 0 && `${libraries.length} ${libraries.length === 1 ? 'library' : 'libraries'}`,
  ].filter(Boolean) as string[]

  const tabs: { key: Tab; label: string; count?: number }[] = [
    { key: 'exposure', label: 'Am I affected?', count: versionChecks.length || undefined },
    { key: 'scan', label: 'Active scan', count: scans.length },
    { key: 'network', label: 'Network IDS', count: suricata.length },
    { key: 'logs', label: 'Logs / SIEM', count: sigma.length },
    { key: 'hunt', label: 'What to look for', count: hints.length || undefined },
  ]
  const firstWithData = tabs.find((t) => t.key !== 'exposure' && t.key !== 'hunt' && t.count)?.key
  const [tab, setTab] = useState<Tab | null>(null)
  const [allSuricata, setAllSuricata] = useState(false)
  const current = tab ?? (versionChecks.length ? 'exposure' : firstWithData ?? 'exposure')

  // "Start here": the most direct way to know, then the way to catch attempts.
  const steps: [string, Tab][] = []
  if (versionChecks.length) steps.push([`check the installed version (${versionChecks.join(', ')})`, 'exposure'])
  if (scans.length) steps.push([`scan exposed hosts with ${scans.length === 1 ? 'the ready-made check' : `${scans.length} ready-made checks`}`, 'scan'])
  if (suricata.length) steps.push([`watch traffic with ${suricata.length} Suricata rule${suricata.length > 1 ? 's' : ''}`, 'network'])
  if (sigma.length) steps.push([`alert on logs with ${sigma.length} Sigma rule${sigma.length > 1 ? 's' : ''}`, 'logs'])
  if (!steps.length && hints.length) steps.push(['hunt for the weakness class indicators', 'hunt'])

  const coverage: [string, boolean, string, Tab][] = [
    ['Version check', versionChecks.length > 0, versionChecks.join(' · ') || (pending ? 'loading…' : 'none'), 'exposure'],
    ['Remote scan', scans.length > 0, scans.length ? String(scans.length) : 'none', 'scan'],
    ['Network IDS', suricata.length > 0, suricata.length ? String(suricata.length) : 'none', 'network'],
    ['Logs / SIEM', sigma.length > 0, sigma.length ? String(sigma.length) : 'none', 'logs'],
  ]

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
            placeholder="host, IP, or URL to scan"
          />
        </label>
      }
    >
      <div className="mb-4 space-y-2">
        <div className="flex flex-wrap gap-1.5">
          {coverage.map(([label, ok, detail, t]) => (
            <button
              key={label}
              onClick={() => setTab(t)}
              className={`inline-flex max-w-full flex-wrap items-baseline gap-x-1.5 rounded-md border px-2 py-1 text-left text-xs ${ok ? 'border-emerald-400/25 bg-emerald-500/[0.07] text-emerald-100' : 'border-zinc-800 text-zinc-500'}`}
            >
              <span aria-hidden>{ok ? '✓' : '✗'}</span>
              <span className="font-medium whitespace-nowrap">{label}</span>
              <span className={ok ? 'text-emerald-200/70' : 'text-zinc-600'}>{detail}</span>
            </button>
          ))}
        </div>
        {steps.length > 0 && (
          <p className="text-sm text-zinc-300">
            <span className="font-semibold text-zinc-100">Start here: </span>
            {steps.slice(0, 2).map(([text, t], i) => (
              // Links, not buttons: a button is an atomic box and would wrap
              // as a whole on narrow screens.
              <span key={t}>{i > 0 && ', then '}<a href={`#${t}`} className={link} onClick={(e) => { e.preventDefault(); setTab(t) }}>{text}</a></span>
            ))}.
          </p>
        )}
      </div>

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

      <div className="space-y-6 text-sm">
        {current === 'exposure' && (
          <>
            {pending && <p className="text-xs text-zinc-500">Loading package data from OSV, Ubuntu, Red Hat, and MSRC…</p>}
            {distro.packages.length > 0 && <DistroSection id={c.id} packages={distro.packages} hidden={distro.hidden} />}
            {redhat && <RhelSection id={c.id} fixedIn={redhat.fixed_in} />}
            {(builds.length > 0 || kbs.length > 0) && (builds.length > 0 ? <WindowsSection id={c.id} builds={builds} kbs={kbs} /> : <Section title="Microsoft updates (KB)" hint="MSRC lists these updates without a Windows build to compare (often .NET, Office, or other products). If Get-HotFix returns nothing, the update is missing or was replaced by a later one."><Commands items={kbs} /></Section>)}
            {libraries.length > 0 && <LibrarySection packages={libraries} />}
            {lookups.length > 0 && <Section title="Scanners" hint="Look the CVE up with a vulnerability scanner across a source tree, containers, a cluster, or a host."><Commands items={lookups} /></Section>}
            {network && (
              <Section title="Network fingerprint" hint="Finds the service and version listening on the target and lists CVEs known for that version (Nmap's vulners script).">
                <Commands items={[{ label: 'Service version and known CVEs', cmd: `nmap -sV --script vulners ${host.replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, '')}` }]} />
              </Section>
            )}
            {!pending && !versionChecks.length && !lookups.length && (
              <p className="text-zinc-500">No package-level data for this CVE. Check the product version against <strong className="font-medium text-zinc-300">Affected products</strong> and the vendor advisory.</p>
            )}
          </>
        )}

        {current === 'scan' && (
          scans.length > 0 ? (
            <Section title="Active checks" hint="Run these only against systems you own or are authorised to test. Set the target above. Update Nuclei templates first with nuclei -update-templates.">
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
