import type { ReactNode } from 'react'
import { ApiError } from '../api/client'
import type { SeverityCounts, Severity } from '../api/types'
import { severityBadge, severityFill, severityLabel } from '../lib/severity'
import { fmtNumber } from '../lib/format'

export function SeverityBadge({ severity, score }: { severity: Severity; score?: number | null }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium whitespace-nowrap ring-1 ring-inset ${severityBadge[severity]}`}>
      {severityLabel(severity)}
      {score != null && <span className="font-mono">{score.toFixed(1)}</span>}
    </span>
  )
}

export function Tag({ children, tone = 'zinc', title }: { children: ReactNode; tone?: 'red' | 'violet' | 'amber' | 'cyan' | 'zinc'; title?: string }) {
  const tones = {
    red: 'bg-red-500/10 text-red-300 ring-red-400/25',
    violet: 'bg-violet-500/10 text-violet-300 ring-violet-400/25',
    amber: 'bg-amber-500/10 text-amber-200 ring-amber-400/25',
    cyan: 'bg-cyan-500/10 text-cyan-300 ring-cyan-400/25',
    zinc: 'bg-zinc-800 text-zinc-300 ring-zinc-700',
  }
  return (
    <span title={title} className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium ring-1 ring-inset whitespace-nowrap ${tones[tone]}`}>
      {children}
    </span>
  )
}

export function KevTag() {
  return <Tag tone="red" title="Listed in CISA Known Exploited Vulnerabilities">KEV</Tag>
}

export function RansomwareTag() {
  return <Tag tone="amber" title="CISA: known use in ransomware campaigns">Ransomware</Tag>
}

export function ExploitTag() {
  return <Tag tone="violet" title="Public exploit, Metasploit module, Nuclei template, or exploit reference">Exploit</Tag>
}

export function Card({ title, children, actions, className = '' }: { title?: ReactNode; children: ReactNode; actions?: ReactNode; className?: string }) {
  return (
    // min-w-0: as a grid/flex item a card must be allowed to shrink below its
    // content's width, or wide rows (and charts measuring them) overflow.
    <section className={`min-w-0 rounded-lg border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900 ${className}`}>
      {(title || actions) && (
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          {title && <h2 className="text-sm font-semibold tracking-wide text-zinc-500 uppercase dark:text-zinc-400">{title}</h2>}
          {actions}
        </div>
      )}
      {children}
    </section>
  )
}

export function Spinner({ label = 'Loading…' }: { label?: string }) {
  return <p className="py-8 text-center text-sm text-zinc-500">{label}</p>
}

export function ErrorBox({ error }: { error: unknown }) {
  const msg = error instanceof ApiError ? `${error.message} (HTTP ${error.status})` : String(error)
  return (
    <div className="rounded-lg border border-red-400/25 bg-red-500/10 p-4 text-sm text-red-200">
      {msg}
    </div>
  )
}

// Stat tile. Values stay in text colour; a swatch beside the label carries
// series identity. Proportional figures, not tabular, at display size.
export function Stat({ label, value, swatch, hint }: { label: string; value: ReactNode; swatch?: string; hint?: ReactNode }) {
  return (
    <div>
      <div className="flex items-center gap-1.5 text-xs text-zinc-500 dark:text-zinc-400">
        {swatch && <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: swatch }} />}
        {label}
      </div>
      <div className="text-2xl font-semibold">{value}</div>
      {hint && <div className="text-xs text-zinc-500">{hint}</div>}
    </div>
  )
}

// Horizontal stacked bar of severity counts, segments split by 2px gaps.
// Unscored CVEs fill the remainder in the track colour.
export function SeverityBar({ counts, className = 'h-2' }: { counts: SeverityCounts; className?: string }) {
  const parts: [Severity, number][] = [
    ['CRITICAL', counts.critical],
    ['HIGH', counts.high],
    ['MEDIUM', counts.medium],
    ['LOW', counts.low],
  ]
  const total = Math.max(counts.cves, 1)
  const rest = Math.max(counts.cves - parts.reduce((a, [, n]) => a + n, 0), 0)
  return (
    <div
      className={`flex w-full gap-[2px] overflow-hidden rounded ${className}`}
      title={[...parts.map(([s, n]) => `${severityLabel(s)}: ${fmtNumber(n)}`), `Unscored: ${fmtNumber(rest)}`].join(' · ')}
    >
      {parts.filter(([, n]) => n > 0).map(([s, n]) => (
        <div key={s} style={{ flexBasis: `${(n / total) * 100}%`, background: severityFill[s] }} />
      ))}
      {rest > 0 && <div style={{ flexBasis: `${(rest / total) * 100}%`, background: 'var(--track)' }} />}
    </div>
  )
}

export function SeverityStats({ counts }: { counts: SeverityCounts }) {
  return (
    <div className="grid grid-cols-3 gap-4 sm:grid-cols-6">
      <Stat label="CVEs" value={fmtNumber(counts.cves)} />
      <Stat label="Critical" value={fmtNumber(counts.critical)} swatch={severityFill.CRITICAL} />
      <Stat label="High" value={fmtNumber(counts.high)} swatch={severityFill.HIGH} />
      <Stat label="Medium" value={fmtNumber(counts.medium)} swatch={severityFill.MEDIUM} />
      <Stat label="Low" value={fmtNumber(counts.low)} swatch={severityFill.LOW} />
      <Stat label="In KEV" value={fmtNumber(counts.kev)} />
    </div>
  )
}

export function Pagination({ page, pageSize, total, onPage }: { page: number; pageSize: number; total: number; onPage: (p: number) => void }) {
  // The API caps offsets at 10,000.
  const last = Math.max(1, Math.min(Math.ceil(total / pageSize), Math.floor(10000 / pageSize) + 1))
  const btn = 'rounded border border-zinc-300 px-3 py-1 text-sm disabled:opacity-40 dark:border-zinc-700 hover:bg-zinc-100 dark:hover:bg-zinc-800'
  return (
    <div className="flex items-center justify-between gap-2 text-sm">
      <span className="text-zinc-500">
        {fmtNumber(total)} result{total === 1 ? '' : 's'} · page {page} of {fmtNumber(last)}
      </span>
      <div className="flex gap-2">
        <button className={btn} disabled={page <= 1} onClick={() => onPage(1)}>First</button>
        <button className={btn} disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button>
        <button className={btn} disabled={page >= last} onClick={() => onPage(page + 1)}>Next</button>
      </div>
    </div>
  )
}

// Page title block shown above each top-level page's content.
export function PageHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-white">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-zinc-400">{subtitle}</p>}
      </div>
      {actions}
    </div>
  )
}
