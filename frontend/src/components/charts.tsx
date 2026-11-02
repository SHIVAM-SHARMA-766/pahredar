import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { EpssPoint, YearCount } from '../api/types'
import { fmtEpss, fmtNumber } from '../lib/format'

// Each chart sits in an overflow-hidden box: ResponsiveContainer measures with
// a ResizeObserver, and a stale measurement should clip, not widen the card.
// Mark specs (dataviz skill): solid hairline grid, recessive axes, bars at
// most 24px with a 4px rounded data end and square baseline, 2px lines, no
// animation. The dashboard's multi-series chart is MetricWidget.tsx.
const axisTick = { fontSize: 12, fill: 'var(--axis-text)' }
const grid = <CartesianGrid stroke="var(--grid)" vertical={false} />
const MAX_BAR = 24

export function compact(n: number): string {
  if (n >= 1_000_000) return `${+(n / 1_000_000).toFixed(1)}M`
  if (n >= 1000) return `${+(n / 1000).toFixed(1)}K`
  return String(n)
}

function shortDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' })
}

function TooltipBox({ title, rows }: { title: string; rows: { label: string; value: string; swatch?: string }[] }) {
  return (
    <div className="rounded border border-zinc-200 bg-white px-3 py-2 text-xs shadow-sm dark:border-zinc-700 dark:bg-zinc-900">
      <div className="mb-1 font-semibold text-zinc-900 dark:text-zinc-100">{title}</div>
      {rows.map((r) => (
        <div key={r.label} className="flex items-center justify-between gap-4 text-zinc-600 dark:text-zinc-300">
          <span className="flex items-center gap-1.5">
            {r.swatch && <span className="inline-block h-2 w-2 rounded-sm" style={{ background: r.swatch }} />}
            {r.label}
          </span>
          <span className="font-medium text-zinc-900 tabular-nums dark:text-zinc-100">{r.value}</span>
        </div>
      ))}
    </div>
  )
}

export function YearChart({ years }: { years: YearCount[] }) {
  if (years.length === 0) return <p className="text-sm text-zinc-500">No dated CVEs.</p>
  return (
    <div className="overflow-hidden"><ResponsiveContainer width="100%" height={220}>
      <BarChart data={years} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
        {grid}
        <XAxis dataKey="year" tick={axisTick} tickLine={false} axisLine={{ stroke: 'var(--grid)' }} />
        <YAxis tick={axisTick} width={44} allowDecimals={false} tickFormatter={compact} axisLine={false} tickLine={false} />
        <Tooltip
          cursor={{ fill: 'var(--grid)', opacity: 0.5 }}
          content={({ active, payload, label }) =>
            active && payload?.length ? <TooltipBox title={String(label)} rows={[{ label: 'CVEs', value: fmtNumber(Number(payload[0].value)) }]} /> : null
          }
        />
        <Bar dataKey="cves" fill="var(--chart-accent)" maxBarSize={MAX_BAR} radius={[4, 4, 0, 0]} isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer></div>
  )
}

export function EpssChart({ history }: { history: EpssPoint[] }) {
  if (history.length < 2) {
    return <p className="text-sm text-zinc-500">History starts when Pahredar first loaded EPSS; points are added when the score moves by ≥ 1 point.</p>
  }
  const data = history.map((p) => ({ date: p.score_date, score: p.score }))
  return (
    <div className="overflow-hidden"><ResponsiveContainer width="100%" height={180}>
      <LineChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
        {grid}
        <XAxis dataKey="date" tick={axisTick} tickFormatter={shortDate} tickLine={false} axisLine={{ stroke: 'var(--grid)' }} minTickGap={24} />
        <YAxis tick={axisTick} width={44} domain={[0, 1]} tickFormatter={(v) => `${Math.round(v * 100)}%`} axisLine={false} tickLine={false} />
        <Tooltip
          content={({ active, payload, label }) =>
            active && payload?.length ? <TooltipBox title={shortDate(String(label))} rows={[{ label: 'EPSS', value: fmtEpss(Number(payload[0].value)) }]} /> : null
          }
        />
        <Line type="stepAfter" dataKey="score" stroke="var(--chart-accent)" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" dot={false} isAnimationActive={false} />
      </LineChart>
    </ResponsiveContainer></div>
  )
}
