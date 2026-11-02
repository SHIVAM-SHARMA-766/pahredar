import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { DailyCount, EpssPoint, YearCount } from '../api/types'
import { fmtEpss, fmtNumber } from '../lib/format'
import { chartSeries } from '../lib/severity'

// Each chart sits in an overflow-hidden box: ResponsiveContainer measures with
// a ResizeObserver, and a stale measurement should clip, not widen the card.
// Mark specs (dataviz skill): solid hairline grid, recessive axes, bars at
// most 24px with a 4px rounded data end and square baseline, 2px lines, no
// animation, a 2px surface gap between stacked segments.
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

// Bar path with only the top corners rounded.
function roundedTop(x: number, y: number, w: number, h: number, r: number): string {
  r = Math.max(0, Math.min(r, w / 2, h))
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`
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

type SeriesKey = (typeof chartSeries)[number]['key']
const stackKeys = chartSeries.map((s) => s.key)

// Stacked segment: the lowest non-empty segment sits on the baseline; every
// segment above it gives up 2px at its bottom (the surface gap); only the top
// non-empty segment gets the rounded data end.
function stackedShape(key: SeriesKey) {
  return (props: unknown) => {
    const { x, y, width, height, fill, payload } = props as { x: number; y: number; width: number; height: number; fill: string; payload: DailyCount }
    if (!height || height <= 0) return <g />
    const present = stackKeys.filter((k) => payload[k] > 0)
    const isBottom = present[0] === key
    const isTop = present[present.length - 1] === key
    const h = isBottom ? height : height - 2
    if (h <= 0) return <g />
    return <path d={isTop ? roundedTop(x, y, width, h, 4) : `M${x},${y}h${width}v${h}h${-width}Z`} fill={fill} />
  }
}

export function Legend() {
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-600 dark:text-zinc-300">
      {chartSeries.map((s) => (
        <span key={s.key} className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: s.fill }} />
          {s.label}
        </span>
      ))}
    </div>
  )
}

const total = (d: DailyCount) => stackKeys.reduce((a, k) => a + d[k], 0)

export type VolumeRange = '30d' | '90d'

// Daily bars for 30 days; for 90 days, 7-day buckets ending today, so the
// bars stay readable. Each bucket is dated by its first day.
export function volumeSeries(daily: DailyCount[], range: VolumeRange): DailyCount[] {
  if (range === '30d') return daily.slice(-30)
  const out: DailyCount[] = []
  for (let end = daily.length; end > 0; end -= 7) {
    const chunk = daily.slice(Math.max(0, end - 7), end)
    const sum = { ...chunk[0] }
    for (const k of stackKeys) sum[k] = chunk.reduce((a, d) => a + d[k], 0)
    out.unshift(sum)
  }
  return out
}

export function DailyVolumeChart({ daily, range = '30d' }: { daily: DailyCount[]; range?: VolumeRange }) {
  const data = volumeSeries(daily, range)
  const label = (iso: string) => (range === '90d' ? `Week of ${shortDate(iso)}` : shortDate(iso))
  return (
    <div className="space-y-3">
      <Legend />
      <div className="overflow-hidden">
      <ResponsiveContainer width="100%" height={260}>
        <BarChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: 0 }} barCategoryGap="20%">
          {grid}
          <XAxis dataKey="date" tick={axisTick} tickFormatter={shortDate} tickLine={false} axisLine={{ stroke: 'var(--grid)' }} minTickGap={32} />
          <YAxis tick={axisTick} width={44} allowDecimals={false} tickFormatter={compact} axisLine={false} tickLine={false} />
          <Tooltip
            cursor={{ fill: 'var(--grid)', opacity: 0.5 }}
            content={({ active, payload }) => {
              if (!active || !payload?.length) return null
              const d = payload[0].payload as DailyCount
              return (
                <TooltipBox
                  title={`${label(String(d.date))} · ${fmtNumber(total(d))} CVEs`}
                  rows={chartSeries.map((s) => ({ label: s.label, value: fmtNumber(d[s.key]), swatch: s.fill }))}
                />
              )
            }}
          />
          {chartSeries.map((s) => (
            <Bar key={s.key} dataKey={s.key} stackId="sev" fill={s.fill} maxBarSize={MAX_BAR} shape={stackedShape(s.key)} isAnimationActive={false} />
          ))}
        </BarChart>
      </ResponsiveContainer>
      </div>
      <details className="text-sm">
        <summary className="cursor-pointer text-zinc-500">Show as table</summary>
        <div className="mt-2 max-h-72 overflow-y-auto">
          <table className="w-full text-right tabular-nums">
            <thead className="sticky top-0 bg-white text-xs text-zinc-500 dark:bg-zinc-900">
              <tr>
                <th className="py-1 text-left font-medium">Date</th>
                {chartSeries.map((s) => <th key={s.key} className="py-1 font-medium">{s.label}</th>)}
                <th className="py-1 font-medium">Total</th>
              </tr>
            </thead>
            <tbody>
              {[...data].reverse().map((d) => (
                <tr key={d.date} className="border-t border-zinc-100 dark:border-zinc-800">
                  <td className="py-0.5 text-left">{range === '90d' ? `week of ${d.date.slice(0, 10)}` : d.date.slice(0, 10)}</td>
                  {chartSeries.map((s) => <td key={s.key} className="py-0.5">{fmtNumber(d[s.key])}</td>)}
                  <td className="py-0.5 font-medium">{fmtNumber(total(d))}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  )
}
