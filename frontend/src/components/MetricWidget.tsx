import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { RefreshCw, ZoomOut } from 'lucide-react'
import { useState } from 'react'
import { Area, Bar, CartesianGrid, ComposedChart, Line, ReferenceArea, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../api/client'
import type { Series } from '../api/types'
import { fmtNumber } from '../lib/format'
import { ErrorBox, Spinner } from './ui'

// A CloudWatch-style metric widget: metric picker, relative or custom time
// range, period (granularity), graph type, a legend that toggles series and
// shows their sums, a crosshair tooltip, and drag-to-zoom. All settings live
// in the page URL so a view is linkable.

export type Metric = 'published' | 'kev_added' | 'exploits'
type RangeKey = '1w' | '2w' | '1m' | '3m' | '6m' | '1y' | '2y' | 'custom'
type Period = 'auto' | 'day' | 'week' | 'month'
type GraphType = 'line' | 'area' | 'bar'

const METRICS: { value: Metric; label: string }[] = [
  { value: 'published', label: 'CVEs published, by severity' },
  { value: 'kev_added', label: 'CVEs added to CISA KEV' },
  { value: 'exploits', label: 'Public exploits published' },
]

const RANGES: { key: Exclude<RangeKey, 'custom'>; days: number }[] = [
  { key: '1w', days: 7 }, { key: '2w', days: 14 }, { key: '1m', days: 30 }, { key: '3m', days: 90 },
  { key: '6m', days: 182 }, { key: '1y', days: 365 }, { key: '2y', days: 730 },
]

// Series colours: severity uses the emphasis tokens; two-series metrics use
// pairs validated against the card surface (see index.css).
const COLORS: Record<string, string> = {
  critical: 'var(--sev-critical)', high: 'var(--sev-high)', medium: 'var(--sev-medium)', low: 'var(--sev-low)',
  ransomware: 'var(--sev-critical)', exploitdb: 'var(--chart-accent)', metasploit: 'var(--sev-high)',
}
const colorFor = (metric: Metric, key: string) =>
  key === 'other' ? (metric === 'published' ? 'var(--sev-other)' : 'var(--chart-accent)') : COLORS[key] ?? 'var(--chart-accent)'

const axisTick = { fontSize: 12, fill: 'var(--axis-text)' }

function isoDay(d: Date): string {
  return d.toISOString().slice(0, 10)
}

function addDays(day: string, n: number): string {
  const d = new Date(`${day}T00:00:00Z`)
  d.setUTCDate(d.getUTCDate() + n)
  return isoDay(d)
}

function spanDays(from: string, to: string): number {
  return Math.round((Date.parse(to) - Date.parse(from)) / 86_400_000) + 1
}

function autoPeriod(days: number): Exclude<Period, 'auto'> {
  return days <= 45 ? 'day' : days <= 200 ? 'week' : 'month'
}

interface Bucket {
  start: string
  end: string
  values: Record<string, number>
}

// Groups daily points into periods. Weeks are 7-day buckets ending on the last
// day of the range; months are calendar months (UTC), partial at the edges.
function bucketize(series: Series, period: Exclude<Period, 'auto'>): Bucket[] {
  const keys = series.keys.map((k) => k.key)
  const empty = () => Object.fromEntries(keys.map((k) => [k, 0]))
  const pts = series.points.map((p) => ({ day: p.date.slice(0, 10), values: p.values }))
  if (period === 'day') return pts.map((p) => ({ start: p.day, end: p.day, values: { ...empty(), ...p.values } }))
  const out: Bucket[] = []
  if (period === 'week') {
    for (let end = pts.length; end > 0; end -= 7) {
      const chunk = pts.slice(Math.max(0, end - 7), end)
      const values = empty()
      for (const p of chunk) for (const k of keys) values[k] += p.values[k] ?? 0
      out.unshift({ start: chunk[0].day, end: chunk[chunk.length - 1].day, values })
    }
    return out
  }
  for (const p of pts) {
    const month = p.day.slice(0, 7)
    let b = out[out.length - 1]
    if (!b || b.start.slice(0, 7) !== month) {
      b = { start: p.day, end: p.day, values: empty() }
      out.push(b)
    }
    b.end = p.day
    for (const k of keys) b.values[k] += p.values[k] ?? 0
  }
  return out
}

function bucketLabel(b: Bucket, period: Exclude<Period, 'auto'>, long = false): string {
  const d = new Date(`${b.start}T00:00:00Z`)
  if (period === 'month') return d.toLocaleDateString(undefined, { month: 'short', year: long ? 'numeric' : '2-digit', timeZone: 'UTC' })
  const day = d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: long ? 'numeric' : undefined, timeZone: 'UTC' })
  if (period === 'week' && long) {
    const e = new Date(`${b.end}T00:00:00Z`).toLocaleDateString(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' })
    return `${day} – ${e}`
  }
  return day
}

function compact(n: number): string {
  if (n >= 1_000_000) return `${+(n / 1_000_000).toFixed(1)}M`
  if (n >= 1000) return `${+(n / 1000).toFixed(1)}K`
  return String(n)
}

export function MetricWidget({ params, setParams }: { params: URLSearchParams; setParams: (p: URLSearchParams) => void }) {
  const metric = (METRICS.some((m) => m.value === params.get('metric')) ? params.get('metric') : 'published') as Metric
  const rangeKey = (params.get('range') ?? '1m') as RangeKey
  const period = (['auto', 'day', 'week', 'month'].includes(params.get('period') ?? '') ? params.get('period') : 'auto') as Period
  const graph = (['line', 'area', 'bar'].includes(params.get('chart') ?? '') ? params.get('chart') : 'bar') as GraphType

  const today = isoDay(new Date())
  const preset = RANGES.find((r) => r.key === rangeKey) ?? RANGES[2]
  const custom = rangeKey === 'custom' && params.get('from') && params.get('to')
  const rawFrom = custom ? params.get('from')! : addDays(today, -(preset.days - 1))
  const to = custom ? params.get('to')! : today
  const effPeriod = period === 'auto' ? autoPeriod(spanDays(rawFrom, to)) : period
  // Monthly buckets start on the 1st, so the first month is not a misleading
  // partial; only the current month is partial (labelled "to date").
  const from = effPeriod === 'month' && !custom ? `${rawFrom.slice(0, 7)}-01` : rawFrom

  const set = (changes: Record<string, string | null>) => {
    const next = new URLSearchParams(params)
    for (const [k, v] of Object.entries(changes)) {
      if (v == null) next.delete(k)
      else next.set(k, v)
    }
    setParams(next)
  }

  const query = useQuery({
    queryKey: ['series', metric, from, to],
    queryFn: () => api.series(metric, from, to),
    placeholderData: keepPreviousData,
  })

  const [hidden, setHidden] = useState<Set<string>>(new Set())
  const [drag, setDrag] = useState<{ a: number; b: number } | null>(null)

  const buckets = query.data ? bucketize(query.data, effPeriod) : []
  const data = buckets.map((b, i) => ({ i, ...b.values }))
  const keys = query.data?.keys ?? []
  const visible = keys.filter((k) => !hidden.has(k.key))
  const stacked = graph !== 'line'

  const toggle = (key: string) =>
    setHidden((h) => {
      const next = new Set(h)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })

  // Drag across the plot to zoom into those buckets (a custom range).
  const finishDrag = () => {
    if (drag && drag.a !== drag.b && buckets.length) {
      const lo = buckets[Math.min(drag.a, drag.b)]
      const hi = buckets[Math.max(drag.a, drag.b)]
      set({ range: 'custom', from: lo.start, to: hi.end, period: null })
    }
    setDrag(null)
  }

  const seg = (active: boolean) =>
    `px-2.5 py-1 text-xs ${active ? 'bg-zinc-700 text-white' : 'text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200'}`
  const select = 'rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs text-zinc-200 focus:border-cyan-400/40 focus:outline-none'

  return (
    <section className="min-w-0 rounded-lg border border-zinc-800 bg-zinc-900">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-zinc-800 px-4 py-2.5">
        <select className={`${select} text-sm font-medium`} value={metric} onChange={(e) => set({ metric: e.target.value })} aria-label="Metric">
          {METRICS.map((m) => <option key={m.value} value={m.value}>{m.label}</option>)}
        </select>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <div className="flex overflow-hidden rounded-md border border-zinc-700" role="group" aria-label="Time range">
            {RANGES.map((r) => (
              <button key={r.key} className={seg(rangeKey === r.key)} onClick={() => set({ range: r.key, from: null, to: null })}>{r.key}</button>
            ))}
            <button className={seg(rangeKey === 'custom')} onClick={() => set({ range: 'custom', from, to })}>Custom</button>
          </div>
          <select className={select} value={period} onChange={(e) => set({ period: e.target.value === 'auto' ? null : e.target.value })} aria-label="Period">
            <option value="auto">Period: auto ({effPeriod === 'day' ? '1 day' : effPeriod === 'week' ? '1 week' : '1 month'})</option>
            <option value="day">Period: 1 day</option>
            <option value="week">Period: 1 week</option>
            <option value="month">Period: 1 month</option>
          </select>
          <div className="flex overflow-hidden rounded-md border border-zinc-700" role="group" aria-label="Graph type">
            {(['line', 'area', 'bar'] as const).map((g) => (
              <button key={g} className={seg(graph === g)} onClick={() => set({ chart: g === 'bar' ? null : g })}>
                {g === 'line' ? 'Line' : g === 'area' ? 'Stacked area' : 'Stacked bar'}
              </button>
            ))}
          </div>
          <button className="rounded-md border border-zinc-700 p-1.5 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200" title="Refresh" onClick={() => query.refetch()}>
            <RefreshCw className={`h-3.5 w-3.5 ${query.isFetching ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {rangeKey === 'custom' && (
        <div className="flex flex-wrap items-center gap-2 border-b border-zinc-800 px-4 py-2 text-xs text-zinc-400">
          <span>From</span>
          <input type="date" className={select} value={from} max={to} onChange={(e) => e.target.value && set({ from: e.target.value })} />
          <span>to</span>
          <input type="date" className={select} value={to} min={from} max={today} onChange={(e) => e.target.value && set({ to: e.target.value })} />
          <span className="text-zinc-500">(up to about 3 years)</span>
          <button className="ml-auto inline-flex items-center gap-1 text-cyan-300 hover:text-cyan-200" onClick={() => set({ range: '1m', from: null, to: null })}>
            <ZoomOut className="h-3.5 w-3.5" /> Reset to 1 month
          </button>
        </div>
      )}

      <div className="px-2 pt-3 pb-1">
        <div className="flex items-baseline justify-between px-2 pb-1 text-xs text-zinc-500">
          <span className="text-zinc-300">{query.data?.label ?? 'Loading…'}</span>
          <span>{bucketLabel({ start: from, end: from, values: {} }, 'day', true)} – {bucketLabel({ start: to, end: to, values: {} }, 'day', true)} · UTC · drag on the chart to zoom</span>
        </div>
        {query.isPending ? <Spinner /> : query.isError ? <div className="p-2"><ErrorBox error={query.error} /></div> : (
          <div className={`overflow-hidden select-none ${query.isPlaceholderData ? 'opacity-60' : ''}`}>
            <ResponsiveContainer width="100%" height={280}>
              <ComposedChart
                data={data}
                margin={{ top: 8, right: 12, bottom: 0, left: 0 }}
                barCategoryGap="20%"
                onMouseDown={(e) => e?.activeTooltipIndex != null && setDrag({ a: Number(e.activeTooltipIndex), b: Number(e.activeTooltipIndex) })}
                onMouseMove={(e) => drag && e?.activeTooltipIndex != null && setDrag({ ...drag, b: Number(e.activeTooltipIndex) })}
                onMouseUp={finishDrag}
                onMouseLeave={() => setDrag(null)}
              >
                <CartesianGrid stroke="var(--grid)" vertical={false} />
                <XAxis
                  dataKey="i"
                  tick={axisTick}
                  tickFormatter={(i: number) => (buckets[i] ? bucketLabel(buckets[i], effPeriod) : '')}
                  tickLine={false}
                  axisLine={{ stroke: 'var(--grid)' }}
                  minTickGap={28}
                />
                <YAxis tick={axisTick} width={44} allowDecimals={false} tickFormatter={compact} axisLine={false} tickLine={false} />
                <Tooltip
                  cursor={graph === 'bar' ? { fill: 'var(--grid)', opacity: 0.5 } : { stroke: 'var(--axis-text)', strokeDasharray: '0', strokeWidth: 1 }}
                  content={({ active, payload }) => {
                    if (!active || !payload?.length) return null
                    const b = buckets[Number(payload[0].payload.i)]
                    if (!b) return null
                    const total = visible.reduce((a, k) => a + (b.values[k.key] ?? 0), 0)
                    return (
                      <div className="rounded-md border border-zinc-700 bg-zinc-900/95 px-3 py-2 text-xs shadow-lg">
                        <div className="mb-1 font-semibold text-zinc-100">
                          {bucketLabel(b, effPeriod, true)}
                          {b.end === today && effPeriod !== 'day' && <span className="ml-1 font-normal text-zinc-500">({effPeriod} to date)</span>}
                        </div>
                        {[...visible].reverse().map((k) => (
                          <div key={k.key} className="flex items-center justify-between gap-6 text-zinc-300">
                            <span className="flex items-center gap-1.5">
                              <span className="inline-block h-2 w-2 rounded-sm" style={{ background: colorFor(metric, k.key) }} />
                              {k.label}
                            </span>
                            <span className="font-medium text-zinc-100 tabular-nums">{fmtNumber(b.values[k.key] ?? 0)}</span>
                          </div>
                        ))}
                        {visible.length > 1 && (
                          <div className="mt-1 flex justify-between gap-6 border-t border-zinc-700 pt-1 text-zinc-400">
                            <span>Total</span>
                            <span className="font-medium text-zinc-100 tabular-nums">{fmtNumber(total)}</span>
                          </div>
                        )}
                      </div>
                    )
                  }}
                />
                {visible.map((k, idx) => {
                  const color = colorFor(metric, k.key)
                  const top = idx === visible.length - 1
                  if (graph === 'line') {
                    return <Line key={k.key} dataKey={k.key} name={k.label} stroke={color} strokeWidth={2} dot={false} activeDot={{ r: 4, stroke: 'var(--surface)', strokeWidth: 2 }} isAnimationActive={false} />
                  }
                  if (graph === 'area') {
                    return <Area key={k.key} dataKey={k.key} name={k.label} stackId="s" stroke={color} strokeWidth={1.5} fill={color} fillOpacity={0.25} isAnimationActive={false} />
                  }
                  return <Bar key={k.key} dataKey={k.key} name={k.label} stackId="s" fill={color} maxBarSize={24} radius={top ? [3, 3, 0, 0] : 0} stroke="var(--surface)" strokeWidth={stacked ? 1 : 0} isAnimationActive={false} />
                })}
                {drag && drag.a !== drag.b && (
                  <ReferenceArea x1={Math.min(drag.a, drag.b)} x2={Math.max(drag.a, drag.b)} fill="var(--chart-accent)" fillOpacity={0.12} stroke="var(--chart-accent)" strokeOpacity={0.4} />
                )}
              </ComposedChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Legend: click to show or hide a series; each shows its sum over the range. */}
      <div className="flex flex-wrap gap-x-5 gap-y-1.5 border-t border-zinc-800 px-4 py-2.5 text-xs">
        {keys.map((k) => {
          const off = hidden.has(k.key)
          const sum = buckets.reduce((a, b) => a + (b.values[k.key] ?? 0), 0)
          return (
            <button key={k.key} onClick={() => toggle(k.key)} className={`flex items-center gap-1.5 ${off ? 'text-zinc-600 line-through' : 'text-zinc-300 hover:text-white'}`} title={off ? 'Show series' : 'Hide series'}>
              <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: off ? 'var(--grid)' : colorFor(metric, k.key) }} />
              {k.label}
              <span className="text-zinc-500 tabular-nums">Σ {fmtNumber(sum)}</span>
            </button>
          )
        })}
        {buckets.length > 0 && (
          <details className="ml-auto text-zinc-500">
            <summary className="cursor-pointer hover:text-zinc-300">Table</summary>
            <div className="mt-2 max-h-64 overflow-y-auto">
              <table className="w-full text-right tabular-nums">
                <thead className="sticky top-0 bg-zinc-900">
                  <tr>
                    <th className="py-1 pr-3 text-left font-medium">Period</th>
                    {keys.map((k) => <th key={k.key} className="py-1 pl-3 font-medium">{k.label}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {[...buckets].reverse().map((b) => (
                    <tr key={b.start} className="border-t border-zinc-800 text-zinc-300">
                      <td className="py-0.5 pr-3 text-left">{bucketLabel(b, effPeriod, true)}</td>
                      {keys.map((k) => <td key={k.key} className="py-0.5 pl-3">{fmtNumber(b.values[k.key] ?? 0)}</td>)}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </details>
        )}
      </div>
    </section>
  )
}
