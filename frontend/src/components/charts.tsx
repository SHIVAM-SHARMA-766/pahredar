import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { EpssPoint, YearCount } from '../api/types'
import { fmtEpss } from '../lib/format'

const axis = { fontSize: 12, fill: '#71717a' }

export function YearChart({ years }: { years: YearCount[] }) {
  if (years.length === 0) return <p className="text-sm text-zinc-500">No dated CVEs.</p>
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={years} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#71717a33" vertical={false} />
        <XAxis dataKey="year" tick={axis} />
        <YAxis tick={axis} width={48} allowDecimals={false} />
        <Tooltip formatter={(v) => [v, 'CVEs']} labelStyle={{ color: '#18181b' }} />
        <Bar dataKey="cves" fill="#dc2626" radius={[2, 2, 0, 0]} isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  )
}

export function EpssChart({ history }: { history: EpssPoint[] }) {
  if (history.length < 2) {
    return <p className="text-sm text-zinc-500">History starts when Pahredar first loaded EPSS; points are added when the score moves by ≥ 1 point.</p>
  }
  const data = history.map((p) => ({ date: p.score_date.slice(0, 10), score: p.score }))
  return (
    <ResponsiveContainer width="100%" height={180}>
      <LineChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#71717a33" vertical={false} />
        <XAxis dataKey="date" tick={axis} />
        <YAxis tick={axis} width={48} domain={[0, 1]} tickFormatter={(v) => `${Math.round(v * 100)}%`} />
        <Tooltip formatter={(v) => [fmtEpss(Number(v)), 'EPSS']} labelStyle={{ color: '#18181b' }} />
        <Line type="stepAfter" dataKey="score" stroke="#7c3aed" strokeWidth={2} dot={false} isAnimationActive={false} />
      </LineChart>
    </ResponsiveContainer>
  )
}
