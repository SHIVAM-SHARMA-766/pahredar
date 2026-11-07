import { useQuery } from '@tanstack/react-query'
import { Bell, Boxes, ShieldAlert } from 'lucide-react'
import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { api } from '../api/client'
import type { Alert } from '../api/types'
import { Tag } from './ui'
import { useAuth } from '../lib/auth'
import { relativeTime } from '../lib/format'

// The operator's own posture, surfaced on the dashboard: what they track, what
// is at risk, and the newest alerts. The CVE landscape below it is "the world";
// this strip is "what's mine". Composed from the assets + alerts endpoints, so
// it needs no new backend route.

const alertTag: Record<string, ReactNode> = {
  kev_match: <Tag tone="red">KEV</Tag>,
  epss_high: <Tag tone="amber">High EPSS</Tag>,
  critical_finding: <Tag tone="red">Critical</Tag>,
}

export function MonitoringStrip() {
  // Monitoring data is private (viewer+). Anonymous visitors on the public
  // dashboard see no strip, and the queries stay disabled so they never 401.
  const { isAuthenticated } = useAuth()
  const assets = useQuery({ queryKey: ['assets'], queryFn: api.assets, refetchInterval: 5 * 60_000, enabled: isAuthenticated })
  const unread = useQuery({ queryKey: ['alerts-unread'], queryFn: api.alertsUnread, refetchInterval: 60_000, enabled: isAuthenticated })
  const recent = useQuery({ queryKey: ['alerts', false], queryFn: () => api.alerts(false), refetchInterval: 60_000, enabled: isAuthenticated })

  if (!isAuthenticated) return null

  // Until the first asset exists, this is a one-line nudge, not a wall of zeros.
  if (assets.isSuccess && assets.data.items.length === 0) {
    return (
      <Link
        to="/inventory"
        className="flex items-center justify-between gap-3 rounded-lg border border-dashed border-zinc-800 bg-zinc-900/50 px-5 py-4 text-sm hover:border-cyan-400/30 hover:bg-zinc-900"
      >
        <span className="flex items-center gap-2 text-zinc-300">
          <Boxes className="h-4 w-4 text-cyan-300" />
          Track your assets to be alerted when a known-exploited CVE affects one of them.
        </span>
        <span className="shrink-0 text-cyan-300">Add an asset →</span>
      </Link>
    )
  }

  const items = assets.data?.items ?? []
  const total = items.length
  const atRisk = items.filter((a) => a.kev_count > 0).length
  const unreadCount = unread.data?.unread ?? 0
  const feed = (recent.data?.items ?? []).slice(0, 4)

  return (
    <div className="grid gap-px overflow-hidden rounded-lg border border-zinc-800 bg-zinc-800 lg:grid-cols-[repeat(3,minmax(0,1fr))_2fr]">
      <StatTile to="/inventory" icon={<Boxes className="h-4 w-4 text-zinc-400" />} label="Assets tracked" value={total} />
      <StatTile
        to="/inventory"
        icon={<ShieldAlert className={`h-4 w-4 ${atRisk > 0 ? 'text-red-300' : 'text-zinc-400'}`} />}
        label="With KEV exposure"
        value={atRisk}
        tone={atRisk > 0 ? 'bad' : undefined}
      />
      <StatTile
        to="/alerts"
        icon={<Bell className={`h-4 w-4 ${unreadCount > 0 ? 'text-cyan-300' : 'text-zinc-400'}`} />}
        label="Unread alerts"
        value={unreadCount}
        tone={unreadCount > 0 ? 'alert' : undefined}
      />
      <div className="flex min-w-0 flex-col bg-zinc-900 px-5 py-3">
        <div className="mb-1 flex items-center justify-between">
          <span className="text-xs font-medium text-zinc-400">Recent alerts</span>
          <Link to="/alerts" className="text-xs text-cyan-300 hover:text-cyan-200">View all →</Link>
        </div>
        {feed.length === 0 ? (
          <p className="flex flex-1 items-center text-xs text-zinc-500">No alerts yet — your tracked assets are clear.</p>
        ) : (
          <ul className="divide-y divide-zinc-800/70 text-sm">
            {feed.map((a) => <AlertLine key={a.id} a={a} />)}
          </ul>
        )}
      </div>
    </div>
  )
}

function StatTile({ to, icon, label, value, tone }: { to: string; icon: ReactNode; label: string; value: number; tone?: 'bad' | 'alert' }) {
  const valueColor = tone === 'bad' ? 'text-red-300' : tone === 'alert' ? 'text-cyan-200' : 'text-white'
  return (
    <Link to={to} className="block bg-zinc-900 px-5 py-4 transition-colors hover:bg-zinc-800/70">
      <div className="flex items-center gap-1.5 text-xs font-medium text-zinc-400">{icon}{label}</div>
      <div className={`mt-1 text-2xl font-semibold tabular-nums ${valueColor}`}>{value}</div>
    </Link>
  )
}

function AlertLine({ a }: { a: Alert }) {
  const unread = !a.read_at
  return (
    <li className={`flex items-center gap-2 py-1.5 ${unread ? '' : 'opacity-60'}`}>
      {alertTag[a.type] ?? <Tag tone="zinc">alert</Tag>}
      <span className="min-w-0 flex-1 truncate text-zinc-300" title={a.title}>{a.title}</span>
      {a.asset_value && <span className="shrink-0 truncate font-mono text-xs text-zinc-500">{a.asset_value}</span>}
      <span className="shrink-0 text-xs text-zinc-600">{relativeTime(a.created_at)}</span>
    </li>
  )
}
