import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { BellOff, CheckCheck } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router'
import { api } from '../api/client'
import type { Alert } from '../api/types'
import { Card, ErrorBox, PageHeader, Spinner, Tag } from '../components/ui'
import { relativeTime } from '../lib/format'
import { useOrigin } from '../lib/origin'

// Alerts raised about tracked assets — today, when a CVE matched to an asset is
// known-exploited (CISA KEV). The reverse of the asset inventory: not "scan
// this" but "this now matters".

const sevDot: Record<string, string> = { critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-amber-500', low: 'bg-sky-500', info: 'bg-zinc-500' }

export function AlertsPage() {
  useOrigin('Alerts')
  const qc = useQueryClient()
  const [unreadOnly, setUnreadOnly] = useState(false)
  const alerts = useQuery({ queryKey: ['alerts', unreadOnly], queryFn: () => api.alerts(unreadOnly), refetchInterval: 60_000 })

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['alerts'] })
    qc.invalidateQueries({ queryKey: ['alerts-unread'] })
  }
  const read = useMutation({ mutationFn: (id: number) => api.markAlertRead(id), onSuccess: invalidate })
  const readAll = useMutation({ mutationFn: () => api.markAllAlertsRead(), onSuccess: invalidate })

  const seg = (on: boolean) => `rounded-md px-3 py-1 text-sm ${on ? 'bg-zinc-800 text-white' : 'text-zinc-400 hover:text-zinc-200'}`

  return (
    <>
      <PageHeader title="Alerts" subtitle="Raised when something matters for a tracked asset — a CVE matched to one of your assets is known-exploited." />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="flex rounded-lg border border-zinc-800 bg-zinc-900 p-0.5">
          <button className={seg(!unreadOnly)} onClick={() => setUnreadOnly(false)}>All</button>
          <button className={seg(unreadOnly)} onClick={() => setUnreadOnly(true)}>Unread</button>
        </div>
        <button onClick={() => readAll.mutate()} disabled={readAll.isPending} className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-800 px-3 py-1.5 text-sm text-zinc-300 hover:bg-zinc-800 disabled:opacity-50">
          <CheckCheck className="h-4 w-4" /> Mark all read
        </button>
      </div>

      <Card>
        {alerts.isPending ? <Spinner /> : alerts.isError ? <ErrorBox error={alerts.error} /> : alerts.data.items.length === 0 ? (
          <div className="py-10 text-center text-sm text-zinc-500">
            <BellOff className="mx-auto mb-2 h-6 w-6 text-zinc-600" />
            {unreadOnly ? 'No unread alerts.' : 'No alerts. Add assets and scan them; you’ll be told when a known-exploited CVE matches one.'}
          </div>
        ) : (
          <ul className="divide-y divide-zinc-800">
            {alerts.data.items.map((a) => <AlertRow key={a.id} a={a} onRead={() => read.mutate(a.id)} />)}
          </ul>
        )}
      </Card>
    </>
  )
}

function AlertRow({ a, onRead }: { a: Alert; onRead: () => void }) {
  const unread = !a.read_at
  return (
    <li className={`flex gap-3 py-3 ${unread ? '' : 'opacity-60'}`}>
      <span className={`mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full ${sevDot[a.severity] ?? 'bg-zinc-500'}`} />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium text-zinc-100">{a.title}</span>
          {a.type === 'kev_match' && <Tag tone="red">KEV</Tag>}
          {unread && <Tag tone="cyan">new</Tag>}
        </div>
        {a.detail && <p className="mt-0.5 text-sm text-zinc-400">{a.detail}</p>}
        <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-zinc-500">
          <span>{relativeTime(a.created_at)}</span>
          {a.cve_id && <Link to={`/cves/${a.cve_id}`} className="font-mono text-cyan-300 hover:text-cyan-200">{a.cve_id}</Link>}
          {a.asset_id && <Link to={`/inventory/${a.asset_id}`} className="text-cyan-300 hover:text-cyan-200">{a.asset_value || 'asset'}</Link>}
        </div>
      </div>
      {unread && (
        <button onClick={onRead} className="h-7 shrink-0 self-start rounded-md border border-zinc-800 px-2 text-xs text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200">Mark read</button>
      )}
    </li>
  )
}
