import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { BellOff, Check, CheckCheck, ChevronDown, ChevronRight } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router'
import { api } from '../api/client'
import type { Incident } from '../api/types'
import { Card, ErrorBox, PageHeader, Spinner, Tag } from '../components/ui'
import { useAuth } from '../lib/auth'
import { relativeTime } from '../lib/format'
import { useOrigin } from '../lib/origin'

// Incidents: one per asset, rolling up its problems. The operator acknowledges
// and resolves them; a new vulnerability re-opens a resolved incident.

const sevDot: Record<string, string> = { critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-amber-500', low: 'bg-sky-500', info: 'bg-zinc-500' }
const statusTone: Record<string, 'red' | 'amber' | 'zinc'> = { triggered: 'red', acknowledged: 'amber', resolved: 'zinc' }
const itemTag: Record<string, { tone: 'red' | 'amber'; label: string }> = {
  kev_match: { tone: 'red', label: 'KEV' },
  epss_high: { tone: 'amber', label: 'High EPSS' },
  critical_finding: { tone: 'red', label: 'Critical finding' },
}

export function IncidentsPage() {
  useOrigin('Incidents')
  const qc = useQueryClient()
  const canEdit = useAuth().can('operator')
  const [showResolved, setShowResolved] = useState(false)
  const incidents = useQuery({ queryKey: ['incidents'], queryFn: api.incidents, refetchInterval: 60_000 })

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['incidents'] })
    qc.invalidateQueries({ queryKey: ['incidents-unread'] })
  }
  const readAll = useMutation({ mutationFn: () => api.markAllIncidentsRead(), onSuccess: invalidate })

  const seg = (on: boolean) => `rounded-md px-3 py-1 text-sm ${on ? 'bg-zinc-800 text-white' : 'text-zinc-400 hover:text-zinc-200'}`
  const items = (incidents.data?.items ?? []).filter((i) => showResolved || i.status !== 'resolved')

  return (
    <>
      <PageHeader title="Incidents" subtitle="One incident per affected asset, rolling up its known-exploited, likely-exploited, and critical-finding issues. Acknowledge and resolve as you work them." />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="flex rounded-lg border border-zinc-800 bg-zinc-900 p-0.5">
          <button className={seg(!showResolved)} onClick={() => setShowResolved(false)}>Open</button>
          <button className={seg(showResolved)} onClick={() => setShowResolved(true)}>All</button>
        </div>
        {canEdit && (
          <button onClick={() => readAll.mutate()} disabled={readAll.isPending} className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-800 px-3 py-1.5 text-sm text-zinc-300 hover:bg-zinc-800 disabled:opacity-50">
            <CheckCheck className="h-4 w-4" /> Mark all read
          </button>
        )}
      </div>

      <Card>
        {incidents.isPending ? <Spinner /> : incidents.isError ? <ErrorBox error={incidents.error} /> : items.length === 0 ? (
          <div className="py-10 text-center text-sm text-zinc-500">
            <BellOff className="mx-auto mb-2 h-6 w-6 text-zinc-600" />
            {showResolved ? 'No incidents.' : 'No open incidents. Tracked assets are clear.'}
          </div>
        ) : (
          <ul className="divide-y divide-zinc-800">
            {items.map((i) => <IncidentRow key={i.id} inc={i} canEdit={canEdit} onChange={invalidate} />)}
          </ul>
        )}
      </Card>
    </>
  )
}

function IncidentRow({ inc, canEdit, onChange }: { inc: Incident; canEdit: boolean; onChange: () => void }) {
  const [open, setOpen] = useState(false)
  const unread = !inc.read_at
  const resolved = inc.status === 'resolved'
  const items = useQuery({ queryKey: ['incident-items', inc.id], queryFn: () => api.incidentItems(inc.id), enabled: open })

  const act = (p: Promise<unknown>) => p.then(onChange)
  const ack = () => act(api.acknowledgeIncident(inc.id))
  const resolve = () => act(api.resolveIncident(inc.id))
  const toggle = () => {
    if (!open && unread) act(api.markIncidentRead(inc.id))
    setOpen((o) => !o)
  }

  return (
    <li className={`py-3 ${resolved ? 'opacity-60' : ''}`}>
      <div className="flex items-start gap-3">
        <button onClick={toggle} className="mt-0.5 shrink-0 text-zinc-500 hover:text-zinc-300" title={open ? 'Collapse' : 'Show issues'}>
          {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </button>
        <span className={`mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full ${sevDot[inc.severity] ?? 'bg-zinc-500'}`} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <Link to={`/inventory/${inc.asset_id}`} className="text-sm font-medium text-zinc-100 hover:text-cyan-200">{inc.asset_value || inc.title}</Link>
            <Tag tone={statusTone[inc.status] ?? 'zinc'}>{inc.status}</Tag>
            {inc.client_name && <Tag tone="violet">{inc.client_name}</Tag>}
            {unread && <Tag tone="cyan">new</Tag>}
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-zinc-500">
            <span>{inc.item_count} issue{inc.item_count === 1 ? '' : 's'}</span>
            <span>·</span>
            <span>updated {relativeTime(inc.last_event_at)}</span>
          </div>
          {open && (
            <div className="mt-2 rounded-lg border border-zinc-800 bg-zinc-950/50 p-2">
              {items.isPending ? <Spinner /> : items.isError ? <ErrorBox error={items.error} /> : (items.data?.items.length ?? 0) === 0 ? (
                <p className="text-xs text-zinc-500">No issues.</p>
              ) : (
                <ul className="space-y-1.5 text-sm">
                  {items.data!.items.map((it) => {
                    const t = itemTag[it.type]
                    return (
                      <li key={it.id} className="flex flex-wrap items-center gap-2">
                        {t && <Tag tone={t.tone}>{t.label}</Tag>}
                        <span className="min-w-0 flex-1 truncate text-zinc-300" title={it.title}>{it.title}</span>
                        {it.cve_id && !it.cve_id.startsWith('finding:') && (
                          <Link to={`/cves/${it.cve_id}`} className="font-mono text-xs text-cyan-300 hover:text-cyan-200">{it.cve_id}</Link>
                        )}
                      </li>
                    )
                  })}
                </ul>
              )}
            </div>
          )}
        </div>
        {canEdit && !resolved && (
          <div className="flex shrink-0 gap-1.5 self-start">
            {inc.status === 'triggered' && (
              <button onClick={ack} className="rounded-md border border-zinc-800 px-2 py-1 text-xs text-zinc-300 hover:bg-zinc-800" title="Acknowledge">Ack</button>
            )}
            <button onClick={resolve} className="inline-flex items-center gap-1 rounded-md border border-emerald-400/30 bg-emerald-500/10 px-2 py-1 text-xs text-emerald-200 hover:bg-emerald-500/20" title="Resolve">
              <Check className="h-3.5 w-3.5" /> Resolve
            </button>
          </div>
        )}
      </div>
    </li>
  )
}
