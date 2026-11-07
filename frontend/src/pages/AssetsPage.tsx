import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Loader2, Plus, Radar, Trash2 } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { api } from '../api/client'
import type { Asset } from '../api/types'
import { Card, ErrorBox, PageHeader, Spinner, Tag } from '../components/ui'
import { useAuth } from '../lib/auth'
import { relativeTime } from '../lib/format'
import { useOrigin } from '../lib/origin'

// The asset inventory: the domains/URLs/IPs/products tracked per client, each
// with its latest scan's grade. Scanning an asset reuses the endpoint scanner.

const KINDS = ['domain', 'url', 'ip', 'product', 'repo']
const SCANNABLE = new Set(['domain', 'url', 'ip'])

const gradeColor: Record<string, string> = {
  A: 'text-emerald-300 ring-emerald-400/30 bg-emerald-500/10',
  B: 'text-cyan-300 ring-cyan-400/30 bg-cyan-500/10',
  C: 'text-amber-200 ring-amber-400/30 bg-amber-500/10',
  D: 'text-orange-300 ring-orange-400/30 bg-orange-500/10',
  F: 'text-red-300 ring-red-400/30 bg-red-500/10',
}

export function AssetsPage() {
  useOrigin('Assets')
  const qc = useQueryClient()
  const navigate = useNavigate()
  const { can, role } = useAuth()
  const canEdit = can('operator')
  const assets = useQuery({ queryKey: ['assets'], queryFn: api.assets })
  const clients = useQuery({ queryKey: ['clients'], queryFn: api.clients })

  const [kind, setKind] = useState('domain')
  const [value, setValue] = useState('')
  const [label, setLabel] = useState('')
  const [clientId, setClientId] = useState(0)
  const [filter, setFilter] = useState(0) // 0 = all clients

  const clientName = useMemo(() => {
    const m = new Map<number, string>()
    for (const c of clients.data?.items ?? []) m.set(c.id, c.name)
    return m
  }, [clients.data])

  const create = useMutation({
    mutationFn: () => api.createAsset({ client_id: clientId, kind, value: value.trim(), label: label.trim() }),
    onSuccess: () => { setValue(''); setLabel(''); qc.invalidateQueries({ queryKey: ['assets'] }) },
  })
  const remove = useMutation({
    mutationFn: (id: number) => api.deleteAsset(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets'] }),
  })
  const scan = useMutation({
    mutationFn: (a: Asset) => api.scanAsset(a.id).then((r) => ({ r, a })),
    onSuccess: ({ r, a }) => navigate(`/scan?job=${r.job_id}&target=${encodeURIComponent(a.value)}`),
  })

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    if (value.trim() && clientId) create.mutate()
  }

  const noClients = clients.isSuccess && clients.data.items.length === 0
  const items = (assets.data?.items ?? []).filter((a) => filter === 0 || a.client_id === filter)

  return (
    <>
      <PageHeader title="Asset inventory" subtitle="The things you track per client — domains, URLs, IPs, products. Scan an asset to see its posture; its latest grade shows here." />

      {canEdit && noClients && (
        <Card className="mb-6">
          <p className="py-2 text-sm text-zinc-400">
            Create a client first — every asset belongs to one. {role === 'admin' ? <Link to="/clients" className="text-cyan-300 hover:text-cyan-200">Go to Clients →</Link> : 'Ask an admin to add a client and assign it to you.'}
          </p>
        </Card>
      )}

      {canEdit && !noClients && (
      <Card title="Add an asset" className="mb-6">
        <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
          <label className="text-sm">
            <span className="mb-1 block text-[11px] tracking-wider text-zinc-500 uppercase">Client</span>
            <select value={clientId} onChange={(e) => setClientId(Number(e.target.value))} className="rounded-lg border border-zinc-800 bg-zinc-950 px-2 py-2 text-sm text-zinc-100 focus:border-cyan-400/40 focus:outline-none">
              <option value={0}>Select…</option>
              {(clients.data?.items ?? []).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-[11px] tracking-wider text-zinc-500 uppercase">Kind</span>
            <select value={kind} onChange={(e) => setKind(e.target.value)} className="rounded-lg border border-zinc-800 bg-zinc-950 px-2 py-2 text-sm text-zinc-100 focus:border-cyan-400/40 focus:outline-none">
              {KINDS.map((k) => <option key={k}>{k}</option>)}
            </select>
          </label>
          <label className="min-w-48 flex-1 text-sm">
            <span className="mb-1 block text-[11px] tracking-wider text-zinc-500 uppercase">Value</span>
            <input value={value} onChange={(e) => setValue(e.target.value)} placeholder={kind === 'product' ? 'nginx' : 'example.com'}
              className="w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 font-mono text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-cyan-400/40 focus:outline-none" />
          </label>
          <label className="min-w-40 flex-1 text-sm">
            <span className="mb-1 block text-[11px] tracking-wider text-zinc-500 uppercase">Label (optional)</span>
            <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Production site"
              className="w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-cyan-400/40 focus:outline-none" />
          </label>
          <button type="submit" disabled={!value.trim() || !clientId || create.isPending} className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-500 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-400 disabled:opacity-50">
            {create.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Add
          </button>
        </form>
        {create.isError && <p className="mt-2 text-sm text-red-300">Could not add the asset. Check the client, kind and value.</p>}
      </Card>
      )}

      {(clients.data?.items.length ?? 0) > 1 && (
        <div className="mb-4 flex items-center gap-2 text-sm">
          <span className="text-zinc-500">Client:</span>
          <select value={filter} onChange={(e) => setFilter(Number(e.target.value))} className="rounded-lg border border-zinc-800 bg-zinc-900 px-2 py-1.5 text-sm text-zinc-200 focus:border-cyan-400/40 focus:outline-none">
            <option value={0}>All clients</option>
            {clients.data!.items.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </div>
      )}

      <Card title={`Assets (${items.length})`}>
        {assets.isPending ? <Spinner /> : assets.isError ? <ErrorBox error={assets.error} /> : items.length === 0 ? (
          <p className="py-8 text-center text-sm text-zinc-500">No assets{filter ? ' for this client' : ''} yet.</p>
        ) : (
          <ul className="divide-y divide-zinc-800">
            {items.map((a) => (
              <li key={a.id} className="flex flex-wrap items-center gap-3 py-3">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <Link to={`/inventory/${a.id}`} className="font-mono text-sm text-cyan-300 hover:text-cyan-200">{a.value}</Link>
                    <Tag tone="zinc">{a.kind}</Tag>
                    {a.client_id && <Tag tone="violet">{clientName.get(a.client_id) ?? 'client'}</Tag>}
                    {a.tags.map((t) => <Tag key={t} tone="violet">{t}</Tag>)}
                  </div>
                  <div className="mt-0.5 text-xs text-zinc-500">
                    {a.label && <span className="text-zinc-400">{a.label} · </span>}
                    {a.last_scanned_at ? <>scanned {relativeTime(a.last_scanned_at)}</> : 'never scanned'}
                  </div>
                </div>
                {a.kev_count > 0 ? (
                  <span className="rounded px-2 py-0.5 text-xs font-medium text-red-300 ring-1 ring-inset ring-red-400/30 bg-red-500/10">{a.kev_count} KEV</span>
                ) : a.cve_count > 0 ? (
                  <span className="rounded px-2 py-0.5 text-xs text-zinc-400 ring-1 ring-inset ring-zinc-700">{a.cve_count} CVEs</span>
                ) : null}
                {a.last_grade && (
                  <span className={`rounded px-2 py-0.5 text-xs font-semibold ring-1 ring-inset ${gradeColor[a.last_grade] ?? gradeColor.F}`}>
                    Grade {a.last_grade}{a.last_score != null && ` · ${a.last_score}`}
                  </span>
                )}
                {SCANNABLE.has(a.kind) && canEdit && (
                  <button onClick={() => scan.mutate(a)} disabled={scan.isPending} className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-xs text-cyan-200 hover:bg-cyan-500/20 disabled:opacity-50">
                    <Radar className="h-3.5 w-3.5" /> Scan
                  </button>
                )}
                {canEdit && (
                  <button onClick={() => { if (confirm(`Delete asset ${a.value}?`)) remove.mutate(a.id) }} title="Delete asset" className="rounded-lg p-1.5 text-zinc-500 hover:bg-zinc-800 hover:text-red-300">
                    <Trash2 className="h-4 w-4" />
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  )
}
