import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Building2, Loader2, Plus, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { api } from '../api/client'
import type { Client } from '../api/types'
import { Card, ErrorBox, PageHeader, Spinner, Tag } from '../components/ui'
import { relativeTime } from '../lib/format'
import { useOrigin } from '../lib/origin'

// Admin-only client (tenant) management. Assets belong to a client; operators
// and viewers only see the clients they are assigned to (on the Users page).

export function ClientsPage() {
  useOrigin('Clients')
  const qc = useQueryClient()
  const clients = useQuery({ queryKey: ['clients'], queryFn: api.clients })
  const invalidate = () => qc.invalidateQueries({ queryKey: ['clients'] })

  const [name, setName] = useState('')
  const [notes, setNotes] = useState('')
  const [err, setErr] = useState('')

  const create = useMutation({
    mutationFn: () => api.createClient({ name: name.trim(), notes: notes.trim() }),
    onSuccess: () => { setName(''); setNotes(''); setErr(''); invalidate() },
    onError: (e: unknown) => setErr(e instanceof Error ? e.message : 'Could not create the client.'),
  })

  return (
    <>
      <PageHeader title="Clients" subtitle="The tenants whose assets you watch. Each asset belongs to a client; assign users to clients on the Users page." />

      <Card title="Add a client" className="mb-6">
        <form onSubmit={(e) => { e.preventDefault(); if (name.trim()) create.mutate() }} className="flex flex-wrap items-end gap-3">
          <label className="min-w-56 flex-1 text-sm">
            <span className="mb-1 block text-[11px] tracking-wider text-zinc-500 uppercase">Name</span>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Suzuki Digital"
              className="w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-cyan-400/40 focus:outline-none" />
          </label>
          <label className="min-w-56 flex-1 text-sm">
            <span className="mb-1 block text-[11px] tracking-wider text-zinc-500 uppercase">Notes (optional)</span>
            <input value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Infra security engagement"
              className="w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-cyan-400/40 focus:outline-none" />
          </label>
          <button type="submit" disabled={!name.trim() || create.isPending}
            className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-500 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-400 disabled:opacity-50">
            {create.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Add
          </button>
        </form>
        {err && <p className="mt-2 text-sm text-red-300">{err}</p>}
      </Card>

      <Card title={clients.data ? `Clients (${clients.data.items.length})` : 'Clients'}>
        {clients.isPending ? <Spinner /> : clients.isError ? <ErrorBox error={clients.error} /> : clients.data.items.length === 0 ? (
          <p className="py-8 text-center text-sm text-zinc-500">No clients yet. Add one above.</p>
        ) : (
          <ul className="divide-y divide-zinc-800">
            {clients.data.items.map((c) => <ClientRow key={c.id} c={c} onChange={invalidate} />)}
          </ul>
        )}
      </Card>
    </>
  )
}

function ClientRow({ c, onChange }: { c: Client; onChange: () => void }) {
  const [err, setErr] = useState('')
  const remove = () => {
    if (!window.confirm(`Delete client ${c.name}? Its assets and incidents are removed too.`)) return
    setErr('')
    api.deleteClient(c.id).then(onChange).catch((e) => setErr(e instanceof Error ? e.message : 'Delete failed.'))
  }
  return (
    <li className="flex flex-wrap items-center gap-3 py-3">
      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-violet-500/10 ring-1 ring-violet-400/25">
        <Building2 className="h-4 w-4 text-violet-300" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium text-zinc-100">{c.name}</span>
          <Tag tone="zinc">{c.slug}</Tag>
        </div>
        <div className="mt-0.5 text-xs text-zinc-500">
          {c.notes && <span className="text-zinc-400">{c.notes} · </span>}added {relativeTime(c.created_at)}
        </div>
        {err && <p className="mt-1 text-xs text-red-300">{err}</p>}
      </div>
      <button onClick={remove} title="Delete client" className="rounded-lg p-1.5 text-zinc-500 hover:bg-zinc-800 hover:text-red-300">
        <Trash2 className="h-4 w-4" />
      </button>
    </li>
  )
}
