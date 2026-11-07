import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Building2, KeyRound, Loader2, Plus, Trash2, UserX } from 'lucide-react'
import { useState } from 'react'
import { api } from '../api/client'
import type { User } from '../api/types'
import { Card, ErrorBox, PageHeader, Spinner, Tag } from '../components/ui'
import { useAuth } from '../lib/auth'
import { relativeTime } from '../lib/format'
import { useOrigin } from '../lib/origin'

// Admin-only account management: create users, change roles, disable/enable,
// reset passwords, delete. The server refuses removing the last admin, so this
// page surfaces that error rather than preventing it client-side.

const ROLES = ['viewer', 'operator', 'admin']
const roleTone: Record<string, 'red' | 'amber' | 'zinc'> = { admin: 'red', operator: 'amber', viewer: 'zinc' }

export function UsersPage() {
  useOrigin('Users')
  const qc = useQueryClient()
  const { email: myEmail } = useAuth()
  const users = useQuery({ queryKey: ['users'], queryFn: api.users })
  const invalidate = () => qc.invalidateQueries({ queryKey: ['users'] })

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('viewer')
  const [formErr, setFormErr] = useState('')

  const create = useMutation({
    mutationFn: () => api.createUser({ email: email.trim(), password, role }),
    onSuccess: () => { setEmail(''); setPassword(''); setRole('viewer'); setFormErr(''); invalidate() },
    onError: (e: unknown) => setFormErr(e instanceof Error ? e.message : 'Could not create the user.'),
  })

  return (
    <>
      <PageHeader title="Users" subtitle="Accounts and roles. Public pages need no account; viewers read private data, operators act, admins manage users." />

      <Card title="Add a user" className="mb-6">
        <form
          onSubmit={(e) => { e.preventDefault(); if (email.trim() && password) create.mutate() }}
          className="flex flex-wrap items-end gap-3"
        >
          <label className="min-w-56 flex-1 text-sm">
            <span className="mb-1 block text-[11px] tracking-wider text-zinc-500 uppercase">Email</span>
            <input value={email} onChange={(e) => setEmail(e.target.value)} type="email" placeholder="user@example.com"
              className="w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-cyan-400/40 focus:outline-none" />
          </label>
          <label className="min-w-44 flex-1 text-sm">
            <span className="mb-1 block text-[11px] tracking-wider text-zinc-500 uppercase">Password (min 8)</span>
            <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" autoComplete="new-password"
              className="w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-cyan-400/40 focus:outline-none" />
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-[11px] tracking-wider text-zinc-500 uppercase">Role</span>
            <select value={role} onChange={(e) => setRole(e.target.value)}
              className="rounded-lg border border-zinc-800 bg-zinc-950 px-2 py-2 text-sm text-zinc-100 focus:border-cyan-400/40 focus:outline-none">
              {ROLES.map((r) => <option key={r}>{r}</option>)}
            </select>
          </label>
          <button type="submit" disabled={!email.trim() || password.length < 8 || create.isPending}
            className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-500 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-400 disabled:opacity-50">
            {create.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Add
          </button>
        </form>
        {formErr && <p className="mt-2 text-sm text-red-300">{formErr}</p>}
      </Card>

      <Card title={users.data ? `Accounts (${users.data.items.length})` : 'Accounts'}>
        {users.isPending ? <Spinner /> : users.isError ? <ErrorBox error={users.error} /> : (
          <ul className="divide-y divide-zinc-800">
            {users.data.items.map((u) => <UserRow key={u.id} u={u} isSelf={u.email === myEmail} onChange={invalidate} />)}
          </ul>
        )}
      </Card>
    </>
  )
}

function UserRow({ u, isSelf, onChange }: { u: User; isSelf: boolean; onChange: () => void }) {
  const [err, setErr] = useState('')
  const [showClients, setShowClients] = useState(false)
  const disabled = !!u.disabled_at

  const run = (p: Promise<unknown>) => { setErr(''); p.then(onChange).catch((e) => setErr(e instanceof Error ? e.message : 'Action failed.')) }
  const setRole = (role: string) => run(api.updateUser(u.id, { role }))
  const toggleDisabled = () => run(api.updateUser(u.id, { disabled: !disabled }))
  const resetPw = () => {
    const pw = window.prompt(`Set a new password for ${u.email} (min 8 chars):`)
    if (pw != null) run(api.resetUserPassword(u.id, pw))
  }
  const remove = () => { if (window.confirm(`Delete ${u.email}? This cannot be undone.`)) run(api.deleteUser(u.id)) }

  return (
    <li className={`py-3 ${disabled ? 'opacity-60' : ''}`}>
      <div className="flex flex-wrap items-center gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="truncate text-sm font-medium text-zinc-100">{u.email}</span>
            {isSelf && <Tag tone="cyan">you</Tag>}
            {disabled && <Tag tone="zinc">disabled</Tag>}
          </div>
          <div className="mt-0.5 text-xs text-zinc-500">added {relativeTime(u.created_at)}</div>
          {err && <p className="mt-1 text-xs text-red-300">{err}</p>}
        </div>

        <Tag tone={roleTone[u.role] ?? 'zinc'}>{u.role}</Tag>
        <select value={u.role} onChange={(e) => setRole(e.target.value)} title="Change role"
          className="rounded-lg border border-zinc-800 bg-zinc-950 px-2 py-1.5 text-xs text-zinc-200 focus:border-cyan-400/40 focus:outline-none">
          {ROLES.map((r) => <option key={r}>{r}</option>)}
        </select>

        {u.role === 'admin' ? (
          <span className="text-xs text-zinc-500" title="Admins can access every client">all clients</span>
        ) : (
          <button onClick={() => setShowClients((s) => !s)} title="Assign clients" className="inline-flex items-center gap-1 rounded-lg border border-zinc-800 px-2 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800">
            <Building2 className="h-3.5 w-3.5" /> Clients
          </button>
        )}
        <button onClick={resetPw} title="Reset password" className="rounded-lg p-1.5 text-zinc-400 hover:bg-zinc-800 hover:text-cyan-300">
          <KeyRound className="h-4 w-4" />
        </button>
        <button onClick={toggleDisabled} title={disabled ? 'Enable' : 'Disable'} className="rounded-lg p-1.5 text-zinc-400 hover:bg-zinc-800 hover:text-amber-300">
          <UserX className="h-4 w-4" />
        </button>
        <button onClick={remove} title="Delete user" className="rounded-lg p-1.5 text-zinc-400 hover:bg-zinc-800 hover:text-red-300">
          <Trash2 className="h-4 w-4" />
        </button>
      </div>
      {showClients && u.role !== 'admin' && (
        <div className="mt-2 rounded-lg border border-zinc-800 bg-zinc-950/50 p-2">
          <p className="mb-2 text-[11px] tracking-wider text-zinc-500 uppercase">Clients this user can access</p>
          <ClientsControl userId={u.id} />
        </div>
      )}
    </li>
  )
}

// ClientsControl toggles a user's client assignments (chips: on = assigned).
function ClientsControl({ userId }: { userId: number }) {
  const qc = useQueryClient()
  const all = useQuery({ queryKey: ['clients'], queryFn: api.clients })
  const mine = useQuery({ queryKey: ['user-clients', userId], queryFn: () => api.userClients(userId) })
  const [saving, setSaving] = useState(false)
  const assigned = new Set((mine.data?.items ?? []).map((c) => c.id))

  const toggle = (id: number) => {
    const next = new Set(assigned)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    setSaving(true)
    api.setUserClients(userId, [...next]).finally(() => {
      setSaving(false)
      qc.invalidateQueries({ queryKey: ['user-clients', userId] })
    })
  }

  if (all.isPending || mine.isPending) return <Spinner />
  if ((all.data?.items.length ?? 0) === 0) return <p className="text-xs text-zinc-500">No clients yet — add some on the Clients page.</p>
  return (
    <div className="flex flex-wrap gap-2">
      {all.data!.items.map((c) => {
        const on = assigned.has(c.id)
        return (
          <button key={c.id} onClick={() => toggle(c.id)} disabled={saving}
            className={`rounded px-2 py-0.5 text-xs ring-1 ring-inset disabled:opacity-50 ${on ? 'bg-violet-500/15 text-violet-200 ring-violet-400/30' : 'text-zinc-400 ring-zinc-700 hover:bg-zinc-800'}`}>
            {c.name}
          </button>
        )
      })}
    </div>
  )
}
