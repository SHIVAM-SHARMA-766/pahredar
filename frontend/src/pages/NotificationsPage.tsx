import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Loader2, Plus, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { api } from '../api/client'
import type { Channel, EscalationPolicy, EscalationStep, OnCallSchedule } from '../api/types'
import { Card, ErrorBox, PageHeader, Spinner, Tag } from '../components/ui'
import { relativeTime } from '../lib/format'
import { useOrigin } from '../lib/origin'

// Notification settings (Phase 4C): channels, escalation policies, on-call
// schedules, and suppression windows. Operators manage their clients' config;
// global config (no client) is admin-only.

const input = 'rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-cyan-400/40 focus:outline-none'
const lbl = 'mb-1 block text-[11px] tracking-wider text-zinc-500 uppercase'
const btn = 'inline-flex items-center gap-1.5 rounded-lg bg-cyan-500 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-400 disabled:opacity-50'

export function NotificationsPage() {
  useOrigin('Notifications')
  const clients = useQuery({ queryKey: ['clients'], queryFn: api.clients })
  const clientOpts = clients.data?.items ?? []

  return (
    <>
      <PageHeader title="Notifications" subtitle="Where incidents go and how they escalate: delivery channels, escalation policies, on-call schedules, and maintenance suppression." />
      <div className="space-y-6">
        <ChannelsSection clientOpts={clientOpts} />
        <PoliciesSection clientOpts={clientOpts} />
        <OncallSection clientOpts={clientOpts} />
        <SuppressionSection clientOpts={clientOpts} />
      </div>
    </>
  )
}

type ClientOpt = { id: number; name: string }

// A <select> for the scope: "Global" (null) or a specific client.
function ScopePicker({ value, onChange, clientOpts }: { value: number; onChange: (v: number) => void; clientOpts: ClientOpt[] }) {
  return (
    <select value={value} onChange={(e) => onChange(Number(e.target.value))} className={input}>
      <option value={0}>Global (all clients)</option>
      {clientOpts.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
    </select>
  )
}

function scopeLabel(clientId: number | undefined, clientOpts: ClientOpt[]): string {
  if (!clientId) return 'Global'
  return clientOpts.find((c) => c.id === clientId)?.name ?? `client ${clientId}`
}

// ---- Channels ----
function ChannelsSection({ clientOpts }: { clientOpts: ClientOpt[] }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['channels'], queryFn: api.channels })
  const inv = () => qc.invalidateQueries({ queryKey: ['channels'] })
  const [type, setType] = useState('webhook')
  const [name, setName] = useState('')
  const [target, setTarget] = useState('')
  const [scope, setScope] = useState(0)
  const [err, setErr] = useState('')
  const add = useMutation({
    mutationFn: () => api.createChannel({ client_id: scope || null, type, name: name.trim(), target: target.trim() }),
    onSuccess: () => { setName(''); setTarget(''); setErr(''); inv() },
    onError: (e: unknown) => setErr(e instanceof Error ? e.message : 'Could not create the channel.'),
  })

  return (
    <Card title="Delivery channels">
      <form onSubmit={(e) => { e.preventDefault(); if (target.trim()) add.mutate() }} className="mb-4 flex flex-wrap items-end gap-3">
        <label className="text-sm"><span className={lbl}>Type</span>
          <select value={type} onChange={(e) => setType(e.target.value)} className={input}><option value="webhook">webhook</option><option value="email">email</option></select>
        </label>
        <label className="min-w-64 flex-1 text-sm"><span className={lbl}>{type === 'email' ? 'Email address' : 'Webhook URL'}</span>
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder={type === 'email' ? 'oncall@example.com' : 'https://hooks.slack.com/...'} className={`w-full ${input}`} />
        </label>
        <label className="min-w-32 flex-1 text-sm"><span className={lbl}>Name</span>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Slack #alerts" className={`w-full ${input}`} />
        </label>
        <label className="text-sm"><span className={lbl}>Scope</span><ScopePicker value={scope} onChange={setScope} clientOpts={clientOpts} /></label>
        <button type="submit" disabled={!target.trim() || add.isPending} className={btn}>{add.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Add</button>
      </form>
      {err && <p className="mb-2 text-sm text-red-300">{err}</p>}
      {q.isPending ? <Spinner /> : q.isError ? <ErrorBox error={q.error} /> : q.data.items.length === 0 ? (
        <p className="text-sm text-zinc-500">No channels yet. Without one, delivery falls back to the server's env webhook/email.</p>
      ) : (
        <ul className="divide-y divide-zinc-800">
          {q.data.items.map((c: Channel) => (
            <li key={c.id} className={`flex flex-wrap items-center gap-3 py-2.5 ${c.enabled ? '' : 'opacity-50'}`}>
              <Tag tone={c.type === 'email' ? 'amber' : 'cyan'}>{c.type}</Tag>
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm text-zinc-200">{c.name || c.target}</div>
                <div className="truncate text-xs text-zinc-500">{c.target}</div>
              </div>
              <Tag tone="violet">{scopeLabel(c.client_id, clientOpts)}</Tag>
              <button onClick={() => api.updateChannel(c.id, { enabled: !c.enabled }).then(inv)} className="rounded-md border border-zinc-800 px-2 py-1 text-xs text-zinc-300 hover:bg-zinc-800">{c.enabled ? 'Disable' : 'Enable'}</button>
              <button onClick={() => { if (confirm('Delete channel?')) api.deleteChannel(c.id).then(inv) }} className="rounded-lg p-1.5 text-zinc-500 hover:bg-zinc-800 hover:text-red-300"><Trash2 className="h-4 w-4" /></button>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}

// ---- Escalation policies ----
function PoliciesSection({ clientOpts }: { clientOpts: ClientOpt[] }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['escalation-policies'], queryFn: api.escalationPolicies })
  const inv = () => qc.invalidateQueries({ queryKey: ['escalation-policies'] })
  const [name, setName] = useState('')
  const [scope, setScope] = useState(0)
  const [isDefault, setIsDefault] = useState(false)
  const add = useMutation({
    mutationFn: () => api.createEscalationPolicy({ client_id: scope || null, name: name.trim(), is_default: isDefault }),
    onSuccess: () => { setName(''); setIsDefault(false); inv() },
  })

  return (
    <Card title="Escalation policies">
      <form onSubmit={(e) => { e.preventDefault(); if (name.trim()) add.mutate() }} className="mb-4 flex flex-wrap items-end gap-3">
        <label className="min-w-48 flex-1 text-sm"><span className={lbl}>Name</span>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Default escalation" className={`w-full ${input}`} />
        </label>
        <label className="text-sm"><span className={lbl}>Scope</span><ScopePicker value={scope} onChange={setScope} clientOpts={clientOpts} /></label>
        <label className="flex items-center gap-1.5 pb-2 text-sm text-zinc-300"><input type="checkbox" checked={isDefault} onChange={(e) => setIsDefault(e.target.checked)} className="accent-cyan-400" /> Default</label>
        <button type="submit" disabled={!name.trim() || add.isPending} className={btn}>{add.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Add</button>
      </form>
      {q.isPending ? <Spinner /> : q.isError ? <ErrorBox error={q.error} /> : q.data.items.length === 0 ? (
        <p className="text-sm text-zinc-500">No policies. Without one, an incident is delivered once to its channels.</p>
      ) : (
        <ul className="space-y-3">
          {q.data.items.map((p: EscalationPolicy) => <PolicyRow key={p.id} policy={p} clientOpts={clientOpts} onChange={inv} />)}
        </ul>
      )}
    </Card>
  )
}

function PolicyRow({ policy, clientOpts, onChange }: { policy: EscalationPolicy; clientOpts: ClientOpt[]; onChange: () => void }) {
  const channels = useQuery({ queryKey: ['channels'], queryFn: api.channels })
  const [steps, setSteps] = useState<EscalationStep[]>(policy.steps ?? [])
  const [dirty, setDirty] = useState(false)

  const update = (i: number, patch: Partial<EscalationStep>) => { setSteps((s) => s.map((st, j) => (j === i ? { ...st, ...patch } : st))); setDirty(true) }
  const addStep = () => { setSteps((s) => [...s, { delay_minutes: 15, channel_id: null, notify_oncall: false }]); setDirty(true) }
  const removeStep = (i: number) => { setSteps((s) => s.filter((_, j) => j !== i)); setDirty(true) }
  const save = () => api.setPolicySteps(policy.id, steps).then(() => { setDirty(false); onChange() })

  return (
    <li className="rounded-lg border border-zinc-800 bg-zinc-950/40 p-3">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium text-zinc-100">{policy.name}</span>
        <Tag tone="violet">{scopeLabel(policy.client_id, clientOpts)}</Tag>
        {policy.is_default && <Tag tone="cyan">default</Tag>}
        <span className="flex-1" />
        <button onClick={() => { if (confirm('Delete policy?')) api.deleteEscalationPolicy(policy.id).then(onChange) }} className="rounded-lg p-1.5 text-zinc-500 hover:bg-zinc-800 hover:text-red-300"><Trash2 className="h-4 w-4" /></button>
      </div>
      <ol className="space-y-1.5">
        {steps.map((st, i) => (
          <li key={i} className="flex flex-wrap items-center gap-2 text-sm">
            <span className="w-6 text-xs text-zinc-500">#{i + 1}</span>
            <select value={st.channel_id ?? 0} onChange={(e) => update(i, { channel_id: Number(e.target.value) || null })} className={input}>
              <option value={0}>No channel</option>
              {(channels.data?.items ?? []).map((c) => <option key={c.id} value={c.id}>{c.name || c.target}</option>)}
            </select>
            <label className="flex items-center gap-1 text-xs text-zinc-400"><input type="checkbox" checked={st.notify_oncall} onChange={(e) => update(i, { notify_oncall: e.target.checked })} className="accent-cyan-400" /> on-call</label>
            <label className="flex items-center gap-1 text-xs text-zinc-400">wait <input type="number" min={0} value={st.delay_minutes} onChange={(e) => update(i, { delay_minutes: Number(e.target.value) })} className={`w-16 ${input}`} /> min</label>
            <button onClick={() => removeStep(i)} className="rounded p-1 text-zinc-500 hover:text-red-300"><Trash2 className="h-3.5 w-3.5" /></button>
          </li>
        ))}
      </ol>
      <div className="mt-2 flex items-center gap-2">
        <button onClick={addStep} className="rounded-md border border-zinc-800 px-2 py-1 text-xs text-zinc-300 hover:bg-zinc-800">+ Step</button>
        {dirty && <button onClick={save} className="rounded-md bg-cyan-500 px-3 py-1 text-xs font-medium text-white hover:bg-cyan-400">Save steps</button>}
      </div>
    </li>
  )
}

// ---- On-call ----
function OncallSection({ clientOpts }: { clientOpts: ClientOpt[] }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['oncall'], queryFn: api.oncallSchedules })
  const users = useQuery({ queryKey: ['users'], queryFn: api.users, retry: false })
  const inv = () => qc.invalidateQueries({ queryKey: ['oncall'] })
  const [name, setName] = useState('')
  const [scope, setScope] = useState(0)
  const add = useMutation({ mutationFn: () => api.createOncallSchedule({ client_id: scope || null, name: name.trim() }), onSuccess: () => { setName(''); inv() } })

  return (
    <Card title="On-call schedules">
      <form onSubmit={(e) => { e.preventDefault(); if (name.trim()) add.mutate() }} className="mb-4 flex flex-wrap items-end gap-3">
        <label className="min-w-48 flex-1 text-sm"><span className={lbl}>Schedule name</span>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Primary rota" className={`w-full ${input}`} />
        </label>
        <label className="text-sm"><span className={lbl}>Scope</span><ScopePicker value={scope} onChange={setScope} clientOpts={clientOpts} /></label>
        <button type="submit" disabled={!name.trim() || add.isPending} className={btn}>{add.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Add</button>
      </form>
      {q.isPending ? <Spinner /> : q.isError ? <ErrorBox error={q.error} /> : q.data.items.length === 0 ? (
        <p className="text-sm text-zinc-500">No schedules. Escalation steps with “on-call” email whoever is on call here.</p>
      ) : (
        <ul className="space-y-3">
          {q.data.items.map((sc: OnCallSchedule) => (
            <li key={sc.id} className="rounded-lg border border-zinc-800 bg-zinc-950/40 p-3">
              <div className="mb-2 flex items-center gap-2">
                <span className="text-sm font-medium text-zinc-100">{sc.name}</span>
                <Tag tone="violet">{scopeLabel(sc.client_id, clientOpts)}</Tag>
                <span className="flex-1" />
                <button onClick={() => { if (confirm('Delete schedule?')) api.deleteOncallSchedule(sc.id).then(inv) }} className="rounded-lg p-1.5 text-zinc-500 hover:bg-zinc-800 hover:text-red-300"><Trash2 className="h-4 w-4" /></button>
              </div>
              <ul className="mb-2 space-y-1 text-sm">
                {(sc.shifts ?? []).length === 0 ? <li className="text-xs text-zinc-500">No shifts.</li> : sc.shifts!.map((sh) => (
                  <li key={sh.id} className="flex items-center gap-2 text-xs text-zinc-300">
                    <span className="font-medium">{sh.user_email}</span>
                    <span className="text-zinc-500">{relativeTime(sh.starts_at)} → {relativeTime(sh.ends_at)}</span>
                    <button onClick={() => api.deleteOncallShift(sh.id).then(inv)} className="rounded p-0.5 text-zinc-500 hover:text-red-300"><Trash2 className="h-3 w-3" /></button>
                  </li>
                ))}
              </ul>
              <ShiftForm scheduleId={sc.id} users={users.data?.items ?? []} onAdd={inv} />
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}

function ShiftForm({ scheduleId, users, onAdd }: { scheduleId: number; users: { id: number; email: string }[]; onAdd: () => void }) {
  const [userId, setUserId] = useState(0)
  const [starts, setStarts] = useState('')
  const [ends, setEnds] = useState('')
  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!userId || !starts || !ends) return
    api.addOncallShift(scheduleId, { user_id: userId, starts_at: new Date(starts).toISOString(), ends_at: new Date(ends).toISOString() }).then(() => { setStarts(''); setEnds(''); onAdd() })
  }
  if (users.length === 0) return <p className="text-xs text-zinc-600">Adding shifts needs the user list (admin).</p>
  return (
    <form onSubmit={submit} className="flex flex-wrap items-end gap-2 text-xs">
      <select value={userId} onChange={(e) => setUserId(Number(e.target.value))} className={input}><option value={0}>User…</option>{users.map((u) => <option key={u.id} value={u.id}>{u.email}</option>)}</select>
      <input type="datetime-local" value={starts} onChange={(e) => setStarts(e.target.value)} className={input} />
      <input type="datetime-local" value={ends} onChange={(e) => setEnds(e.target.value)} className={input} />
      <button type="submit" disabled={!userId || !starts || !ends} className="rounded-md border border-zinc-800 px-2 py-1.5 text-zinc-300 hover:bg-zinc-800 disabled:opacity-50">+ Shift</button>
    </form>
  )
}

// ---- Suppression ----
function SuppressionSection({ clientOpts }: { clientOpts: ClientOpt[] }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['suppressions'], queryFn: api.suppressions })
  const inv = () => qc.invalidateQueries({ queryKey: ['suppressions'] })
  const [scope, setScope] = useState(0)
  const [reason, setReason] = useState('')
  const [starts, setStarts] = useState('')
  const [ends, setEnds] = useState('')
  const add = useMutation({
    mutationFn: () => api.createSuppression({ client_id: scope || null, reason: reason.trim(), starts_at: new Date(starts).toISOString(), ends_at: new Date(ends).toISOString() }),
    onSuccess: () => { setReason(''); setStarts(''); setEnds(''); inv() },
  })

  return (
    <Card title="Suppression windows">
      <form onSubmit={(e) => { e.preventDefault(); if (starts && ends) add.mutate() }} className="mb-4 flex flex-wrap items-end gap-3 text-sm">
        <label><span className={lbl}>Scope</span><ScopePicker value={scope} onChange={setScope} clientOpts={clientOpts} /></label>
        <label className="min-w-40 flex-1"><span className={lbl}>Reason</span><input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Maintenance" className={`w-full ${input}`} /></label>
        <label><span className={lbl}>From</span><input type="datetime-local" value={starts} onChange={(e) => setStarts(e.target.value)} className={input} /></label>
        <label><span className={lbl}>To</span><input type="datetime-local" value={ends} onChange={(e) => setEnds(e.target.value)} className={input} /></label>
        <button type="submit" disabled={!starts || !ends || add.isPending} className={btn}>{add.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Add</button>
      </form>
      {q.isPending ? <Spinner /> : q.isError ? <ErrorBox error={q.error} /> : q.data.items.length === 0 ? (
        <p className="text-sm text-zinc-500">No suppression windows.</p>
      ) : (
        <ul className="divide-y divide-zinc-800">
          {q.data.items.map((sp) => (
            <li key={sp.id} className="flex flex-wrap items-center gap-3 py-2.5 text-sm">
              <Tag tone="violet">{sp.asset_value || scopeLabel(sp.client_id, clientOpts)}</Tag>
              <span className="min-w-0 flex-1 truncate text-zinc-300">{sp.reason || 'Suppressed'}</span>
              <span className="text-xs text-zinc-500">{relativeTime(sp.starts_at)} → {relativeTime(sp.ends_at)}</span>
              <button onClick={() => api.deleteSuppression(sp.id).then(inv)} className="rounded-lg p-1.5 text-zinc-500 hover:bg-zinc-800 hover:text-red-300"><Trash2 className="h-4 w-4" /></button>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}
