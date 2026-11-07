import { useQueryClient } from '@tanstack/react-query'
import { KeyRound, Loader2 } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { api } from '../api/client'
import { useAuth } from '../lib/auth'

// LoginModal overlays an email/password form. It opens when the API returns 401
// (a protected action without a session) or when the user clicks "Sign in". On
// success the server sets the session cookie and we refetch everything.
export function LoginModal() {
  const { loginOpen, closeLogin } = useAuth()
  const qc = useQueryClient()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  if (!loginOpen) return null

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!email.trim() || !password) return
    setBusy(true)
    setErr('')
    try {
      await api.login(email.trim(), password)
      setEmail('')
      setPassword('')
      closeLogin()
      await qc.invalidateQueries() // pick up the new session everywhere
    } catch {
      setErr('Invalid email or password.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-zinc-950/80 p-4 backdrop-blur-sm">
      <form onSubmit={submit} className="w-full max-w-sm rounded-2xl border border-zinc-800 bg-zinc-900 p-6">
        <div className="mb-4 flex items-center gap-2">
          <span className="grid h-9 w-9 place-items-center rounded-lg bg-cyan-500/10 ring-1 ring-cyan-400/25">
            <KeyRound className="h-4 w-4 text-cyan-300" />
          </span>
          <div>
            <h2 className="text-base font-semibold text-white">Sign in</h2>
            <p className="text-xs text-zinc-500">Account access for operators and admins.</p>
          </div>
        </div>
        <label className="mb-2 block text-sm">
          <span className="mb-1 block text-[11px] tracking-wider text-zinc-500 uppercase">Email</span>
          <input
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            type="email"
            autoFocus
            autoComplete="username"
            className="w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-cyan-400/40 focus:outline-none"
            placeholder="you@example.com"
          />
        </label>
        <label className="block text-sm">
          <span className="mb-1 block text-[11px] tracking-wider text-zinc-500 uppercase">Password</span>
          <input
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            type="password"
            autoComplete="current-password"
            className="w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-cyan-400/40 focus:outline-none"
            placeholder="••••••••"
          />
        </label>
        {err && <p className="mt-3 text-sm text-red-300">{err}</p>}
        <div className="mt-4 flex gap-2">
          <button
            type="button"
            onClick={closeLogin}
            className="flex-1 rounded-lg border border-zinc-800 py-2 text-sm text-zinc-300 hover:bg-zinc-800"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={busy || !email.trim() || !password}
            className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-lg bg-cyan-500 py-2 text-sm font-medium text-white hover:bg-cyan-400 disabled:opacity-50"
          >
            {busy && <Loader2 className="h-4 w-4 animate-spin" />} Sign in
          </button>
        </div>
        <p className="mt-3 text-[11px] text-zinc-600">Public pages (intelligence, news, passive scan) need no sign-in.</p>
      </form>
    </div>
  )
}
