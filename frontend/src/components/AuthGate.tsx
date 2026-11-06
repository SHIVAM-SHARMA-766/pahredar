import { useQueryClient } from '@tanstack/react-query'
import { KeyRound } from 'lucide-react'
import { useEffect, useState, type ReactNode } from 'react'
import { AUTH_REQUIRED_EVENT, setApiKey } from '../lib/auth'

// AuthGate renders the app, and overlays a key prompt when the API returns 401
// (auth is enabled on the server but this browser has no valid key). Entering
// the key stores it and retries. With auth off on the server, this never shows.
export function AuthGate({ children }: { children: ReactNode }) {
  const qc = useQueryClient()
  const [needed, setNeeded] = useState(false)
  const [value, setValue] = useState('')

  useEffect(() => {
    const onRequired = () => setNeeded(true)
    window.addEventListener(AUTH_REQUIRED_EVENT, onRequired)
    return () => window.removeEventListener(AUTH_REQUIRED_EVENT, onRequired)
  }, [])

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const k = value.trim()
    if (!k) return
    setApiKey(k)
    setValue('')
    setNeeded(false)
    qc.invalidateQueries()
  }

  return (
    <>
      {children}
      {needed && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-zinc-950/80 p-4 backdrop-blur-sm">
          <form onSubmit={submit} className="w-full max-w-sm rounded-2xl border border-zinc-800 bg-zinc-900 p-6">
            <div className="mb-3 flex items-center gap-2">
              <span className="grid h-9 w-9 place-items-center rounded-lg bg-cyan-500/10 ring-1 ring-cyan-400/25">
                <KeyRound className="h-4 w-4 text-cyan-300" />
              </span>
              <div>
                <h2 className="text-base font-semibold text-white">API key required</h2>
                <p className="text-xs text-zinc-500">This server has authentication enabled.</p>
              </div>
            </div>
            <input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              type="password"
              autoFocus
              placeholder="Paste your API key"
              className="w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 font-mono text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-cyan-400/40 focus:outline-none"
            />
            <button type="submit" disabled={!value.trim()} className="mt-3 w-full rounded-lg bg-cyan-500 py-2 text-sm font-medium text-white hover:bg-cyan-400 disabled:opacity-50">
              Continue
            </button>
            <p className="mt-3 text-[11px] text-zinc-600">Stored in this browser only. It is the server's API_KEY.</p>
          </form>
        </div>
      )}
    </>
  )
}
