import { useState, type FormEvent } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router'

const CVE_ID = /^cve-\d{4}-\d{4,}$/i

export function Layout() {
  const navigate = useNavigate()
  const [q, setQ] = useState('')

  // The header search jumps straight to a CVE when given an ID, otherwise it
  // opens the CVE list with a full-text query.
  function submit(e: FormEvent) {
    e.preventDefault()
    const term = q.trim()
    if (!term) return
    navigate(CVE_ID.test(term) ? `/cves/${term.toUpperCase()}` : `/cves?${new URLSearchParams({ q: term })}`)
    setQ('')
  }

  const link = ({ isActive }: { isActive: boolean }) =>
    `rounded px-3 py-1.5 text-sm font-medium ${isActive ? 'bg-zinc-800 text-white dark:bg-zinc-100 dark:text-zinc-900' : 'text-zinc-600 hover:bg-zinc-200 dark:text-zinc-300 dark:hover:bg-zinc-800'}`

  return (
    <div className="min-h-screen bg-zinc-50 text-zinc-900 dark:bg-zinc-950 dark:text-zinc-100">
      <header className="sticky top-0 z-10 border-b border-zinc-200 bg-white/90 backdrop-blur dark:border-zinc-800 dark:bg-zinc-900/90">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-4 px-4 py-3">
          <NavLink to="/" className="flex items-center gap-2 font-bold tracking-tight">
            <svg viewBox="0 0 32 32" className="h-6 w-6" aria-hidden>
              <path d="M16 2 4 7v8c0 7.5 5.1 13.6 12 15 6.9-1.4 12-7.5 12-15V7z" fill="#dc2626" />
            </svg>
            Pahredar
          </NavLink>
          <nav className="flex gap-1">
            <NavLink to="/" end className={link}>Dashboard</NavLink>
            <NavLink to="/cves" className={link}>CVEs</NavLink>
            <NavLink to="/vendors" className={link}>Vendors</NavLink>
            <NavLink to="/sync" className={link}>Sync</NavLink>
          </nav>
          <form onSubmit={submit} className="ml-auto w-full sm:w-80">
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="CVE ID or keywords…"
              className="w-full rounded border border-zinc-300 bg-white px-3 py-1.5 text-sm dark:border-zinc-700 dark:bg-zinc-950"
            />
          </form>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 py-6">
        <Outlet />
      </main>
    </div>
  )
}
