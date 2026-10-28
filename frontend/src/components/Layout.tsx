import { useQuery } from '@tanstack/react-query'
import {
  Building2,
  Bug,
  ChevronsLeft,
  ChevronsRight,
  Flame,
  LayoutDashboard,
  Menu,
  RefreshCw,
  Search,
  TrendingUp,
  X,
  type LucideIcon,
} from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { Link, Outlet, useLocation, useNavigate, type Location } from 'react-router'
import { api } from '../api/client'
import { relativeTime } from '../lib/format'
import { explorerLink } from '../lib/query'

const CVE_ID = /^cve-\d{4}-\d{4,}$/i
const COLLAPSE_KEY = 'pahredar.sidebar.collapsed'

interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  active: (loc: Location) => boolean
}

// Saved views are queries in the explorer's query language (lib/query.ts).
const KEV_QUERY = 'is:kev'
const LIKELY_QUERY = 'epss:>10 -is:kev'
const queryOf = (loc: Location) => (loc.pathname === '/cves' ? new URLSearchParams(loc.search).get('query') : null)
const isKevList = (loc: Location) => queryOf(loc) === KEV_QUERY
const isLikelyList = (loc: Location) => queryOf(loc) === LIKELY_QUERY

// Sections mirror what Pahredar does; "Known exploited" and "Likely exploited"
// are saved views of the CVE explorer, so they share its route.
const SECTIONS: { title: string; dot: string; items: NavItem[] }[] = [
  {
    title: 'Overview',
    dot: 'bg-sky-400',
    items: [{ to: '/', label: 'Dashboard', icon: LayoutDashboard, active: (l) => l.pathname === '/' }],
  },
  {
    title: 'Vulnerability intelligence',
    dot: 'bg-amber-400',
    items: [
      { to: '/cves', label: 'CVE explorer', icon: Bug, active: (l) => l.pathname.startsWith('/cves') && !isKevList(l) && !isLikelyList(l) },
      { to: explorerLink(KEV_QUERY, 'kev_added'), label: 'Known exploited', icon: Flame, active: isKevList },
      { to: explorerLink(LIKELY_QUERY, 'epss'), label: 'Likely exploited', icon: TrendingUp, active: isLikelyList },
      { to: '/vendors', label: 'Vendors & products', icon: Building2, active: (l) => l.pathname.startsWith('/vendors') },
    ],
  },
  {
    title: 'System',
    dot: 'bg-emerald-400',
    items: [{ to: '/sync', label: 'Data sync', icon: RefreshCw, active: (l) => l.pathname === '/sync' }],
  },
]

function readCollapsed(): boolean {
  try {
    return localStorage.getItem(COLLAPSE_KEY) === '1'
  } catch {
    return false
  }
}

export function Layout() {
  const location = useLocation()
  const [collapsed, setCollapsed] = useState(readCollapsed)
  const [drawerOpen, setDrawerOpen] = useState(false)

  useEffect(() => {
    try {
      localStorage.setItem(COLLAPSE_KEY, collapsed ? '1' : '0')
    } catch {
      // Storage unavailable (private mode): the choice just isn't remembered.
    }
  }, [collapsed])

  // Close the mobile drawer whenever the route changes.
  useEffect(() => setDrawerOpen(false), [location.pathname, location.search])

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      {/* Mobile top bar */}
      <header className="sticky top-0 z-30 flex items-center gap-3 border-b border-zinc-800 bg-zinc-900/95 px-4 py-3 backdrop-blur lg:hidden">
        <button onClick={() => setDrawerOpen(true)} className="rounded-md p-1.5 text-zinc-300 hover:bg-zinc-800" aria-label="Open navigation">
          <Menu className="h-5 w-5" />
        </button>
        <Brand compact={false} />
      </header>

      {/* Mobile drawer backdrop */}
      {drawerOpen && <div className="fixed inset-0 z-40 bg-black/60 lg:hidden" onClick={() => setDrawerOpen(false)} />}

      <aside
        className={`fixed inset-y-0 left-0 z-50 flex flex-col border-r border-zinc-800 bg-zinc-900 transition-[width,transform] duration-200
          ${collapsed ? 'lg:w-[72px]' : 'lg:w-64'} w-72
          ${drawerOpen ? 'translate-x-0' : '-translate-x-full'} lg:translate-x-0`}
      >
        <Sidebar collapsed={collapsed && !drawerOpen} location={location} onToggle={() => setCollapsed((c) => !c)} onClose={() => setDrawerOpen(false)} drawer={drawerOpen} />
      </aside>

      <div className={`transition-[padding] duration-200 ${collapsed ? 'lg:pl-[72px]' : 'lg:pl-64'}`}>
        <main className="mx-auto max-w-7xl px-4 py-6 lg:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}

function Brand({ compact }: { compact: boolean }) {
  return (
    <Link to="/" className="flex items-center gap-2.5" title="Pahredar">
      <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-cyan-500/10 ring-1 ring-cyan-400/25">
        <svg viewBox="0 0 32 32" className="h-5 w-5" aria-hidden>
          <path d="M16 2 4 7v8c0 7.5 5.1 13.6 12 15 6.9-1.4 12-7.5 12-15V7z" fill="#22d3ee" />
          <path d="m11 16 3.5 3.5L21 13" fill="none" stroke="#0e0f11" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </span>
      {!compact && (
        <span className="leading-tight">
          <span className="block text-base font-bold tracking-tight text-white">Pahredar</span>
          <span className="block text-[11px] text-zinc-400">CVE intelligence</span>
        </span>
      )}
    </Link>
  )
}

function Sidebar({ collapsed, location, onToggle, onClose, drawer }: {
  collapsed: boolean
  location: Location
  onToggle: () => void
  onClose: () => void
  drawer: boolean
}) {
  return (
    <>
      <div className={`flex items-center border-b border-zinc-800 px-4 py-4 ${collapsed ? 'justify-center' : 'justify-between'}`}>
        <Brand compact={collapsed} />
        {drawer && (
          <button onClick={onClose} className="rounded-md p-1.5 text-zinc-400 hover:bg-zinc-800 lg:hidden" aria-label="Close navigation">
            <X className="h-5 w-5" />
          </button>
        )}
      </div>

      <div className="px-3 pt-4">
        <SearchBox collapsed={collapsed} />
      </div>

      <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-4">
        {SECTIONS.map((section) => (
          <div key={section.title}>
            {collapsed ? (
              <div className="mx-auto mb-2 h-px w-6 bg-zinc-800" />
            ) : (
              <div className="mb-1.5 flex items-center gap-2 px-3 text-[11px] font-semibold tracking-wider text-zinc-500 uppercase">
                <span className={`h-1.5 w-1.5 rounded-full ${section.dot}`} />
                {section.title}
              </div>
            )}
            <ul className="space-y-0.5">
              {section.items.map((item) => (
                <li key={item.label}>
                  <NavRow item={item} active={item.active(location)} collapsed={collapsed} />
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>

      <div className="space-y-2 border-t border-zinc-800 p-3">
        <SyncCard collapsed={collapsed} />
        <button
          onClick={onToggle}
          className={`hidden w-full items-center gap-3 rounded-lg px-3 py-2 text-sm text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200 lg:flex ${collapsed ? 'justify-center' : ''}`}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <ChevronsRight className="h-4 w-4" /> : <ChevronsLeft className="h-4 w-4" />}
          {!collapsed && 'Collapse'}
        </button>
      </div>
    </>
  )
}

function NavRow({ item, active, collapsed }: { item: NavItem; active: boolean; collapsed: boolean }) {
  const Icon = item.icon
  return (
    <Link
      to={item.to}
      title={collapsed ? item.label : undefined}
      aria-current={active ? 'page' : undefined}
      className={`relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors
        ${collapsed ? 'justify-center' : ''}
        ${active ? 'bg-white/[0.04] text-white ring-1 ring-white/10' : 'text-zinc-300 hover:bg-zinc-800 hover:text-white'}`}
    >
      {active && <span className="absolute inset-y-1.5 left-0 w-[3px] rounded-r bg-cyan-400" />}
      <Icon className={`h-[18px] w-[18px] shrink-0 ${active ? 'text-cyan-300' : 'text-zinc-400'}`} />
      {!collapsed && <span className="truncate">{item.label}</span>}
    </Link>
  )
}

// The search box jumps straight to a CVE when given an ID, otherwise it
// opens the explorer with a full-text query.
function SearchBox({ collapsed }: { collapsed: boolean }) {
  const navigate = useNavigate()
  const [q, setQ] = useState('')
  function submit(e: FormEvent) {
    e.preventDefault()
    const term = q.trim()
    if (!term) return
    navigate(CVE_ID.test(term) ? `/cves/${term.toUpperCase()}` : explorerLink(term))
    setQ('')
  }
  if (collapsed) {
    return (
      <Link to="/cves" title="Search CVEs" className="flex justify-center rounded-lg px-3 py-2 text-zinc-400 hover:bg-zinc-800 hover:text-white">
        <Search className="h-[18px] w-[18px]" />
      </Link>
    )
  }
  return (
    <form onSubmit={submit} className="relative">
      <Search className="pointer-events-none absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-zinc-500" />
      <input
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="CVE ID or keywords…"
        className="w-full rounded-lg border border-zinc-800 bg-zinc-950 py-2 pr-3 pl-9 text-sm text-zinc-100 placeholder:text-zinc-500 focus:border-cyan-400/40 focus:ring-1 focus:ring-cyan-400/25 focus:outline-none"
      />
    </form>
  )
}

// Freshness at a glance: when the CVE list last synced, and whether any
// source's latest run failed.
function SyncCard({ collapsed }: { collapsed: boolean }) {
  const { data } = useQuery({ queryKey: ['sync'], queryFn: api.syncStatus, refetchInterval: 60_000 })
  const cvelist = data?.sources.find((s) => s.source === 'cvelist')
  const latest = new Map<string, string>()
  for (const r of data?.recent_runs ?? []) if (!latest.has(r.source)) latest.set(r.source, r.status)
  const failing = [...latest.values()].includes('failed')
  const dot = !data ? 'bg-zinc-500' : failing ? 'bg-cyan-400' : 'bg-emerald-400'

  if (collapsed) {
    return (
      <Link to="/sync" title={failing ? 'A sync source is failing' : `CVEs synced ${relativeTime(cvelist?.last_success_at)}`} className="flex justify-center py-2">
        <span className={`h-2 w-2 rounded-full ${dot}`} />
      </Link>
    )
  }
  return (
    <Link to="/sync" className="block rounded-lg border border-zinc-800 bg-zinc-950/60 px-3 py-2.5 hover:border-zinc-700">
      <div className="flex items-center gap-2 text-xs font-medium text-zinc-300">
        <span className={`h-2 w-2 rounded-full ${dot}`} />
        {failing ? 'A source is failing' : 'All sources healthy'}
      </div>
      <div className="mt-0.5 text-[11px] text-zinc-500">CVEs synced {relativeTime(cvelist?.last_success_at)}</div>
    </Link>
  )
}
