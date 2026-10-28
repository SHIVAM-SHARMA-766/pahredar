import { useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { api } from '../api/client'
import type { CveSummary, Dashboard, SeverityMix } from '../api/types'
import { DailyVolumeChart } from '../components/charts'
import { Card, ErrorBox, ExploitTag, KevTag, SeverityBadge, Spinner, Stat } from '../components/ui'
import { fmtDate, fmtEpss, fmtNumber, relativeTime } from '../lib/format'
import { bestScore, chartSeries } from '../lib/severity'

// Dates for the list links, as YYYY-MM-DD (UTC) days before today.
function daysAgo(n: number): string {
  const d = new Date()
  d.setUTCDate(d.getUTCDate() - n)
  return d.toISOString().slice(0, 10)
}

const link = 'text-blue-700 hover:underline dark:text-blue-400'

export function DashboardPage() {
  const query = useQuery({ queryKey: ['dashboard'], queryFn: api.dashboard, refetchInterval: 5 * 60_000 })
  if (query.isPending) return <Spinner />
  if (query.isError) return <ErrorBox error={query.error} />
  const d = query.data
  const week = daysAgo(6)

  return (
    <div className="space-y-6">
      <Headline d={d} week={week} />

      <Card title="Published per day, last 90 days">
        <DailyVolumeChart daily={d.daily} />
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Severity, published in the last 30 days">
          <SeverityRows mix={d.severity_30d} />
        </Card>
        <Card title="Biggest EPSS increases, last 7 days">
          {d.epss_movers.length === 0 ? (
            <p className="text-sm text-zinc-500">
              Needs a week of EPSS history; Pahredar records a point each time a score moves by 1 point or more.
            </p>
          ) : (
            <ul className="divide-y divide-zinc-100 text-sm dark:divide-zinc-800">
              {d.epss_movers.map((m) => (
                <li key={m.id} className="flex items-baseline gap-3 py-1.5">
                  <Link to={`/cves/${m.id}`} className={`font-mono whitespace-nowrap ${link}`}>{m.id}</Link>
                  {m.kev && <KevTag />}
                  <span className="min-w-0 flex-1 truncate text-zinc-600 dark:text-zinc-400">{m.title}</span>
                  <span className="shrink-0 tabular-nums">
                    {fmtEpss(m.from)} → <span className="font-semibold">{fmtEpss(m.to)}</span>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="grid gap-6 xl:grid-cols-3">
        <CveListCard
          title="Newest critical"
          params={{ severity: 'CRITICAL', page_size: '8' }}
          more={`/cves?severity=CRITICAL`}
          meta={(c) => fmtDate(c.date_published)}
        />
        <CveListCard
          title="Recently added to CISA KEV"
          params={{ kev: 'true', sort: 'kev_added', page_size: '8' }}
          more="/cves?kev=true&sort=kev_added"
          meta={(c) => fmtDate(c.kev_date_added)}
          metaTitle="Date added to KEV"
        />
        <CveListCard
          title="Likely exploited, not yet in KEV"
          subtitle="Highest EPSS among CVEs published in the last 90 days"
          params={{ kev: 'false', sort: 'epss', published_from: daysAgo(89), page_size: '8' }}
          more={`/cves?kev=false&sort=epss&published_from=${daysAgo(89)}`}
          meta={(c) => fmtEpss(c.epss_score)}
        />
      </div>

      <p className="text-right text-xs text-zinc-500">Updated {relativeTime(d.generated_at)} · counts use UTC days</p>
    </div>
  )
}

function Headline({ d, week }: { d: Dashboard; week: string }) {
  return (
    <div className="grid gap-6 rounded-lg border border-zinc-200 bg-white p-5 md:grid-cols-[auto_1fr] dark:border-zinc-800 dark:bg-zinc-900">
      <div className="md:border-r md:border-zinc-200 md:pr-8 dark:md:border-zinc-800">
        <div className="text-sm text-zinc-500">Critical CVEs published in the last 7 days</div>
        <Link to={`/cves?severity=CRITICAL&published_from=${week}`} className="block text-5xl font-semibold hover:underline">
          {fmtNumber(d.critical_7d)}
        </Link>
        <div className="mt-1 text-xs text-zinc-500">of {fmtNumber(d.published_7d)} published this week</div>
      </div>
      <div className="grid min-w-0 grid-cols-2 gap-4 sm:grid-cols-5">
        <TileLink to={`/cves?published_from=${daysAgo(0)}`}><Stat label="Published today" value={fmtNumber(d.published_today)} hint="UTC, so far" /></TileLink>
        <TileLink to={`/cves?published_from=${week}`}><Stat label="Last 7 days" value={fmtNumber(d.published_7d)} /></TileLink>
        <TileLink to={`/cves?published_from=${daysAgo(29)}`}><Stat label="Last 30 days" value={fmtNumber(d.published_30d)} /></TileLink>
        <TileLink to="/cves?kev=true&sort=kev_added"><Stat label="Added to KEV, 30 days" value={fmtNumber(d.kev_added_30d)} hint={`${fmtNumber(d.kev_total)} in catalog`} /></TileLink>
        <TileLink to="/cves?state=PUBLISHED"><Stat label="Published CVEs tracked" value={fmtNumber(d.total_published)} /></TileLink>
      </div>
    </div>
  )
}

function TileLink({ to, children }: { to: string; children: ReactNode }) {
  return <Link to={to} className="-m-2 rounded p-2 hover:bg-zinc-50 dark:hover:bg-zinc-800">{children}</Link>
}

// One horizontal bar per severity, value at the tip in text colour.
function SeverityRows({ mix }: { mix: SeverityMix }) {
  const max = Math.max(...chartSeries.map((s) => mix[s.key]), 1)
  const total = chartSeries.reduce((a, s) => a + mix[s.key], 0)
  return (
    <div className="space-y-2 text-sm">
      {chartSeries.map((s) => (
        <div key={s.key} className="grid grid-cols-[5.5rem_1fr_6rem] items-center gap-3">
          <span className="text-zinc-600 dark:text-zinc-300">{s.label}</span>
          <div className="h-3">
            <div className="h-full rounded-r" style={{ width: `${(mix[s.key] / max) * 100}%`, background: s.fill, minWidth: mix[s.key] ? 2 : 0 }} />
          </div>
          <span className="text-right tabular-nums">
            {fmtNumber(mix[s.key])} <span className="text-xs text-zinc-500">{total ? Math.round((mix[s.key] / total) * 100) : 0}%</span>
          </span>
        </div>
      ))}
    </div>
  )
}

function CveListCard({ title, subtitle, params, more, meta, metaTitle }: {
  title: string
  subtitle?: string
  params: Record<string, string>
  more: string
  meta: (c: CveSummary) => string
  metaTitle?: string
}) {
  const search = new URLSearchParams(params)
  const query = useQuery({ queryKey: ['cves', search.toString()], queryFn: () => api.listCves(search) })
  return (
    <Card title={title} actions={<Link to={more} className={`text-xs ${link}`}>View all →</Link>}>
      {subtitle && <p className="-mt-2 mb-2 text-xs text-zinc-500">{subtitle}</p>}
      {metaTitle && !subtitle && <p className="-mt-2 mb-2 text-xs text-zinc-500">Dates are when CISA added the CVE</p>}
      {query.isPending ? (
        <Spinner />
      ) : query.isError ? (
        <ErrorBox error={query.error} />
      ) : (
        <ul className="divide-y divide-zinc-100 text-sm dark:divide-zinc-800">
          {query.data.items.map((c) => (
            <li key={c.id} className="py-2">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <Link to={`/cves/${c.id}`} className={`font-mono whitespace-nowrap ${link}`}>{c.id}</Link>
                <SeverityBadge severity={c.severity} score={bestScore(c)} />
                {c.kev && <KevTag />}
                {c.has_exploit && <ExploitTag />}
                <span className="ml-auto text-xs text-zinc-500 tabular-nums" title={metaTitle}>{meta(c)}</span>
              </div>
              <div className="mt-0.5 line-clamp-1 text-zinc-600 dark:text-zinc-400">{c.title ?? c.description}</div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}
