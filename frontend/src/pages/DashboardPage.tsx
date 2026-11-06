import { useQuery } from '@tanstack/react-query'
import { ArrowDownRight, ArrowRight, ArrowUpRight } from 'lucide-react'
import type { ReactNode } from 'react'
import { Link, useSearchParams } from 'react-router'
import { api } from '../api/client'
import type { CveSummary, DailyCount, Dashboard, SeverityMix } from '../api/types'
import { LatestAdvisoriesCard, TrendingCard } from '../components/FeedCards'
import { MetricWidget } from '../components/MetricWidget'
import { MonitoringStrip } from '../components/MonitoringStrip'
import { Card, ErrorBox, ExploitTag, KevTag, PageHeader, RansomwareTag, SeverityBadge, Spinner } from '../components/ui'
import { fmtDate, fmtEpss, fmtNumber, relativeTime } from '../lib/format'
import { useOrigin } from '../lib/origin'
import { explorerLink } from '../lib/query'
import { bestScore, chartSeries } from '../lib/severity'

const link = 'text-cyan-300 hover:text-cyan-200'

export function DashboardPage() {
  useOrigin('Dashboard')
  const query = useQuery({ queryKey: ['dashboard'], queryFn: api.dashboard, refetchInterval: 5 * 60_000 })
  // The metric widget keeps its settings in the URL so a view is linkable.
  const [params, setParams] = useSearchParams()
  if (query.isPending) return <Spinner />
  if (query.isError) return <ErrorBox error={query.error} />
  const d = query.data

  return (
    <div className="space-y-6">
      <PageHeader title="Dashboard" subtitle={`What changed in the CVE landscape · updated ${relativeTime(d.generated_at)} · counts use UTC days`} />
      <MonitoringStrip />
      <Headline d={d} />

      <MetricWidget params={params} setParams={(p) => setParams(p, { replace: true })} />

      <div className="grid items-stretch gap-6 lg:grid-cols-5">
        <div className="min-w-0 lg:col-span-3">
          <TrendingCard />
        </div>
        <div className="min-w-0 lg:col-span-2">
          <Card title="Severity mix · last 30 days" className="h-full">
            <SeverityRows mix={d.severity_30d} />
          </Card>
        </div>
      </div>

      <div className="grid items-stretch gap-6 lg:grid-cols-5">
        <div className="min-w-0 lg:col-span-3">
          <LatestAdvisoriesCard />
        </div>
        <div className="min-w-0 lg:col-span-2">
          <EpssCard d={d} />
        </div>
      </div>

      <div className="grid items-stretch gap-6 xl:grid-cols-3">
        <CveListCard
          title="Newest critical"
          params={{ severity: 'CRITICAL', page_size: '7' }}
          more={explorerLink('severity:critical')}
          meta={(c) => fmtDate(c.date_published)}
        />
        <CveListCard
          title="Recently added to CISA KEV"
          params={{ kev: 'true', sort: 'kev_added', page_size: '7' }}
          more={explorerLink('is:kev', 'kev_added')}
          meta={(c) => fmtDate(c.kev_date_added)}
          metaTitle="Date CISA added the CVE to KEV"
        />
        <CveListCard
          title="Likely exploited, not in KEV"
          params={{ kev: 'false', sort: 'epss', published_from: daysAgo(89), page_size: '7' }}
          more={explorerLink('age:<90 -is:kev', 'epss')}
          meta={(c) => `EPSS ${fmtEpss(c.epss_score)}`}
          metaTitle="Probability of exploitation in the next 30 days (published in the last 90 days)"
        />
      </div>
    </div>
  )
}

// YYYY-MM-DD (UTC) n days before today.
function daysAgo(n: number): string {
  const d = new Date()
  d.setUTCDate(d.getUTCDate() - n)
  return d.toISOString().slice(0, 10)
}

// Sums a field over the n days ending `back` days before the last day.
function window(daily: DailyCount[], n: number, back: number, pick: (d: DailyCount) => number): number {
  const end = daily.length - back
  return daily.slice(Math.max(0, end - n), end).reduce((a, d) => a + pick(d), 0)
}

const all = (d: DailyCount) => d.critical + d.high + d.medium + d.low + d.other

function Headline({ d }: { d: Dashboard }) {
  const crit7Prev = window(d.daily, 7, 7, (x) => x.critical)
  const pub7Prev = window(d.daily, 7, 7, all)
  const pub30Prev = window(d.daily, 30, 30, all)
  return (
    <div className="grid gap-px overflow-hidden rounded-lg border border-zinc-800 bg-zinc-800 md:grid-cols-[1.3fr_repeat(4,1fr)]">
      <Tile to={explorerLink('severity:critical age:<7')} hero>
        <TileLabel>Critical CVEs · last 7 days</TileLabel>
        <div className="mt-1 text-5xl font-semibold tracking-tight text-white">{fmtNumber(d.critical_7d)}</div>
        <Delta now={d.critical_7d} prev={crit7Prev} label="vs previous 7 days" />
      </Tile>
      <Tile to={explorerLink('age:<1')}>
        <TileLabel>Published today</TileLabel>
        <TileValue>{fmtNumber(d.published_today)}</TileValue>
        <div className="text-xs text-zinc-500">UTC day so far</div>
      </Tile>
      <Tile to={explorerLink('age:<7')}>
        <TileLabel>Published · 7 days</TileLabel>
        <TileValue>{fmtNumber(d.published_7d)}</TileValue>
        <Delta now={d.published_7d} prev={pub7Prev} label="vs previous 7 days" />
      </Tile>
      <Tile to={explorerLink('age:<30')}>
        <TileLabel>Published · 30 days</TileLabel>
        <TileValue>{fmtNumber(d.published_30d)}</TileValue>
        <Delta now={d.published_30d} prev={pub30Prev} label="vs previous 30 days" />
      </Tile>
      <Tile to={explorerLink('is:kev', 'kev_added')}>
        <TileLabel>Added to KEV · 30 days</TileLabel>
        <TileValue>{fmtNumber(d.kev_added_30d)}</TileValue>
        <div className="text-xs text-zinc-500">{fmtNumber(d.kev_total)} in catalog · {fmtNumber(d.total_published)} CVEs tracked</div>
      </Tile>
    </div>
  )
}

function Tile({ to, hero, children }: { to: string; hero?: boolean; children: ReactNode }) {
  return (
    <Link to={to} className={`block bg-zinc-900 px-5 py-4 transition-colors hover:bg-zinc-800/70 ${hero ? 'md:py-5' : ''}`}>
      {children}
    </Link>
  )
}

function TileLabel({ children }: { children: ReactNode }) {
  return <div className="text-xs font-medium text-zinc-400">{children}</div>
}

function TileValue({ children }: { children: ReactNode }) {
  return <div className="mt-1 text-2xl font-semibold text-white">{children}</div>
}

// Change against the previous period, in neutral ink: more CVEs is neither
// good nor bad news by itself.
function Delta({ now, prev, label }: { now: number; prev: number; label: string }) {
  if (!prev) return <div className="text-xs text-zinc-500">{label}: n/a</div>
  const pct = Math.round(((now - prev) / prev) * 100)
  const Icon = pct > 0 ? ArrowUpRight : pct < 0 ? ArrowDownRight : ArrowRight
  return (
    <div className="flex items-center gap-1 text-xs text-zinc-400" title={`${fmtNumber(prev)} in the previous period`}>
      <Icon className="h-3.5 w-3.5" />
      <span className="font-medium text-zinc-200">{pct > 0 ? '+' : ''}{pct}%</span>
      <span className="text-zinc-500">{label}</span>
    </div>
  )
}

// A 100% segmented bar for the overall split, then one row per severity with
// its count and share.
function SeverityRows({ mix }: { mix: SeverityMix }) {
  const total = chartSeries.reduce((a, s) => a + mix[s.key], 0) || 1
  return (
    <div className="space-y-4">
      <div className="flex h-3 w-full gap-[2px] overflow-hidden rounded">
        {chartSeries.filter((s) => mix[s.key] > 0).map((s) => (
          <div key={s.key} style={{ flexBasis: `${(mix[s.key] / total) * 100}%`, background: s.fill }} title={`${s.label}: ${fmtNumber(mix[s.key])}`} />
        ))}
      </div>
      <ul className="space-y-2 text-sm">
        {chartSeries.map((s) => (
          <li key={s.key} className="flex items-center gap-3">
            <span className="inline-block h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: s.fill }} />
            <span className="flex-1 text-zinc-300">{s.label}</span>
            <span className="font-medium text-zinc-100 tabular-nums">{fmtNumber(mix[s.key])}</span>
            <span className="w-10 text-right text-xs text-zinc-500 tabular-nums">{Math.round((mix[s.key] / total) * 100)}%</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

// EPSS movers need a week of history; until then show the highest-EPSS CVEs
// published this week so the card is never empty.
function EpssCard({ d }: { d: Dashboard }) {
  const hasMovers = d.epss_movers.length > 0
  const fallback = useQuery({
    queryKey: ['cves', 'epss-week'],
    queryFn: () => api.listCves(new URLSearchParams({ sort: 'epss', published_from: daysAgo(6), page_size: '6' })),
    enabled: !hasMovers,
  })
  if (hasMovers) {
    return (
      <Card className="h-full" title="Biggest EPSS increases · last 7 days" actions={<Link to={explorerLink('epss:>10', 'epss')} className={`text-xs ${link}`}>View all →</Link>}>
        <ul className="divide-y divide-zinc-800 text-sm">
          {d.epss_movers.slice(0, 6).map((m) => (
            <li key={m.id} className="flex items-center gap-3 py-2">
              <Link to={`/cves/${m.id}`} className={`font-mono text-[13px] font-semibold whitespace-nowrap ${link}`}>{m.id}</Link>
              {m.kev && <KevTag />}
              <span className="min-w-0 flex-1 truncate text-zinc-400">{m.title}</span>
              <span className="shrink-0 text-xs text-zinc-400 tabular-nums">
                {fmtEpss(m.from)} → <span className="font-semibold text-zinc-100">{fmtEpss(m.to)}</span>
              </span>
            </li>
          ))}
        </ul>
      </Card>
    )
  }
  return (
    <Card className="h-full" title="Highest EPSS · published this week" actions={<Link to={explorerLink('age:<7', 'epss')} className={`text-xs ${link}`}>View all →</Link>}>
      {fallback.isPending ? <Spinner /> : fallback.isError ? <ErrorBox error={fallback.error} /> : (
        <ul className="divide-y divide-zinc-800 text-sm">
          {fallback.data.items.map((c) => (
            <li key={c.id} className="flex items-center gap-3 py-2">
              <Link to={`/cves/${c.id}`} className={`font-mono text-[13px] font-semibold whitespace-nowrap ${link}`}>{c.id}</Link>
              <span className="min-w-0 flex-1 truncate text-zinc-400">{c.title ?? c.description}</span>
              <span className="shrink-0 font-semibold text-zinc-100 tabular-nums">{fmtEpss(c.epss_score)}</span>
            </li>
          ))}
        </ul>
      )}
      <p className="mt-2 text-xs text-zinc-500">The 7-day EPSS movers list appears once a week of score history has been collected.</p>
    </Card>
  )
}

function CveListCard({ title, params, more, meta, metaTitle }: {
  title: string
  params: Record<string, string>
  more: string
  meta: (c: CveSummary) => string
  metaTitle?: string
}) {
  const search = new URLSearchParams(params)
  const query = useQuery({ queryKey: ['cves', search.toString()], queryFn: () => api.listCves(search) })
  return (
    <section className="flex min-w-0 flex-col rounded-lg border border-zinc-800 bg-zinc-900">
      <div className="flex items-center justify-between gap-2 border-b border-zinc-800 px-4 py-3">
        <h2 className="text-sm font-semibold tracking-wide text-zinc-400 uppercase">{title}</h2>
        <Link to={more} className={`text-xs ${link}`}>View all →</Link>
      </div>
      {query.isPending ? (
        <Spinner />
      ) : query.isError ? (
        <div className="p-4"><ErrorBox error={query.error} /></div>
      ) : (
        <ul className="flex-1 divide-y divide-zinc-800/70">
          {query.data.items.map((c) => (
            <li key={c.id}>
              <Link to={`/cves/${c.id}`} className="block px-4 py-2.5 hover:bg-white/[0.02]">
                <div className="flex items-baseline justify-between gap-3">
                  <span className="font-mono text-[13px] font-semibold text-cyan-300">{c.id}</span>
                  <span className="shrink-0 text-xs text-zinc-500 tabular-nums" title={metaTitle}>{meta(c)}</span>
                </div>
                <div className="mt-1 flex min-w-0 items-center gap-1.5">
                  <SeverityBadge severity={c.severity} score={bestScore(c)} />
                  {c.kev && <KevTag />}
                  {c.ransomware && <RansomwareTag />}
                  {c.has_exploit && <ExploitTag />}
                  <span className="min-w-0 flex-1 truncate text-sm text-zinc-300">{c.title ?? c.description}</span>
                </div>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
