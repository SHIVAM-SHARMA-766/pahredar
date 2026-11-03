import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bookmark, BookmarkCheck, ExternalLink, Search, X } from 'lucide-react'
import { useDeferredValue } from 'react'
import { Link, useSearchParams } from 'react-router'
import { api } from '../api/client'
import type { CveBadge, FeedKind, NewsArticle, Severity, TrendingItem } from '../api/types'
import { KIND_LABEL, KindTag, TrendingCard } from '../components/FeedCards'
import { Gauge } from '../components/Gauge'
import { Card, ErrorBox, KevTag, Spinner, Tag } from '../components/ui'
import { fmtDate, fmtNumber, relativeTime } from '../lib/format'
import { useOrigin } from '../lib/origin'
import { bestScore, severityFill, severityText } from '../lib/severity'

// Security news from Pahredar's own feeds (GET /api/v1/news). Every filter
// lives in the URL: kind, feed, q, days, cves, saved, sort, page. Saved
// (bookmarked) articles are listed regardless of the time range.

const link = 'text-cyan-300 hover:text-cyan-200'
const PAGE_SIZE = 30
// Articles naming more CVEs than this are roundups (matches the backend).
const ROUNDUP = 15

const KINDS: [FeedKind | '', string][] = [['', 'All'], ['news', 'News'], ['research', 'Research'], ['vendor', 'Vendor advisories'], ['government', 'Government']]
const RANGES: [number, string][] = [[1, '24 h'], [7, '7 days'], [30, '30 days'], [0, 'All stored']]

export function NewsPage() {
  const [params, setParams] = useSearchParams()
  useOrigin('Security news')
  const kind = (params.get('kind') ?? '') as FeedKind | ''
  const feed = params.get('feed') ?? ''
  const q = params.get('q') ?? ''
  const days = params.has('days') ? Number(params.get('days')) : 7
  const cves = params.get('cves') === '1'
  const saved = params.get('saved') === '1'
  const sort = params.get('sort') === 'newest' ? 'newest' : 'top'
  const page = Math.max(1, Number(params.get('page')) || 1)
  const deferredQ = useDeferredValue(q.trim())

  const set = (changes: Record<string, string>) => {
    const next = new URLSearchParams(params)
    for (const [k, v] of Object.entries(changes)) {
      if (v) next.set(k, v)
      else next.delete(k)
    }
    // Any filter change starts again from the first page.
    if (!('page' in changes)) next.delete('page')
    setParams(next, { replace: true })
  }

  const feeds = useQuery({ queryKey: ['feeds'], queryFn: api.feeds, staleTime: 10 * 60_000 })
  const trending = useQuery({ queryKey: ['trending', 7, 10], queryFn: () => api.trending(7, 10), staleTime: 5 * 60_000 })
  const news = useQuery({
    queryKey: ['news', kind, feed, deferredQ, saved ? 0 : days, cves, saved, sort, page],
    queryFn: () => api.news({ kind: kind || undefined, feed: feed || undefined, q: deferredQ, days: saved ? 0 : days, cves, bookmarked: saved, sort, page, limit: PAGE_SIZE }),
    placeholderData: keepPreviousData,
    refetchInterval: 10 * 60_000,
  })
  const feedName = feeds.data?.items.find((f) => f.key === feed)?.name ?? feed
  const latest = feeds.data?.items.reduce<string | null>((m, f) => (f.latest && (!m || f.latest > m) ? f.latest : m), null)
  const pages = news.data ? Math.max(1, Math.ceil(news.data.total / PAGE_SIZE)) : 1

  const seg = (on: boolean) => `rounded-md px-3 py-1.5 text-sm whitespace-nowrap ${on ? 'bg-zinc-800 text-white' : 'text-zinc-400 hover:text-zinc-200'}`
  return (
    <>
      <NewsBrief feeds={feeds.data?.items.length} latest={latest} trending={trending.data?.items} />

      <div className="mb-4 space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <div className="no-scrollbar flex max-w-full overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-900 p-0.5">
            {KINDS.map(([k, label]) => (
              <button key={label} className={seg(!feed && kind === k)} onClick={() => set({ kind: k, feed: '' })}>{label}</button>
            ))}
          </div>
          <div className={`flex rounded-lg border border-zinc-800 bg-zinc-900 p-0.5 ${saved ? 'opacity-40' : ''}`} title={saved ? 'Saved articles are shown whatever their date' : undefined}>
            {RANGES.map(([d, label]) => (
              <button key={d} disabled={saved} className={seg(!saved && days === d)} onClick={() => set({ days: d === 7 ? '' : String(d) })}>{label}</button>
            ))}
          </div>
          <div className="flex rounded-lg border border-zinc-800 bg-zinc-900 p-0.5">
            <button className={seg(sort === 'top')} onClick={() => set({ sort: '' })} title="Exploited and critical CVEs, widely covered, first">Top</button>
            <button className={seg(sort === 'newest')} onClick={() => set({ sort: 'newest' })}>Newest</button>
          </div>
          <button
            onClick={() => set({ saved: saved ? '' : '1' })}
            className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-sm ${saved ? 'border-cyan-400/40 bg-cyan-500/10 text-cyan-100' : 'border-zinc-800 bg-zinc-900 text-zinc-400 hover:text-zinc-200'}`}
          >
            <BookmarkCheck className="h-4 w-4" /> Saved
          </button>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative min-w-64 flex-1">
            <Search className="pointer-events-none absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-zinc-500" />
            <input
              value={q}
              onChange={(e) => set({ q: e.target.value })}
              placeholder="Search titles and summaries, e.g. ivanti, ransomware, zero-day"
              className="w-full rounded-lg border border-zinc-800 bg-zinc-950 py-2 pr-3 pl-9 text-sm placeholder:text-zinc-500 focus:border-cyan-400/40 focus:ring-1 focus:ring-cyan-400/20 focus:outline-none"
            />
          </div>
          <label className="flex cursor-pointer items-center gap-2 text-sm text-zinc-300">
            <input type="checkbox" checked={cves} onChange={(e) => set({ cves: e.target.checked ? '1' : '' })} className="accent-cyan-400" />
            Only articles naming a CVE
          </label>
          {feed && (
            <button onClick={() => set({ feed: '' })} className="inline-flex items-center gap-1.5 rounded-md border border-cyan-400/30 bg-cyan-500/10 px-2.5 py-1 text-sm text-cyan-100 hover:bg-cyan-500/20">
              Source: {feedName} <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="min-w-0 lg:col-span-2">
          <Card title={news.data ? `${fmtNumber(news.data.total)} article${news.data.total === 1 ? '' : 's'}` : 'Articles'}>
            {news.isPending ? <Spinner /> : news.isError ? <ErrorBox error={news.error} /> : news.data.items.length === 0 ? (
              <p className="py-8 text-center text-sm text-zinc-500">{saved ? 'No saved articles yet. Use the bookmark icon on an article to keep it here.' : 'No articles match. Try a longer time range or fewer filters.'}</p>
            ) : (
              <>
                <ul className={`divide-y divide-zinc-800 ${news.isPlaceholderData ? 'opacity-60' : ''}`}>
                  {news.data.items.map((a) => <Article key={a.url} a={a} badges={news.data.cves} onFeed={(f) => set({ feed: f, kind: '' })} />)}
                </ul>
                {pages > 1 && (
                  <div className="mt-4 flex items-center justify-between text-sm">
                    <button disabled={page <= 1} onClick={() => set({ page: String(page - 1) })} className={`${link} disabled:text-zinc-600`}>← Newer</button>
                    <span className="text-zinc-500">Page {page} of {pages}</span>
                    <button disabled={page >= pages} onClick={() => set({ page: String(page + 1) })} className={`${link} disabled:text-zinc-600`}>Older →</button>
                  </div>
                )}
              </>
            )}
          </Card>
        </div>
        <div className="min-w-0 space-y-6">
          <TrendingCard days={days === 0 ? 30 : days} limit={10} className="" showMore={false} />
          <Card title="Sources">
            {feeds.isPending ? <Spinner /> : feeds.isError ? <p className="text-sm text-zinc-500">Sources are unavailable.</p> : (
              <div className="space-y-4">
                {(['news', 'research', 'vendor', 'government'] as FeedKind[]).map((k) => (
                  <div key={k}>
                    <div className="mb-1 text-xs font-semibold tracking-wider text-zinc-500 uppercase">{KIND_LABEL[k]}</div>
                    <ul className="text-sm">
                      {feeds.data.items.filter((f) => f.kind === k).sort((x, y) => y.articles - x.articles).map((f) => (
                        <li key={f.key}>
                          <button onClick={() => set({ feed: f.key === feed ? '' : f.key, kind: '' })} className={`flex w-full items-baseline justify-between gap-3 rounded px-1.5 py-0.5 text-left hover:bg-zinc-800 ${f.key === feed ? 'bg-zinc-800 text-white' : 'text-zinc-300'}`}>
                            <span className="truncate">{f.name}</span>
                            <span className="shrink-0 text-xs text-zinc-500 tabular-nums" title={`${f.with_cve} name a CVE · newest ${fmtDate(f.latest)}`}>{fmtNumber(f.articles)}</span>
                          </button>
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>
    </>
  )
}

function Article({ a, badges, onFeed }: { a: NewsArticle; badges: Record<string, CveBadge>; onFeed: (feed: string) => void }) {
  const qc = useQueryClient()
  const bookmark = useMutation({
    mutationFn: (on: boolean) => api.setBookmark(a.url, on),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['news'] }),
  })
  // Show the requested state while the request is in flight.
  const on = bookmark.isPending ? !!bookmark.variables : a.bookmarked
  const roundup = a.cve_ids.length > ROUNDUP
  // Exploited first, then by score, so the CVEs that make a story matter
  // lead the chip row.
  const ids = [...a.cve_ids].sort((x, y) => rank(badges[y]) - rank(badges[x]))
  return (
    <li className="flex gap-3 py-3">
      <div className="min-w-0 flex-1">
        <a href={a.url} target="_blank" rel="noreferrer" className="group inline font-medium text-zinc-100 hover:text-cyan-200">
          {a.title}
          <ExternalLink className="ml-1 inline h-3 w-3 text-zinc-600 group-hover:text-cyan-300" />
        </a>
        <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-zinc-500">
          <KindTag kind={a.feed_kind} />
          <button onClick={() => onFeed(a.feed)} className="text-zinc-300 hover:text-cyan-200">{a.feed_name}</button>
          <span>·</span>
          <span title={fmtDate(a.published)}>{relativeTime(a.published)}</span>
        </div>
        {a.summary && <p className="mt-1.5 line-clamp-2 text-sm text-zinc-400">{a.summary}</p>}
        {ids.length > 0 && (
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            {roundup && <span className="text-xs text-zinc-500">Roundup naming {ids.length} CVEs:</span>}
            {ids.slice(0, roundup ? 6 : 8).map((id) => <CveChip key={id} id={id} b={badges[id]} />)}
            {ids.length > (roundup ? 6 : 8) && <span className="text-xs text-zinc-500">+{ids.length - (roundup ? 6 : 8)} more</span>}
          </div>
        )}
        {bookmark.isError && <p className="mt-1 text-xs text-red-300">Could not save the bookmark; try again.</p>}
      </div>
      <button
        onClick={() => bookmark.mutate(!on)}
        disabled={bookmark.isPending}
        title={on ? 'Remove bookmark' : 'Bookmark: keep this article and find it under Saved'}
        aria-label={on ? 'Remove bookmark' : 'Bookmark'}
        aria-pressed={on}
        className={`h-8 w-8 shrink-0 rounded-md p-1.5 ${on ? 'text-cyan-300 hover:bg-zinc-800' : 'text-zinc-500 hover:bg-zinc-800 hover:text-zinc-200'}`}
      >
        {on ? <BookmarkCheck className="h-5 w-5" /> : <Bookmark className="h-5 w-5" />}
      </button>
    </li>
  )
}

function rank(b: CveBadge | undefined): number {
  if (!b) return -1
  return (b.exploited ? 100 : 0) + (b.score ?? 0)
}

function CveChip({ id, b }: { id: string; b?: CveBadge }) {
  return (
    <Link to={`/cves/${id}`} className="inline-flex items-center gap-1.5 rounded bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700" title={b ? undefined : 'Not in the CVE List yet'}>
      <span className="font-mono text-[11px] text-cyan-300">{id}</span>
      {b?.score != null && <span className={`text-[11px] font-semibold tabular-nums ${severityText[b.severity]}`}>{b.score.toFixed(1)}</span>}
      {b?.kev ? <Tag tone="red">KEV</Tag> : b?.exploited ? <Tag tone="red">Exploited</Tag> : null}
    </Link>
  )
}
// NewsBrief is the graphical hero at the top of the news page: a ranked set of
// top stories from the last 7 days alongside a compact "threat mix" panel
// (severity breakdown of the trending CVEs and the exploited share), with a
// stat strip underneath. All of it is derived from the trending query.
function NewsBrief({ feeds, latest, trending }: { feeds?: number; latest?: string | null; trending?: TrendingItem[] }) {
  const items = trending ?? []
  const [top, ...rest] = items
  const runnersUp = rest.slice(0, 3)
  const exploited = items.filter((t) => t.cve?.kev).length
  const stats: [string, string][] = [
    ['Trending CVEs', String(items.length || 0)],
    ['Exploited (KEV)', String(exploited)],
    ['Feeds', feeds ? String(feeds) : '—'],
    ['Updated', latest ? relativeTime(latest) : '—'],
  ]
  return (
    <div className="mb-6 overflow-hidden rounded-2xl border border-zinc-800 bg-gradient-to-br from-zinc-900 via-zinc-900/80 to-zinc-950">
      <div className="flex flex-col gap-1 border-b border-zinc-800/80 px-5 pt-5 pb-4 sm:flex-row sm:items-start sm:justify-between sm:px-6">
        <div className="min-w-0">
          <h1 className="text-2xl font-bold tracking-tight text-white sm:text-3xl">Security Brief</h1>
          <p className="mt-1 max-w-2xl text-sm text-zinc-400">Vendor, government, research, and news feeds, read hourly and ranked by the CVEs each story covers — exploited first, then critical, then how widely it is reported.</p>
        </div>
        {latest && (
          <span className="mt-2 inline-flex shrink-0 items-center gap-1.5 self-start rounded-full border border-zinc-700/70 bg-zinc-950/60 px-2.5 py-1 text-xs text-zinc-400 sm:mt-0">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" /> Updated {relativeTime(latest)}
          </span>
        )}
      </div>

      <div className="grid gap-5 p-5 sm:p-6 lg:grid-cols-3">
        <div className="min-w-0 space-y-3 lg:col-span-2">
          {top ? (
            <>
              <TopStory t={top} />
              {runnersUp.length > 0 && (
                <ol className="divide-y divide-zinc-800/80 overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950/40">
                  {runnersUp.map((t, i) => <RunnerUp key={t.id} t={t} rank={i + 2} />)}
                </ol>
              )}
            </>
          ) : (
            <div className="rounded-xl border border-dashed border-zinc-800 p-8 text-center text-sm text-zinc-500">No CVE mentions in the last 7 days yet; feeds are read hourly.</div>
          )}
        </div>

        <div className="min-w-0">
          <ThreatMix items={items} exploited={exploited} />
        </div>
      </div>

      <div className="grid grid-cols-2 divide-x divide-zinc-800 border-t border-zinc-800 sm:grid-cols-4">
        {stats.map(([label, value]) => (
          <div key={label} className="px-4 py-3 text-center">
            <div className="font-mono text-lg font-semibold text-zinc-100">{value}</div>
            <div className="text-[11px] tracking-wider text-zinc-500 uppercase">{label}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

// The single most prominent story: a large, accented card.
function TopStory({ t }: { t: TrendingItem }) {
  const score = t.cve ? bestScore(t.cve) : null
  return (
    <Link to={`/cves/${t.id}`} className="block rounded-xl border border-cyan-400/20 bg-gradient-to-br from-cyan-500/[0.07] to-zinc-950/20 p-4 transition-colors hover:border-cyan-400/40">
      <div className="flex items-center gap-2 text-[11px] font-semibold tracking-wider text-cyan-300/80 uppercase">
        <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" /> Top story · last 7 days
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <span className="font-mono text-base font-semibold text-cyan-300">{t.id}</span>
        {score != null && <span className={`text-base font-bold ${severityText[t.cve!.severity]}`}>{score.toFixed(1)}</span>}
        {t.cve?.kev && <KevTag />}
        {!t.cve && <Tag tone="amber">Not in CVE List yet</Tag>}
      </div>
      <p className="mt-2 line-clamp-2 text-[15px] leading-snug text-zinc-100">{t.headline}</p>
      <div className="mt-2 flex items-center gap-3 text-xs text-zinc-500">
        <span className="font-medium text-zinc-300">{t.sources} sources</span>
        <span>·</span>
        <span>{t.articles} articles</span>
        <span>·</span>
        <span>{relativeTime(t.latest)}</span>
      </div>
    </Link>
  )
}

// A compact ranked row for stories 2–4.
function RunnerUp({ t, rank }: { t: TrendingItem; rank: number }) {
  const score = t.cve ? bestScore(t.cve) : null
  return (
    <li>
      <Link to={`/cves/${t.id}`} className="flex items-center gap-3 px-3 py-2.5 transition-colors hover:bg-zinc-900/60">
        <span className="w-4 shrink-0 text-center font-mono text-xs text-zinc-600">{rank}</span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[13px] font-semibold text-cyan-300">{t.id}</span>
            {score != null && <span className={`text-xs font-semibold ${severityText[t.cve!.severity]}`}>{score.toFixed(1)}</span>}
            {t.cve?.kev && <KevTag />}
          </div>
          <p className="mt-0.5 truncate text-sm text-zinc-400" title={t.headline}>{t.headline}</p>
        </div>
        <span className="shrink-0 text-right text-xs text-zinc-500 tabular-nums">{t.sources} src</span>
      </Link>
    </li>
  )
}

// SEV_ORDER drives the severity-mix bar and its legend.
const SEV_ORDER: { key: Severity; label: string }[] = [
  { key: 'CRITICAL', label: 'Critical' },
  { key: 'HIGH', label: 'High' },
  { key: 'MEDIUM', label: 'Medium' },
  { key: 'LOW', label: 'Low' },
]

// ThreatMix is the graphical panel: a stacked severity bar of the trending
// CVEs plus a radial exploited-share gauge.
function ThreatMix({ items, exploited }: { items: TrendingItem[]; exploited: number }) {
  // Count trending CVEs by severity; anything unscored or not in the list
  // falls into an "Other" bucket so the bar always sums to the total.
  const counts = new Map<string, number>()
  for (const t of items) {
    const sev = t.cve && bestScore(t.cve) != null ? t.cve.severity : 'OTHER'
    counts.set(sev, (counts.get(sev) ?? 0) + 1)
  }
  const total = items.length
  const segments = [
    ...SEV_ORDER.map((s) => ({ label: s.label, n: counts.get(s.key) ?? 0, fill: severityFill[s.key] })),
    { label: 'Other', n: counts.get('OTHER') ?? 0, fill: 'var(--sev-other)' },
  ].filter((s) => s.n > 0)

  return (
    <div className="flex h-full flex-col gap-4 rounded-xl border border-zinc-800 bg-zinc-950/40 p-4">
      <div className="text-[11px] font-semibold tracking-wider text-zinc-400 uppercase">Threat mix · last 7 days</div>
      <div className="flex items-center justify-center">
        <Gauge
          value={exploited}
          max={total || 1}
          display={String(exploited)}
          caption="exploited"
          color="var(--sev-critical)"
          risk={total ? `${Math.round((exploited / total) * 100)}% of trending` : 'No data'}
        />
      </div>
      <div>
        <div className="mb-1.5 flex items-center justify-between text-xs">
          <span className="text-zinc-400">By severity</span>
          <span className="text-zinc-500 tabular-nums">{total} CVEs</span>
        </div>
        {total > 0 ? (
          <>
            <div className="flex h-2.5 overflow-hidden rounded-full bg-zinc-800">
              {segments.map((s) => (
                <div key={s.label} className="h-full border-r-2 border-zinc-950 last:border-r-0" style={{ width: `${(s.n / total) * 100}%`, background: s.fill }} title={`${s.label}: ${s.n}`} />
              ))}
            </div>
            <ul className="mt-2.5 grid grid-cols-2 gap-x-3 gap-y-1">
              {segments.map((s) => (
                <li key={s.label} className="flex items-center gap-1.5 text-xs text-zinc-400">
                  <span className="h-2 w-2 shrink-0 rounded-sm" style={{ background: s.fill }} />
                  <span className="truncate">{s.label}</span>
                  <span className="ml-auto font-medium text-zinc-200 tabular-nums">{s.n}</span>
                </li>
              ))}
            </ul>
          </>
        ) : (
          <p className="text-xs text-zinc-500">No scored CVEs in this window.</p>
        )}
      </div>
    </div>
  )
}
