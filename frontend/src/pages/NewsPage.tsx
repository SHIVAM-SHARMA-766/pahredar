import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { ExternalLink, Search, X } from 'lucide-react'
import { useDeferredValue } from 'react'
import { Link, useSearchParams } from 'react-router'
import { api } from '../api/client'
import type { CveBadge, FeedKind, NewsArticle } from '../api/types'
import { KIND_LABEL, KindTag, TrendingCard } from '../components/FeedCards'
import { Card, ErrorBox, PageHeader, Spinner, Tag } from '../components/ui'
import { fmtDate, fmtNumber, relativeTime } from '../lib/format'
import { severityText } from '../lib/severity'

// Security news from Pahredar's own feeds (GET /api/v1/news). Every filter
// lives in the URL: kind, feed, q, days, cves, sort, page.

const link = 'text-cyan-300 hover:text-cyan-200'
const PAGE_SIZE = 30
// Articles naming more CVEs than this are roundups (matches the backend).
const ROUNDUP = 15

const KINDS: [FeedKind | '', string][] = [['', 'All'], ['news', 'News'], ['research', 'Research'], ['vendor', 'Vendor advisories'], ['government', 'Government']]
const RANGES: [number, string][] = [[1, '24 h'], [7, '7 days'], [30, '30 days'], [0, 'All time']]

export function NewsPage() {
  const [params, setParams] = useSearchParams()
  const kind = (params.get('kind') ?? '') as FeedKind | ''
  const feed = params.get('feed') ?? ''
  const q = params.get('q') ?? ''
  const days = params.has('days') ? Number(params.get('days')) : 7
  const cves = params.get('cves') === '1'
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
  const news = useQuery({
    queryKey: ['news', kind, feed, deferredQ, days, cves, sort, page],
    queryFn: () => api.news({ kind: kind || undefined, feed: feed || undefined, q: deferredQ, days, cves, sort, page, limit: PAGE_SIZE }),
    placeholderData: keepPreviousData,
    refetchInterval: 10 * 60_000,
  })
  const feedName = feeds.data?.items.find((f) => f.key === feed)?.name ?? feed
  const latest = feeds.data?.items.reduce<string | null>((m, f) => (f.latest && (!m || f.latest > m) ? f.latest : m), null)
  const pages = news.data ? Math.max(1, Math.ceil(news.data.total / PAGE_SIZE)) : 1

  const seg = (on: boolean) => `rounded-md px-3 py-1.5 text-sm whitespace-nowrap ${on ? 'bg-zinc-800 text-white' : 'text-zinc-400 hover:text-zinc-200'}`
  return (
    <>
      <PageHeader
        title="Security news"
        subtitle={
          <>
            {feeds.data ? `${feeds.data.items.length} vendor, government, research, and news feeds` : 'Vendor, government, research, and news feeds'}, read hourly
            {latest && <> · newest article {relativeTime(latest)}</>}. <b className="font-medium text-zinc-300">Top</b> ranks stories by the CVEs they cover: exploited first, then critical, then how many sources cover them.
          </>
        }
      />

      <div className="mb-4 space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex flex-wrap rounded-lg border border-zinc-800 bg-zinc-900 p-0.5">
            {KINDS.map(([k, label]) => (
              <button key={label} className={seg(!feed && kind === k)} onClick={() => set({ kind: k, feed: '' })}>{label}</button>
            ))}
          </div>
          <div className="flex rounded-lg border border-zinc-800 bg-zinc-900 p-0.5">
            {RANGES.map(([d, label]) => (
              <button key={d} className={seg(days === d)} onClick={() => set({ days: d === 7 ? '' : String(d) })}>{label}</button>
            ))}
          </div>
          <div className="flex rounded-lg border border-zinc-800 bg-zinc-900 p-0.5">
            <button className={seg(sort === 'top')} onClick={() => set({ sort: '' })} title="Exploited and critical CVEs, widely covered, first">Top</button>
            <button className={seg(sort === 'newest')} onClick={() => set({ sort: 'newest' })}>Newest</button>
          </div>
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
              <p className="py-8 text-center text-sm text-zinc-500">No articles match. Try a longer time range or fewer filters.</p>
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
  const roundup = a.cve_ids.length > ROUNDUP
  // Exploited first, then by score, so the CVEs that make a story matter
  // lead the chip row.
  const ids = [...a.cve_ids].sort((x, y) => rank(badges[y]) - rank(badges[x]))
  return (
    <li className="py-3">
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
