import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router'
import { api } from '../api/client'
import type { FeedArticle, FeedKind } from '../api/types'
import { fmtDate, relativeTime } from '../lib/format'
import { bestScore, severityText } from '../lib/severity'
import { Card, KevTag, Spinner, Tag } from './ui'

// Cards backed by the ingested feeds (feed_article): trending CVEs, latest
// vendor and government advisories, and the per-CVE article list.

const link = 'text-cyan-300 hover:text-cyan-200'

export const KIND_LABEL: Record<FeedKind, string> = {
  vendor: 'Vendor advisory',
  government: 'Government',
  research: 'Research',
  news: 'News',
}

export function KindTag({ kind }: { kind: FeedKind | '' }) {
  if (!kind) return null
  const tone = kind === 'vendor' ? 'cyan' : kind === 'government' ? 'amber' : kind === 'research' ? 'violet' : 'zinc'
  return <Tag tone={tone}>{KIND_LABEL[kind]}</Tag>
}

function CveChips({ ids, max = 4 }: { ids: string[]; max?: number }) {
  return (
    <span className="flex flex-wrap gap-1">
      {ids.slice(0, max).map((id) => (
        <Link key={id} to={`/cves/${id}`} className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-[11px] text-cyan-300 hover:bg-zinc-700">{id}</Link>
      ))}
      {ids.length > max && <span className="text-[11px] text-zinc-500">+{ids.length - max}</span>}
    </span>
  )
}

// Dashboard and news page: CVEs mentioned by the most distinct feeds in the
// last `days` days.
// showMore links to the news page.
export function TrendingCard({ days = 7, limit = 8, className = 'h-full', showMore = true }: { days?: number; limit?: number; className?: string; showMore?: boolean }) {
  const q = useQuery({ queryKey: ['trending', days, limit], queryFn: () => api.trending(days, limit), refetchInterval: 10 * 60_000 })
  return (
    <Card
      title={`Trending in security news · ${days === 1 ? '24 hours' : `${days} days`}`}
      className={className}
      actions={showMore ? <Link to="/news" className={`text-xs ${link}`}>All news →</Link> : undefined}
    >
      {q.isPending ? <Spinner /> : q.isError ? <p className="text-sm text-zinc-500">Trending is unavailable.</p> : q.data.items.length === 0 ? (
        <p className="text-sm text-zinc-500">No CVE mentions in this window; feeds are read hourly.</p>
      ) : (
        <ol className="divide-y divide-zinc-800">
          {q.data.items.map((t, i) => (
            <li key={t.id} className="flex items-start gap-3 py-2">
              <span className="w-5 shrink-0 pt-0.5 text-right text-xs text-zinc-500 tabular-nums">{i + 1}</span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <Link to={`/cves/${t.id}`} className={`font-mono text-[13px] font-semibold ${link}`}>{t.id}</Link>
                  {t.cve ? (
                    <>
                      {bestScore(t.cve) != null && <span className={`text-xs font-semibold ${severityText[t.cve.severity]}`}>{bestScore(t.cve)!.toFixed(1)}</span>}
                      {t.cve.kev && <KevTag />}
                    </>
                  ) : (
                    <Tag tone="amber">Not in CVE List yet</Tag>
                  )}
                </div>
                <a href={t.url} target="_blank" rel="noreferrer" className="block truncate text-sm text-zinc-400 hover:text-zinc-200" title={t.headline}>{t.headline}</a>
              </div>
              <div className="shrink-0 text-right text-xs text-zinc-500">
                <div className="font-medium text-zinc-200">{t.sources} sources</div>
                <div>{t.articles} articles</div>
              </div>
            </li>
          ))}
        </ol>
      )}
    </Card>
  )
}

// Dashboard: newest vendor PSIRT and government advisories naming CVEs.
export function LatestAdvisoriesCard() {
  const q = useQuery({ queryKey: ['latest-advisories'], queryFn: () => api.latestAdvisories(8), refetchInterval: 10 * 60_000 })
  return (
    <Card title="Latest vendor & government advisories" className="h-full">
      {q.isPending ? <Spinner /> : q.isError ? <p className="text-sm text-zinc-500">Advisories are unavailable.</p> : (
        <ul className="divide-y divide-zinc-800">
          {q.data.items.map((a) => (
            <li key={a.url} className="py-2">
              <div className="flex items-baseline justify-between gap-3">
                <a href={a.url} target="_blank" rel="noreferrer" className={`min-w-0 truncate text-sm ${link}`} title={a.title}>{a.title}</a>
                <span className="shrink-0 text-xs text-zinc-500 tabular-nums">{fmtDate(a.published)}</span>
              </div>
              <div className="mt-1 flex items-center gap-2">
                <span className="text-xs text-zinc-400">{a.feed_name}</span>
                <CveChips ids={a.cve_ids} max={3} />
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}

// CVE page: articles from the ingested feeds that mention this CVE.
// `current` is left out of each article's CVE chips (it is the page's own CVE).
export function FeedArticleList({ items, current }: { items: FeedArticle[]; current?: string }) {
  return (
    <ul className="divide-y divide-zinc-800">
      {items.map((a) => (
        <li key={a.url} className="py-2">
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <span className="w-24 shrink-0 text-xs text-zinc-500 tabular-nums">{fmtDate(a.published)}</span>
            <a href={a.url} target="_blank" rel="noreferrer" className={`min-w-0 flex-1 text-sm ${link}`}>{a.title}</a>
            <span className="flex shrink-0 items-center gap-2 text-xs text-zinc-400">
              <KindTag kind={a.feed_kind} />
              {a.feed_name}
            </span>
          </div>
          {a.cve_ids.filter((x) => x !== current).length > 0 && (
            <div className="mt-1 pl-[6.75rem] text-xs text-zinc-500">
              {a.cve_ids.length > 15 ? `Roundup naming ${a.cve_ids.length} CVEs` : <CveChips ids={a.cve_ids.filter((x) => x !== current)} max={6} />}
            </div>
          )}
        </li>
      ))}
    </ul>
  )
}

export function useArticles(id: string) {
  return useQuery({ queryKey: ['articles', id], queryFn: () => api.getArticles(id) })
}

// Shown when a CVE ID is not in the CVE List but feeds already mention it,
// typically a vendor advisory published ahead of the CVE record.
export function NotYetPublished({ id }: { id: string }) {
  const q = useArticles(id)
  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-mono text-2xl font-bold text-white">{id}</h1>
        <p className="mt-1 text-sm text-zinc-400">
          This ID is not in the CVE List yet{q.data?.items.length ? ', but security sources already mention it.' : '.'} Its record usually appears once the CNA publishes it; Pahredar syncs the CVE List hourly.
        </p>
      </div>
      <Card title="Mentioned in">
        {q.isPending ? <Spinner /> : !q.data?.items.length ? (
          <p className="text-sm text-zinc-500">No feed article mentions this ID either. Check the ID, or try again later.</p>
        ) : (
          <>
            <FeedArticleList items={q.data.items} current={id} />
            <p className="mt-2 text-xs text-zinc-500">First seen {relativeTime(q.data.items[q.data.items.length - 1].published)}.</p>
          </>
        )}
      </Card>
    </div>
  )
}
