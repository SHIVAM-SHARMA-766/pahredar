import { useQuery } from '@tanstack/react-query'
import { ExternalLink, MessageSquare } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { Link } from 'react-router'
import { api } from '../api/client'
import type { MsrcReport, NewsItem, RelatedGroup } from '../api/types'
import { fmtDate, fmtNumber, productPath } from '../lib/format'
import { explorerLink } from '../lib/query'
import { bestScore, severityText } from '../lib/severity'
import { FeedArticleList, useArticles } from './FeedCards'
import { Card, ExploitTag, KevTag, Spinner, Tag } from './ui'

// Cards on the CVE page that load from the backend's on-demand endpoints
// (/cves/{id}/reports?sources=… and /cves/{id}/related). Each loads on its
// own so a slow third party never holds up the rest of the page.

const link = 'text-cyan-300 hover:text-cyan-200'
const th = 'py-1.5 pr-3 text-left text-[11px] font-semibold tracking-wider text-zinc-500 uppercase'

function Ext({ href, children, className = '' }: { href: string; children: ReactNode; className?: string }) {
  return (
    <a href={href} target="_blank" rel="noreferrer" className={`${link} ${className}`}>
      {children}
    </a>
  )
}

function Label({ children }: { children: ReactNode }) {
  return <div className="mb-1.5 text-xs font-semibold tracking-wider text-zinc-500 uppercase">{children}</div>
}

// --- Vendor advisories ------------------------------------------------------

export function VendorAdvisoriesCard({ id }: { id: string }) {
  const q = useQuery({ queryKey: ['reports', id, 'vendor'], queryFn: () => api.getCveReports(id, ['msrc', 'advisories']), staleTime: 10 * 60_000 })
  if (q.isPending) return <Card title="Vendor advisories"><Spinner label="Reading vendor advisories…" /></Card>
  if (q.isError) return <Card title="Vendor advisories"><p className="text-sm text-zinc-500">Vendor advisories are unavailable right now.</p></Card>
  const { msrc, advisories = [] } = q.data.reports
  if (!msrc && advisories.length === 0) {
    return (
      <Card title="Vendor advisories">
        <p className="text-sm text-zinc-500">No vendor advisory or patch page is referenced by this CVE yet.</p>
      </Card>
    )
  }
  return (
    <Card title="Vendor advisories">
      <div className="space-y-5">
        {msrc && <Msrc r={msrc} />}
        {advisories.length > 0 && (
          <div>
            {msrc && <Label>Other advisories and patches</Label>}
            <ul className="space-y-3">
              {advisories.map((a) => (
                <li key={a.url} className="rounded-md border border-zinc-800 bg-zinc-950/40 p-3">
                  <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5">
                    <Ext href={a.url} className="font-medium">{a.title || a.url}</Ext>
                    <span className="text-xs text-zinc-500">
                      {a.site_name || a.host}
                      {a.published && <> · {fmtDate(a.published)}</>}
                    </span>
                  </div>
                  {a.description && <p className="mt-1 text-sm text-zinc-400">{a.description}</p>}
                  {a.error && <p className="mt-1 text-xs text-zinc-600">{a.host} · {a.error}; open the link to read it.</p>}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </Card>
  )
}

function Msrc({ r }: { r: MsrcReport }) {
  const [all, setAll] = useState(false)
  const shown = all ? r.products : r.products.slice(0, 8)
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <div>
          <div className="text-xs text-zinc-500">Microsoft Security Response Center</div>
          <div className="font-medium text-zinc-100">{r.title}</div>
        </div>
        <Ext href={r.url} className="inline-flex items-center gap-1 text-xs">Security Update Guide <ExternalLink className="h-3 w-3" /></Ext>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {r.severity && <Tag>Microsoft severity: {r.severity}</Tag>}
        {r.impact && <Tag>{r.impact}</Tag>}
        {r.exploited && <Tag tone={r.exploited === 'Yes' ? 'red' : 'zinc'}>Exploited: {r.exploited}</Tag>}
        {r.publicly_disclosed && <Tag>Publicly disclosed: {r.publicly_disclosed}</Tag>}
        {r.release_date && <span className="text-xs text-zinc-500">released {fmtDate(r.release_date)}</span>}
      </div>
      {r.products.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-zinc-800"><th className={th}>Product</th><th className={th}>Update</th><th className={th}>Fixed build</th><th className={th}>Download</th></tr></thead>
            <tbody>
              {shown.map((p) =>
                (p.kb.length ? p.kb : [null]).map((kb, i) => (
                  <tr key={p.product + i} className="border-b border-zinc-800/60 align-top">
                    <td className="py-1.5 pr-3 text-zinc-300">{i === 0 ? p.product : ''}</td>
                    <td className="py-1.5 pr-3">{kb ? (kb.url ? <Ext href={kb.url} className="font-mono text-xs">KB{kb.article}</Ext> : <span className="font-mono text-xs">{kb.article}</span>) : '—'}</td>
                    <td className="py-1.5 pr-3 font-mono text-xs text-emerald-300">{kb?.fixed_build || '—'}</td>
                    <td className="py-1.5">{kb?.download_url ? <Ext href={kb.download_url} className="text-xs">{kb.download || 'Download'}</Ext> : '—'}</td>
                  </tr>
                )),
              )}
            </tbody>
          </table>
          {r.products.length > shown.length && <button className={`mt-2 text-sm ${link}`} onClick={() => setAll(true)}>Show all {r.products.length} products</button>}
        </div>
      )}
    </div>
  )
}

// --- News and discussions ----------------------------------------------------

// Tabs: articles from Pahredar's own feeds (vendor, government, research,
// news; ingested hourly), Google News search, Hacker News, Bluesky posts
// (needs BLUESKY_HANDLE and BLUESKY_APP_PASSWORD), and Mastodon posts
// tagged with the CVE (public, no key).
export function NewsCard({ id }: { id: string }) {
  const q = useQuery({ queryKey: ['reports', id, 'news'], queryFn: () => api.getCveReports(id, ['news', 'discussions', 'bluesky', 'mastodon']), staleTime: 10 * 60_000 })
  const own = useArticles(id)
  const [tab, setTab] = useState<'feeds' | 'news' | 'discussions' | 'bluesky' | 'mastodon' | null>(null)
  if (q.isPending && own.isPending) return <Card title="News & research"><Spinner label="Searching news and discussions…" /></Card>
  const feedItems = own.data?.items ?? []
  const news = q.data?.reports.news ?? []
  const disc = q.data?.reports.discussions ?? []
  const bsky = q.data?.reports.bluesky ?? []
  const masto = q.data?.reports.mastodon ?? []
  const bskyOff = q.data?.sources.find((s) => s.source === 'bluesky')?.status === 'disabled'
  if (!feedItems.length && !news.length && !disc.length && !bsky.length && !masto.length) {
    return <Card title="News & research"><p className="text-sm text-zinc-500">{q.isError ? 'News is unavailable right now.' : 'No articles or discussions mention this CVE ID yet.'}</p></Card>
  }
  const counts = { feeds: feedItems.length, news: news.length, discussions: disc.length, bluesky: bsky.length, mastodon: masto.length }
  const active = tab && counts[tab] ? tab : feedItems.length ? 'feeds' : news.length ? 'news' : disc.length ? 'discussions' : bsky.length ? 'bluesky' : 'mastodon'
  const btn = (on: boolean) => `rounded-md px-3 py-1 text-sm ${on ? 'bg-zinc-800 text-white' : 'text-zinc-400 hover:text-zinc-200'}`
  return (
    <Card
      title="News & research"
      actions={
        <div className="flex flex-wrap rounded-lg border border-zinc-800 p-0.5">
          <button className={btn(active === 'feeds')} onClick={() => setTab('feeds')} disabled={!feedItems.length}>Security feeds ({feedItems.length})</button>
          <button className={btn(active === 'news')} onClick={() => setTab('news')} disabled={!news.length}>Google News ({news.length})</button>
          <button className={btn(active === 'discussions')} onClick={() => setTab('discussions')} disabled={!disc.length}>Hacker News ({disc.length})</button>
          <button className={btn(active === 'bluesky')} onClick={() => setTab('bluesky')} disabled={!bsky.length} title={bskyOff ? 'Set BLUESKY_HANDLE and BLUESKY_APP_PASSWORD in .env' : undefined}>Bluesky ({bskyOff ? 'off' : bsky.length})</button>
          <button className={btn(active === 'mastodon')} onClick={() => setTab('mastodon')} disabled={!masto.length}>Mastodon ({masto.length})</button>
        </div>
      }
    >
      {active === 'feeds' ? <FeedArticleList items={feedItems} current={id} /> : active === 'news' ? <NewsList items={news} /> : active === 'bluesky' ? <DiscussionList items={bsky} social /> : active === 'mastodon' ? <DiscussionList items={masto} social /> : <DiscussionList items={disc} />}
      <p className="mt-3 text-xs text-zinc-500">
        {active === 'feeds'
          ? 'Vendor PSIRT, CISA and CERT/CC, research blogs, and security news that Pahredar reads hourly.'
          : active === 'news'
            ? 'Google News results for the exact CVE ID, refreshed daily.'
            : active === 'bluesky'
              ? 'Bluesky posts mentioning the CVE ID, most engaged first (likes + reposts), refreshed daily.'
              : active === 'mastodon'
                ? 'Mastodon posts tagged with the CVE ID (#CVE202346604 or #CVE_2023_46604) across the fediverse, as seen from mastodon.social and fosstodon.org, most engaged first (favourites + boosts), refreshed daily.'
              : 'Hacker News stories mentioning the CVE ID, by points, refreshed daily.'}
      </p>
    </Card>
  )
}

function NewsList({ items }: { items: NewsItem[] }) {
  const [all, setAll] = useState(false)
  const shown = all ? items : items.slice(0, 10)
  return (
    <>
      <ul className="divide-y divide-zinc-800">
        {shown.map((n) => (
          <li key={n.url} className="flex items-baseline gap-3 py-2 text-sm">
            <span className="w-24 shrink-0 text-xs text-zinc-500 tabular-nums">{n.published ? fmtDate(n.published) : '—'}</span>
            <Ext href={n.url} className="min-w-0 flex-1">{n.title}</Ext>
            {n.source && <span className="shrink-0 text-xs text-zinc-400">{n.source}</span>}
          </li>
        ))}
      </ul>
      {items.length > shown.length && <button className={`mt-2 text-sm ${link}`} onClick={() => setAll(true)}>Show all {items.length}</button>}
    </>
  )
}

// social: Bluesky posts, whose "title" is the post text.
function DiscussionList({ items, social = false }: { items: NewsItem[]; social?: boolean }) {
  return (
    <ul className="divide-y divide-zinc-800">
      {items.map((n) => (
        <li key={n.discussion_url ?? n.url} className="flex items-baseline gap-3 py-2 text-sm">
          <span className="w-14 shrink-0 text-right text-xs text-zinc-400 tabular-nums">{social ? '♥' : '▲'} {fmtNumber(n.points ?? 0)}</span>
          <div className="min-w-0 flex-1">
            {social ? <p className="break-words whitespace-pre-line text-zinc-200">{n.title}</p> : <Ext href={n.url}>{n.title}</Ext>}
            <div className="text-xs text-zinc-500">{n.source} · {n.published ? fmtDate(n.published) : ''}</div>
          </div>
          {n.discussion_url && (
            <Ext href={n.discussion_url} className="inline-flex shrink-0 items-center gap-1 text-xs"><MessageSquare className="h-3 w-3" /> {fmtNumber(n.comments ?? 0)}</Ext>
          )}
        </li>
      ))}
    </ul>
  )
}

// --- Related vulnerabilities -------------------------------------------------

export function RelatedCard({ id }: { id: string }) {
  const q = useQuery({ queryKey: ['related', id], queryFn: () => api.getRelated(id) })
  if (q.isPending) return <Card title="Related vulnerabilities"><Spinner /></Card>
  if (q.isError) return <Card title="Related vulnerabilities"><p className="text-sm text-zinc-500">Related CVEs are unavailable right now.</p></Card>
  const groups = q.data.groups
  return (
    <Card title="Related vulnerabilities">
      {groups.length === 0 ? (
        <p className="text-sm text-zinc-500">No other CVE shares this CVE's advisory or patch, or was published for the same product within 30 days.</p>
      ) : (
        <div className="space-y-5">
          {groups.map((g, i) => <Group key={i} g={g} />)}
        </div>
      )}
    </Card>
  )
}

function Group({ g }: { g: RelatedGroup }) {
  const more = g.total - g.items.length
  return (
    <div>
      <div className="mb-1.5 flex flex-wrap items-baseline justify-between gap-2">
        <div className="text-sm">
          {g.kind === 'advisory' ? (
            <>
              <span className="text-zinc-400">Fixed by the same advisory · </span>
              <Ext href={g.url!} className="break-all">{g.label}</Ext>
            </>
          ) : (
            <span className="text-zinc-400">Same product, published within 30 days · <span className="text-zinc-200">{g.label}</span></span>
          )}
        </div>
        <span className="text-xs text-zinc-500">
          {fmtNumber(g.total)} CVE{g.total === 1 ? '' : 's'}
          {g.kind === 'product' && g.vendor && g.product && <> · <Link className={link} to={productPath(g.vendor, g.product)}>all for this product</Link></>}
        </span>
      </div>
      <ul className="divide-y divide-zinc-800 rounded-md border border-zinc-800">
        {g.items.map((x) => (
          <li key={x.id}>
            <Link to={`/cves/${x.id}`} className="flex items-center gap-3 px-3 py-1.5 text-sm hover:bg-white/[0.02]">
              <span className="font-mono text-[13px] font-semibold whitespace-nowrap text-cyan-300">{x.id}</span>
              <span className="min-w-0 flex-1 truncate text-zinc-300">{x.title ?? x.description}</span>
              {x.kev && <KevTag />}
              {x.has_exploit && <ExploitTag />}
              <span className={`w-9 text-right font-semibold tabular-nums ${severityText[x.severity]}`}>{bestScore(x)?.toFixed(1) ?? '—'}</span>
            </Link>
          </li>
        ))}
      </ul>
      {more > 0 && g.kind === 'product' && g.vendor && g.product && (
        <Link className={`mt-1 inline-block text-xs ${link}`} to={explorerLink(`vendor:"${g.vendor}" product:"${g.product}"`)}>+ {fmtNumber(more)} more in the explorer</Link>
      )}
      {more > 0 && g.kind === 'advisory' && <p className="mt-1 text-xs text-zinc-500">+ {fmtNumber(more)} more CVEs cite this advisory (most severe shown).</p>}
    </div>
  )
}
