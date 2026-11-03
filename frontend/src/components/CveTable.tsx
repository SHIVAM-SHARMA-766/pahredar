import { ArrowDown, ArrowUp } from 'lucide-react'
import { Link } from 'react-router'
import type { CveSummary } from '../api/types'
import { fmtDate, fmtEpss } from '../lib/format'
import { bestScore, severityText } from '../lib/severity'
import { ExploitTag, RansomwareTag, Tag } from './ui'

// Columns the API can sort by, keyed by the API's sort name.
export type SortKey = 'published' | 'kev_added' | 'epss' | 'cvss'

export interface SortState {
  sort: string
  desc: boolean
  onSort: (key: SortKey) => void
}

const muted = <span className="text-zinc-600">n/a</span>

const ssvcTone: Record<string, 'red' | 'amber' | 'zinc'> = { active: 'red', poc: 'amber', none: 'zinc' }

const SORTS: [SortKey, string][] = [['published', 'Published'], ['kev_added', 'KEV listed'], ['epss', 'EPSS'], ['cvss', 'CVSS']]

// Compact one-line-per-CVE table. Long titles and vendors truncate with the
// full text in a tooltip. Below the md breakpoint each CVE is a card
// instead, with a sort picker standing in for the column headers.
export function CveTable({ items, sort }: { items: CveSummary[]; sort: SortState }) {
  if (items.length === 0) {
    return <p className="py-12 text-center text-sm text-zinc-500">No CVEs match this query.</p>
  }
  return (
    <>
      <CveCards items={items} sort={sort} />
      <CveRows items={items} sort={sort} />
    </>
  )
}

function CveCards({ items, sort }: { items: CveSummary[]; sort: SortState }) {
  const current = SORTS.find(([k]) => k === sort.sort)?.[0] ?? 'published'
  const Arrow = sort.desc ? ArrowDown : ArrowUp
  return (
    <div className="md:hidden">
      <div className="mb-1 flex items-center gap-2 text-sm text-zinc-400">
        <label htmlFor="cve-sort">Sort</label>
        <select
          id="cve-sort"
          value={current}
          onChange={(e) => sort.onSort(e.target.value as SortKey)}
          className="rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1 text-sm text-zinc-200"
        >
          {SORTS.map(([k, label]) => <option key={k} value={k}>{label}</option>)}
        </select>
        <button onClick={() => sort.onSort(current)} className="rounded-md border border-zinc-800 p-1.5 text-zinc-300" aria-label={sort.desc ? 'Descending; switch to ascending' : 'Ascending; switch to descending'}>
          <Arrow className="h-4 w-4" />
        </button>
      </div>
      <ul className="divide-y divide-zinc-800/70">
        {items.map((c) => {
          const score = bestScore(c)
          const title = c.state === 'REJECTED' ? `Rejected · ${c.description ?? ''}` : c.title ?? c.description
          return (
            <li key={c.id}>
              <Link to={`/cves/${c.id}`} className="block py-3 active:bg-white/[0.03]">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="font-mono text-[13px] font-semibold text-cyan-300">{c.id}</span>
                  {score != null && <span className={`text-sm font-semibold tabular-nums ${severityText[c.severity]}`}>{score.toFixed(1)}</span>}
                  {c.kev && <Tag tone="red">KEV</Tag>}
                  {c.ransomware && <RansomwareTag />}
                  {c.has_exploit && <ExploitTag />}
                </div>
                <p className={`mt-1 line-clamp-2 text-sm ${c.title ? 'text-zinc-200' : 'text-zinc-400'}`}>{title ?? <span className="text-zinc-600 italic">no title filed</span>}</p>
                <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-zinc-500">
                  {c.vendor && <span className="max-w-[12rem] truncate text-zinc-400">{c.vendor}</span>}
                  <span>{fmtDate(c.date_published)}</span>
                  {c.epss_score != null && <span>EPSS {fmtEpss(c.epss_score)}</span>}
                  {c.ssvc_exploitation && <Tag tone={ssvcTone[c.ssvc_exploitation] ?? 'zinc'}>SSVC {c.ssvc_exploitation}</Tag>}
                </div>
              </Link>
            </li>
          )
        })}
      </ul>
    </div>
  )
}

function CveRows({ items, sort }: { items: CveSummary[]; sort: SortState }) {
  return (
    <div className="hidden overflow-x-auto md:block">
      <table className="w-full min-w-[1000px] table-fixed text-sm">
        <colgroup>
          <col className="w-36" />
          <col />
          <col className="w-36" />
          <col className="w-[5.5rem]" />
          <col className="w-[6.5rem]" />
          <col className="w-[6.5rem]" />
          <col className="w-[4.5rem]" />
          <col className="w-14" />
          <col className="w-40" />
        </colgroup>
        <thead>
          <tr className="border-b border-zinc-800 text-left text-[11px] font-semibold tracking-wider text-zinc-500 uppercase">
            <th className="py-2.5 pr-3">CVE</th>
            <th className="py-2.5 pr-3">Title</th>
            <th className="py-2.5 pr-3">Vendor</th>
            <th className="py-2.5 pr-3">CISA SSVC</th>
            <SortHeader label="KEV listed" k="kev_added" sort={sort} />
            <SortHeader label="Published" k="published" sort={sort} />
            <SortHeader label="EPSS" k="epss" sort={sort} align="right" />
            <SortHeader label="CVSS" k="cvss" sort={sort} align="right" />
            <th className="py-2.5 pl-4">Signals</th>
          </tr>
        </thead>
        <tbody>
          {items.map((c) => {
            const score = bestScore(c)
            const title = c.title ?? c.description
            return (
              <tr key={c.id} className="border-b border-zinc-800/60 hover:bg-white/[0.02]">
                <td className="py-2 pr-3 whitespace-nowrap">
                  <Link to={`/cves/${c.id}`} className="font-mono text-[13px] font-semibold text-cyan-300 hover:text-cyan-200">{c.id}</Link>
                </td>
                <td className="truncate py-2 pr-3" title={title ?? undefined}>
                  {c.state === 'REJECTED' ? (
                    <span className="text-zinc-500">Rejected · {c.description}</span>
                  ) : title ? (
                    <span className={c.title ? 'text-zinc-200' : 'text-zinc-400'}>{title}</span>
                  ) : (
                    <span className="text-zinc-600 italic">no title filed</span>
                  )}
                </td>
                <td className="truncate py-2 pr-3 text-zinc-300" title={c.vendor ?? undefined}>{c.vendor ?? muted}</td>
                <td className="py-2 pr-3">
                  {c.ssvc_exploitation ? <Tag tone={ssvcTone[c.ssvc_exploitation] ?? 'zinc'}>{c.ssvc_exploitation}</Tag> : muted}
                </td>
                <td className="py-2 pr-3 tabular-nums text-zinc-300">{c.kev_date_added ? fmtDate(c.kev_date_added) : muted}</td>
                <td className="py-2 pr-3 tabular-nums text-zinc-300">{fmtDate(c.date_published)}</td>
                <td className="py-2 pr-3 text-right tabular-nums text-zinc-300" title={c.epss_percentile != null ? `${(c.epss_percentile * 100).toFixed(1)}th percentile` : undefined}>
                  {c.epss_score != null ? fmtEpss(c.epss_score) : muted}
                </td>
                <td className={`py-2 pr-1 text-right font-semibold tabular-nums ${score != null ? severityText[c.severity] : ''}`} title={c.severity}>
                  {score != null ? score.toFixed(1) : muted}
                </td>
                <td className="py-2 pl-4">
                  <div className="flex gap-1">
                    {c.ransomware && <RansomwareTag />}
                    {c.has_exploit && <ExploitTag />}
                    {!c.ransomware && !c.has_exploit && <span className="text-zinc-600">none yet</span>}
                  </div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function SortHeader({ label, k, sort, align }: { label: string; k: SortKey; sort: SortState; align?: 'right' }) {
  const active = sort.sort === k
  const Arrow = sort.desc ? ArrowDown : ArrowUp
  return (
    <th className={`py-2.5 pr-3 ${align === 'right' ? 'text-right' : ''}`} aria-sort={active ? (sort.desc ? 'descending' : 'ascending') : undefined}>
      <button
        onClick={() => sort.onSort(k)}
        className={`inline-flex items-center gap-1 uppercase hover:text-zinc-200 ${active ? 'text-cyan-300' : ''}`}
        title={`Sort by ${label.toLowerCase()}`}
      >
        {label}
        {active && <Arrow className="h-3 w-3" />}
      </button>
    </th>
  )
}
