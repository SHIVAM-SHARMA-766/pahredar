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

// Compact one-line-per-CVE table. Long titles and vendors truncate with the
// full text in a tooltip.
export function CveTable({ items, sort }: { items: CveSummary[]; sort: SortState }) {
  if (items.length === 0) {
    return <p className="py-12 text-center text-sm text-zinc-500">No CVEs match this query.</p>
  }
  return (
    <div className="overflow-x-auto">
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
