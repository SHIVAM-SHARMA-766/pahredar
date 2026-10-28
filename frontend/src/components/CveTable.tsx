import { Link } from 'react-router'
import type { CveSummary } from '../api/types'
import { fmtDate, fmtEpss } from '../lib/format'
import { bestScore } from '../lib/severity'
import { ExploitTag, KevTag, SeverityBadge } from './ui'

export function CveTable({ items }: { items: CveSummary[] }) {
  if (items.length === 0) {
    return <p className="py-8 text-center text-sm text-zinc-500">No CVEs match these filters.</p>
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-zinc-200 text-left text-xs text-zinc-500 uppercase dark:border-zinc-800">
            <th className="py-2 pr-3 font-medium">CVE</th>
            <th className="py-2 pr-3 font-medium">Severity</th>
            <th className="py-2 pr-3 text-right font-medium">EPSS</th>
            <th className="py-2 pr-3 font-medium">Signals</th>
            <th className="py-2 pr-3 font-medium">Summary</th>
            <th className="py-2 font-medium whitespace-nowrap">Published</th>
          </tr>
        </thead>
        <tbody>
          {items.map((c) => (
            <tr key={c.id} className="border-b border-zinc-100 align-top hover:bg-zinc-50 dark:border-zinc-800/60 dark:hover:bg-zinc-900">
              <td className="py-2 pr-3 font-mono whitespace-nowrap">
                <Link to={`/cves/${c.id}`} className="text-blue-700 hover:underline dark:text-blue-400">{c.id}</Link>
              </td>
              <td className="py-2 pr-3">
                {c.state === 'REJECTED' ? <span className="text-xs text-zinc-500">Rejected</span> : <SeverityBadge severity={c.severity} score={bestScore(c)} />}
              </td>
              <td className="py-2 pr-3 text-right font-mono tabular-nums whitespace-nowrap" title={c.epss_percentile != null ? `${(c.epss_percentile * 100).toFixed(1)}th percentile` : undefined}>
                {fmtEpss(c.epss_score)}
              </td>
              <td className="py-2 pr-3">
                <div className="flex gap-1">
                  {c.kev && <KevTag />}
                  {c.has_exploit && <ExploitTag />}
                </div>
              </td>
              <td className="max-w-xl py-2 pr-3">
                {c.title && <div className="font-medium">{c.title}</div>}
                <div className="line-clamp-2 text-zinc-600 dark:text-zinc-400">{c.description}</div>
              </td>
              <td className="py-2 whitespace-nowrap text-zinc-500">{fmtDate(c.date_published)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
