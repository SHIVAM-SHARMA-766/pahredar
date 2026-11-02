import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import type { SyncRun } from '../api/types'
import { KindTag } from '../components/FeedCards'
import { Card, ErrorBox, PageHeader, Spinner, Tag } from '../components/ui'
import { duration, fmtDateTime, fmtNumber, relativeTime } from '../lib/format'

// Every source the backend schedules, in display order, with what it feeds.
const SOURCES: [string, string][] = [
  ['cvelist', 'CVE records (CVE Program)'],
  ['nvd', 'NVD scores and CPEs'],
  ['kev', 'CISA KEV catalog'],
  ['epss', 'EPSS scores'],
  ['exploitdb', 'Exploit-DB'],
  ['metasploit', 'Metasploit modules'],
  ['nuclei', 'Nuclei templates'],
  ['github', 'GitHub PoCs (PoC-in-GitHub)'],
  ['cwe', 'MITRE CWE names'],
  ['feeds', 'News, research, PSIRT & CISA feeds'],
  ['stats', 'Vendor/product stats'],
]

export function SyncPage() {
  const qc = useQueryClient()
  const query = useQuery({ queryKey: ['sync'], queryFn: api.syncStatus, refetchInterval: 5000 })
  const trigger = useMutation({
    mutationFn: api.triggerSync,
    onSettled: () => setTimeout(() => qc.invalidateQueries({ queryKey: ['sync'] }), 1000),
  })

  if (query.isPending) return <Spinner />
  if (query.isError) return <ErrorBox error={query.error} />
  const { sources, recent_runs, scheduler_enabled } = query.data
  const lastRun = (source: string) => recent_runs.find((r) => r.source === source)

  return (
    <div className="space-y-6">
      <PageHeader title="Data sync" subtitle="Where Pahredar's data comes from, when each source last updated, and every recent run." />
      {!scheduler_enabled && (
        <div className="rounded-lg border border-amber-400/25 bg-amber-500/10 p-3 text-sm text-amber-200">
          The scheduler is disabled (SYNC_ENABLED=false). Run syncs with <code>pahredar sync &lt;source&gt;</code>.
        </div>
      )}
      {trigger.isError && <ErrorBox error={trigger.error} />}
      <Card title="Sources">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-200 text-left text-xs text-zinc-500 uppercase dark:border-zinc-800">
                <th className="py-2 pr-3 font-medium">Source</th>
                <th className="py-2 pr-3 font-medium">Last success</th>
                <th className="py-2 pr-3 font-medium">Latest run</th>
                <th className="py-2 pr-3 font-medium">Cursor</th>
                <th className="py-2 font-medium" />
              </tr>
            </thead>
            <tbody>
              {SOURCES.map(([name, label]) => {
                const state = sources.find((s) => s.source === name)
                const run = lastRun(name)
                return (
                  <tr key={name} className="border-b border-zinc-100 dark:border-zinc-800/60">
                    <td className="py-2 pr-3">
                      <div className="font-medium">{name}</div>
                      <div className="text-xs text-zinc-500">{label}</div>
                    </td>
                    <td className="py-2 pr-3" title={fmtDateTime(state?.last_success_at)}>{relativeTime(state?.last_success_at)}</td>
                    <td className="py-2 pr-3">{run ? <RunStatus run={run} /> : <span className="text-zinc-500">—</span>}</td>
                    <td className="py-2 pr-3 font-mono text-xs text-zinc-500">{state?.cursor ?? '—'}</td>
                    <td className="py-2 text-right">
                      <button
                        disabled={!scheduler_enabled || run?.status === 'running' || (trigger.isPending && trigger.variables === name)}
                        onClick={() => trigger.mutate(name)}
                        className="rounded border border-zinc-300 px-2 py-1 text-xs hover:bg-zinc-100 disabled:opacity-40 dark:border-zinc-700 dark:hover:bg-zinc-800"
                      >
                        Run now
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </Card>

      <FeedsCard />

      <Card title="Recent runs">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-200 text-left text-xs text-zinc-500 uppercase dark:border-zinc-800">
                <th className="py-2 pr-3 font-medium">#</th>
                <th className="py-2 pr-3 font-medium">Source</th>
                <th className="py-2 pr-3 font-medium">Kind</th>
                <th className="py-2 pr-3 font-medium">Status</th>
                <th className="py-2 pr-3 font-medium">Started</th>
                <th className="py-2 pr-3 text-right font-medium">Duration</th>
                <th className="py-2 pr-3 text-right font-medium">Inserted</th>
                <th className="py-2 pr-3 text-right font-medium">Updated</th>
                <th className="py-2 text-right font-medium">Deleted</th>
              </tr>
            </thead>
            <tbody>
              {recent_runs.map((r) => (
                <tr key={r.id} className="border-b border-zinc-100 align-top dark:border-zinc-800/60">
                  <td className="py-1.5 pr-3 text-zinc-500">{r.id}</td>
                  <td className="py-1.5 pr-3">{r.source}</td>
                  <td className="py-1.5 pr-3 text-zinc-500">{r.kind}</td>
                  <td className="py-1.5 pr-3">
                    <RunStatus run={r} />
                    {r.error && <div className="mt-1 max-w-md text-xs break-words text-red-300">{r.error}</div>}
                  </td>
                  <td className="py-1.5 pr-3 whitespace-nowrap">{fmtDateTime(r.started_at)}</td>
                  <td className="py-1.5 pr-3 text-right tabular-nums">{duration(r.started_at, r.finished_at)}</td>
                  <td className="py-1.5 pr-3 text-right tabular-nums">{fmtNumber(r.inserted)}</td>
                  <td className="py-1.5 pr-3 text-right tabular-nums">{fmtNumber(r.updated)}</td>
                  <td className="py-1.5 text-right tabular-nums">{fmtNumber(r.deleted)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}

function RunStatus({ run }: { run: SyncRun }) {
  if (run.status === 'running') return <Tag tone="violet">running · {duration(run.started_at, null)}</Tag>
  if (run.status === 'failed') return <Tag tone="red">failed</Tag>
  return <Tag>success</Tag>
}

// Every configured feed and what it has contributed, so a feed that stops
// producing items is visible.
function FeedsCard() {
  const q = useQuery({ queryKey: ['feeds'], queryFn: api.feeds, refetchInterval: 60_000 })
  if (q.isPending || q.isError) return null
  return (
    <Card title={`Feeds (${q.data.items.length})`}>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-800 text-left text-[11px] font-semibold tracking-wider text-zinc-500 uppercase">
              <th className="py-2 pr-3">Feed</th>
              <th className="py-2 pr-3">Kind</th>
              <th className="py-2 pr-3 text-right">Articles</th>
              <th className="py-2 pr-3 text-right">With CVE IDs</th>
              <th className="py-2">Latest item</th>
            </tr>
          </thead>
          <tbody>
            {q.data.items.map((f) => (
              <tr key={f.key} className="border-b border-zinc-800/60">
                <td className="py-1.5 pr-3"><a href={f.url} target="_blank" rel="noreferrer" className="text-cyan-300 hover:text-cyan-200">{f.name}</a></td>
                <td className="py-1.5 pr-3"><KindTag kind={f.kind} /></td>
                <td className="py-1.5 pr-3 text-right tabular-nums">{fmtNumber(f.articles)}</td>
                <td className="py-1.5 pr-3 text-right tabular-nums text-zinc-400">{fmtNumber(f.with_cve)}</td>
                <td className={`py-1.5 ${f.articles === 0 ? 'text-amber-200' : 'text-zinc-500'}`}>{f.articles === 0 ? 'no items yet' : relativeTime(f.latest)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}
