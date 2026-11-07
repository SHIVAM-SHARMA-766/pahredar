import { useMutation, useQuery } from '@tanstack/react-query'
import { Loader2, Radar } from 'lucide-react'
import { Link, useNavigate, useParams } from 'react-router'
import { api } from '../api/client'
import type { ScanTech } from '../api/types'
import { Gauge } from '../components/Gauge'
import { Breadcrumbs, Card, ErrorBox, Spinner, Tag } from '../components/ui'
import { useAuth } from '../lib/auth'
import { relativeTime } from '../lib/format'
import { useOrigin } from '../lib/origin'

// Asset detail: the asset-centric view — its latest scan's posture, the tech
// fingerprinted on it, and the CVEs matched to that tech. "What's wrong with
// this asset."

const SCANNABLE = new Set(['domain', 'url', 'ip'])
const gaugeStroke: Record<string, string> = { A: '#34d399', B: '#22d3ee', C: '#fbbf24', D: '#fb923c', F: '#f87171' }
const gradeRisk: Record<string, string> = { A: 'Low risk', B: 'Low risk', C: 'Medium risk', D: 'High risk', F: 'High risk' }

export function AssetDetailPage() {
  const { id = '' } = useParams()
  const assetId = Number(id)
  const navigate = useNavigate()
  const canEdit = useAuth().can('operator')
  const asset = useQuery({ queryKey: ['asset', assetId], queryFn: () => api.getAsset(assetId) })
  useOrigin(asset.data?.value)
  const history = useQuery({ queryKey: ['asset-scans', assetId], queryFn: () => api.assetScans(assetId) })
  const cves = useQuery({ queryKey: ['asset-cves', assetId], queryFn: () => api.assetCves(assetId) })
  const lastScan = asset.data?.last_scan_id
  const report = useQuery({ queryKey: ['scan-report', lastScan], queryFn: () => api.getScan(lastScan as number), enabled: !!lastScan })

  const scan = useMutation({
    mutationFn: () => api.scanAsset(assetId),
    onSuccess: (r) => navigate(`/scan?job=${r.job_id}&target=${encodeURIComponent(asset.data!.value)}`),
  })

  if (asset.isPending) return <Spinner />
  if (asset.isError) return <ErrorBox error={asset.error} />
  const a = asset.data
  const rep = report.data
  const findings = (rep?.findings ?? []).filter((f) => f.severity !== 'good')
  const counts = findings.reduce<Record<string, number>>((m, f) => ((m[f.severity] = (m[f.severity] ?? 0) + 1), m), {})
  const kevTotal = (rep?.tech ?? []).reduce((n, t) => n + (t.cves?.kev ?? 0), 0)

  return (
    <div className="space-y-6">
      <div>
        <Breadcrumbs items={[{ label: 'Assets', to: '/inventory' }, { label: a.value }]} />
        <div className="mt-2 flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="font-mono text-2xl font-bold break-all text-white">{a.value}</h1>
              <Tag tone="zinc">{a.kind}</Tag>
              {a.tags.map((t) => <Tag key={t} tone="violet">{t}</Tag>)}
            </div>
            <p className="mt-1 text-sm text-zinc-500">
              {a.label && <span className="text-zinc-400">{a.label} · </span>}
              {a.last_scanned_at ? <>scanned {relativeTime(a.last_scanned_at)}</> : 'never scanned'}
            </p>
          </div>
          {SCANNABLE.has(a.kind) && canEdit && (
            <button onClick={() => scan.mutate()} disabled={scan.isPending} className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-4 py-2 text-sm text-cyan-200 hover:bg-cyan-500/20 disabled:opacity-50">
              {scan.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />} Scan now
            </button>
          )}
        </div>
      </div>

      {!lastScan ? (
        <Card><p className="py-8 text-center text-sm text-zinc-500">{SCANNABLE.has(a.kind) ? 'Not scanned yet. Run a scan to see this asset’s posture and matched CVEs.' : 'This asset kind is not scannable.'}</p></Card>
      ) : (
        <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
          <div className="min-w-0 space-y-6">
            <Card title="Technology & matched CVEs" actions={kevTotal > 0 ? <Tag tone="red">{kevTotal} KEV</Tag> : undefined}>
              {report.isPending ? <Spinner /> : (rep?.tech?.length ?? 0) === 0 ? (
                <p className="text-sm text-zinc-500">No technology fingerprinted on the last scan.</p>
              ) : (
                <ul className="space-y-3">{rep!.tech.map((t) => <TechRow key={t.name + t.version} t={t} />)}</ul>
              )}
            </Card>
            {(cves.data?.items.length ?? 0) > 0 && (
              <Card title={`Tracked CVEs (${cves.data!.items.length})`} actions={<span className="text-xs text-zinc-500">matched from scans · alert-ready</span>}>
                <div className="flex flex-wrap gap-1.5">
                  {cves.data!.items.map((c) => (
                    <Link key={c.cve_id} to={`/cves/${c.cve_id}`} className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 font-mono text-xs hover:opacity-80 ${c.kev ? 'bg-red-500/15 text-red-300 ring-1 ring-inset ring-red-400/30' : 'bg-zinc-800 text-cyan-300'}`}>
                      {c.cve_id}{c.kev && ' ⚠'}
                    </Link>
                  ))}
                </div>
              </Card>
            )}
            <Card title={`Security issues (${findings.length})`}>
              <div className="mb-3 flex flex-wrap gap-1.5">
                {(['critical', 'high', 'medium', 'low', 'info'] as const).filter((sv) => counts[sv]).map((sv) => (
                  <span key={sv} className={`rounded px-1.5 py-0.5 text-xs font-medium ${sevTag[sv]}`}>{counts[sv]} {sv}</span>
                ))}
              </div>
              {findings.length === 0 ? <p className="text-sm text-zinc-500">No issues on the last scan.</p> : (
                <ul className="space-y-1.5 text-sm">
                  {findings.slice(0, 20).map((f, i) => (
                    <li key={i} className="flex gap-2">
                      <span className={`mt-0.5 h-2 w-2 shrink-0 rounded-full ${sevDot[f.severity] ?? 'bg-zinc-500'}`} />
                      <span className="text-zinc-300">{f.title} <span className="text-xs text-zinc-600">· {f.category}</span></span>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>
          <div className="min-w-0 space-y-6">
            {rep && (
              <Card title="Latest scan">
                <Gauge value={rep.score} max={100} display={String(rep.score)} caption="score" color={gaugeStroke[rep.grade] ?? '#f87171'} risk={`Grade ${rep.grade} · ${gradeRisk[rep.grade] ?? 'Unknown'}`} />
              </Card>
            )}
            <Card title={`Scan history (${history.data?.items.length ?? 0})`}>
              {history.isPending ? <Spinner /> : (history.data?.items.length ?? 0) === 0 ? (
                <p className="text-sm text-zinc-500">No scans recorded yet.</p>
              ) : (
                <ul className="divide-y divide-zinc-800 text-sm">
                  {history.data!.items.map((sc) => (
                    <li key={sc.id} className="flex items-center justify-between gap-2 py-2">
                      <span className="text-zinc-500">{relativeTime(sc.created_at)}</span>
                      <span className={`rounded px-1.5 py-0.5 text-xs font-semibold ${sevGrade[sc.grade] ?? 'text-zinc-300'}`}>Grade {sc.grade} · {sc.score}</span>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>
        </div>
      )}
    </div>
  )
}

function TechRow({ t }: { t: ScanTech }) {
  return (
    <li>
      <div className="flex flex-wrap items-baseline gap-2">
        <span className="font-medium text-zinc-100">{t.name}</span>
        {t.version && <span className="font-mono text-xs text-zinc-400">{t.version}</span>}
        <span className="text-xs text-zinc-600">{t.from}</span>
      </div>
      {t.cves && (
        <div className="mt-1 flex flex-wrap items-center gap-2 text-xs">
          <Link to={`/vendors/${t.cves.vendor}/products/${t.cves.product}`} className="text-cyan-300 hover:text-cyan-200">{t.cves.total} CVEs for {t.cves.product}</Link>
          {t.cves.kev > 0 && <Tag tone="red">{t.cves.kev} in KEV</Tag>}
          {t.cves.critical > 0 && <span className="text-zinc-500">{t.cves.critical} critical</span>}
          <span className="flex flex-wrap gap-1">
            {t.cves.examples.slice(0, 5).map((e) => (
              <Link key={e.id} to={`/cves/${e.id}`} className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-cyan-300 hover:bg-zinc-700">{e.id}{e.kev ? ' ⚠' : ''}</Link>
            ))}
          </span>
        </div>
      )}
    </li>
  )
}

const sevTag: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-300 ring-1 ring-inset ring-red-400/30',
  high: 'bg-orange-500/15 text-orange-300 ring-1 ring-inset ring-orange-400/30',
  medium: 'bg-amber-500/15 text-amber-200 ring-1 ring-inset ring-amber-400/30',
  low: 'bg-sky-500/10 text-sky-300 ring-1 ring-inset ring-sky-400/25',
  info: 'bg-zinc-700/40 text-zinc-300 ring-1 ring-inset ring-zinc-600/40',
}
const sevDot: Record<string, string> = { critical: 'bg-red-400', high: 'bg-orange-400', medium: 'bg-amber-400', low: 'bg-sky-400', info: 'bg-zinc-500' }
const sevGrade: Record<string, string> = { A: 'text-emerald-300', B: 'text-cyan-300', C: 'text-amber-200', D: 'text-orange-300', F: 'text-red-300' }
