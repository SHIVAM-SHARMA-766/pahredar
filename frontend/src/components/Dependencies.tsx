import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Boxes, Loader2, ScanSearch, Upload } from 'lucide-react'
import { useMemo, useRef } from 'react'
import { api } from '../api/client'
import type { EasmRecord } from '../api/types'
import { Card, ErrorBox, Spinner, Tag } from '../components/ui'

// manifestKind maps an uploaded filename to the backend parser kind, or null if
// it is not a supported manifest.
function manifestKind(filename: string): string | null {
  const f = filename.toLowerCase()
  if (f.endsWith('package-lock.json')) return 'package-lock'
  if (f.endsWith('go.mod')) return 'go-mod'
  if (f.endsWith('package.json')) return 'package-json'
  return null
}

// Dependencies shows an asset's software inventory (ingested from its manifests)
// and lets an operator run an OSV analysis — vulnerable versions become findings
// on the asset's incident. See docs/scanner-easm.md (S5).

type Dep = { ecosystem: string; name: string; version: string }

function toDep(r: EasmRecord): Dep {
  const d = r.data as Record<string, string>
  return { ecosystem: d.ecosystem ?? '', name: d.name ?? r.key, version: d.version ?? '' }
}

export function Dependencies({ assetId, canEdit }: { assetId: number; canEdit: boolean }) {
  const qc = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)
  const records = useQuery({ queryKey: ['easm-deps', assetId], queryFn: () => api.easmRecords(assetId, 'dependency') })
  const analyze = useMutation({
    mutationFn: () => api.easmAnalyzeDeps(assetId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['incidents'] })
      qc.invalidateQueries({ queryKey: ['incidents-unread'] })
    },
  })
  const upload = useMutation({
    mutationFn: async (file: File) => {
      const kind = manifestKind(file.name)
      if (!kind) throw new Error('Upload a package-lock.json, package.json, or go.mod file.')
      return api.easmIngestManifest(assetId, kind, await file.text())
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['easm-deps', assetId] }),
  })

  const onPick = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) upload.mutate(file)
    e.target.value = '' // allow re-selecting the same file
  }

  const byEco = useMemo(() => {
    const m = new Map<string, Dep[]>()
    for (const r of records.data?.items ?? []) {
      const d = toDep(r)
      if (!m.has(d.ecosystem)) m.set(d.ecosystem, [])
      m.get(d.ecosystem)!.push(d)
    }
    for (const list of m.values()) list.sort((a, b) => a.name.localeCompare(b.name))
    return [...m.entries()].sort()
  }, [records.data])

  const total = records.data?.items.length ?? 0

  const actions = canEdit ? (
    <div className="flex gap-1.5">
      <input ref={fileRef} type="file" accept=".json,.mod,application/json" onChange={onPick} className="hidden" />
      <button onClick={() => fileRef.current?.click()} disabled={upload.isPending} title="Upload a package-lock.json, package.json, or go.mod" className="inline-flex items-center gap-1 rounded-lg border border-zinc-600/40 bg-zinc-700/30 px-2.5 py-1 text-xs text-zinc-300 hover:bg-zinc-700/50 disabled:opacity-50">
        {upload.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Upload className="h-3.5 w-3.5" />} Upload manifest
      </button>
      {total > 0 && (
        <button onClick={() => analyze.mutate()} disabled={analyze.isPending} className="inline-flex items-center gap-1 rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-2.5 py-1 text-xs text-cyan-200 hover:bg-cyan-500/20 disabled:opacity-50">
          {analyze.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ScanSearch className="h-3.5 w-3.5" />} Analyze (OSV)
        </button>
      )}
    </div>
  ) : undefined

  return (
    <Card title={`Dependencies${total ? ` (${total})` : ''}`} actions={actions}>
      {upload.isError && <ErrorBox error={upload.error} />}
      {upload.data && (
        <p className="mb-3 rounded-lg border border-zinc-800 bg-zinc-950/50 px-3 py-2 text-sm text-zinc-300">
          Ingested {upload.data.ingested} of {upload.data.parsed} parsed dependencies.{total > 0 && ' Run Analyze (OSV) to check them.'}
        </p>
      )}
      {records.isPending ? <Spinner /> : records.isError ? <ErrorBox error={records.error} /> : total === 0 ? (
        <p className="py-3 text-sm text-zinc-500">
          No dependency inventory yet. {canEdit ? 'Upload a package-lock.json, package.json, or go.mod to build the inventory, then analyze it against OSV.' : 'Ask an operator to upload a manifest.'}
        </p>
      ) : (
        <div className="space-y-3">
          {analyze.data && (
            <p className="rounded-lg border border-zinc-800 bg-zinc-950/50 px-3 py-2 text-sm text-zinc-300">
              Analyzing {analyze.data.dependencies} dependencies against OSV… vulnerable ones appear as findings in <span className="text-cyan-300">Incidents</span>.
            </p>
          )}
          {byEco.map(([eco, deps]) => (
            <div key={eco}>
              <div className="mb-1 flex items-center gap-1.5 text-[11px] tracking-wider text-zinc-500 uppercase">
                <Boxes className="h-3 w-3" /> {eco} <Tag tone="zinc">{deps.length}</Tag>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {deps.map((d) => (
                  <span key={d.name} className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-xs text-zinc-300" title={`${d.name}@${d.version}`}>
                    {d.name.length > 28 ? '…' + d.name.slice(-26) : d.name}<span className="text-zinc-500">@{d.version}</span>
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}
