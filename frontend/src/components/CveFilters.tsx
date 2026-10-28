import { useEffect, useState, type ReactNode } from 'react'
import type { Severity } from '../api/types'
import { SEVERITIES, severityLabel } from '../lib/severity'

// Filter state is the URL query string, using the API's parameter names, so
// every filtered view is linkable and maps 1:1 onto GET /api/v1/cves.
interface Props {
  params: URLSearchParams
  onChange: (next: URLSearchParams) => void
  // Parameters fixed by the page (e.g. vendor/product on a product page).
  locked?: string[]
}

const input = 'w-full rounded border border-zinc-300 bg-white px-2 py-1 text-sm dark:border-zinc-700 dark:bg-zinc-950'

export function CveFilters({ params, onChange, locked = [] }: Props) {
  const set = (key: string, value: string) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    next.delete('page')
    onChange(next)
  }

  const severities = new Set((params.get('severity') ?? '').split(',').filter(Boolean))
  const toggleSeverity = (s: Severity) => {
    const next = new Set(severities)
    if (next.has(s)) next.delete(s)
    else next.add(s)
    set('severity', SEVERITIES.filter((x) => next.has(x)).join(','))
  }

  return (
    <div className="space-y-4 text-sm">
      <Field label="Keywords">
        <TextInput value={params.get('q') ?? ''} onCommit={(v) => set('q', v)} placeholder="e.g. remote code execution" />
      </Field>

      <Field label="Severity">
        <div className="grid grid-cols-2 gap-1">
          {SEVERITIES.map((s) => (
            <label key={s} className="flex items-center gap-1.5">
              <input type="checkbox" checked={severities.has(s)} onChange={() => toggleSeverity(s)} />
              {severityLabel(s)}
            </label>
          ))}
        </div>
      </Field>

      <Field label="Signals">
        <TriState label="In CISA KEV" value={params.get('kev')} onChange={(v) => set('kev', v)} />
        <TriState label="Public exploit" value={params.get('exploit')} onChange={(v) => set('exploit', v)} />
      </Field>

      <Field label="Minimum EPSS (%)">
        <TextInput
          value={params.get('epss_min') ? String(+params.get('epss_min')! * 100) : ''}
          onCommit={(v) => set('epss_min', v && !isNaN(+v) ? String(Math.min(Math.max(+v, 0), 100) / 100) : '')}
          placeholder="e.g. 10"
        />
      </Field>

      {!locked.includes('vendor') && (
        <Field label="Vendor">
          <TextInput value={params.get('vendor') ?? ''} onCommit={(v) => set('vendor', v.toLowerCase())} placeholder="exact, e.g. microsoft" />
        </Field>
      )}
      {!locked.includes('product') && (
        <Field label="Product">
          <TextInput value={params.get('product') ?? ''} onCommit={(v) => set('product', v.toLowerCase())} placeholder="exact" />
        </Field>
      )}

      <Field label="CWE">
        <TextInput value={params.get('cwe') ?? ''} onCommit={(v) => set('cwe', v.toUpperCase())} placeholder="e.g. CWE-79" />
      </Field>

      <Field label="Published">
        <label className="flex items-center gap-2">
          <span className="w-8 text-xs text-zinc-500">From</span>
          <input type="date" className={input} value={params.get('published_from') ?? ''} onChange={(e) => set('published_from', e.target.value)} />
        </label>
        <label className="flex items-center gap-2">
          <span className="w-8 text-xs text-zinc-500">To</span>
          <input type="date" className={input} value={params.get('published_to') ?? ''} onChange={(e) => set('published_to', e.target.value)} />
        </label>
      </Field>

      <Field label="State">
        <select className={input} value={params.get('state') ?? ''} onChange={(e) => set('state', e.target.value)}>
          <option value="">Any</option>
          <option value="PUBLISHED">Published</option>
          <option value="REJECTED">Rejected</option>
        </select>
      </Field>
    </div>
  )
}

export function SortControl({ params, onChange }: Omit<Props, 'locked'>) {
  const set = (key: string, value: string) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    next.delete('page')
    onChange(next)
  }
  return (
    <div className="flex items-center gap-2 text-sm">
      <span className="text-zinc-500">Sort</span>
      <select className="rounded border border-zinc-300 bg-white px-2 py-1 dark:border-zinc-700 dark:bg-zinc-950" value={params.get('sort') ?? ''} onChange={(e) => set('sort', e.target.value)}>
        <option value="">Default</option>
        <option value="published">Published</option>
        <option value="updated">Updated</option>
        <option value="cvss">CVSS</option>
        <option value="epss">EPSS</option>
        <option value="relevance">Relevance</option>
      </select>
      <select className="rounded border border-zinc-300 bg-white px-2 py-1 dark:border-zinc-700 dark:bg-zinc-950" value={params.get('order') ?? 'desc'} onChange={(e) => set('order', e.target.value === 'desc' ? '' : e.target.value)}>
        <option value="desc">Descending</option>
        <option value="asc">Ascending</option>
      </select>
    </div>
  )
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <div className="mb-1 text-xs font-semibold tracking-wide text-zinc-500 uppercase">{label}</div>
      <div className="space-y-1">{children}</div>
    </div>
  )
}

// Commits on Enter or blur rather than on every keystroke.
function TextInput({ value, onCommit, placeholder }: { value: string; onCommit: (v: string) => void; placeholder?: string }) {
  const [draft, setDraft] = useState(value)
  useEffect(() => setDraft(value), [value])
  const commit = () => draft.trim() !== value && onCommit(draft.trim())
  return (
    <input
      className={input}
      value={draft}
      placeholder={placeholder}
      onChange={(e) => setDraft(e.target.value)}
      onBlur={commit}
      onKeyDown={(e) => e.key === 'Enter' && commit()}
    />
  )
}

function TriState({ label, value, onChange }: { label: string; value: string | null; onChange: (v: string) => void }) {
  return (
    <label className="flex items-center justify-between gap-2">
      <span>{label}</span>
      <select className="rounded border border-zinc-300 bg-white px-1 py-0.5 dark:border-zinc-700 dark:bg-zinc-950" value={value ?? ''} onChange={(e) => onChange(e.target.value)}>
        <option value="">Any</option>
        <option value="true">Yes</option>
        <option value="false">No</option>
      </select>
    </label>
  )
}
