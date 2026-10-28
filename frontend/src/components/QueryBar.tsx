import { BookOpen, Search, X } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { EXAMPLES, FIELDS } from '../lib/query'

// Search box for the query language in lib/query.ts. The query is applied on
// Enter (or by clicking an example), not on every keystroke.
export function QueryBar({ value, onSubmit, errors }: { value: string; onSubmit: (q: string) => void; errors: string[] }) {
  const [draft, setDraft] = useState(value)
  const [help, setHelp] = useState(false)
  useEffect(() => setDraft(value), [value])

  function submit(e: FormEvent) {
    e.preventDefault()
    onSubmit(draft.trim())
  }

  return (
    <div className="space-y-2">
      <form onSubmit={submit} className="relative">
        <Search className="pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2 text-zinc-500" />
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="Search by CVE, vendor, product, severity, or signal — e.g. is:kev epss:>10 vendor:cisco"
          spellCheck={false}
          className="w-full rounded-lg border border-zinc-800 bg-zinc-950 py-2.5 pr-20 pl-10 font-mono text-sm text-zinc-100 placeholder:font-sans placeholder:text-zinc-500 focus:border-cyan-400/40 focus:ring-1 focus:ring-cyan-400/20 focus:outline-none"
        />
        <div className="absolute top-1/2 right-2 flex -translate-y-1/2 items-center gap-1">
          {draft && (
            <button type="button" onClick={() => { setDraft(''); onSubmit('') }} className="rounded p-1.5 text-zinc-500 hover:bg-zinc-800 hover:text-zinc-200" title="Clear query">
              <X className="h-4 w-4" />
            </button>
          )}
          <button type="button" onClick={() => setHelp((h) => !h)} className={`rounded p-1.5 hover:bg-zinc-800 ${help ? 'text-cyan-300' : 'text-zinc-500 hover:text-zinc-200'}`} title="Query syntax">
            <BookOpen className="h-4 w-4" />
          </button>
        </div>
      </form>

      <div className="flex flex-wrap gap-1.5">
        {EXAMPLES.map((ex) => (
          <button
            key={ex}
            onClick={() => onSubmit(ex)}
            className={`rounded-md border px-2 py-0.5 font-mono text-xs transition-colors ${value === ex ? 'border-cyan-400/40 bg-cyan-500/10 text-cyan-200' : 'border-zinc-800 bg-zinc-900 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200'}`}
          >
            {ex}
          </button>
        ))}
      </div>

      {errors.length > 0 && (
        <ul className="space-y-0.5 text-xs text-amber-300">
          {errors.map((e) => <li key={e}>⚠ {e} — ignored</li>)}
        </ul>
      )}

      {help && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
          <div className="mb-2 text-xs font-semibold tracking-wider text-zinc-500 uppercase">Query syntax</div>
          <p className="mb-3 text-sm text-zinc-400">
            Combine free text with field terms; all terms must match. Free text searches titles, descriptions, vendors and products. A CVE ID on its own opens that exact CVE.
          </p>
          <dl className="grid gap-x-6 gap-y-1.5 text-sm sm:grid-cols-[auto_1fr]">
            {FIELDS.map((f) => (
              <div key={f.syntax} className="contents">
                <dt><code className="rounded bg-zinc-950 px-1.5 py-0.5 font-mono text-xs text-cyan-300">{f.syntax}</code></dt>
                <dd className="text-zinc-400">{f.meaning}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </div>
  )
}
