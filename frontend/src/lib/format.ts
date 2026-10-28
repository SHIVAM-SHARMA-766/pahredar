export function fmtDate(iso: string | null | undefined): string {
  return iso ? iso.slice(0, 10) : '—'
}

export function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

export function fmtNumber(n: number): string {
  return n.toLocaleString()
}

// EPSS scores are probabilities; show them as percentages. Values are
// truncated, not rounded, so 0.99999 reads "99.99%" rather than "100.00%".
export function fmtEpss(score: number | null | undefined): string {
  if (score == null) return '—'
  return `${(Math.floor(score * 10000) / 100).toFixed(2)}%`
}

export function fmtPercentile(p: number | null | undefined): string {
  return p == null ? '—' : `${(Math.floor(p * 1000) / 10).toFixed(1)}th pct`
}

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return 'never'
  const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000)
  if (seconds < 60) return 'just now'
  const units: [number, string][] = [
    [60, 'minute'],
    [3600, 'hour'],
    [86400, 'day'],
  ]
  let [div, unit] = units[0]
  for (const u of units) if (seconds >= u[0]) [div, unit] = u
  const n = Math.floor(seconds / div)
  return `${n} ${unit}${n === 1 ? '' : 's'} ago`
}

export function duration(startIso: string, endIso: string | null): string {
  const end = endIso ? new Date(endIso).getTime() : Date.now()
  const s = Math.max(0, Math.round((end - new Date(startIso).getTime()) / 1000))
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
}

export function vendorPath(vendor: string): string {
  return `/vendors/${encodeURIComponent(vendor)}`
}

export function productPath(vendor: string, product: string): string {
  return `${vendorPath(vendor)}/products/${encodeURIComponent(product)}`
}
