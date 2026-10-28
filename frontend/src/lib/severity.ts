import type { Severity } from '../api/types'

export const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN']

// Badge styles per severity. Full class strings so Tailwind can see them.
export const severityBadge: Record<Severity, string> = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH: 'bg-orange-500 text-white',
  MEDIUM: 'bg-amber-400 text-amber-950',
  LOW: 'bg-sky-500 text-white',
  NONE: 'bg-zinc-300 text-zinc-800 dark:bg-zinc-600 dark:text-zinc-100',
  UNKNOWN: 'bg-zinc-200 text-zinc-600 dark:bg-zinc-700 dark:text-zinc-300',
}

// Chart fills: CSS variables from index.css (an ordinal one-hue ramp that
// changes with the colour scheme). Badges keep the conventional hues above
// because they always carry a text label.
export const severityFill: Record<Severity, string> = {
  CRITICAL: 'var(--sev-critical)',
  HIGH: 'var(--sev-high)',
  MEDIUM: 'var(--sev-medium)',
  LOW: 'var(--sev-low)',
  NONE: 'var(--sev-other)',
  UNKNOWN: 'var(--sev-other)',
}

// Severity series drawn in charts, most severe first, plus the unscored rest.
export const chartSeries = [
  { key: 'critical', label: 'Critical', fill: 'var(--sev-critical)' },
  { key: 'high', label: 'High', fill: 'var(--sev-high)' },
  { key: 'medium', label: 'Medium', fill: 'var(--sev-medium)' },
  { key: 'low', label: 'Low', fill: 'var(--sev-low)' },
  { key: 'other', label: 'Unscored', fill: 'var(--sev-other)' },
] as const

export function severityLabel(s: Severity): string {
  return s.charAt(0) + s.slice(1).toLowerCase()
}

// Best effective score for a summary row: v4, then v3, then v2.
export function bestScore(r: {
  cvss_v4_score: number | null
  cvss_v3_score: number | null
  cvss_v2_score: number | null
}): number | null {
  return r.cvss_v4_score ?? r.cvss_v3_score ?? r.cvss_v2_score
}
