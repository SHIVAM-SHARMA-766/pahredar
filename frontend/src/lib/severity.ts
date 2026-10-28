import type { Severity } from '../api/types'

export const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN']

// Badge styles per severity: tinted, low-saturation, always with a text label.
// Full class strings so Tailwind can see them.
export const severityBadge: Record<Severity, string> = {
  CRITICAL: 'bg-red-500/10 text-red-300 ring-red-400/25',
  HIGH: 'bg-orange-500/10 text-orange-300 ring-orange-400/25',
  MEDIUM: 'bg-amber-500/10 text-amber-200 ring-amber-400/25',
  LOW: 'bg-sky-500/10 text-sky-300 ring-sky-400/25',
  NONE: 'bg-zinc-500/10 text-zinc-400 ring-zinc-500/25',
  UNKNOWN: 'bg-zinc-500/10 text-zinc-400 ring-zinc-500/25',
}

// Text colour for a bare score, matching the badge hue.
export const severityText: Record<Severity, string> = {
  CRITICAL: 'text-red-300',
  HIGH: 'text-orange-300',
  MEDIUM: 'text-amber-200',
  LOW: 'text-sky-300',
  NONE: 'text-zinc-400',
  UNKNOWN: 'text-zinc-500',
}

// Chart fills: CSS variables from index.css (an ordinal one-hue ramp that
// is validated for the dark surface). Badges use conventional hues because
// they always carry a text label.
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
