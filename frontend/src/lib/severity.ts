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

// Solid fills for bars and charts, in the same order as SEVERITIES.
export const severityFill: Record<Severity, string> = {
  CRITICAL: '#dc2626',
  HIGH: '#f97316',
  MEDIUM: '#fbbf24',
  LOW: '#0ea5e9',
  NONE: '#a1a1aa',
  UNKNOWN: '#d4d4d8',
}

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
