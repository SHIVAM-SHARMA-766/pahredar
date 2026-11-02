import type { Affected, CnaVersion, CpeMatch } from '../api/types'

// Turns an affected product's version data into short range strings such as
// "≥ 2.0 < 2.15.0". CNA/ADP and NVD use different shapes (see types.ts).
export function describeVersions(a: Affected): string[] {
  const out =
    a.source === 'nvd'
      ? (a.versions as CpeMatch[]).map(describeCpeMatch)
      : (a.versions as CnaVersion[]).filter((v) => (v.status ?? 'affected') === 'affected').map(describeCnaVersion)
  return [...new Set(out.filter(Boolean))]
}

function describeCnaVersion(v: CnaVersion): string {
  const from = v.version && v.version !== '0' && v.version !== '*' ? v.version : ''
  if (v.lessThan) return [from && `≥ ${from}`, `< ${v.lessThan}`].filter(Boolean).join(' ')
  if (v.lessThanOrEqual) return [from && `≥ ${from}`, `≤ ${v.lessThanOrEqual}`].filter(Boolean).join(' ')
  return v.version ?? ''
}

function describeCpeMatch(m: CpeMatch): string {
  const parts = [
    m.versionStartIncluding && `≥ ${m.versionStartIncluding}`,
    m.versionStartExcluding && `> ${m.versionStartExcluding}`,
    m.versionEndIncluding && `≤ ${m.versionEndIncluding}`,
    m.versionEndExcluding && `< ${m.versionEndExcluding}`,
  ].filter(Boolean)
  if (parts.length > 0) return parts.join(' ')
  // CPE 2.3: cpe:2.3:part:vendor:product:version:update:... (escapes are rare
  // here). The update field carries pre-releases such as "beta9" or "rc1".
  const [, , , , , version, update] = m.criteria.split(':')
  if (version === undefined) return m.criteria
  if (version === '*') return 'all versions'
  if (version === '-') return 'n/a'
  return update && update !== '*' && update !== '-' ? `${version}-${update}` : version
}

// Version strings that look like a release (contain a digit, no wildcard).
const isVersion = (v?: string) => !!v && /\d/.test(v) && !v.includes('*')

// Versions in which the product is fixed. CNA/ADP: the `lessThan` bound of an
// affected range, and versions marked "unaffected" (other than the "0"
// placeholder). NVD: `versionEndExcluding`. Empty when the record names no
// fix (e.g. only "≤ x" ranges, or an end-of-life product).
export function fixedVersions(a: Affected): string[] {
  const out: string[] = []
  if (a.source === 'nvd') {
    for (const m of a.versions as CpeMatch[]) if (isVersion(m.versionEndExcluding)) out.push(m.versionEndExcluding!)
  } else {
    for (const v of a.versions as CnaVersion[]) {
      if ((v.status ?? 'affected') === 'affected' && isVersion(v.lessThan)) out.push(v.lessThan!)
      if (v.status === 'unaffected' && v.version !== '0' && isVersion(v.version)) out.push(v.version!)
    }
  }
  return [...new Set(out)]
}
