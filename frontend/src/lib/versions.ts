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
