// "Am I affected?" verdicts: scripts that compare what a machine has
// installed with the fixed versions Pahredar knows (Debian tracker, Ubuntu,
// Red Hat, MSRC), and an in-page check for library versions (OSV ranges).
//
// The scripts are meant to be run as root / admin, and package names and
// versions come from third-party data, so every value that reaches a script
// passes a strict allowlist; anything else is dropped, never quoted around.
import type { CveReports, DebianStatus, OsvAdvisory } from '../api/types'

const safePkg = /^[a-z0-9][a-z0-9.+-]*$/
const safeVersion = /^[A-Za-z0-9.+~:_-]+$/
const safeRelease = /^[a-z]+$/

// --- Version comparison and OSV ranges ----------------------------------------

const preRelease = /^(dev|alpha|a|beta|b|pre|preview|rc|c)$/i

// compareVersions orders dotted versions the way most ecosystems do: numeric
// parts numerically, and a pre-release tag (rc, beta, …) before the release
// it precedes (1.0.0-rc1 < 1.0.0). Good for PyPI, npm, Maven, Go, Cargo,
// NuGet, and RubyGems versions; not for distro versions (use dpkg / rpm).
export function compareVersions(a: string, b: string): number {
  const parts = (v: string) => v.trim().replace(/^v/i, '').split('+')[0].match(/\d+|[A-Za-z]+/g) ?? []
  const pa = parts(a)
  const pb = parts(b)
  const isNum = (t: string) => /^\d+$/.test(t)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i]
    const y = pb[i]
    if (x === undefined || y === undefined) {
      // One version continues: "1.0" vs "1.0.0" are equal, "1.0" vs
      // "1.0-rc1" makes the release newer, "1.0" vs "1.0.1" the longer one.
      const sign = x === undefined ? -1 : 1 // +1 when a is the longer one
      const rest = (x === undefined ? pb : pa).slice(i)
      if (rest.every((t) => t === '0')) return 0
      return preRelease.test(rest[0]) ? -sign : sign
    }
    if (isNum(x) && isNum(y)) {
      const d = Number(x) - Number(y)
      if (d) return Math.sign(d)
    } else if (isNum(x) !== isNum(y)) {
      // A number outranks a pre-release tag (1.0.1 > 1.0.rc1).
      return isNum(x) ? 1 : -1
    } else if (x.toLowerCase() !== y.toLowerCase()) {
      const px = preRelease.test(x)
      const py = preRelease.test(y)
      if (px !== py) return px ? -1 : 1
      return x.toLowerCase() < y.toLowerCase() ? -1 : 1
    }
  }
  return 0
}

export type Verdict = 'affected' | 'not-affected'

// osvVerdict applies OSV range events to a version: affected from an
// "introduced" version (0 when none is given) until a "fixed" version, or
// through a "last_affected" one. OSV lists several ranges' events
// together; sorted, they still alternate, which is what this relies on.
export function osvVerdict(version: string, a: OsvAdvisory['affected'][number]): Verdict {
  const events = [
    ...(a.introduced.length ? a.introduced : ['0']).map((v) => ({ v, k: 'i' as const })),
    ...a.fixed.map((v) => ({ v, k: 'f' as const })),
    ...a.last_affected.map((v) => ({ v, k: 'l' as const })),
  ].sort((x, y) => compareVersions(x.v, y.v))
  let affected = false
  for (const e of events) {
    const c = compareVersions(version, e.v)
    if (e.k === 'i' && c >= 0) affected = true
    if (e.k === 'f' && c >= 0) affected = false
    if (e.k === 'l' && c > 0) affected = false
  }
  return affected ? 'affected' : 'not-affected'
}

// Library and application packages from OSV (not distro packages, which the
// scripts below cover with the distro's own version rules).
const distroEcosystems = /^(Debian|Ubuntu|Alpine|Red Hat|AlmaLinux|Rocky Linux|SUSE|openSUSE|Mageia|Linux|Android|Chainguard|Wolfi)(:|$)/

export interface LibraryPackage {
  ecosystem: string
  pkg: string
  ranges: OsvAdvisory['affected'][number][]
  fixed: string[]
}

export function libraryPackages(osv: OsvAdvisory[] | undefined): LibraryPackage[] {
  const out = new Map<string, LibraryPackage>()
  for (const adv of osv ?? []) {
    for (const a of adv.affected) {
      if (distroEcosystems.test(a.ecosystem)) continue
      const key = a.ecosystem + ' ' + a.package
      const prev = out.get(key) ?? { ecosystem: a.ecosystem, pkg: a.package, ranges: [], fixed: [] }
      prev.ranges.push(a)
      prev.fixed = [...new Set([...prev.fixed, ...a.fixed])].sort(compareVersions)
      out.set(key, prev)
    }
  }
  return [...out.values()]
}

// --- Debian and Ubuntu ------------------------------------------------------

// What a release needs for one source package: a fixed version, "none"
// (affected, no fix yet), "-" (not affected or not shipped), or "?" (not
// yet triaged).
type Need = string

export interface DistroPackage {
  pkg: string
  // release codename → need
  debian: Map<string, Need>
  ubuntu: Map<string, Need>
}

function ubuntuNeed(status: string, description?: string): Need {
  switch (status) {
    case 'released':
      return description && safeVersion.test(description) ? description : '?'
    case 'not-affected':
    case 'DNE':
      return '-'
    case 'needed':
    case 'deferred':
    case 'pending':
    case 'ignored':
      return 'none'
    default:
      return '?'
  }
}

function debianNeed(d: DebianStatus): Need {
  if (d.status === 'resolved') return d.fixed_version === '0' ? '-' : d.fixed_version && safeVersion.test(d.fixed_version) ? d.fixed_version : '?'
  if (d.status === 'open') return 'none'
  return '?'
}

// distroPackages merges the Debian tracker and Ubuntu's statuses per source
// package. Packages that no release needs to act on are left out.
export function distroPackages(debian: DebianStatus[], ubuntu: CveReports['reports']['ubuntu']): { packages: DistroPackage[]; hidden: number } {
  const byPkg = new Map<string, DistroPackage>()
  const get = (pkg: string) => {
    let p = byPkg.get(pkg)
    if (!p) byPkg.set(pkg, (p = { pkg, debian: new Map(), ubuntu: new Map() }))
    return p
  }
  for (const d of debian) {
    if (safePkg.test(d.package) && safeRelease.test(d.release)) get(d.package).debian.set(d.release, debianNeed(d))
  }
  for (const p of ubuntu?.packages ?? []) {
    if (!safePkg.test(p.name)) continue
    for (const s of p.statuses) {
      if (s.release !== 'upstream' && safeRelease.test(s.release)) get(p.name).ubuntu.set(s.release, ubuntuNeed(s.status, s.description))
    }
  }
  const all = [...byPkg.values()]
  const relevant = all.filter((p) => [...p.debian.values(), ...p.ubuntu.values()].some((n) => n !== '-'))
  return { packages: relevant, hidden: all.length - relevant.length }
}

// debianScript prints one verdict line per source package for the machine's
// release. It compares the installed *source* version (binary packages such
// as libbrotli1 come from source brotli) with dpkg's own version rules.
export function debianScript(id: string, packages: DistroPackage[]): string {
  const cases: string[] = []
  for (const [distro, field] of [['debian', 'debian'], ['ubuntu', 'ubuntu']] as const) {
    const releases = new Set(packages.flatMap((p) => [...p[field].keys()]))
    for (const rel of [...releases].sort()) {
      const checks = packages.filter((p) => p[field].has(rel)).map((p) => `check ${p.pkg} '${p[field].get(rel)}'`)
      if (checks.length) cases.push(`  ${distro}:${rel})\n    ${checks.join('\n    ')} ;;`)
    }
  }
  return [
    '#!/bin/sh',
    `# ${id}: is this Debian / Ubuntu machine affected? (generated by Pahredar)`,
    '# Prints one line per source package: AFFECTED, PATCHED, NOT AFFECTED, UNKNOWN, or not installed.',
    '. /etc/os-release',
    'src_version() {',
    "  dpkg-query -W -f='${db:Status-Abbrev}|${source:Package}|${source:Version}\\n' 2>/dev/null |",
    "    awk -F'|' -v p=\"$1\" '$1 ~ /^ii/ && $2 == p { print $3; exit }'",
    '}',
    'check() {',
    '  v=$(src_version "$1")',
    '  if [ -z "$v" ]; then echo "not installed  $1"; return; fi',
    '  case "$2" in',
    '    -) echo "NOT AFFECTED   $1 $v ($VERSION_CODENAME is not affected)" ;;',
    '    none) echo "AFFECTED       $1 $v (no fix for $VERSION_CODENAME yet)" ;;',
    "    '?') echo \"UNKNOWN        $1 $v (not yet triaged for $VERSION_CODENAME)\" ;;",
    '    *) if dpkg --compare-versions "$v" lt "$2"; then echo "AFFECTED       $1 $v, fixed in $2"; else echo "PATCHED        $1 $v (fixed in $2)"; fi ;;',
    '  esac',
    '}',
    'case "$ID:$VERSION_CODENAME" in',
    ...cases,
    `  *) echo "No data for $ID $VERSION_CODENAME in ${id}" ;;`,
    'esac',
    '',
  ].join('\n')
}

// --- Red Hat family ---------------------------------------------------------

// rhelScript asks dnf, which knows which advisory fixes the CVE and whether
// it is installed; dnf 4 syntax (RHEL 8 to 10, Alma, Rocky).
export function rhelScript(id: string): string {
  return [
    '#!/bin/sh',
    `# ${id}: is this RHEL / Alma / Rocky machine affected? (generated by Pahredar)`,
    `if dnf -q updateinfo list --cve ${id} 2>/dev/null | grep -q .; then`,
    '  echo "AFFECTED: a fix is available but not installed:"',
    `  dnf -q updateinfo list --cve ${id}`,
    `  echo "Fix with: sudo dnf upgrade --cve ${id}"`,
    `elif dnf -q updateinfo list --installed --cve ${id} 2>/dev/null | grep -q .; then`,
    '  echo "PATCHED: the advisory fixing it is installed"',
    'else',
    '  echo "NO ADVISORY for the installed packages: not installed, not affected, or no fix released yet"',
    'fi',
    '',
  ].join('\n')
}

// --- Windows ----------------------------------------------------------------

// windowsBuilds maps each affected Windows build (10.0.19045) to the first
// fixed full build (10.0.19045.4046), from MSRC's per-product fixed builds.
export function windowsBuilds(msrc: CveReports['reports']['msrc']): { build: string; fixed: string; products: string[] }[] {
  const out = new Map<string, { build: string; fixed: string; products: string[] }>()
  for (const p of msrc?.products ?? []) {
    if (!/^Windows/.test(p.product)) continue
    for (const k of p.kb) {
      const fb = k.fixed_build
      if (!fb || !/^\d+\.\d+\.\d+\.\d+$/.test(fb)) continue
      const build = fb.split('.').slice(0, 3).join('.')
      const prev = out.get(build)
      if (!prev) out.set(build, { build, fixed: fb, products: [p.product] })
      else if (!prev.products.includes(p.product)) prev.products.push(p.product)
    }
  }
  return [...out.values()].sort((a, b) => compareVersions(a.build, b.build))
}

// windowsScript compares the running build (major.minor.build.UBR) with the
// fixed build for that Windows version; unlike Get-HotFix it is not fooled
// by a later cumulative update that supersedes the KB.
export function windowsScript(id: string, builds: { build: string; fixed: string }[]): string {
  return [
    `# ${id}: is this Windows machine patched? (generated by Pahredar)`,
    '$fixed = @{',
    ...builds.map((b) => `  '${b.build}' = '${b.fixed}'`),
    '}',
    "$cv = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'",
    '$mm = if ($null -ne $cv.CurrentMajorVersionNumber) { "$($cv.CurrentMajorVersionNumber).$($cv.CurrentMinorVersionNumber)" } else { $cv.CurrentVersion }',
    '$build = "$mm.$($cv.CurrentBuild)"',
    '$current = [version]"$build.$($cv.UBR)"',
    'if (-not $fixed.ContainsKey($build)) { "NOT LISTED  build $current is not one of the affected Windows versions" }',
    'elseif ($current -lt [version]$fixed[$build]) { "AFFECTED    build $current, fixed in $($fixed[$build])" }',
    'else { "PATCHED     build $current (fixed in $($fixed[$build]))" }',
    '',
  ].join('\n')
}

// fleetCommands runs a generated shell script on many hosts.
export function fleetCommands(file: string): { label: string; cmd: string; note?: string }[] {
  return [
    { label: 'Every host in an Ansible inventory', cmd: `ansible all -b -m script -a ./${file}` },
    { label: 'Hosts listed in hosts.txt, over SSH', cmd: `while read -r h; do ssh "$h" 'sudo sh -s' < ${file} | sed "s/^/$h: /"; done < hosts.txt`, note: 'ssh reads the script, not hosts.txt, so the loop sees every host.' },
  ]
}
