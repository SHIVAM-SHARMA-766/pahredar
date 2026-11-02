// Detection commands and hints built from data Pahredar already has: exploit
// modules (Metasploit, Nuclei), detection rules (Nmap, Suricata, Sigma),
// affected packages (OSV, Ubuntu, Red Hat), Windows KBs (MSRC), and CWEs.
import type { CveReports, DebianStatus, DetectionRule, Exploit } from '../api/types'

export interface Command {
  label: string
  cmd: string
  note?: string
}

// Package version checks per OSV ecosystem (the part before any ":").
const ecosystemCheck: Record<string, (pkg: string) => string> = {
  PyPI: (p) => `pip show ${p} 2>/dev/null | grep -i '^version'`,
  npm: (p) => `npm ls ${p} --all`,
  // Servers rarely have the build; look for the jar itself.
  Maven: (p) => `find / -name '${p.split(':').pop()}-*.jar' 2>/dev/null`,
  Go: (p) => `go list -m all | grep '${p}'`,
  'crates.io': (p) => `cargo tree -i ${p}`,
  RubyGems: (p) => `bundle list | grep -i ' ${p} '`,
  NuGet: (p) => `dotnet list package --include-transitive | grep -i '${p}'`,
  Packagist: (p) => `composer show ${p}`,
  Hex: (p) => `mix deps | grep ${p}`,
  Pub: (p) => `dart pub deps | grep ${p}`,
  Debian: (p) => `dpkg-query -W -f='\${Package} \${Version}\\n' ${p}`,
  Ubuntu: (p) => `dpkg-query -W -f='\${Package} \${Version}\\n' ${p}`,
  Alpine: (p) => `apk info -v ${p}`,
  'Red Hat': (p) => `rpm -q ${p}`,
  AlmaLinux: (p) => `rpm -q ${p}`,
  'Rocky Linux': (p) => `rpm -q ${p}`,
  SUSE: (p) => `rpm -q ${p}`,
  openSUSE: (p) => `rpm -q ${p}`,
  'GitHub Actions': (p) => `grep -rn '${p}@' .github/workflows`,
  Linux: () => 'uname -r',
}

export interface PackageCheck {
  ecosystem: string
  pkg: string
  cmd: string
  fixed: string[]
}

// One version check per distinct command across OSV, Ubuntu, and Red Hat;
// packages sharing a command (Maven forks with the same jar name) merge.
export function packageChecks(r: CveReports['reports'] | undefined, debian: DebianStatus[] = []): PackageCheck[] {
  const out = new Map<string, PackageCheck>()
  const add = (ecosystem: string, pkg: string, fixed: string[] = []) => {
    const base = ecosystem.split(':')[0]
    const check = ecosystemCheck[base]
    if (!check || !pkg) return
    const cmd = check(pkg)
    const prev = out.get(cmd)
    if (prev) {
      prev.fixed = [...new Set([...prev.fixed, ...fixed])]
      if (!prev.pkg.split(', ').includes(pkg)) prev.pkg += `, ${pkg}`
      return
    }
    out.set(cmd, { ecosystem: base, pkg, cmd, fixed })
  }
  for (const adv of r?.osv ?? []) for (const a of adv.affected) add(a.ecosystem, a.package, a.fixed)
  for (const d of debian) add('Debian', d.package, d.status === 'resolved' && d.fixed_version && d.fixed_version !== '0' ? [`${d.fixed_version} (${d.release})`] : [])
  for (const p of r?.ubuntu?.packages ?? []) add('Ubuntu', p.name)
  for (const f of r?.redhat?.fixed_in ?? []) if (f.package) add('Red Hat', f.package.replace(/-\d.*$/, ''))
  return [...out.values()]
}

// Distribution and scanner commands that look up the CVE directly.
export function cveLookups(id: string, r: CveReports['reports'] | undefined, checks: PackageCheck[]): Command[] {
  const eco = new Set(checks.map((c) => c.ecosystem))
  const out: Command[] = []
  if (r?.ubuntu || eco.has('Ubuntu')) out.push({ label: 'Ubuntu', cmd: `sudo pro fix ${id} --dry-run`, note: 'Reports whether this machine is affected and what the fix would install.' })
  if (eco.has('Debian')) out.push({ label: 'Debian', cmd: `debsecan --format detail | grep -A3 ${id}` })
  if (r?.redhat || eco.has('Red Hat') || eco.has('AlmaLinux') || eco.has('Rocky Linux')) {
    out.push({ label: 'RHEL / Alma / Rocky', cmd: `sudo dnf updateinfo info --cve ${id}`, note: 'Lists the advisory and packages fixing this CVE that are not yet installed.' })
  }
  const appEcosystems = [...eco].filter((e) => !['Ubuntu', 'Debian', 'Red Hat', 'AlmaLinux', 'Rocky Linux', 'SUSE', 'openSUSE', 'Alpine', 'Linux'].includes(e))
  if (appEcosystems.length) {
    out.push({ label: 'Source tree (OSV-Scanner)', cmd: `osv-scanner scan -r . | grep ${id}` })
  }
  if (checks.length) {
    out.push(
      { label: 'Filesystem or repo (Trivy)', cmd: `trivy fs --scanners vuln . 2>/dev/null | grep ${id}` },
      { label: 'Container image (Trivy)', cmd: `trivy image IMAGE 2>/dev/null | grep ${id}` },
      { label: 'Host (Grype)', cmd: `grype dir:/ 2>/dev/null | grep ${id}` },
    )
  }
  return out
}

// Windows KB checks from the MSRC report.
export function windowsChecks(r: CveReports['reports'] | undefined): Command[] {
  const kbs = new Map<string, string[]>()
  for (const p of r?.msrc?.products ?? []) {
    for (const k of p.kb) {
      if (!/^\d+$/.test(k.article)) continue
      kbs.set(k.article, [...(kbs.get(k.article) ?? []), p.product])
    }
  }
  return [...kbs.entries()].slice(0, 12).map(([kb, products]) => ({
    label: `KB${kb}`,
    cmd: `Get-HotFix -Id KB${kb}`,
    note: products.slice(0, 3).join(', ') + (products.length > 3 ? ` +${products.length - 3} more` : ''),
  }))
}

// Default port from the CVSS-scored service, when Metasploit knows one.
function port(e: Exploit) {
  const p = e.meta?.rport
  return p !== undefined && p !== '' ? String(p) : undefined
}

// Active checks: Nuclei templates, Nmap scripts, Metasploit check/scanner
// modules. `target` is a host, URL, or IP the user typed.
export function activeScans(id: string, exploits: Exploit[], rules: DetectionRule[], target: string): Command[] {
  const out: Command[] = []
  const host = target.replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, '')
  for (const e of exploits.filter((x) => x.source === 'nuclei')) {
    const http = (e.meta?.protocol ?? 'http') === 'http'
    const url = http && !/^https?:\/\//i.test(target) ? `https://${target}` : target
    const templateId = e.source_ref.split('/').pop()?.replace(/\.ya?ml$/, '') ?? id
    out.push({ label: `Nuclei · ${e.title ?? templateId}`, cmd: `nuclei -id ${templateId} -u ${url}`, note: e.meta?.severity ? `Template severity: ${e.meta.severity}` : undefined })
  }
  for (const r of rules.filter((x) => x.source === 'nmap')) {
    out.push({ label: `Nmap NSE · ${r.rule_id}`, cmd: `nmap -sV --script ${r.rule_id} ${host}`, note: r.meta.categories?.includes('intrusive') ? 'Intrusive: may disturb the service.' : undefined })
  }
  for (const e of exploits.filter((x) => x.source === 'metasploit')) {
    const isScanner = e.meta?.type === 'auxiliary' && e.source_ref.includes('/scanner/')
    if (!e.meta?.check && !isScanner) continue
    const p = port(e)
    const action = e.meta?.check ? 'check' : 'run'
    out.push({
      label: `Metasploit · ${e.title ?? e.source_ref}`,
      cmd: `msfconsole -q -x "use ${e.source_ref}; set RHOSTS ${host};${p ? ` set RPORT ${p};` : ''} ${action}; exit"`,
      note: e.meta?.check ? 'Uses the module\'s check method, which tests without exploiting.' : 'Auxiliary scanner module.',
    })
  }
  return out
}

// Suricata: make sure the rules are loaded, then hunt past alerts.
export function suricataCommands(rules: DetectionRule[]): Command[] {
  const sids = rules.filter((r) => r.source === 'suricata').map((r) => r.rule_id)
  if (!sids.length) return []
  const disabled = rules.filter((r) => r.source === 'suricata' && r.meta.enabled === false).map((r) => r.rule_id)
  const shown = sids.slice(0, 40)
  const out: Command[] = [{ label: 'Update rules (ET Open is suricata-update\'s default source)', cmd: 'sudo suricata-update && sudo systemctl reload suricata' }]
  if (disabled.length) {
    out.push({
      label: `Enable the ${disabled.length} rule${disabled.length > 1 ? 's' : ''} ET ships disabled`,
      cmd: `printf '%s\\n' ${disabled.slice(0, 40).join(' ')} | sudo tee -a /etc/suricata/enable.conf && sudo suricata-update`,
    })
  }
  out.push(
    { label: 'Check the rules are loaded', cmd: `grep -cE 'sid:(${shown.join('|')});' /var/lib/suricata/rules/suricata.rules` },
    { label: 'Hunt past alerts in eve.json', cmd: `jq -c 'select(.event_type=="alert" and (.alert.signature_id|IN(${shown.join(',')})))' /var/log/suricata/eve.json` },
  )
  return out
}

// Raw file URL for a rule hosted on GitHub.
export function rawUrl(url: string | null): string | null {
  const m = url?.match(/^https:\/\/github\.com\/([^/]+\/[^/]+)\/blob\/(.+)$/)
  return m ? `https://raw.githubusercontent.com/${m[1]}/${m[2]}` : null
}

export function sigmaCommands(rule: DetectionRule): Command[] {
  const raw = rawUrl(rule.url)
  if (!raw) return []
  const file = raw.split('/').pop()!
  const windows = rule.meta.logsource?.product === 'windows'
  return [
    { label: 'Download', cmd: `curl -sLO ${raw}` },
    { label: 'Convert to Splunk SPL (sigma-cli)', cmd: `sigma convert -t splunk ${windows ? '-p splunk_windows' : '--without-pipeline'} ${file}` },
    { label: 'Convert to Elastic (Lucene)', cmd: `sigma convert -t lucene ${windows ? '-p ecs_windows' : '--without-pipeline'} ${file}` },
  ]
}

// What exploitation of each weakness class tends to leave behind. Hints, not
// signatures: they tell you where to look when no rule exists.
const cweHints: Record<string, string[]> = {
  'CWE-78': ['Shell metacharacters (; | ` $( && ||) in request parameters or form fields.', 'The web server or application process spawning sh, bash, cmd.exe, or powershell.', 'Outbound connections (curl, wget, nc) from the service account.'],
  'CWE-77': ['Command separators or injected arguments in input that reaches a command line.', 'Unexpected child processes of the vulnerable service.'],
  'CWE-89': ['SQL keywords in parameters: UNION SELECT, SLEEP(, WAITFOR DELAY, OR 1=1, information_schema.', 'Database error messages in responses; bursts of near-identical requests (sqlmap).'],
  'CWE-79': ['<script, javascript:, onerror=, onload= in parameters or stored fields.', 'Session tokens sent to unfamiliar hosts.'],
  'CWE-22': ['../, ..%2f, %2e%2e, ..\\ in URLs or file parameters.', 'Requests returning /etc/passwd, win.ini, web.config, or application config files.'],
  'CWE-23': ['Relative path sequences (../) in file name parameters.'],
  'CWE-502': ['Serialized object markers in bodies or cookies: rO0AB / aced0005 (Java), O:<n>: (PHP), AAEAAAD (.NET).', 'The application process spawning shells or making outbound connections.'],
  'CWE-918': ['Server-side requests to internal ranges or 169.254.169.254 (cloud metadata).', 'URL parameters pointing at localhost, internal hostnames, or file:// / gopher://.'],
  'CWE-287': ['Access to admin or API endpoints without a preceding successful login.', 'New administrator accounts, API tokens, or SSH keys.'],
  'CWE-306': ['Requests to sensitive endpoints from unexpected sources with no authentication.', 'Configuration changes with no matching admin session.'],
  'CWE-288': ['Alternate paths or headers reaching authenticated functions (e.g. path normalisation tricks).'],
  'CWE-862': ['Users reading or changing objects that belong to others; sequential ID enumeration.'],
  'CWE-863': ['Low-privilege accounts performing admin actions.'],
  'CWE-434': ['New .php, .jsp, .jspx, .aspx, .ashx files in web roots or upload folders.', 'Requests to recently uploaded files followed by command execution (webshells).'],
  'CWE-94': ['Template or code syntax in input: ${, #{, %{, {{, <%=.', 'The application process spawning shells.'],
  'CWE-917': ['Expression language payloads: ${jndi:, ${env:, %{(#, #{ in headers, URLs, or bodies.', 'Outbound LDAP, RMI, or DNS lookups from servers.'],
  'CWE-611': ['<!DOCTYPE with <!ENTITY ... SYSTEM in XML bodies.', 'Outbound HTTP or DNS from the XML-parsing service.'],
  'CWE-1336': ['Template syntax ({{ }}, ${ }) in user input rendered by the server.'],
  'CWE-787': ['Crashes, restarts, or core dumps of the affected service.', 'Unexpected child processes or injected threads after a crash-free request (successful exploitation).'],
  'CWE-119': ['Service crashes or restarts; oversized or malformed protocol fields in traffic.'],
  'CWE-120': ['Oversized input fields in traffic; crashes of the parsing service.'],
  'CWE-125': ['Malformed input to the parser; crashes; unexpected data in responses.'],
  'CWE-416': ['Crashes of the affected process; browser or document-reader child processes.'],
  'CWE-122': ['Heap corruption crashes in the affected process.'],
  'CWE-190': ['Very large length or count fields in input; crashes.'],
  'CWE-269': ['Processes running as root / SYSTEM whose parent runs as a normal user.', 'New privileged accounts or group memberships.'],
  'CWE-250': ['Actions performed with elevated rights by a component that should not need them.'],
  'CWE-798': ['Logins using the vendor\'s default or hard-coded account names.'],
  'CWE-521': ['Successful logins after many failures (password spraying).'],
  'CWE-352': ['State-changing requests with a foreign Origin or Referer.'],
  'CWE-601': ['Redirect parameters (url=, next=, redirect=) pointing to external domains.'],
  'CWE-400': ['CPU, memory, or connection spikes on the service; repeated identical requests.'],
  'CWE-770': ['Resource exhaustion: connection or memory spikes from few sources.'],
  'CWE-200': ['Requests to the disclosing endpoint; unusually large responses to unauthenticated clients.'],
  'CWE-532': ['Secrets appearing in log files; access to log files from unexpected users.'],
  'CWE-367': ['Rapid repeated file operations (symlink races) by local users.'],
  'CWE-59': ['Symlinks created in shared or temporary directories pointing at sensitive files.'],
}

export function weaknessHints(cweIds: string[]): { cwe: string; hints: string[] }[] {
  return cweIds.filter((c) => cweHints[c]).map((c) => ({ cwe: c, hints: cweHints[c] }))
}
