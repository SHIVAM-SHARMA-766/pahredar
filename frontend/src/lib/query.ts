// Kibana-style query language for the CVE explorer. A query is free text plus
// field:value terms, translated into GET /api/v1/cves parameters:
//
//   apache struts is:kev epss:>10 vendor:cisco,citrix -has:exploit age:<30
//
// Free text becomes the full-text `q` (a lone CVE ID is an exact lookup).
// FIELDS below is the reference; the help panel in QueryBar renders it.

export interface Field {
  syntax: string
  meaning: string
}

export const FIELDS: Field[] = [
  { syntax: 'is:kev', meaning: 'Listed in CISA KEV (negate with -is:kev)' },
  { syntax: 'has:exploit', meaning: 'Public exploit, Metasploit module, Nuclei template, or exploit reference' },
  { syntax: 'has:ransomware', meaning: 'KEV entry with known ransomware use' },
  { syntax: 'severity:critical,high', meaning: 'Any of critical, high, medium, low, none, unknown' },
  { syntax: 'epss:>10', meaning: 'EPSS percent; >, >=, <, <=' },
  { syntax: 'cvss:>=9', meaning: 'Best CVSS score (v4, else v3, else v2); >, >=, <, <=' },
  { syntax: 'vendor:cisco,citrix', meaning: 'Affected vendor, any of; quote names with spaces: vendor:"palo alto networks"' },
  { syntax: 'product:log4j', meaning: 'Affected product, any of' },
  { syntax: 'cwe:79', meaning: 'Weakness, CWE number or CWE-79' },
  { syntax: 'age:<30', meaning: 'Published within N days (age:>365 = older than a year)' },
  { syntax: 'published:>=2024-01-01', meaning: 'Publish date; >, >=, <, <=, =' },
  { syntax: 'is:rejected', meaning: 'Rejected IDs only (is:published for the rest)' },
  { syntax: '-term', meaning: 'Negate is:/has:/severity: terms' },
]

export const EXAMPLES = [
  'is:kev has:ransomware',
  'epss:>10 -is:kev',
  'severity:critical age:<7',
  'vendor:microsoft,cisco is:kev',
  'has:exploit cvss:>=9 age:<90',
  'cwe:79 age:<30',
]

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'none', 'unknown']

export interface ParsedQuery {
  // Parameters for GET /api/v1/cves (filters only; no sort or paging).
  api: URLSearchParams
  // Free text, if any (it switches the default sort to relevance).
  text: string
  errors: string[]
}

// field:value, field:"quoted value", "quoted text", or a bare word.
const TOKEN = /-?[a-z_]+:"[^"]*"|-?[a-z_]+:\S+|"[^"]*"|\S+/gi
const FIELD = /^(-?)([a-z_]+):(.*)$/i
const COMPARE = /^(>=|<=|>|<|=)?(.+)$/

function unquote(s: string): string {
  return s.length >= 2 && s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1) : s
}

function isoDay(d: Date): string {
  return d.toISOString().slice(0, 10)
}

function daysAgo(n: number): string {
  const d = new Date()
  d.setUTCDate(d.getUTCDate() - n)
  return isoDay(d)
}

function shiftDay(day: string, n: number): string {
  const d = new Date(`${day}T00:00:00Z`)
  d.setUTCDate(d.getUTCDate() + n)
  return isoDay(d)
}

export function parseQuery(input: string): ParsedQuery {
  const api = new URLSearchParams()
  const text: string[] = []
  const errors: string[] = []

  for (const token of input.match(TOKEN) ?? []) {
    const m = token.match(FIELD)
    if (!m) {
      text.push(unquote(token))
      continue
    }
    const [, neg, rawKey, rawValue] = m
    const key = rawKey.toLowerCase()
    const value = unquote(rawValue).trim()
    const negated = neg === '-'
    if (!value) {
      errors.push(`${key}: needs a value`)
      continue
    }
    const noNegation = () => negated && errors.push(`${key}: cannot be negated`)

    switch (key) {
      case 'is':
        if (value === 'kev') api.set('kev', String(!negated))
        else if (value === 'rejected') api.set('state', negated ? 'PUBLISHED' : 'REJECTED')
        else if (value === 'published') api.set('state', negated ? 'REJECTED' : 'PUBLISHED')
        else errors.push(`is:${value} is not supported (use kev, rejected, published)`)
        break
      case 'has':
        if (value === 'exploit') api.set('exploit', String(!negated))
        else if (value === 'ransomware') api.set('ransomware', String(!negated))
        else errors.push(`has:${value} is not supported (use exploit, ransomware)`)
        break
      case 'severity':
      case 'sev': {
        const picked = value.toLowerCase().split(',').filter(Boolean)
        const bad = picked.filter((s) => !SEVERITIES.includes(s))
        if (bad.length) {
          errors.push(`severity: unknown value ${bad.join(', ')}`)
          break
        }
        const set = negated ? SEVERITIES.filter((s) => !picked.includes(s)) : picked
        api.set('severity', set.join(',').toUpperCase())
        break
      }
      case 'epss':
      case 'cvss': {
        noNegation()
        const [, op = '', numText] = value.match(COMPARE)!
        const num = Number(numText)
        const max = key === 'epss' ? 100 : 10
        if (!op || op === '=' || isNaN(num) || num < 0 || num > max) {
          errors.push(`${key}: use a comparison such as ${key}:>${key === 'epss' ? 10 : 7} (0–${max})`)
          break
        }
        const v = key === 'epss' ? String(num / 100) : String(num)
        api.set(`${key}_${op.startsWith('>') ? 'min' : 'max'}`, v)
        break
      }
      case 'vendor':
      case 'product':
        noNegation()
        api.set(key, value.toLowerCase())
        break
      case 'cwe': {
        noNegation()
        const n = value.toUpperCase().replace(/^CWE-/, '')
        if (!/^\d+$/.test(n)) errors.push('cwe: use a number such as cwe:79')
        else api.set('cwe', `CWE-${n}`)
        break
      }
      case 'age': {
        noNegation()
        const [, op = '', numText] = value.match(COMPARE)!
        const days = Number(numText)
        if (!op || op === '=' || !Number.isInteger(days) || days < 0) {
          errors.push('age: use age:<30 (newer than) or age:>365 (older than), in days')
          break
        }
        if (op.startsWith('<')) api.set('published_from', daysAgo(op === '<' ? days - 1 : days))
        else api.set('published_to', daysAgo(op === '>' ? days + 1 : days))
        break
      }
      case 'published': {
        noNegation()
        const [, op = '=', day] = value.match(COMPARE)!
        if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) {
          errors.push('published: use a date such as published:>=2024-01-01')
          break
        }
        if (op === '>') api.set('published_from', shiftDay(day, 1))
        else if (op === '>=') api.set('published_from', day)
        else if (op === '<') api.set('published_to', shiftDay(day, -1))
        else if (op === '<=') api.set('published_to', day)
        else {
          api.set('published_from', day)
          api.set('published_to', day)
        }
        break
      }
      default:
        errors.push(`unknown field "${key}"`)
    }
  }

  const joined = text.join(' ').trim()
  if (joined) api.set('q', joined)
  return { api, text: joined, errors }
}

// Link to the explorer with a query (and optional sort).
export function explorerLink(query: string, sort?: string): string {
  const p = new URLSearchParams({ query })
  if (sort) p.set('sort', sort)
  return `/cves?${p}`
}
