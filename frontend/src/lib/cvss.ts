// Human-readable breakdown of CVSS vector strings (v2, v3.x, v4.0 base metrics).

type Dict = Record<string, { name: string; values: Record<string, string> }>

const impact3 = { N: 'None', L: 'Low', H: 'High' }

const v3: Dict = {
  AV: { name: 'Attack vector', values: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' } },
  AC: { name: 'Attack complexity', values: { L: 'Low', H: 'High' } },
  PR: { name: 'Privileges required', values: impact3 },
  UI: { name: 'User interaction', values: { N: 'None', R: 'Required' } },
  S: { name: 'Scope', values: { U: 'Unchanged', C: 'Changed' } },
  C: { name: 'Confidentiality', values: impact3 },
  I: { name: 'Integrity', values: impact3 },
  A: { name: 'Availability', values: impact3 },
  // Temporal metrics, present in some vectors.
  E: { name: 'Exploit code maturity', values: { X: 'Not defined', U: 'Unproven', P: 'Proof of concept', F: 'Functional', H: 'High' } },
  RL: { name: 'Remediation level', values: { X: 'Not defined', O: 'Official fix', T: 'Temporary fix', W: 'Workaround', U: 'Unavailable' } },
  RC: { name: 'Report confidence', values: { X: 'Not defined', U: 'Unknown', R: 'Reasonable', C: 'Confirmed' } },
}

const v4: Dict = {
  AV: v3.AV,
  AC: v3.AC,
  AT: { name: 'Attack requirements', values: { N: 'None', P: 'Present' } },
  PR: v3.PR,
  UI: { name: 'User interaction', values: { N: 'None', P: 'Passive', A: 'Active' } },
  VC: { name: 'Confidentiality (vulnerable system)', values: impact3 },
  VI: { name: 'Integrity (vulnerable system)', values: impact3 },
  VA: { name: 'Availability (vulnerable system)', values: impact3 },
  SC: { name: 'Confidentiality (subsequent systems)', values: impact3 },
  SI: { name: 'Integrity (subsequent systems)', values: impact3 },
  SA: { name: 'Availability (subsequent systems)', values: impact3 },
  E: { name: 'Exploit maturity', values: { X: 'Not defined', A: 'Attacked', P: 'Proof of concept', U: 'Unreported' } },
}

const impact2 = { N: 'None', P: 'Partial', C: 'Complete' }
const v2: Dict = {
  AV: { name: 'Access vector', values: { L: 'Local', A: 'Adjacent network', N: 'Network' } },
  AC: { name: 'Access complexity', values: { H: 'High', M: 'Medium', L: 'Low' } },
  Au: { name: 'Authentication', values: { M: 'Multiple', S: 'Single', N: 'None' } },
  C: { name: 'Confidentiality', values: impact2 },
  I: { name: 'Integrity', values: impact2 },
  A: { name: 'Availability', values: impact2 },
}

export interface VectorPart {
  key: string
  name: string
  value: string
  label: string
}

export function parseVector(version: string, vector: string): VectorPart[] {
  const dict = version === '4.0' ? v4 : version.startsWith('3') ? v3 : v2
  return vector
    .split('/')
    .filter((p) => p.includes(':') && !p.startsWith('CVSS:'))
    .map((p) => {
      const [key, value] = p.split(':')
      const d = dict[key]
      return { key, value, name: d?.name ?? key, label: d?.values[value] ?? value }
    })
    // v4 vectors list every supplemental metric; hide the "not defined" ones.
    .filter((p) => !(version === '4.0' && p.value === 'X'))
}
