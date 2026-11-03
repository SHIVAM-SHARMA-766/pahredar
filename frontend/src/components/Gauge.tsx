// A radial score gauge, shared by the scanner, CVE, and vendor pages.
export function Gauge({ value, max, display, caption, color, risk }: {
  value: number
  max: number
  display: string
  caption: string
  color: string
  risk?: string
}) {
  const r = 52
  const circ = 2 * Math.PI * r
  const off = circ * (1 - Math.min(Math.max(value, 0), max) / max)
  return (
    <div className="flex flex-col items-center">
      <div className="relative h-36 w-36">
        <svg viewBox="0 0 140 140" className="h-36 w-36 -rotate-90">
          <circle cx="70" cy="70" r={r} fill="none" stroke="currentColor" strokeWidth="10" className="text-zinc-800" />
          <circle cx="70" cy="70" r={r} fill="none" stroke={color} strokeWidth="10" strokeLinecap="round" strokeDasharray={circ} strokeDashoffset={off} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-bold text-white">{display}</span>
          <span className="text-xs tracking-wider text-zinc-500 uppercase">{caption}</span>
        </div>
      </div>
      {risk && <div className="mt-3 text-sm font-medium" style={{ color }}>{risk}</div>}
    </div>
  )
}
