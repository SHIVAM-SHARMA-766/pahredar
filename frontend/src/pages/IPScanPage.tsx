import { useMutation } from '@tanstack/react-query'
import { AlertTriangle, Loader2, MapPin, Send, ShieldCheck } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { api, ApiError } from '../api/client'
import type { IPScanReport } from '../api/types'
import { Card, Tag } from '../components/ui'
import { Gauge } from '../components/Gauge'

// Row is a small label/value line (local copy; the scan page has its own).
function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[8rem_1fr] gap-2 py-1 text-sm">
      <dt className="text-zinc-500">{label}</dt>
      <dd className="min-w-0 break-words text-zinc-200">{children}</dd>
    </div>
  )
}

const ipVerdict: Record<string, { color: string; risk: string; tone: 'red' | 'amber' | 'cyan' }> = {
  clean: { color: '#34d399', risk: 'Clean', tone: 'cyan' },
  suspicious: { color: '#fbbf24', risk: 'Suspicious', tone: 'amber' },
  malicious: { color: '#f87171', risk: 'Malicious', tone: 'red' },
}

// IPScanner aggregates one IP's reputation and network profile from several
// public databases (DNS blocklists, Team Cymru, RDAP, ip-api) into one view.
export function IPScanPage() {
  const [input, setInput] = useState('')
  const scan = useMutation({ mutationFn: (ip: string) => api.ipScan(ip) })
  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const ip = input.trim()
    if (ip) scan.mutate(ip)
  }
  const rep = scan.data

  return (
    <div className="space-y-5">
      <div className="rounded-2xl border border-zinc-800 bg-gradient-to-b from-zinc-900/80 to-zinc-950 px-5 py-8 text-center sm:px-8 sm:py-10">
        <h1 className="text-2xl font-bold tracking-tight text-white sm:text-3xl">IP Scanner</h1>
        <p className="mt-2 text-sm text-zinc-400">Reputation, network, and geolocation for any IP — aggregated from DNS blocklists, Team Cymru, RDAP and ip-api. No key, no signup.</p>
        <form onSubmit={submit} className="mx-auto mt-5 flex max-w-lg gap-2">
          <input value={input} onChange={(e) => setInput(e.target.value)} autoFocus placeholder="8.8.8.8 or 2001:4860:4860::8888"
            className="min-w-0 flex-1 rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 font-mono text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-cyan-400/40 focus:outline-none" />
          <button type="submit" disabled={!input.trim() || scan.isPending} className="inline-flex shrink-0 items-center gap-1.5 rounded-lg bg-cyan-500 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-400 disabled:opacity-50">
            {scan.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />} Scan
          </button>
        </form>
        {scan.isError && <p className="mt-3 text-sm text-red-300">{scan.error instanceof ApiError ? scan.error.message : String(scan.error)}</p>}
      </div>

      {scan.isPending && <Card><div className="flex items-center gap-2 py-6 text-sm text-zinc-400"><Loader2 className="h-4 w-4 animate-spin text-cyan-300" /> Querying databases…</div></Card>}

      {rep && (
        <div className="grid gap-5 lg:grid-cols-3">
          <div className="lg:col-span-1"><IPVerdictCard rep={rep} /></div>
          <div className="space-y-5 lg:col-span-2">
            <IPNetworkCard rep={rep} />
            {rep.geo && <IPGeoCard geo={rep.geo} />}
            <IPBlocklistCard rep={rep} />
          </div>
          {rep.errors.length > 0 && (
            <div className="lg:col-span-3">
              <Card title="Lookup notes">
                <ul className="space-y-1 text-xs text-zinc-500">{rep.errors.map((e, i) => <li key={i} className="font-mono">{e}</li>)}</ul>
              </Card>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function IPVerdictCard({ rep }: { rep: IPScanReport }) {
  const v = ipVerdict[rep.verdict] ?? ipVerdict.clean
  return (
    <Card>
      <div className="flex flex-col items-center">
        <Gauge value={rep.score} max={100} display={String(rep.score)} caption="risk" color={v.color} risk={v.risk} />
        <div className="mt-3 text-center">
          <div className="font-mono text-lg text-white">{rep.ip}</div>
          <div className="mt-1 flex flex-wrap justify-center gap-1.5">
            <Tag tone="zinc">IPv{rep.version}</Tag>
            <Tag tone={rep.type === 'public' ? 'cyan' : 'amber'}>{rep.type}</Tag>
          </div>
        </div>
        {rep.flags.length > 0 && (
          <div className="mt-3 flex flex-wrap justify-center gap-1.5">
            {rep.flags.map((f, i) => <Tag key={i} tone={v.tone}>{f}</Tag>)}
          </div>
        )}
        <p className="mt-3 text-center text-[11px] text-zinc-600">{new Date(rep.scanned_at).toLocaleString()} · {rep.duration}</p>
      </div>
    </Card>
  )
}

function IPNetworkCard({ rep }: { rep: IPScanReport }) {
  const n = rep.net
  return (
    <Card title="Network & allocation">
      <dl>
        {rep.ptr && <Row label="Reverse DNS"><span className="font-mono text-sm">{rep.ptr}</span></Row>}
        {n?.asn && <Row label="ASN"><span className="font-mono">{n.asn}</span>{n.as_org && <span className="text-zinc-400"> · {n.as_org}</span>}</Row>}
        {n?.net_name && <Row label="Network">{n.net_name}</Row>}
        {n?.net_range && <Row label="Range"><span className="font-mono text-xs">{n.net_range}</span></Row>}
        {n?.org && <Row label="Org">{n.org}</Row>}
        {n?.country && <Row label="Country">{n.country}</Row>}
      </dl>
      {!rep.ptr && !n?.asn && !n?.net_name && <p className="text-sm text-zinc-500">No network data resolved (private or unallocated address).</p>}
    </Card>
  )
}

function IPGeoCard({ geo }: { geo: NonNullable<IPScanReport['geo']> }) {
  const place = [geo.city, geo.region, geo.country].filter(Boolean).join(', ')
  return (
    <Card title={<span className="inline-flex items-center gap-1.5"><MapPin className="h-4 w-4 text-cyan-300" /> Geolocation</span>}>
      <dl>
        {place && <Row label="Location">{place}{geo.country_code && <span className="text-zinc-500"> ({geo.country_code})</span>}</Row>}
        {geo.timezone && <Row label="Timezone">{geo.timezone}</Row>}
        {geo.isp && <Row label="ISP">{geo.isp}</Row>}
        {geo.as && <Row label="AS"><span className="font-mono text-xs">{geo.as}</span></Row>}
        {(geo.lat !== undefined && geo.lon !== undefined) && <Row label="Coords"><span className="font-mono text-xs">{geo.lat}, {geo.lon}</span></Row>}
        <Row label="Flags">
          <div className="flex flex-wrap gap-1.5">
            {geo.proxy && <Tag tone="red">proxy / VPN</Tag>}
            {geo.hosting && <Tag tone="amber">hosting</Tag>}
            {geo.mobile && <Tag tone="zinc">mobile</Tag>}
            {!geo.proxy && !geo.hosting && !geo.mobile && <span className="text-sm text-zinc-500">none</span>}
          </div>
        </Row>
      </dl>
    </Card>
  )
}

function IPBlocklistCard({ rep }: { rep: IPScanReport }) {
  const bl = rep.blocklist
  if (!bl) return null
  const clean = bl.listed === 0
  return (
    <Card title={<span className="inline-flex items-center gap-1.5">{clean ? <ShieldCheck className="h-4 w-4 text-emerald-400" /> : <AlertTriangle className="h-4 w-4 text-red-400" />} DNS blocklists</span>}
      actions={<span className={`text-xs font-medium ${clean ? 'text-emerald-300' : 'text-red-300'}`}>{bl.listed} / {bl.checked} listed</span>}>
      {clean ? (
        <p className="text-sm text-zinc-400">{bl.checked > 0 ? `Not listed on any of the ${bl.checked} blocklists checked.` : 'Blocklists apply to public IPv4 only; skipped for this address.'}</p>
      ) : (
        <ul className="space-y-2">
          {bl.hits.map((h) => (
            <li key={h.zone} className="flex items-start gap-2 text-sm">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-red-400" />
              <div className="min-w-0">
                <span className="font-mono text-zinc-200">{h.zone}</span>
                <span className="ml-2 font-mono text-xs text-zinc-500">{h.codes.join(' ')}</span>
                {h.reason && <p className="text-xs break-words text-zinc-500">{h.reason}</p>}
              </div>
            </li>
          ))}
        </ul>
      )}
      {bl.lists.length > 0 && <p className="mt-3 text-[11px] text-zinc-600">Checked: {bl.lists.join(', ')}</p>}
    </Card>
  )
}
