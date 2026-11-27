package easm

import (
	"bytes"
	"encoding/csv"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
)

// Reporting is a derived view over the record store (spec §10): JSON, CSV, and a
// print-ready HTML page (the browser's "Save as PDF" covers PDF with no server
// dependency). A report bundles the summary, the security findings, the full
// record inventory, and a data-quality section (R16).

// Report is the full structured attack-surface report for an asset.
type Report struct {
	AssetID     int64            `json:"asset_id"`
	Asset       string           `json:"asset"`
	ClientID    *int64           `json:"client_id,omitempty"`
	GeneratedAt time.Time        `json:"generated_at"`
	Summary     Summary          `json:"summary"`
	Findings    []db.Alert       `json:"findings"`
	Records     []db.AssetRecord `json:"records"`
	Quality     DataQuality      `json:"data_quality"`
}

// DataQuality is the coverage/freshness section (spec R16).
type DataQuality struct {
	TotalRecords int            `json:"total_records"`
	BySource     map[string]int `json:"by_source"`
	ByMethod     map[string]int `json:"by_method"`
	ByConfidence map[string]int `json:"by_confidence"`
	Unverified   int            `json:"unverified"`
	Stale        int            `json:"stale"` // not re-observed by the latest scan
}

// buildReport assembles the report from an asset's records, findings, and runs.
func buildReport(a *db.Asset, records []db.AssetRecord, findings []db.Alert, runs []db.ScanRun) Report {
	rep := Report{
		AssetID: a.ID, Asset: a.Value, ClientID: a.ClientID,
		GeneratedAt: time.Now().UTC(),
		Summary:     buildSummary(a.ID, records),
		Findings:    findings,
		Records:     records,
		Quality: DataQuality{
			TotalRecords: len(records),
			BySource:     map[string]int{}, ByMethod: map[string]int{}, ByConfidence: map[string]int{},
		},
	}
	if rep.Findings == nil {
		rep.Findings = []db.Alert{}
	}
	var latestStart *time.Time
	if len(runs) > 0 {
		rep.Summary.LastRun = &runs[0]
		latestStart = &runs[0].StartedAt
	}
	for _, rec := range records {
		rep.Quality.BySource[rec.Source]++
		rep.Quality.ByMethod[rec.Method]++
		rep.Quality.ByConfidence[rec.Confidence]++
		if rec.Verification != "verified" {
			rep.Quality.Unverified++
		}
		if latestStart != nil && rec.LastSeen.Before(*latestStart) {
			rep.Quality.Stale++
		}
	}
	return rep
}

// report serves an asset report in the requested format (json|csv|html).
func (s *Service) report(w http.ResponseWriter, r *http.Request) {
	a, ok := s.accessibleAssetByPath(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	records, err := s.Store.ListRecords(ctx, a.ID, "")
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	findings, err := s.Store.IncidentItems(ctx, a.ID)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	runs, _ := s.Store.ListScanRuns(ctx, a.ID, 1)
	rep := buildReport(a, records, findings, runs)

	fname := "easm-" + sanitizeFilename(a.Value) + "-" + rep.GeneratedAt.Format("20060102")
	switch r.URL.Query().Get("format") {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`.csv"`)
		writeRecordsCSV(w, rep.Records)
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := reportTemplate.Execute(w, rep); err != nil {
			platform.InternalError(w, r, err)
		}
	default: // json
		platform.WriteJSON(w, http.StatusOK, rep)
	}
}

// writeRecordsCSV writes the record inventory as CSV (the flat evidence export).
func writeRecordsCSV(w http.ResponseWriter, records []db.AssetRecord) {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"category", "key", "source", "method", "confidence", "verification", "scope", "first_seen", "last_seen"})
	for _, rec := range records {
		_ = cw.Write([]string{
			rec.Category, rec.Key, rec.Source, rec.Method, rec.Confidence, rec.Verification, rec.Scope,
			rec.FirstSeen.Format(time.RFC3339), rec.LastSeen.Format(time.RFC3339),
		})
	}
}

// sanitizeFilename keeps a value safe for a Content-Disposition filename.
func sanitizeFilename(v string) string {
	var b bytes.Buffer
	for _, c := range v {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
			b.WriteRune(c)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "asset"
	}
	return b.String()
}

// sortedPairs turns a count map into a stable, descending slice for templates.
func sortedPairs(m map[string]int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value != out[j].Value {
			return out[i].Value > out[j].Value
		}
		return out[i].Key < out[j].Key
	})
	return out
}

type kv struct {
	Key   string
	Value int
}

var reportFuncs = template.FuncMap{
	"pairs":   sortedPairs,
	"fmtTime": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
	"deref": func(p *int64) string {
		if p == nil {
			return "—"
		}
		return strconv.FormatInt(*p, 10)
	},
	"present": func(p *bool) string {
		if p == nil {
			return "unknown"
		}
		if *p {
			return "present"
		}
		return "missing"
	},
}

var reportTemplate = template.Must(template.New("report").Funcs(reportFuncs).Parse(reportHTML))

const reportHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EASM report · {{.Asset}}</title>
<style>
  :root { --ink:#1a1a1a; --muted:#666; --line:#e2e2e2; --bg:#fff; --accent:#0b7285;
          --crit:#c92a2a; --high:#e8590c; --med:#f08c00; --low:#1971c2; --info:#868e96; }
  * { box-sizing:border-box; }
  body { font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; color:var(--ink);
         background:var(--bg); margin:0; padding:32px; max-width:960px; margin-inline:auto; }
  h1 { font-size:22px; margin:0 0 4px; } h2 { font-size:15px; text-transform:uppercase; letter-spacing:.04em;
       color:var(--accent); border-bottom:2px solid var(--line); padding-bottom:4px; margin:28px 0 12px; }
  .sub { color:var(--muted); font-size:13px; margin-bottom:20px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:5px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--muted); font-weight:600; }
  code { font-family:ui-monospace,Menlo,monospace; font-size:12px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(150px,1fr)); gap:8px; }
  .stat { border:1px solid var(--line); border-radius:8px; padding:10px 12px; }
  .stat .n { font-size:20px; font-weight:700; } .stat .l { color:var(--muted); font-size:12px; }
  .sev { display:inline-block; padding:1px 7px; border-radius:10px; font-size:11px; font-weight:700; color:#fff; }
  .sev.critical{background:var(--crit)} .sev.high{background:var(--high)} .sev.medium{background:var(--med)}
  .sev.low{background:var(--low)} .sev.info{background:var(--info)}
  .muted { color:var(--muted); } .empty { color:var(--muted); font-style:italic; }
  @media print { body { padding:0; } h2 { break-after:avoid; } tr { break-inside:avoid; } }
</style></head>
<body>
  <h1>External Attack Surface — {{.Asset}}</h1>
  <div class="sub">Generated {{fmtTime .GeneratedAt}} · asset #{{.AssetID}} · client {{deref .ClientID}}
    {{with .Summary.LastRun}} · last scan {{fmtTime .StartedAt}} ({{.Profile}}, {{.RecordCount}} records){{end}}</div>

  <h2>Overview</h2>
  <div class="grid">
    {{range pairs .Summary.Counts}}<div class="stat"><div class="n">{{.Value}}</div><div class="l">{{.Key}}</div></div>{{end}}
  </div>

  <h2>Registration</h2>
  {{if .Summary.Registration}}<pre><code>{{printf "%s" .Summary.Registration}}</code></pre>{{else}}<p class="empty">No registration record.</p>{{end}}

  <h2>Email posture</h2>
  <table>
    <tr><th>SPF</th><td>{{present .Summary.Email.SPF}}</td></tr>
    <tr><th>DMARC</th><td>{{present .Summary.Email.DMARC}}{{with .Summary.Email.Policy}} · policy {{.}}{{end}}</td></tr>
  </table>

  <h2>Certificates</h2>
  <p>{{.Summary.Certs.Count}} certificate record(s){{with .Summary.Certs.SoonestNotAfter}} · soonest expiry {{.}}{{end}}.</p>

  <h2>IP / network</h2>
  {{if .Summary.IPs}}<table><tr><th>IP</th><th>Org</th><th>Network</th><th>Country</th></tr>
    {{range .Summary.IPs}}<tr><td><code>{{.IP}}</code></td><td>{{.Org}}</td><td>{{.Network}}</td><td>{{.Country}}</td></tr>{{end}}
  </table>{{else}}<p class="empty">No IP records.</p>{{end}}

  <h2>Subdomains ({{len .Summary.Subdomains}})</h2>
  {{if .Summary.Subdomains}}<div>{{range .Summary.Subdomains}}<code>{{.}}</code>&nbsp; {{end}}</div>{{else}}<p class="empty">No subdomains discovered.</p>{{end}}

  <h2>Security findings ({{len .Findings}})</h2>
  {{if .Findings}}<table><tr><th>Severity</th><th>Title</th><th>Reference</th></tr>
    {{range .Findings}}<tr><td><span class="sev {{.Severity}}">{{.Severity}}</span></td><td>{{.Title}}</td><td><code>{{.CVEID}}</code></td></tr>{{end}}
  </table>{{else}}<p class="empty">No open findings.</p>{{end}}

  <h2>Data quality</h2>
  <table>
    <tr><th>Total records</th><td>{{.Quality.TotalRecords}}</td></tr>
    <tr><th>Unverified</th><td>{{.Quality.Unverified}}</td></tr>
    <tr><th>Stale (not in latest scan)</th><td>{{.Quality.Stale}}</td></tr>
    <tr><th>By source</th><td>{{range pairs .Quality.BySource}}{{.Key}} ({{.Value}})&nbsp; {{end}}</td></tr>
    <tr><th>By method</th><td>{{range pairs .Quality.ByMethod}}{{.Key}} ({{.Value}})&nbsp; {{end}}</td></tr>
  </table>

  <h2>Record inventory ({{len .Records}})</h2>
  {{if .Records}}<table><tr><th>Category</th><th>Key</th><th>Source</th><th>Method</th><th>Last seen</th></tr>
    {{range .Records}}<tr><td>{{.Category}}</td><td><code>{{.Key}}</code></td><td>{{.Source}}</td><td>{{.Method}}</td><td class="muted">{{fmtTime .LastSeen}}</td></tr>{{end}}
  </table>{{else}}<p class="empty">No records.</p>{{end}}
</body></html>`
