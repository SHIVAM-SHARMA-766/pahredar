package db

import (
	"context"
	"fmt"
	"time"
)

// MaxSeriesDays bounds a series request (about three years of days).
const MaxSeriesDays = 1100

// SeriesKey is one plotted series of a metric.
type SeriesKey struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

// SeriesPoint is one UTC day; Values holds a count per series key, with
// every key present.
type SeriesPoint struct {
	Date   time.Time      `json:"date"`
	Values map[string]int `json:"values"`
}

type Series struct {
	Metric string        `json:"metric"`
	Label  string        `json:"label"`
	Keys   []SeriesKey   `json:"keys"`
	Points []SeriesPoint `json:"points"`
}

type metricDef struct {
	label string
	keys  []SeriesKey
	// query returns (day, key, count) rows for days in [$1, $2).
	query string
}

// metrics are the daily series the dashboard chart can plot. Keys are listed
// in stacking order, bottom first.
var metrics = map[string]metricDef{
	"published": {
		label: "CVEs published",
		keys: []SeriesKey{
			{"critical", "Critical"}, {"high", "High"}, {"medium", "Medium"}, {"low", "Low"}, {"other", "Unscored"},
		},
		query: `SELECT date_trunc('day', date_published AT TIME ZONE 'UTC'),
		               CASE severity WHEN 'CRITICAL' THEN 'critical' WHEN 'HIGH' THEN 'high'
		                             WHEN 'MEDIUM' THEN 'medium' WHEN 'LOW' THEN 'low' ELSE 'other' END,
		               count(*)
		        FROM cve WHERE state = 'PUBLISHED' AND date_published >= $1 AND date_published < $2
		        GROUP BY 1, 2`,
	},
	"kev_added": {
		label: "CVEs added to CISA KEV",
		keys:  []SeriesKey{{"ransomware", "Known ransomware use"}, {"other", "Other"}},
		query: `SELECT date_added::timestamp,
		               CASE WHEN known_ransomware_use = 'Known' THEN 'ransomware' ELSE 'other' END,
		               count(*)
		        FROM kev WHERE date_added >= $1 AND date_added < $2
		        GROUP BY 1, 2`,
	},
	"exploits": {
		label: "Public exploits published",
		keys:  []SeriesKey{{"exploitdb", "Exploit-DB"}, {"metasploit", "Metasploit"}},
		query: `SELECT date_trunc('day', published_at AT TIME ZONE 'UTC'), source, count(DISTINCT source_ref)
		        FROM exploit
		        WHERE source IN ('exploitdb', 'metasploit') AND published_at >= $1 AND published_at < $2
		        GROUP BY 1, 2`,
	},
}

// IsMetric reports whether name is a metric DailySeries knows.
func IsMetric(name string) bool {
	_, ok := metrics[name]
	return ok
}

// DailySeries returns one point per UTC day in [from, to] (inclusive).
func (s *Store) DailySeries(ctx context.Context, metric string, from, to time.Time) (*Series, error) {
	def, ok := metrics[metric]
	if !ok {
		return nil, fmt.Errorf("unknown metric %q", metric)
	}
	from, to = from.UTC().Truncate(24*time.Hour), to.UTC().Truncate(24*time.Hour)
	end := to.AddDate(0, 0, 1)

	rows, err := s.pool.Query(ctx, def.query, from, end)
	if err != nil {
		return nil, err
	}
	counts := map[time.Time]map[string]int{}
	for rows.Next() {
		var day time.Time
		var key string
		var n int
		if err := rows.Scan(&day, &key, &n); err != nil {
			rows.Close()
			return nil, err
		}
		day = time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC)
		if counts[day] == nil {
			counts[day] = map[string]int{}
		}
		counts[day][key] += n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := &Series{Metric: metric, Label: def.label, Keys: def.keys}
	for day := from; day.Before(end); day = day.AddDate(0, 0, 1) {
		values := make(map[string]int, len(def.keys))
		for _, k := range def.keys {
			values[k.Key] = counts[day][k.Key]
		}
		out.Points = append(out.Points, SeriesPoint{Date: day, Values: values})
	}
	return out, nil
}
