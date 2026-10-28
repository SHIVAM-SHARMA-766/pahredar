package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// DashboardDays is the length of the daily publish-volume series.
const DashboardDays = 90

type Dashboard struct {
	GeneratedAt time.Time `json:"generated_at"`
	// Counts of published CVEs by publish date (UTC days; today is partial).
	PublishedToday int `json:"published_today"`
	Published7d    int `json:"published_7d"`
	Published30d   int `json:"published_30d"`
	Critical7d     int `json:"critical_7d"`
	TotalPublished int `json:"total_published"`
	KEVTotal       int `json:"kev_total"`
	KEVAdded30d    int `json:"kev_added_30d"`
	// Severity mix of CVEs published in the last 30 days.
	Severity30d SeverityMix  `json:"severity_30d"`
	Daily       []DailyCount `json:"daily"`
	EPSSMovers  []EPSSMover  `json:"epss_movers"`
}

type SeverityMix struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	// Other is NONE plus UNKNOWN (not yet scored).
	Other int `json:"other"`
}

type DailyCount struct {
	Date time.Time `json:"date"`
	SeverityMix
}

type EPSSMover struct {
	CVEID     string    `json:"id"`
	Title     *string   `json:"title"`
	Severity  string    `json:"severity"`
	KEV       bool      `json:"kev"`
	From      float64   `json:"from"`
	To        float64   `json:"to"`
	ScoreDate time.Time `json:"score_date"`
}

const severityMixCols = `
	count(*) FILTER (WHERE severity = 'CRITICAL'),
	count(*) FILTER (WHERE severity = 'HIGH'),
	count(*) FILTER (WHERE severity = 'MEDIUM'),
	count(*) FILTER (WHERE severity = 'LOW'),
	count(*) FILTER (WHERE severity IN ('NONE', 'UNKNOWN'))`

// Dashboard aggregates the landing page's numbers. now is passed in so the
// day boundaries are explicit (UTC).
func (s *Store) Dashboard(ctx context.Context, now time.Time) (*Dashboard, error) {
	today := now.UTC().Truncate(24 * time.Hour)
	d := &Dashboard{GeneratedAt: now.UTC()}

	m := &d.Severity30d
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE date_published >= $1),
		       count(*) FILTER (WHERE date_published >= $2),
		       count(*),
		       count(*) FILTER (WHERE date_published >= $2 AND severity = 'CRITICAL'),`+severityMixCols+`
		FROM cve WHERE state = 'PUBLISHED' AND date_published >= $3`,
		today, today.AddDate(0, 0, -6), today.AddDate(0, 0, -29)).Scan(
		&d.PublishedToday, &d.Published7d, &d.Published30d, &d.Critical7d,
		&m.Critical, &m.High, &m.Medium, &m.Low, &m.Other)
	if err != nil {
		return nil, err
	}

	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM cve WHERE state = 'PUBLISHED'`).Scan(&d.TotalPublished); err != nil {
		return nil, err
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE date_added >= $1) FROM kev`,
		today.AddDate(0, 0, -29)).Scan(&d.KEVTotal, &d.KEVAdded30d); err != nil {
		return nil, err
	}

	// Daily series with every day present, including days with no CVEs.
	start := today.AddDate(0, 0, -(DashboardDays - 1))
	rows, err := s.pool.Query(ctx, `
		SELECT date_trunc('day', date_published AT TIME ZONE 'UTC'),`+severityMixCols+`
		FROM cve WHERE state = 'PUBLISHED' AND date_published >= $1
		GROUP BY 1`, start)
	if err != nil {
		return nil, err
	}
	byDay := map[time.Time]SeverityMix{}
	for rows.Next() {
		var day time.Time
		var mix SeverityMix
		if err := rows.Scan(&day, &mix.Critical, &mix.High, &mix.Medium, &mix.Low, &mix.Other); err != nil {
			rows.Close()
			return nil, err
		}
		byDay[time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC)] = mix
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	d.Daily = make([]DailyCount, DashboardDays)
	for i := range d.Daily {
		day := start.AddDate(0, 0, i)
		d.Daily[i] = DailyCount{Date: day, SeverityMix: byDay[day]}
	}

	// Largest EPSS increases over the last 7 days (epss.delta_7d, written by
	// the EPSS sync). Empty until a week of history exists.
	rows, err = s.pool.Query(ctx, `
		SELECT e.cve_id, c.title, c.severity, EXISTS (SELECT 1 FROM kev k WHERE k.cve_id = e.cve_id),
		       e.score_7d_ago, e.score, e.score_date
		FROM epss e JOIN cve c ON c.id = e.cve_id
		WHERE e.delta_7d > 0
		ORDER BY e.delta_7d DESC NULLS LAST, e.cve_id
		LIMIT 10`)
	if err != nil {
		return nil, err
	}
	d.EPSSMovers, err = pgx.CollectRows(rows, pgx.RowToStructByPos[EPSSMover])
	if err != nil {
		return nil, err
	}
	if d.EPSSMovers == nil {
		d.EPSSMovers = []EPSSMover{}
	}
	return d, nil
}
