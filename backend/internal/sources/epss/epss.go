// Package epss downloads the daily EPSS scores published by FIRST via
// Empirical Security (https://www.first.org/epss/data_stats).
package epss

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/fetch"
)

const feedURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

type Score struct {
	CVEID      string
	Score      float64
	Percentile float64
}

// Fetch returns every score and the date they were computed for. The file
// starts with a "#model_version:...,score_date:<RFC3339>" comment line, then
// a "cve,epss,percentile" header.
func Fetch(ctx context.Context, c *http.Client) (time.Time, []Score, error) {
	resp, err := fetch.Get(ctx, c, feedURL, nil)
	if err != nil {
		return time.Time{}, nil, err
	}
	defer resp.Body.Close()
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return time.Time{}, nil, err
	}
	defer gz.Close()
	return parse(gz)
}

func parse(r io.Reader) (time.Time, []Score, error) {
	br := bufio.NewReader(r)
	comment, err := br.ReadString('\n')
	if err != nil {
		return time.Time{}, nil, fmt.Errorf("read EPSS comment line: %w", err)
	}
	var scoreDate time.Time
	for _, part := range strings.Split(strings.TrimPrefix(strings.TrimSpace(comment), "#"), ",") {
		if v, ok := strings.CutPrefix(part, "score_date:"); ok {
			if scoreDate, err = time.Parse(time.RFC3339, v); err != nil {
				return time.Time{}, nil, fmt.Errorf("EPSS score_date %q: %w", v, err)
			}
		}
	}
	if scoreDate.IsZero() {
		return time.Time{}, nil, fmt.Errorf("EPSS file has no score_date in %q", comment)
	}

	cr := csv.NewReader(br)
	cr.ReuseRecord = true
	header, err := cr.Read()
	if err != nil {
		return time.Time{}, nil, err
	}
	if strings.Join(header, ",") != "cve,epss,percentile" {
		return time.Time{}, nil, fmt.Errorf("unexpected EPSS header %q", header)
	}
	scores := make([]Score, 0, 400_000)
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return time.Time{}, nil, err
		}
		score, err1 := strconv.ParseFloat(rec[1], 64)
		pct, err2 := strconv.ParseFloat(rec[2], 64)
		if err1 != nil || err2 != nil {
			return time.Time{}, nil, fmt.Errorf("bad EPSS row %q", rec)
		}
		scores = append(scores, Score{CVEID: strings.ToUpper(rec[0]), Score: score, Percentile: pct})
	}
	return scoreDate.UTC().Truncate(24 * time.Hour), scores, nil
}
