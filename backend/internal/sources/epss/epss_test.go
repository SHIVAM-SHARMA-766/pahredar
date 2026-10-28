package epss

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	date, scores, err := parse(strings.NewReader(
		"#model_version:v2026.06.15,score_date:2026-10-27T12:03:15Z\n" +
			"cve,epss,percentile\n" +
			"CVE-1999-0001,0.04753,0.91834\n" +
			"cve-2021-44228,0.94358,0.99990\n"))
	if err != nil {
		t.Fatal(err)
	}
	if date.Format("2006-01-02") != "2026-10-27" || date.Hour() != 0 {
		t.Fatalf("date = %s", date)
	}
	if len(scores) != 2 || scores[1].CVEID != "CVE-2021-44228" || scores[1].Score != 0.94358 {
		t.Fatalf("scores = %+v", scores)
	}
}

func TestParseRejectsMissingDateOrHeader(t *testing.T) {
	for _, in := range []string{
		"#model_version:v1\ncve,epss,percentile\n",
		"#score_date:2026-10-27T12:03:15Z\ncve,score\n",
	} {
		if _, _, err := parse(strings.NewReader(in)); err == nil {
			t.Errorf("parse(%q) succeeded", in)
		}
	}
}
