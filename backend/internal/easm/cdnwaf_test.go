package easm

import (
	"net/http"
	"testing"
)

func TestCDNWAFRecords(t *testing.T) {
	h := http.Header{}
	h.Set("CF-Ray", "abc123-DEL")
	h.Set("Server", "cloudflare")
	recs := cdnWAFRecords(h)
	got := map[string]bool{}
	for _, r := range recs {
		got[r.Key] = true
	}
	if !got["cloudflare:cdn"] {
		t.Errorf("want cloudflare:cdn, got %v", got)
	}

	// CloudFront via Via header.
	h2 := http.Header{}
	h2.Set("Via", "1.1 abc.cloudfront.net (CloudFront)")
	h2.Set("X-Amz-Cf-Id", "xyz")
	recs2 := cdnWAFRecords(h2)
	if len(recs2) == 0 || recs2[0].Key != "aws cloudfront:cdn" {
		t.Errorf("cloudfront detection = %+v", recs2)
	}

	// Sucuri WAF.
	h3 := http.Header{}
	h3.Set("X-Sucuri-ID", "12")
	if recs3 := cdnWAFRecords(h3); len(recs3) != 1 || recs3[0].Key != "sucuri:waf" {
		t.Errorf("sucuri detection = %+v", recs3)
	}

	// No edge headers → no records.
	if recs4 := cdnWAFRecords(http.Header{}); len(recs4) != 0 {
		t.Errorf("want no records for plain headers, got %+v", recs4)
	}
}
