package easm

import (
	"encoding/json"
	"testing"
)

func TestWaybackRecords(t *testing.T) {
	rows := [][]string{
		{"original"}, // header
		{"https://example.com/"},
		{"https://example.com/login"},
		{"http://api.example.com/v1/users"},
		{"https://example.com/login"}, // dup path
		{"https://evil.com/phish"},    // off-scope
		{"not a url"},
	}
	recs := waybackRecords("example.com", rows)

	subs, urls := map[string]bool{}, map[string]bool{}
	for _, r := range recs {
		switch r.Category {
		case "subdomain":
			subs[r.Key] = true
		case "url":
			urls[r.Key] = true
			if r.Source != "wayback" {
				t.Errorf("url source = %q, want wayback", r.Source)
			}
		}
	}
	if !subs["api.example.com"] || len(subs) != 1 {
		t.Errorf("subs = %v, want only api.example.com", subs)
	}
	if !urls["example.com/login"] || !urls["api.example.com/v1/users"] {
		t.Errorf("urls = %v, missing expected paths", urls)
	}
	if urls["example.com/"] {
		t.Error("root path '/' must not be stored as a url record")
	}
	for k := range urls {
		if k == "evil.com/phish" {
			t.Error("off-scope host must be dropped")
		}
	}
	// url record data carries host + path.
	for _, r := range recs {
		if r.Category == "url" && r.Key == "api.example.com/v1/users" {
			var d struct{ Host, Path string }
			_ = json.Unmarshal(r.Data, &d)
			if d.Host != "api.example.com" || d.Path != "/v1/users" {
				t.Errorf("url data = %+v", d)
			}
		}
	}
}
