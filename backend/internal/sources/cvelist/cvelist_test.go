package cvelist

import (
	"archive/zip"
	"bytes"
	"testing"
)

func TestExtractFirstEntryStreamsNestedZip(t *testing.T) {
	// Build inner.zip holding one CVE file, then wrap it the way the baseline
	// asset is wrapped: an outer zip whose only entry is the inner zip.
	var inner bytes.Buffer
	iw := zip.NewWriter(&inner)
	f, _ := iw.Create("cves/2024/1xxx/CVE-2024-1234.json")
	f.Write([]byte(`{"id":1}`))
	iw.Create("cves/delta.json") // not a CVE file; must be skipped
	iw.Close()

	var outer bytes.Buffer
	ow := zip.NewWriter(&outer)
	of, _ := ow.CreateHeader(&zip.FileHeader{Name: "cves.zip", Method: zip.Deflate})
	of.Write(inner.Bytes())
	ow.Close()

	var extracted bytes.Buffer
	if err := extractFirstEntry(bytes.NewReader(outer.Bytes()), &extracted); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(extracted.Bytes()), int64(extracted.Len()))
	if err != nil {
		t.Fatalf("inner zip unreadable: %v", err)
	}
	var got []string
	if err := forEachEntry(t.Context(), zr, func(b []byte) error { got = append(got, string(b)); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != `{"id":1}` {
		t.Fatalf("entries = %q", got)
	}
}

func TestReleaseHourly(t *testing.T) {
	cases := map[string]bool{
		"cve_2026-10-28_0700Z":         true,
		"cve_2026-10-27_at_end_of_day": false,
		"something_else":               false,
	}
	for tag, want := range cases {
		day, hour, ok := Release{Tag: tag}.Hourly()
		if ok != want {
			t.Errorf("%s: ok = %v", tag, ok)
		}
		if ok && (day != "2026-10-28" || hour != "0700Z") {
			t.Errorf("%s: day %s hour %s", tag, day, hour)
		}
	}
}
