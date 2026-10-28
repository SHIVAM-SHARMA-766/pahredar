// Package cwe downloads CWE names from MITRE's research view (CWE-1000).
package cwe

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/fetch"
)

const feedURL = "https://cwe.mitre.org/data/csv/1000.csv.zip"

type Weakness struct {
	ID   string // CWE-79
	Name string
}

// Fetch returns every weakness in the view. The zip holds one CSV whose first
// two columns are "CWE-ID" (a bare number) and "Name".
func Fetch(ctx context.Context, c *http.Client) ([]Weakness, error) {
	resp, err := fetch.Get(ctx, c, feedURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("open CWE zip: %w", err)
	}
	if len(zr.File) != 1 {
		return nil, fmt.Errorf("CWE zip has %d files, want 1", len(zr.File))
	}
	f, err := zr.File[0].Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parse(f)
}

func parse(r io.Reader) ([]Weakness, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	header, err := cr.Read()
	if err != nil {
		return nil, err
	}
	if len(header) < 2 || header[0] != "CWE-ID" || header[1] != "Name" {
		return nil, fmt.Errorf("unexpected CWE header %q", header)
	}
	var out []Weakness
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		id, name := strings.TrimSpace(rec[0]), strings.TrimSpace(rec[1])
		if id == "" || name == "" {
			continue
		}
		out = append(out, Weakness{ID: "CWE-" + id, Name: name})
	}
	return out, nil
}
