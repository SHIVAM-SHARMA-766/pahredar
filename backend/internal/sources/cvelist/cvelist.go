// Package cvelist downloads CVE records from the CVEProject/cvelistV5 GitHub
// releases. Each hourly release carries:
//
//   - YYYY-MM-DD_all_CVEs_at_midnight.zip.zip: the full corpus at 00:00 UTC
//     (a zip containing one entry, cves.zip, which holds one JSON file per CVE)
//   - YYYY-MM-DD_delta_CVEs_at_HHMMZ.zip: every record changed since 00:00 UTC
//     that day (cumulative, not just the last hour)
//
// After midnight a cve_YYYY-MM-DD_at_end_of_day release adds the full-day
// delta for the previous day.
package cvelist

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

const apiBase = "https://api.github.com/repos/CVEProject/cvelistV5"

// maxRecordSize bounds a single CVE JSON file; real records are a few KB.
const maxRecordSize = 16 << 20

var (
	entryPattern  = regexp.MustCompile(`^CVE-\d{4}-\d{4,}\.json$`)
	hourlyPattern = regexp.MustCompile(`^cve_(\d{4}-\d{2}-\d{2})_(\d{4}Z)$`)
)

type Client struct {
	http    *http.Client
	token   string
	dataDir string
}

// New returns a client. token is an optional GitHub token; dataDir holds the
// temporary extracted baseline (~700 MB) during a bootstrap.
func New(token, dataDir string) *Client {
	return &Client{
		http: &http.Client{Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ResponseHeaderTimeout: 60 * time.Second,
			IdleConnTimeout:       90 * time.Second,
		}},
		token:   token,
		dataDir: dataDir,
	}
}

type Release struct {
	Tag    string  `json:"tag_name"`
	Assets []Asset `json:"assets"`
}

type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// Asset returns the first asset whose name ends with suffix.
func (r Release) Asset(suffix string) (Asset, bool) {
	for _, a := range r.Assets {
		if strings.HasSuffix(a.Name, suffix) {
			return a, true
		}
	}
	return Asset{}, false
}

// Hourly reports the day and hour ("0700Z") of an hourly release tag.
func (r Release) Hourly() (day, hour string, ok bool) {
	m := hourlyPattern.FindStringSubmatch(r.Tag)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

func (c *Client) Latest(ctx context.Context) (Release, error) {
	var r Release
	found, err := c.getJSON(ctx, apiBase+"/releases/latest", &r)
	if err == nil && !found {
		err = errors.New("no latest release")
	}
	return r, err
}

// ByTag returns the release with the given tag; found is false on 404.
func (c *Client) ByTag(ctx context.Context, tag string) (r Release, found bool, err error) {
	found, err = c.getJSON(ctx, apiBase+"/releases/tags/"+tag, &r)
	return r, found, err
}

// Recent returns the newest releases (about two days' worth).
func (c *Client) Recent(ctx context.Context) ([]Release, error) {
	var rs []Release
	_, err := c.getJSON(ctx, apiBase+"/releases?per_page=50", &rs)
	return rs, err
}

func (c *Client) getJSON(ctx context.Context, url string, v any) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return false, fmt.Errorf("GET %s: %s: %s", url, resp.Status, bytes.TrimSpace(body))
	}
	return true, json.NewDecoder(resp.Body).Decode(v)
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", "pahredar")
	return c.http.Do(req)
}

func (c *Client) download(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return resp, nil
}

// ForEachInDelta downloads a delta zip and calls fn with each CVE record.
func (c *Client) ForEachInDelta(ctx context.Context, a Asset, fn func([]byte) error) error {
	resp, err := c.download(ctx, a.URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<30))
	if err != nil {
		return fmt.Errorf("read %s: %w", a.Name, err)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return fmt.Errorf("open %s: %w", a.Name, err)
	}
	return forEachEntry(ctx, zr, fn)
}

// ForEachInBaseline downloads the full-corpus baseline and calls fn with each
// CVE record. The outer zip is decompressed while streaming, so only the
// inner cves.zip touches disk; it is removed before returning.
func (c *Client) ForEachInBaseline(ctx context.Context, a Asset, fn func([]byte) error) error {
	resp, err := c.download(ctx, a.URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	tmp, err := os.CreateTemp(c.dataDir, "cves-*.zip")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	if err := extractFirstEntry(resp.Body, tmp); err != nil {
		return fmt.Errorf("extract %s: %w", a.Name, err)
	}
	size, err := tmp.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(tmp, size)
	if err != nil {
		return fmt.Errorf("open inner zip: %w", err)
	}
	return forEachEntry(ctx, zr, fn)
}

// extractFirstEntry streams the first entry of a zip archive from r to w,
// reading the local file header instead of the central directory (which sits
// at the end of the archive and would require buffering the whole download).
func extractFirstEntry(r io.Reader, w io.Writer) error {
	br := bufio.NewReaderSize(r, 1<<20)
	var hdr [30]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return err
	}
	if binary.LittleEndian.Uint32(hdr[0:4]) != 0x04034b50 {
		return errors.New("not a zip local file header")
	}
	method := binary.LittleEndian.Uint16(hdr[8:10])
	compressed := int64(binary.LittleEndian.Uint32(hdr[18:22]))
	skip := int64(binary.LittleEndian.Uint16(hdr[26:28])) + int64(binary.LittleEndian.Uint16(hdr[28:30]))
	if _, err := io.CopyN(io.Discard, br, skip); err != nil {
		return err
	}
	switch method {
	case zip.Deflate:
		fr := flate.NewReader(br)
		defer fr.Close()
		_, err := io.Copy(w, fr)
		return err
	case zip.Store:
		_, err := io.CopyN(w, br, compressed)
		return err
	default:
		return fmt.Errorf("unsupported compression method %d", method)
	}
}

func forEachEntry(ctx context.Context, zr *zip.Reader, fn func([]byte) error) error {
	for _, f := range zr.File {
		if !entryPattern.MatchString(path.Base(f.Name)) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open %s: %w", f.Name, err)
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxRecordSize))
		rc.Close()
		if err != nil {
			return fmt.Errorf("read %s: %w", f.Name, err)
		}
		if err := fn(data); err != nil {
			return err
		}
	}
	return nil
}
