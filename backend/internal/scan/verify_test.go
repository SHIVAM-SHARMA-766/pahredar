package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// newTestScanner builds a scanner allowed to reach loopback (httptest servers).
func newTestScanner() *Scanner { return NewScanner(nil, true, nil) }

// collect runs fn and returns the verify-category findings it produced.
func collect(t *testing.T, srv *httptest.Server, fn func(sc *Scanner, base *url.URL, rep *Report, mu *sync.Mutex)) []Finding {
	t.Helper()
	sc := newTestScanner()
	base, _ := url.Parse(srv.URL)
	rep := &Report{Findings: []Finding{}}
	var mu sync.Mutex
	fn(sc, base, rep, &mu)
	return rep.Findings
}

func mkAdd(rep *Report, mu *sync.Mutex) addFn {
	return func(sev, title, detail string, ev *Evidence) {
		mu.Lock()
		rep.addEv(sev, "verify", title, detail, ev)
		mu.Unlock()
	}
}

func TestCORSReflectsOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	fs := collect(t, srv, func(sc *Scanner, base *url.URL, rep *Report, mu *sync.Mutex) {
		sc.checkCORS(context.Background(), base, mkAdd(rep, mu))
	})
	if len(fs) != 1 || fs[0].Severity != SevHigh {
		t.Fatalf("want 1 high CORS finding, got %+v", fs)
	}
	if fs[0].Evidence == nil || !strings.Contains(fs[0].Evidence.Response, "Access-Control-Allow-Origin") {
		t.Fatalf("missing evidence: %+v", fs[0].Evidence)
	}
}

func TestOpenRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := r.URL.Query().Get("next"); u != "" {
			http.Redirect(w, r, u, http.StatusFound)
			return
		}
		w.Write([]byte("home"))
	}))
	defer srv.Close()
	sc := newTestScanner()
	base, _ := url.Parse(srv.URL)
	rep := &Report{Findings: []Finding{}}
	var mu sync.Mutex
	nr := sc.newClient(5e9)
	nr.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	sc.checkOpenRedirect(context.Background(), nr, base, mkAdd(rep, &mu))
	if len(rep.Findings) != 1 || !strings.Contains(rep.Findings[0].Title, "Open redirect") {
		t.Fatalf("want open-redirect finding, got %+v", rep.Findings)
	}
	if rep.Findings[0].Evidence == nil || !strings.Contains(rep.Findings[0].Evidence.Response, "Location:") {
		t.Fatalf("missing Location evidence: %+v", rep.Findings[0].Evidence)
	}
}

func TestReflectedInput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>hi " + r.URL.Query().Get("pahredar") + "</html>"))
	}))
	defer srv.Close()
	fs := collect(t, srv, func(sc *Scanner, base *url.URL, rep *Report, mu *sync.Mutex) {
		sc.checkReflection(context.Background(), base, mkAdd(rep, mu))
	})
	if len(fs) != 1 || !strings.Contains(fs[0].Title, "Reflected") {
		t.Fatalf("want reflected-input finding, got %+v", fs)
	}
	if fs[0].Evidence == nil || fs[0].Evidence.Snippet == "" {
		t.Fatalf("missing snippet evidence: %+v", fs[0].Evidence)
	}
}

func TestReflectedInputEscapedIsSafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Properly escaped: < > encoded, so not exploitable.
		v := strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(r.URL.Query().Get("pahredar"))
		w.Write([]byte("<html>hi " + v + "</html>"))
	}))
	defer srv.Close()
	fs := collect(t, srv, func(sc *Scanner, base *url.URL, rep *Report, mu *sync.Mutex) {
		sc.checkReflection(context.Background(), base, mkAdd(rep, mu))
	})
	if len(fs) != 0 {
		t.Fatalf("escaped reflection should not be flagged, got %+v", fs)
	}
}

func TestDirListing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/uploads/" {
			w.Write([]byte("<html><head><title>Index of /uploads/</title></head><body>…</body></html>"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	fs := collect(t, srv, func(sc *Scanner, base *url.URL, rep *Report, mu *sync.Mutex) {
		sc.checkDirListing(context.Background(), base, mkAdd(rep, mu))
	})
	if len(fs) != 1 || !strings.Contains(fs[0].Title, "Directory listing") {
		t.Fatalf("want dir-listing finding, got %+v", fs)
	}
}

func TestDangerousMethods(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(201)
			return
		}
		w.WriteHeader(405)
	}))
	defer srv.Close()
	fs := collect(t, srv, func(sc *Scanner, base *url.URL, rep *Report, mu *sync.Mutex) {
		sc.checkMethods(context.Background(), base, mkAdd(rep, mu))
	})
	if len(fs) != 1 || !strings.Contains(fs[0].Title, "PUT accepted") {
		t.Fatalf("want PUT-accepted finding, got %+v", fs)
	}
}

func TestHostHeaderReflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>welcome to " + r.Host + "</html>"))
	}))
	defer srv.Close()
	sc := newTestScanner()
	base, _ := url.Parse(srv.URL)
	rep := &Report{Findings: []Finding{}}
	var mu sync.Mutex
	sc.checkHostHeader(context.Background(), base, base.Hostname(), mkAdd(rep, &mu))
	if len(rep.Findings) != 1 || !strings.Contains(rep.Findings[0].Title, "Host header reflected") {
		t.Fatalf("want host-header finding, got %+v", rep.Findings)
	}
}

func TestCleanServerNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(405)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>static</html>"))
	}))
	defer srv.Close()
	sc := newTestScanner()
	base, _ := url.Parse(srv.URL)
	rep := &Report{Findings: []Finding{}}
	var mu sync.Mutex
	sc.verify(context.Background(), base.Hostname(), base, rep, &mu, func() {})
	if len(rep.Findings) != 0 {
		t.Fatalf("clean server should have no verify findings, got %+v", rep.Findings)
	}
}
