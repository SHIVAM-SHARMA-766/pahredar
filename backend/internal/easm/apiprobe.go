package easm

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// apiProbe actively looks for API surface — OpenAPI/Swagger schemas, API-docs
// UIs, and GraphQL endpoints — plus a permissive CORS signal (A12/A13). GET-only
// and bounded to a fixed path list; it never sends mutations. method=active.
type apiProbe struct{}

func (apiProbe) Name() string { return "api_probe" }

// apiPaths are well-known API discovery locations and the kind each implies.
var apiPaths = []struct{ path, kind string }{
	{"/openapi.json", "openapi"},
	{"/swagger.json", "swagger"},
	{"/v3/api-docs", "openapi"},
	{"/v2/api-docs", "swagger"},
	{"/api-docs", "swagger"},
	{"/.well-known/openapi", "openapi"},
	{"/swagger-ui/", "swagger-ui"},
	{"/graphql", "graphql"},
}

func (apiProbe) Collect(ctx context.Context, domain string) ([]db.AssetRecord, error) {
	client := wellKnownClient()
	out := []db.AssetRecord{}
	corsSeen := false
	for _, p := range apiPaths {
		status, body, acao := apiGet(ctx, client, "https://"+domain+p.path)
		if status == 0 {
			continue // request failed
		}
		if apiHit(p.kind, status, body) {
			out = append(out, recActive("api", p.path, "http_probe",
				map[string]any{"path": p.path, "kind": p.kind, "status": status}, "API discovery"))
		}
		if !corsSeen && strings.TrimSpace(acao) == "*" {
			corsSeen = true
			out = append(out, recActive("api", "cors", "http_probe",
				map[string]any{"access_control_allow_origin": "*", "seen_at": p.path}, "permissive CORS"))
		}
	}
	return out, nil
}

// apiHit decides whether a response indicates the expected API kind is present.
func apiHit(kind string, status int, body string) bool {
	lb := strings.ToLower(body)
	switch kind {
	case "graphql":
		// A GraphQL endpoint typically rejects a bare GET (400/405) but exists;
		// a 404 means it does not.
		return status != http.StatusNotFound
	case "swagger-ui":
		return status == http.StatusOK && (strings.Contains(lb, "swagger") || strings.Contains(lb, "redoc"))
	default: // openapi / swagger schema documents
		return status == http.StatusOK && (strings.Contains(lb, `"openapi"`) || strings.Contains(lb, `"swagger"`))
	}
}

// apiGet does a bounded GET, returning status, a body sample, and the
// Access-Control-Allow-Origin header. status 0 means the request failed.
func apiGet(ctx context.Context, client *http.Client, u string) (int, string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, "", ""
	}
	req.Header.Set("User-Agent", "pahredar-easm")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, string(body), resp.Header.Get("Access-Control-Allow-Origin")
}
