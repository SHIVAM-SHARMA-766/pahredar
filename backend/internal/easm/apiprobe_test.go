package easm

import "testing"

func TestAPIHit(t *testing.T) {
	cases := []struct {
		kind   string
		status int
		body   string
		want   bool
	}{
		{"openapi", 200, `{"openapi":"3.0.0"}`, true},
		{"swagger", 200, `{"swagger":"2.0"}`, true},
		{"openapi", 200, `<html>not json</html>`, false},
		{"openapi", 404, `{"openapi":"3.0.0"}`, false}, // not served
		{"swagger-ui", 200, `<title>Swagger UI</title>`, true},
		{"swagger-ui", 200, `<html>nope</html>`, false},
		{"graphql", 400, ``, true},  // GET rejected but endpoint exists
		{"graphql", 405, ``, true},  // method not allowed → exists
		{"graphql", 404, ``, false}, // absent
	}
	for _, c := range cases {
		if got := apiHit(c.kind, c.status, c.body); got != c.want {
			t.Errorf("apiHit(%q,%d,%q) = %v, want %v", c.kind, c.status, c.body, got, c.want)
		}
	}
}
