package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/oauth"
	"github.com/anywaye/identity/internal/platform/id"
)

func jsonUnmarshal(data []byte, into any) error { return json.Unmarshal(data, into) }


type oidcResponse struct {
	*httptest.ResponseRecorder
	JSON map[string]any
}

func newResponse(rec *httptest.ResponseRecorder) *oidcResponse {
	out := &oidcResponse{ResponseRecorder: rec}
	fields := map[string]any{}
	if err := jsonUnmarshal(rec.Body.Bytes(), &fields); err == nil {
		out.JSON = fields
	}
	return out
}

func mustCode(t *testing.T, location string) string {
	t.Helper()

	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("the redirect %q is not a URL: %v", location, err)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("the redirect %q carries no code", location)
	}
	return code
}

func mustParseID(t *testing.T, raw string) id.UUID {
	t.Helper()

	parsed, err := id.Parse(raw)
	if err != nil {
		t.Fatalf("the service returned an id that does not parse (%q): %v", raw, err)
	}
	return parsed
}

func newRequestWithBearer(method, target, token string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), method, target, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func newRequestNoCookie(method, target string) *http.Request {
	return httptest.NewRequestWithContext(context.Background(), method, target, nil)
}

func newRequestForm(method, target string, form url.Values) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func serveRecorder(handler http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func sortedKeys(fields map[string]any) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

const oauthStateSeparator = "."

func oauthVerifyState(provider, sealed, presented string) bool {
	return oauth.VerifyState(provider, sealed, presented)
}

func audienceContains(claim any, want string) bool {
	switch value := claim.(type) {
	case string:
		return value == want
	case []any:
		for _, entry := range value {
			if entry == want {
				return true
			}
		}
	}
	return false
}
