package client


import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/anywaye/identity/client/generated"
)

func keysOf(fields map[string]json.RawMessage) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

var mintPair = generated.SignupTimestamp{
	Timestamp: 1759843200,
	Signature: "gtgjejEJsFxhBcnLydfWAw4T0Sl1xZQQm44LIEN0lSw",
}

type registrationServer struct {
	*httptest.Server

	sent map[string]json.RawMessage
}

func newRegistrationServer(t *testing.T, status int, body string) *registrationServer {
	t.Helper()

	s := &registrationServer{sent: map[string]json.RawMessage{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err == nil {
			_ = json.Unmarshal(raw, &s.sent)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

func TestRegisterUserWithSignupTimestampCarriesThePairOnTheWire(t *testing.T) {
	t.Parallel()

	server := newRegistrationServer(t, http.StatusCreated, `{"id":"ab000000-0000-0000-0000-0000000000a1","email":"kaka@example.com"}`)
	client := newTestClient(t, server.URL, fakeSessionToken)

	body := generated.RegisterUserJSONRequestBody{
		Email:    "kaka@example.com",
		Password: "correct horse battery staple",
	}
	user, err := client.RegisterUserWithSignupTimestamp(context.Background(), body, mintPair)
	if err != nil {
		t.Fatalf("registering with a pair: %v", err)
	}
	if user.Email != "kaka@example.com" {
		t.Errorf("email = %q, want the registered address", user.Email)
	}

	raw, ok := server.sent["timestamp"]
	if !ok {
		t.Fatalf("the request carried no timestamp; fields sent: %v", keysOf(server.sent))
	}
	var timestamp int64
	if err := json.Unmarshal(raw, &timestamp); err != nil {
		t.Fatalf("timestamp was sent as %s, which is not an integer: %v", raw, err)
	}
	if timestamp != mintPair.Timestamp {
		t.Errorf("timestamp = %d, want the minted %d", timestamp, mintPair.Timestamp)
	}

	raw, ok = server.sent["signature"]
	if !ok {
		t.Fatalf("the request carried no signature; fields sent: %v", keysOf(server.sent))
	}
	var signature string
	if err := json.Unmarshal(raw, &signature); err != nil {
		t.Fatalf("signature was sent as %s, which is not a string: %v", raw, err)
	}
	if signature != mintPair.Signature {
		t.Errorf("signature = %q, want the minted pair's signature", signature)
	}

	for field, want := range map[string]string{"email": string(body.Email), "password": body.Password} {
		raw, ok := server.sent[field]
		if !ok {
			t.Errorf("the rewrite dropped %q; fields sent: %v", field, keysOf(server.sent))
			continue
		}
		var got string
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Errorf("%s was sent as %s, which is not a string: %v", field, raw, err)
			continue
		}
		if got != want {
			t.Errorf("%s = %q, want %q", field, got, want)
		}
	}
}

func TestRegisterUserWithoutThePairIsStillRefusedTheSameWay(t *testing.T) {
	t.Parallel()

	const refusal = `{"type":"https://docs.anywaye.com/errors/validation_failed",` +
		`"title":"Validation failed","status":422,` +
		`"detail":"the request has an invalid field",` +
		`"code":"validation_failed","trace_id":"0f9c2a1e-0000-4000-8000-000000000000"}`
	server := newRegistrationServer(t, http.StatusUnprocessableEntity, refusal)
	client := newTestClient(t, server.URL, fakeSessionToken)

	_, err := client.RegisterUser(context.Background(), generated.RegisterUserJSONRequestBody{
		Email:    "kaka@example.com",
		Password: "correct horse battery staple",
	})

	var validation *ValidationError
	if !errorsAs(err, &validation) {
		t.Fatalf("err = %v, want a *ValidationError the way every other 422 in this document arrives", err)
	}
	if strings.Contains(err.Error(), "timestamp") || strings.Contains(err.Error(), "signature") {
		t.Errorf("the error names the pair's fields: %v. The server's refusal named no field, and "+
			"this package must not add one the service deliberately withheld", err)
	}

	if _, present := server.sent["timestamp"]; present {
		t.Error("RegisterUser sent a timestamp, so this test is not measuring the pairless path")
	}
}

func TestTheMintAndTheRegisterAreTwoRoundTrips(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	var carried json.RawMessage
	mux.HandleFunc("/v1/signup-timestamp", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"timestamp":1759843200,"signature":"` + mintPair.Signature + `"}`))
	})
	mux.HandleFunc("/v1/users", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		carried = fields["signature"]
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"ab000000-0000-0000-0000-0000000000a1","email":"kaka@example.com"}`))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client := newTestClient(t, server.URL, fakeSessionToken)

	minted, err := client.MintSignupTimestamp(context.Background())
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	if minted.Signature != mintPair.Signature {
		t.Fatalf("minted signature = %q, want the server's %q", minted.Signature, mintPair.Signature)
	}

	if _, err := client.RegisterUserWithSignupTimestamp(context.Background(),
		generated.RegisterUserJSONRequestBody{
			Email:    "kaka@example.com",
			Password: "correct horse battery staple",
		}, *minted); err != nil {
		t.Fatalf("registering with the minted pair: %v", err)
	}

	var signature string
	if err := json.Unmarshal(carried, &signature); err != nil {
		t.Fatalf("the register carried %s, which is not a string: %v", carried, err)
	}
	if signature != mintPair.Signature {
		t.Errorf("the register carried %q, want the pair the mint handed out %q", signature, mintPair.Signature)
	}
}

func TestThePairEditorRefusesABodyItCannotRewrite(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "a body that is not JSON at all",
			body: "this is not json",
			want: "not a JSON object",
		},
		{
			name: "a JSON array is not an object the fields can be added to",
			body: `["kaka@example.com"]`,
			want: "not a JSON object",
		},
		{
			name: "a bare JSON string",
			body: `"kaka@example.com"`,
			want: "not a JSON object",
		},
		{
			name: "a JSON null",
			body: `null`,
			want: "JSON null",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://identity.example.com/v1/users",
				strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("building the request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")

			if err := withSignupTimestamp(mintPair)(context.Background(), req); err == nil {
				t.Fatalf("the editor accepted %q; the request would go out with no pair and the server "+
					"would answer the generic 422, which is indistinguishable from a bot", tt.body)
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to say %q", err, tt.want)
			}
		})
	}
}

func TestThePairEditorRefusesAnEmptyBody(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://identity.example.com/v1/users", http.NoBody)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}

	err = withSignupTimestamp(mintPair)(context.Background(), req)
	if err == nil {
		t.Fatal("the editor accepted a body-less registration; the pair would be dropped")
	}
	if !strings.Contains(err.Error(), "empty body") && !strings.Contains(err.Error(), "no body") {
		t.Errorf("error = %q, want it to name the missing body rather than report a JSON parse failure "+
			"about this function's own input", err)
	}
}

func TestThePairEditorNeverPutsTheSignatureInAnError(t *testing.T) {
	t.Parallel()

	bodies := []string{
		"this is not json",
		`["kaka@example.com"]`,
		`"kaka@example.com"`,
		`null`,
		string(make([]byte, 0)),
	}

	for _, body := range bodies {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			"https://identity.example.com/v1/users", strings.NewReader(body))
		if err != nil {
			t.Fatalf("building the request: %v", err)
		}

		err = withSignupTimestamp(mintPair)(context.Background(), req)
		if err == nil {
			continue
		}
		for _, verb := range []string{"%v", "%+v", "%s", "%q"} {
			printed := fmt.Sprintf(verb, err)
			if strings.Contains(printed, mintPair.Signature) {
				t.Errorf("%s of the editor's error carries the signature: %s", verb, printed)
			}
		}
	}
}

func TestThePreflightRefusesBeforeAnyRequestGoesOut(t *testing.T) {
	t.Parallel()

	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"ab000000-0000-0000-0000-0000000000a1","email":"kaka@example.com"}`))
	}))
	t.Cleanup(server.Close)
	client := newTestClient(t, server.URL, fakeSessionToken)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		server.URL+"/v1/users", strings.NewReader("not json"))
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	if err := withSignupTimestamp(mintPair)(context.Background(), req); err == nil {
		t.Fatal("the editor accepted a body it cannot rewrite")
	}
	if requests != 0 {
		t.Errorf("%d requests reached the server, want 0", requests)
	}

	user, err := client.RegisterUserWithSignupTimestamp(context.Background(),
		generated.RegisterUserJSONRequestBody{
			Email:    "kaka@example.com",
			Password: "correct horse battery staple",
		}, mintPair)
	if err != nil {
		t.Fatalf("registering with a pair: %v", err)
	}
	if user.Email != "kaka@example.com" {
		t.Errorf("email = %q, want the registered address", user.Email)
	}
	if requests != 1 {
		t.Errorf("%d requests reached the server, want exactly 1 — the pre-flight must not send", requests)
	}
}
