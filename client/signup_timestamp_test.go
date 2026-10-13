package client

// THE CLIENT'S HALF OF THE SIGNUP TIMESTAMP: MINT IT, THEN CARRY IT.
//
// # WHY THERE IS A TEST FILE FOR THIS AND NOT A COMMENT ON THE METHOD
//
// The pair is DELIBERATELY ABSENT from `openapi/v1.yaml` — a bot defense in the
// contract is a bot defense the next bot reads around — so the generated request
// body cannot carry it. That leaves two failure modes, and both of them are
// invisible:
//
//  1. the wrapper adds the pair and adds it WRONG. A body with the pair
//     misspelled, or a timestamp rendered as a string, is refused by the server
//     with the same generic `422` a bot defense gives, and a caller debugging it
//     has no way to tell a wiring mistake from a bot. So the wire bytes are
//     asserted here, not just the status.
//  2. the wrapper stops adding the pair. A registration then succeeds or fails
//     for reasons that have nothing to do with this code, and nothing in the
//     client says why.
//
// # AND THE NEGATIVE CONTROL
//
// `TestRegisterUserWithoutThePairIsStillRefusedTheSameWay` drives the documented
// `RegisterUser` against a server that REFUSES a body with no pair, which is what
// this service does. It exists because the honest shape of the wrapper is a
// convenience: a reader who saw only `RegisterUserWithSignupTimestamp` working
// would not know whether `RegisterUser` is broken, deprecated, or a live path
// that now always fails. It is a live path that always fails, deliberately, and
// the test says so.

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

	"github.com/cafaye/identity/client/generated"
)

// keysOf is the field names of a raw JSON object, for a failure message that has
// to say what the server actually received.
func keysOf(fields map[string]json.RawMessage) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// mintPair is a pair shaped like a real one: a Unix integer and a 43-character
// base64url signature (32 bytes, unpadded).
var mintPair = generated.SignupTimestamp{
	Timestamp: 1759843200,
	Signature: "gtgjejEJsFxhBcnLydfWAw4T0Sl1xZQQm44LIEN0lSw",
}

// registrationServer records the body it was sent and answers as asked.
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
			// A body that will not unmarshal is recorded as such rather than
			// ignored: the assertion this file exists for is about the bytes,
			// and a malformed body that parsed to nothing would look like a body
			// with no fields.
			_ = json.Unmarshal(raw, &s.sent)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

// TestRegisterUserWithSignupTimestampCarriesThePairOnTheWire is the wire shape.
//
// IT READS THE BYTES THE SERVER SAW rather than the arguments it was handed,
// because the whole risk in this wrapper is a transformation between those two
// points: a field spelled differently, a number rendered as a string, a body
// dropped on the way out.
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

	// The two fields the generated body cannot carry, under the names the handler
	// reads them by.
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

	// And the fields the caller's body already had survive the rewrite — a body
	// re-rendered from a map is a body that can quietly lose what it had.
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

// TestRegisterUserWithoutThePairIsStillRefusedTheSameWay is the negative
// control, and it is here because the wrapper above makes the documented method
// look vestigial.
//
// IT IS NOT VESTIGIL. `POST /v1/users` refuses a body with no pair — that is the
// defense — so `RegisterUser` against a real deployment always yields a
// `*ValidationError`. It is kept because it is the documented operation's method
// and a client whose method set changes without a document change is its own kind
// of drift; a caller that needs a registration to succeed uses the pair method.
func TestRegisterUserWithoutThePairIsStillRefusedTheSameWay(t *testing.T) {
	t.Parallel()

	// The server refuses a pairless body the way this service does: the generic
	// validation failure, naming nothing.
	const refusal = `{"type":"https://docs.cafaye.com/errors/validation_failed",` +
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
	// The refusal must not have invented a field name. The server named none, and
	// a wrapper that appended one would be naming the check the service hid.
	if strings.Contains(err.Error(), "timestamp") || strings.Contains(err.Error(), "signature") {
		t.Errorf("the error names the pair's fields: %v. The server's refusal named no field, and "+
			"this package must not add one the service deliberately withheld", err)
	}

	// And the pair really was absent — otherwise this test would be proving the
	// server's refusal rather than the client's omission.
	if _, present := server.sent["timestamp"]; present {
		t.Error("RegisterUser sent a timestamp, so this test is not measuring the pairless path")
	}
}

// TestTheMintAndTheRegisterAreTwoRoundTrips is the pairing: mint, then carry.
//
// It is the shape a form uses and the reason `MintSignupTimestamp` and
// `RegisterUserWithSignupTimestamp` are one feature rather than two — a mint
// with nothing to carry it on, and a register that requires a pair nothing
// mints, is a surface whose halves cannot be tested against each other.
func TestTheMintAndTheRegisterAreTwoRoundTrips(t *testing.T) {
	t.Parallel()

	// One server for both calls, so the pair the mint handed out is the pair the
	// register carries. Two servers would let this pass with two unrelated
	// values.
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

// TestThePairEditorRefusesABodyItCannotRewrite is the editor's own contract.
//
// IT IS A TABLE over the shapes that make the rewrite impossible, and every row
// expects an ERROR rather than a request. A body this function cannot parse must
// never reach the network with the pair silently missing: the server would answer
// the generic `422`, and the caller would be debugging a bot defense instead of
// the bug that is actually there.
//
// IT WAS WRITTEN BECAUSE A ROW IN IT PANICKED. `json.Unmarshal` of `null` into a
// map succeeds and leaves the map nil, and the assignment that follows panicked
// on it — a caller-supplied body taking the process down, which is the worst
// answer this package can give. The `null` row is the one that found it.
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
			// `null` is its own row rather than a member of the pattern above,
			// because it is the one input that unmarshals with NO error and still
			// leaves nothing to add fields to. A refusal that shares a message
			// with the malformed rows would hide which of the two happened.
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

// TestThePairEditorRefusesAnEmptyBody is the one shape the table above cannot
// build through `http.NewRequest`, because a reader turns "" into
// `http.NoBody` and `NoBody.Read` returns EOF rather than an error.
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

// TestThePairEditorNeverPutsTheSignatureInAnError is this package's own rule
// applied to a new value.
//
// A signature is a bearer credential for one form submission, and this package's
// invariant is that no credential reaches a string a human reads — an error
// message is the most likely one to end up in a log. Every refusal the editor can
// produce is driven here and swept.
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

// TestThePreflightRefusesBeforeAnyRequestGoesOut is why the pre-flight exists.
//
// THE EDITOR IS RUN TWICE — once here against a throwaway request, once on the
// real one — and this test is the reason a reader can be sure that is not a
// double-send. A transport that saw a request despite the pre-flight failing
// would be a request carrying no pair, which the server answers with the generic
// `422`: the caller would be handed a refusal about a bot defense for a body
// mistake, and the refusal would be indistinguishable from the real thing.
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

	// A body the editor cannot rewrite. The generated type cannot produce one —
	// it is two string fields — so the editor is exercised directly and the
	// transport is not involved at all, which is exactly the claim: the editor's
	// refusal does not depend on a request being built.
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

	// And the real path, which is the part that is actually wired: a well-formed
	// body goes out exactly ONCE. A pre-flight that also sent would show up here
	// as two, which is why the count is asserted rather than assumed.
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
