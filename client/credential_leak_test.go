package client


import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/client/generated"
)

const fakeToken = "anywaye_FAKE_FAKE_FAKE_FAKE_FAKE_FAKE_FAKE_FAKE_FAKE_FA"

const fakeSessionToken = "FAKEfakeSessionTokenFAKEfakeSessionTokenFAKEfake"

var leakyResponseHeaders = map[string]string{
	"Set-Cookie": "__Host-session=" + fakeToken + "; Path=/; Secure; HttpOnly; SameSite=Lax",
	"Authorization": "Bearer " + fakeToken,
	"X-Debug-Request": "Cookie: __Host-session=" + fakeToken,
	"X-Request-Id": fakeToken,
}

const leakyProblemBody = `{
  "type": "https://docs.anywaye.com/errors/validation_failed",
  "title": "Validation failed",
  "status": 422,
  "detail": "the field 'token' was rejected: '` + fakeToken + `'",
  "instance": "/v1/me",
  "code": "validation_failed",
  "trace_id": "0af7651916cd43dd8448eb211c80319c",
  "errors": [{"field": "token", "code": "invalid_format"}]
}`

func TestTheClientNeverPrintsACredential(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token string
	}{
		{"a scoped api token", fakeToken},
		{"a session token", fakeSessionToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := leakyServer(t)
			defer server.Close()

			client := newTestClient(t, server.URL, tc.token)

			user, err := client.GetCurrentUser(context.Background())
			if err != nil {
				t.Fatalf("the success path must succeed for this test to mean anything: %v", err)
			}
			if user.Email != "someone@example.com" {
				t.Fatalf("the fixture answered with %q, so this test is not exercising the "+
					"success path it claims to", user.Email)
			}
			sweep(t, "after a successful call", tc.token, client, nil)

			failure := leakyServerFailure(t)
			defer failure.Close()

			failing := newTestClient(t, failure.URL, tc.token)
			_, err = failing.GetCurrentUser(context.Background())
			if err == nil {
				t.Fatal("the failure fixture answered successfully, so the error path this " +
					"test claims to exercise was never taken")
			}
			sweep(t, "after a failed call", tc.token, failing, err)
		})
	}
}

func sweep(t *testing.T, when, token string, client *Client, err error) {
	t.Helper()

	surfaces := map[string]string{}

	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		surfaces["fmt.Sprintf("+verb+", client)"] = fmt.Sprintf(verb, client)
		surfaces["fmt.Sprintf("+verb+", client.Transport())"] = fmt.Sprintf(verb, client.Transport())
	}

	surfaces["client.BaseURL()"] = client.BaseURL()
	surfaces["client.HasCredential()"] = fmt.Sprintf("%v", client.HasCredential())

	if err != nil {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			surfaces["error "+verb] = fmt.Sprintf(verb, err)
		}
		surfaces["redactor.Error(err)"] = client.redactor.Error(err)

		for link, depth := err, 0; link != nil && depth < 8; depth++ {
			unwrapper, ok := link.(interface{ Unwrap() error })
			if !ok {
				break
			}
			link = unwrapper.Unwrap()
			if link != nil {
				surfaces[fmt.Sprintf("error chain link %d", depth)] = fmt.Sprintf("%+v", link)
			}
		}
	}

	surfaces["reflected client fields"] = reflectAll(client)

	for name, value := range secretBearingValues() {
		surfaces["client.SafeToLog(generated."+name+")"] = client.SafeToLog(value)
	}

	for surface, printed := range surfaces {
		if strings.Contains(printed, token) {
			t.Errorf("the credential appears in %s %s.\n\n"+
				"printed as: %s\n\n"+
				"This is the security invariant this package rests on: a credential must "+
				"reach no string a human reads — not a log record, not an error message, "+
				"not a serialized form, not a `fmt.Stringer`, not a `%%v` of the client. "+
				"The fix is in the redactor, not at the call site: every string this "+
				"package builds out of anything a caller or a service supplied goes "+
				"through Redactor.String.",
				surface, when, truncate(printed, 400))
		}
	}
}

func reflectAll(value any) string {
	var out strings.Builder
	seen := map[uintptr]bool{}

	var walk func(reflect.Value, int)
	walk = func(v reflect.Value, depth int) {
		if depth > 6 || !v.IsValid() {
			return
		}

		switch v.Kind() {
		case reflect.Struct:
			if v.CanAddr() {
				if seen[v.Addr().Pointer()] {
					return
				}
				seen[v.Addr().Pointer()] = true
			}

			t := v.Type()
			for i := 0; i < v.NumField(); i++ {
				field := t.Field(i)

				if field.IsExported() {
					out.WriteString(field.Name + "=")
				} else {
					out.WriteString("unexported:" + field.Name + "=")
				}

				if !field.IsExported() {
					out.WriteString("<unreadable>")
					out.WriteString("\n")
					continue
				}

				walk(v.Field(i), depth+1)
				out.WriteString("\n")
			}

		case reflect.Pointer, reflect.Interface:
			if v.IsNil() {
				out.WriteString("<nil>")
				return
			}
			walk(v.Elem(), depth+1)

		case reflect.Slice, reflect.Array:
			for i := 0; i < v.Len() && i < 16; i++ {
				walk(v.Index(i), depth+1)
				out.WriteString(",")
			}

		case reflect.Map:
			for _, key := range v.MapKeys() {
				walk(key, depth+1)
				out.WriteString("=>")
				walk(v.MapIndex(key), depth+1)
				out.WriteString(",")
			}

		default:
			fmt.Fprintf(&out, "%v", v.Interface())
		}
	}

	walk(reflect.ValueOf(value), 0)
	return out.String()
}

func secretBearingValues() map[string]any {
	issued := generated.IssuedAPIKey{
		ID:        uuidOf("ab000000-0000-0000-0000-0000000000a1"),
		Name:      "ci-deploy",
		AccountID: uuidOf("ab000000-0000-0000-0000-0000000000c1"),
		UserID:    uuidOf("ab000000-0000-0000-0000-0000000000d1"),
		Token:     fakeToken,
	}
	session := generated.Session{
		Token:     fakeSessionToken,
		ExpiresAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
	}
	login := generated.LoginRequest{Email: "someone@example.com", Password: fakeToken}
	registered := generated.RegisteredOIDCClient{
		ID:           uuidOf("ab000000-0000-0000-0000-000000000001"),
		ClientID:     "8Jm1xQ0pQz7rV2nK4wL9cT6bY3hA5sD0fG1eI2jK",
		ClientSecret: fakeToken,
		Name:         "Anytalk",
		RedirectUris: []string{"https://app.anytalk.com/callback"},
		GrantTypes:   []generated.RegisteredOIDCClientGrantTypes{"authorization_code"},
		Scopes:       []generated.RegisteredOIDCClientScopes{"openid", "email"},
		CreatedAt:    time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
	}
	enrollment := generated.StartedEnrollment{
		Secret:          fakeToken,
		ProvisioningURI: "otpauth://totp/anywaye:" + fakeToken,
		EnrollmentID:    uuidOf("ab000000-0000-0000-0000-0000000000e1"),
		Method:          "totp",
		Digits:          6,
		PeriodSeconds:   30,
		Algorithm:       "SHA1",
		ExpiresAt:       time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
		Replaced:        false,
	}
	challenge := generated.MFAChallenge{
		MfaRequired: true,
		Challenge:   fakeToken,
		ExpiresAt:   time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
	}
	factor := generated.FactorRequest{Code: fakeToken}
	introspect := generated.IntrospectRequest{Token: fakeToken}

	return map[string]any{
		"IssuedAPIKey.Token":                issued,
		"Session.Token":                     session,
		"LoginRequest.Password":             login,
		"RegisteredOIDCClient.ClientSecret": registered,
		"StartedEnrollment.Secret":          enrollment,
		"MFAChallenge.Challenge":            challenge,
		"FactorRequest.Code":                factor,
		"IntrospectRequest.Token":           introspect,
		"CompleteSecondFactorRequest.Challenge": generated.CompleteSecondFactorRequest{
			Challenge: ptr(fakeToken),
			Code:      fakeToken,
		},
		"ConfirmEnrollmentRequest.Code": generated.ConfirmEnrollmentRequest{Code: fakeToken},
		"ConfirmedEnrollment.RecoveryCodes": generated.ConfirmedEnrollment{
			Enabled:                true,
			Method:                 "totp",
			EnrolledAt:             time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
			RecoveryCodes:          []string{fakeToken},
			ReplacedExistingSecret: false,
		},
		"RecoveryCodesResponse.RecoveryCodes": generated.RecoveryCodesResponse{
			RecoveryCodes:          []string{fakeToken},
			IssuedAt:               time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
			RecoveryCodesRemaining: 10,
		},
	}
}

func TestTheResponseHeadersThisPackageKeepsAreCredentialFree(t *testing.T) {
	server := leakyServerFailure(t)
	defer server.Close()

	client := newTestClient(t, server.URL, fakeToken)
	_, err := client.GetCurrentUser(context.Background())
	if err == nil {
		t.Fatal("the failure fixture answered successfully")
	}

	problem := asProblem(t, err)
	serialized, marshalErr := json.Marshal(problem.Document())
	if marshalErr != nil {
		t.Fatalf("marshaling the ProblemError: %v", marshalErr)
	}

	if strings.Contains(string(serialized), fakeToken) {
		t.Errorf("the ProblemError serializes to something containing the credential:\n%s\n\n"+
			"Every member of a problem document is passed through the redactor before it "+
			"reaches the error type — including `detail`, including the per-field `errors`, "+
			"and including the members this package did not know the contract had.",
			truncate(string(serialized), 400))
	}

	for _, verb := range []string{"%v", "%+v", "%s"} {
		if rendered := fmt.Sprintf(verb, err); strings.Contains(rendered, fakeToken) {
			t.Errorf("the error rendered with %s contains the credential:\n%s", verb, rendered)
		}
	}
}

func TestTheGeneratedSecretBearingTypesAreSafeToPrint(t *testing.T) {
	issued := generated.IssuedAPIKey{Token: fakeToken, Name: "ci-deploy"}

	printed := fmt.Sprintf("%v", issued)
	if !strings.Contains(printed, fakeToken) {
		t.Fatalf("`fmt.Sprintf(\"%%v\", IssuedAPIKey{...})` did not print the token: %s\n"+
			"If a future oapi-codegen adds a redacting `String()`, this test needs "+
			"rewriting — and that would be good news, so read this failure as an "+
			"opportunity rather than a regression.", printed)
	}

	if _, has := any(issued).(interface{ String() string }); has {
		t.Error("the generated IssuedAPIKey now implements fmt.Stringer.\n" +
			"Check that the implementation REDACTS before relaxing anything here: a " +
			"generated String() that prints its fields would make `log.Println(issued)` " +
			"a credential leak that looks safe because a Stringer exists.")
	}

	if got := SafeToLog(issued); strings.Contains(got, fakeToken) {
		t.Errorf("SafeToLog printed the credential: %s", got)
	}
	if !strings.Contains(SafeToLog(issued), "IssuedAPIKey") {
		t.Errorf("SafeToLog must still name the type, so a log line stays diagnosable: %s",
			SafeToLog(issued))
	}

	if got := SafeToLog(generated.Session{Token: fakeToken}); strings.Contains(got, fakeToken) {
		t.Errorf("SafeToLog printed a Session's token: %s", got)
	}
	if got := SafeToLog(generated.LoginRequest{Password: fakeToken}); strings.Contains(got, fakeToken) {
		t.Errorf("SafeToLog printed a LoginRequest's password: %s", got)
	}
}


func leakyServer(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name, value := range leakyResponseHeaders {
			w.Header().Add(name, value)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"ab000000-0000-0000-0000-000000000000",` +
			`"email":"someone@example.com"}`))
	}))
}

func leakyServerFailure(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name, value := range leakyResponseHeaders {
			w.Header().Add(name, value)
		}
		w.Header().Set("Content-Type", ProblemContentType)
		w.Header().Set("X-Trace-Id", "0af7651916cd43dd8448eb211c80319c")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(leakyProblemBody))
	}))
}

func newTestClient(t *testing.T, baseURL, token string) *Client {
	t.Helper()

	client, err := New(Options{
		BaseURL: baseURL,
		Token:   token,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("building a client against %s: %v", baseURL, err)
	}
	return client
}

func asProblem(t *testing.T, err error) ProblemError {
	t.Helper()

	var problem ProblemError
	if !errorsAs(err, &problem) {
		t.Fatalf("expected a client.ProblemError, got %T: %v\n"+
			"The interface is what a caller catches; a concrete base struct embedded by "+
			"value would NOT match here, which is the failure this shape exists to avoid.",
			err, err)
	}
	return problem
}
