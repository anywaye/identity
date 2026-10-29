package oidc

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)


const testLoginUIURL = "https://login.example.com/sign-in/oidc"

func testProviderFor(t *testing.T, loginUI string) *Provider {
	t.Helper()

	key, err := LoadSigningKey(pemFor(t, 2048, pkcs8), "anywaye-test-key")
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}
	storage := NewStorage(nil, NewProfileReader(), nil, key, testClock{}, nil, PathLogin)
	provider, err := NewProvider(Config{
		Issuer:     "https://identity.test",
		SigningKey: key,
		LoginUIURL: loginUI,
	}, storage)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return provider
}

func TestNewProviderRefusesToBuildWithoutALoginUI(t *testing.T) {
	t.Parallel()

	key, err := LoadSigningKey(pemFor(t, 2048, pkcs8), "anywaye-test-key")
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}
	storage := NewStorage(nil, NewProfileReader(), nil, key, testClock{}, nil, PathLogin)

	_, err = NewProvider(Config{Issuer: "https://identity.test", SigningKey: key}, storage)
	if err == nil {
		t.Fatal("NewProvider built a provider that cannot send a browser anywhere to sign in")
	}
	if !errors.Is(err, ErrNoLoginUI) {
		t.Errorf("the refusal is %v, want one matching ErrNoLoginUI", err)
	}
	if !strings.Contains(err.Error(), LoginUIEnvVar) {
		t.Errorf("the refusal does not name %s: %v", LoginUIEnvVar, err)
	}
}

func TestValidateLoginUIURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want error
	}{
		{name: "empty", raw: "", want: ErrNoLoginUI},
		{name: "no scheme", raw: "login.example.com/sign-in", want: ErrInvalidLoginUI},
		{name: "a scheme that is not http", raw: "javascript:alert(1)", want: ErrInvalidLoginUI},
		{name: "a data url", raw: "data:text/html,<form></form>", want: ErrInvalidLoginUI},
		{name: "no host", raw: "https:///sign-in", want: ErrInvalidLoginUI},
		{name: "userinfo", raw: "https://parlor@evil.example.com/login", want: ErrInvalidLoginUI},
		{name: "a fragment", raw: "https://login.example.com/sign-in#top", want: ErrInvalidLoginUI},
		{
			name: "a query", raw: "https://login.example.com/sign-in?variant=acme", want: ErrInvalidLoginUI,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateLoginUIURL(tt.raw)
			if !errors.Is(err, tt.want) {
				t.Errorf("ValidateLoginUIURL(%q) = %v, want one matching %v", tt.raw, err, tt.want)
			}
		})
	}
}

func TestValidateLoginUIURLAccepts(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"https://login.example.com/sign-in/oidc",
		"https://login.example.com",
		"https://login.example.com/",
		"http://localhost:4000/sign-in/oidc",
		"https://login.example.com/sign-in/oidc/",
	} {
		if err := ValidateLoginUIURL(raw); err != nil {
			t.Errorf("ValidateLoginUIURL(%q) = %v, want it accepted", raw, err)
		}
	}
}

func TestLoginRedirect(t *testing.T) {
	t.Parallel()

	p := testProviderFor(t, testLoginUIURL)
	params := LoginRedirectParams{
		RequestID:   "11111111-2222-3333-4444-555555555555",
		State:       "oidc.a-token",
		Step:        LoginStepPassword,
		ClientName:  "Anytalk",
		LoginHint:   "person@example.com",
		Error:       LoginErrorInvalidCredentials,
		ErrorDetail: "that email address and password were not accepted",
		RetryAfter:  "900",
	}

	raw := p.LoginRedirect(params)
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("the redirect is not a URL: %v", err)
	}

	if got := parsed.Scheme + "://" + parsed.Host + parsed.Path; got != testLoginUIURL {
		t.Errorf("the redirect is %q, want the configured login UI %q with only a query added", got, testLoginUIURL)
	}
	query := parsed.Query()
	for name, want := range map[string]string{
		LoginParamRequestID:   params.RequestID,
		LoginParamState:       params.State,
		LoginParamStep:        params.Step,
		LoginParamClientName:  params.ClientName,
		LoginParamLoginHint:   params.LoginHint,
		LoginParamError:       params.Error,
		LoginParamErrorDetail: params.ErrorDetail,
		LoginParamRetryAfter:  params.RetryAfter,
	} {
		if got := query.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	if again := p.LoginRedirect(params); again != raw {
		t.Errorf("two identical interactions produced two URLs:\n  %s\n  %s", raw, again)
	}
}

func TestLoginRedirectOmitsEmptyParametersRatherThanSendingThemEmpty(t *testing.T) {
	t.Parallel()

	p := testProviderFor(t, testLoginUIURL)
	parsed, err := url.Parse(p.LoginRedirect(LoginRedirectParams{
		RequestID:  "11111111-2222-3333-4444-555555555555",
		State:      "oidc.a-token",
		Step:       LoginStepPassword,
		ClientName: "Anytalk",
	}))
	if err != nil {
		t.Fatalf("the redirect is not a URL: %v", err)
	}

	query := parsed.Query()
	for _, name := range []string{LoginParamError, LoginParamErrorDetail, LoginParamRetryAfter, LoginParamLoginHint} {
		if _, present := query[name]; present {
			t.Errorf("a fresh step carried %s=%q; an absent error and an empty one must "+
				"not both read as no error", name, query.Get(name))
		}
	}
	for _, name := range []string{LoginParamRequestID, LoginParamState, LoginParamStep} {
		if query.Get(name) == "" {
			t.Errorf("a fresh step carried no %s", name)
		}
	}
}

func TestLoginRedirectEscapesWhatTravelsInIt(t *testing.T) {
	t.Parallel()

	p := testProviderFor(t, testLoginUIURL)
	const hostile = `<script>alert("x")</script> & ?=#`

	raw := p.LoginRedirect(LoginRedirectParams{
		RequestID:  "11111111-2222-3333-4444-555555555555",
		State:      "oidc.a-token",
		Step:       LoginStepPassword,
		ClientName: hostile,
	})
	if strings.Contains(raw, "<script>") {
		t.Errorf("the redirect carries a raw script tag: %s", raw)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("the redirect is not a URL: %v", err)
	}
	if got := parsed.Query().Get(LoginParamClientName); got != hostile {
		t.Errorf("%s came back as %q after a round trip, want the value unchanged — "+
			"escaping must survive the decode", LoginParamClientName, got)
	}
	if strings.Contains(raw, "error=") {
		t.Errorf("a product name injected a parameter into the redirect: %s", raw)
	}
}

func TestLoginRedirectKeepsEveryValueInsideTheQuery(t *testing.T) {
	t.Parallel()

	p := testProviderFor(t, testLoginUIURL)
	raw := p.LoginRedirect(LoginRedirectParams{
		RequestID:  "11111111-2222-3333-4444-555555555555",
		State:      "oidc.a-token",
		Step:       LoginStepPassword,
		LoginHint:  "person@example.com?next=https://evil.example.com",
		ClientName: "Anytalk",
	})

	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("the redirect is not a URL: %v", err)
	}
	if got := parsed.Scheme + "://" + parsed.Host + parsed.Path; got != testLoginUIURL {
		t.Errorf("the redirect's origin and path are %q, want %q; a value reached outside "+
			"the query", got, testLoginUIURL)
	}
	if parsed.Fragment != "" {
		t.Errorf("the redirect carries a fragment: %q", parsed.Fragment)
	}
}

func TestEveryLoginRedirectParameterIsCarriedAndEveryCarriedOneIsNamed(t *testing.T) {
	t.Parallel()

	declared := map[string]bool{
		LoginParamRequestID:   true,
		LoginParamState:       true,
		LoginParamStep:        true,
		LoginParamClientName:  true,
		LoginParamLoginHint:   true,
		LoginParamError:       true,
		LoginParamErrorDetail: true,
		LoginParamRetryAfter:  true,
	}

	carried := LoginRedirectParams{
		RequestID:   "11111111-2222-3333-4444-555555555555",
		State:       "oidc.a-token",
		Step:        LoginStepPassword,
		ClientName:  "Anytalk",
		LoginHint:   "person@example.com",
		Error:       LoginErrorInvalidCredentials,
		ErrorDetail: "a sentence",
		RetryAfter:  "900",
	}.Values()

	for name := range declared {
		if _, carried := carried[name]; !carried {
			t.Errorf("the contract publishes %q and no field of LoginRedirectParams ever "+
				"sends it; a login UI told to expect it would never receive it", name)
		}
	}
	for name := range carried {
		if !declared[name] {
			t.Errorf("LoginRedirectParams carries %q and the contract does not name it, so "+
				"it is a parameter the login UI has no reason to read", name)
		}
	}
}

func TestAnInteractionErrorCodeThatNamesAProblemCodeIsTheSameString(t *testing.T) {
	t.Parallel()

	twins := map[string]string{
		LoginErrorInteractionExpired: "none — new. There is no problem code for " +
			"'the form expired': before this packet it was a 400 with `invalid_request`, " +
			"which is a different claim.",
		LoginErrorMissingCredentials: "none — new. The 422's `validation_failed` said " +
			"'the request is not acceptable', which is a statement about a request body. " +
			"This one is a statement about a form a person filled in.",
		LoginErrorInvalidCredentials: "none — new. The 401's `unauthorized` says 'you are " +
			"not signed in', which is a different claim from 'those credentials were not " +
			"accepted'; a login UI showing the wrong one of those tells a user their " +
			"session expired.",
		LoginErrorChallengeRejected: "none — new, for the same reason: the 401's " +
			"`unauthorized` is about a session, and this is about a code.",
		LoginErrorAccountLocked: "httpapi.CodeAccountLocked — the SAME WORD on purpose. " +
			"A UI that already switches on `account_locked` for a 423 must not have to " +
			"learn a second spelling of it.",
	}

	for code, note := range twins {
		if code == "" {
			t.Error("a code in the table is empty")
		}
		if !strings.Contains(note, " — ") {
			t.Errorf("the code %q has no note saying whether it has a problem-code twin; "+
				"adding a code without that sentence is how two vocabularies start", code)
		}
	}

	if twins[LoginErrorAccountLocked] == "" {
		t.Error("account_locked lost its note")
	}
}

func TestTheStepValuesAreTheDocumentedOnes(t *testing.T) {
	t.Parallel()

	if LoginStepPassword != "password" {
		t.Errorf("the password step is %q, want \"password\"; the value is a published constant",
			LoginStepPassword)
	}
	if LoginStepChallenge != "challenge" {
		t.Errorf("the challenge step is %q, want \"challenge\"; the value is a published constant",
			LoginStepChallenge)
	}
}
