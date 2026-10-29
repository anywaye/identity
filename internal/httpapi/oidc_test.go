package httpapi

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
)


func TestOIDCAuthorizationCodeRoundTrip(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	tokens := f.roundTrip(t, client)

	if tokens["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", tokens["token_type"])
	}
	accessToken, _ := tokens["access_token"].(string)
	if accessToken == "" {
		t.Fatal("the token response carried no access_token")
	}
	idToken, _ := tokens["id_token"].(string)
	if idToken == "" {
		t.Fatal("the token response carried no id_token")
	}
	if got, _ := tokens["scope"].(string); got != "openid email profile accounts" {
		t.Errorf("scope = %q, want the four granted scopes", got)
	}
	if expires, _ := tokens["expires_in"].(float64); expires > 15*60 || expires <= 0 {
		t.Errorf("expires_in = %v, want a positive number at or under core's fifteen-minute cap", expires)
	}

	idClaims := f.verify(t, idToken)

	if idClaims["iss"] != oidcTestIssuer {
		t.Errorf("id_token iss = %v, want %q; every verifier compares this for equality", idClaims["iss"], oidcTestIssuer)
	}
	if !audienceContains(idClaims["aud"], client.ClientID) {
		t.Errorf("id_token aud = %v, want it to contain the client %q", idClaims["aud"], client.ClientID)
	}
	if idClaims["sub"] != f.owner.String() {
		t.Errorf("id_token sub = %v, want the user %s", idClaims["sub"], f.owner)
	}
	if idClaims["nonce"] != "nonce-round-trip" {
		t.Errorf("id_token nonce = %v, want the one the client sent; a token that does not echo it is a "+
			"replayable token", idClaims["nonce"])
	}
	if idClaims["email"] != f.email {
		t.Errorf("id_token email = %v, want %q", idClaims["email"], f.email)
	}
	verified, present := idClaims["email_verified"]
	if !present {
		t.Error("id_token has no email_verified claim; a relying party that cannot see it has to assume it is verified")
	}
	if verified != false {
		t.Errorf("id_token email_verified = %v, want false: identity cannot prove an address yet", verified)
	}
	if name, _ := idClaims["name"].(string); name == "" {
		t.Error("id_token has no name claim; the profile scope was granted")
	}
	if _, present := idClaims["auth_time"]; !present {
		t.Error("id_token has no auth_time; the user authenticated and the moment is a protocol claim")
	}
	amr, _ := idClaims["amr"].([]any)
	if !slices.Contains(amr, "pwd") {
		t.Errorf("id_token amr = %v, want it to include pwd; a token that claimed no method is a token a "+
			"relying party might make a decision on", idClaims["amr"])
	}
	accounts, _ := idClaims["accounts"].([]any)
	if len(accounts) == 0 {
		t.Fatal("id_token has no accounts claim; the accounts scope was granted and the user owns one account")
	}
	first, _ := accounts[0].(map[string]any)
	if first["account_id"] != f.account.String() {
		t.Errorf("accounts[0].account_id = %v, want %s", first["account_id"], f.account)
	}
	if first["role"] != "owner" {
		t.Errorf("accounts[0].role = %v, want owner", first["role"])
	}
	if first["personal"] != true {
		t.Errorf("accounts[0].personal = %v, want true", first["personal"])
	}

	accessClaims := f.verify(t, accessToken)
	if accessClaims["iss"] != oidcTestIssuer {
		t.Errorf("access_token iss = %v, want %q", accessClaims["iss"], oidcTestIssuer)
	}
	if accessClaims["sub"] != f.owner.String() {
		t.Errorf("access_token sub = %v, want %s", accessClaims["sub"], f.owner)
	}
	if scope, _ := accessClaims["scope"].(string); scope != "accounts openid" {
		t.Errorf("access_token scope = %q, want the granted scopes space-delimited; gateway splits this on whitespace",
			scope)
	}
	if _, present := accessClaims["jti"]; !present {
		t.Error("access_token has no jti; it is the only handle userinfo has on the token")
	}
	if _, present := accessClaims["accounts"]; !present {
		t.Error("access_token has no accounts claim; core asks for the account claims on service traffic")
	}

	if _, present := idClaims["at_hash"]; !present {
		t.Error("id_token has no at_hash; it is what binds it to this access token")
	}

	info := f.do(t, http.MethodGet, oidc.PathUserinfo, "", nil)
	if info.Code != http.StatusUnauthorized {
		t.Fatalf("GET userinfo with no token = %d, want 401", info.Code)
	}

	rec := newResponse(serveRecorder(f.handler, newRequestWithBearer(http.MethodGet, oidc.PathUserinfo, accessToken)))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET userinfo = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var claims map[string]any
	mustJSON(t, rec.Body.Bytes(), &claims)
	if claims["sub"] != f.owner.String() {
		t.Errorf("userinfo sub = %v, want %s", claims["sub"], f.owner)
	}
	if claims["email"] != f.email {
		t.Errorf("userinfo email = %v, want %q", claims["email"], f.email)
	}
	if verified, present := claims["email_verified"]; !present || verified != false {
		t.Errorf("userinfo email_verified = %v (present %t), want false and present", verified, present)
	}
	if name, _ := claims["name"].(string); name == "" {
		t.Error("userinfo has no name")
	}
	if list, _ := claims["accounts"].([]any); len(list) == 0 {
		t.Error("userinfo has no accounts; the brief asks for the account/role claims from account_users")
	}
	for _, forbidden := range []string{"password_digest", "secret", "digest", "client_id", "row_id"} {
		if _, present := claims[forbidden]; present {
			t.Errorf("userinfo carries %q", forbidden)
		}
	}
}

func TestOIDCReplayedCodeIsRefused(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	verifier, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-replay", "nonce-replay", nil)

	rec := f.login(t, loginURL, client.Email, client.Password)
	if rec.Code != http.StatusFound {
		t.Fatalf("POST the login form = %d, want 302; body: %s", rec.Code, rec.Body)
	}
	code := mustCode(t, rec.Header().Get("Location"))

	first := f.exchange(t, client, code, verifier, oidcTestRedirect)
	if first.Code != http.StatusOK {
		t.Fatalf("the first exchange = %d, want 200; body: %s", first.Code, first.Body)
	}

	second := f.exchange(t, client, code, verifier, oidcTestRedirect)
	if second.Code != http.StatusBadRequest {
		t.Fatalf("the second exchange of the same code = %d, want 400; body: %s", second.Code, second.Body)
	}
	if err, _ := second.JSON["error"].(string); err != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant; the protocol's name for a code that will not redeem", err)
	}
}

func TestOIDCReplayedCodeWithAFreshVerifierIsStillRefused(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	verifier, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-replay-2", "nonce-replay-2", nil)
	rec := f.login(t, loginURL, client.Email, client.Password)
	code := mustCode(t, rec.Header().Get("Location"))

	if got := f.exchange(t, client, code, verifier, oidcTestRedirect).Code; got != http.StatusOK {
		t.Fatalf("the first exchange = %d, want 200", got)
	}

	other, _ := codeVerifier(t)
	again := f.exchange(t, client, code, other, oidcTestRedirect)
	if again.Code != http.StatusBadRequest {
		t.Fatalf("the replay = %d, want 400; body: %s", again.Code, again.Body)
	}
}

func TestOIDCPKCERefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		challenge  string
		method     string
		wantDetail string
	}{ //nolint:govet // the field alignment is the point
		{name: "neither parameter", wantDetail: "PKCE is required"},
		{name: "the method alone", method: "S256", wantDetail: "no code_challenge"},
		{name: "the challenge alone, which RFC 7636 says is plain", challenge: "not-hashed", wantDetail: "PKCE is required"},
		{name: "plain, spelled out", challenge: "not-hashed", method: "plain", wantDetail: "must be S256"},
		{name: "an unknown method", challenge: "not-hashed", method: "S512", wantDetail: "must be S256"},
		{name: "S256, spelled exactly", challenge: "s256-challenge", method: "s256", wantDetail: "must be S256"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newOIDCFixture(t)
			client := f.registerClient(t)

			query := url.Values{
				"client_id":     []string{client.ClientID},
				"redirect_uri":  []string{oidcTestRedirect},
				"response_type": []string{"code"},
				"scope":         []string{"openid email"},
				"state":         []string{"state-pkce"},
				"nonce":         []string{"nonce-pkce"},
			}
			if tt.challenge != "" {
				query.Set("code_challenge", tt.challenge)
			}
			if tt.method != "" {
				query.Set("code_challenge_method", tt.method)
			}

			rec := f.do(t, http.MethodGet, oidc.PathAuthorize+"?"+query.Encode(), "", nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("GET /oidc/authorize = %d, want 400; body: %s", rec.Code, rec.Body)
			}
			if rec.Header().Get("Content-Type") != "application/problem+json" {
				t.Errorf("Content-Type = %q, want application/problem+json", rec.Header().Get("Content-Type"))
			}
			if !strings.Contains(rec.Body.String(), tt.wantDetail) {
				t.Errorf("the detail does not mention %q:\n%s", tt.wantDetail, rec.Body)
			}
		})
	}
}

func TestOIDCRedirectURINotOnTheAllowList(t *testing.T) {
	t.Parallel()

	offList := []struct {
		name   string
		target string
	}{
		{name: "the prefix-confusion case", target: "https://app.example.com.evil.com/cb"},
		{name: "a different host entirely", target: "https://evil.com/cb"},
		{name: "the same host over http", target: "http://app.example.com/cb"},
		{name: "a subdomain", target: "https://evil.app.example.com/cb"},
		{name: "a deeper path", target: "https://app.example.com/cb/attacker"},
		{name: "a trailing path segment", target: "https://app.example.com/cbevil"},
		{name: "an explicit port", target: "https://app.example.com:8443/cb"},
		{name: "a userinfo trick", target: "https://app.example.com@evil.com/cb"},
		{name: "no scheme at all", target: "app.example.com/cb"},
		{name: "empty", target: ""},
		{name: "a javascript scheme", target: "javascript:alert(1)"},
	}

	for _, tt := range offList {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newOIDCFixture(t)
			client := f.registerClient(t)

			_, challenge := codeVerifier(t)
			query := url.Values{
				"client_id":             []string{client.ClientID},
				"redirect_uri":          []string{tt.target},
				"response_type":         []string{"code"},
				"scope":                 []string{"openid email"},
				"state":                 []string{"state-redirect"},
				"nonce":                 []string{"nonce-redirect"},
				"code_challenge":        []string{challenge},
				"code_challenge_method": []string{"S256"},
			}

			rec := f.do(t, http.MethodGet, oidc.PathAuthorize+"?"+query.Encode(), "", nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("GET /oidc/authorize with redirect_uri %q = %d, want 400; body: %s",
					tt.target, rec.Code, rec.Body)
			}
			if location := rec.Header().Get("Location"); location != "" {
				t.Errorf("the refusal carried Location %q; a redirect to an unregistered origin is the bug", location)
			}
			if tt.target == "" && !strings.Contains(rec.Body.String(), "redirect_uri") {
				t.Errorf("the refusal does not say what was missing:\n%s", rec.Body)
			}
		})
	}
}

func TestOIDCTokenRedirectURIMustMatchTheAuthorizationRequest(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	verifier, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-token-redirect", "nonce-token-redirect", nil)
	rec := f.login(t, loginURL, client.Email, client.Password)
	code := mustCode(t, rec.Header().Get("Location"))

	swapped := f.exchange(t, client, code, verifier, "https://app.example.com.evil.com/cb")
	if swapped.Code != http.StatusBadRequest {
		t.Fatalf("the exchange with a swapped redirect_uri = %d, want 400; body: %s", swapped.Code, swapped.Body)
	}
	if err, _ := swapped.JSON["error"].(string); err != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", err)
	}

	again := f.exchange(t, client, code, verifier, oidcTestRedirect)
	if again.Code != http.StatusBadRequest {
		t.Errorf("the code survived a rejected exchange: %d, want 400", again.Code)
	}
}

func TestOIDCRevokedClientAndWrongSecret(t *testing.T) {
	t.Parallel()

	t.Run("a wrong secret", func(t *testing.T) {
		t.Parallel()

		f := newOIDCFixture(t)
		client := f.registerClient(t)
		client.ClientSecret = "not-the-secret"

		verifier, challenge := codeVerifier(t)
		loginURL := f.authorize(t, client, challenge, "state-badsecret", "nonce-badsecret", nil)
		rec := f.login(t, loginURL, client.Email, client.Password)
		code := mustCode(t, rec.Header().Get("Location"))

		refused := f.exchange(t, client, code, verifier, oidcTestRedirect)
		if refused.Code != http.StatusUnauthorized {
			t.Fatalf("the exchange with a wrong secret = %d, want 401; body: %s", refused.Code, refused.Body)
		}
		if err, _ := refused.JSON["error"].(string); err != "invalid_client" {
			t.Errorf("error = %q, want invalid_client", err)
		}
	})

	t.Run("a revoked client", func(t *testing.T) {
		t.Parallel()

		f := newOIDCFixture(t)
		client := f.registerClient(t)

		verifier, challenge := codeVerifier(t)
		loginURL := f.authorize(t, client, challenge, "state-revoked", "nonce-revoked", nil)
		rec := f.login(t, loginURL, client.Email, client.Password)
		code := mustCode(t, rec.Header().Get("Location"))

		f.revoke(t, client)

		refused := f.exchange(t, client, code, verifier, oidcTestRedirect)
		if refused.Code != http.StatusUnauthorized {
			t.Fatalf("the exchange as a revoked client = %d, want 401; body: %s", refused.Code, refused.Body)
		}
		if err, _ := refused.JSON["error"].(string); err != "invalid_client" {
			t.Errorf("error = %q, want invalid_client; a revoked client and a wrong secret are one answer", err)
		}
	})

	t.Run("a revoked client cannot start a flow at all", func(t *testing.T) {
		t.Parallel()

		f := newOIDCFixture(t)
		client := f.registerClient(t)
		f.revoke(t, client)

		_, challenge := codeVerifier(t)
		query := url.Values{
			"client_id":             []string{client.ClientID},
			"redirect_uri":          []string{oidcTestRedirect},
			"response_type":         []string{"code"},
			"scope":                 []string{"openid email"},
			"state":                 []string{"state-revoked-authorize"},
			"nonce":                 []string{"nonce-revoked-authorize"},
			"code_challenge":        []string{challenge},
			"code_challenge_method": []string{"S256"},
		}

		rec := f.do(t, http.MethodGet, oidc.PathAuthorize+"?"+query.Encode(), "", nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("authorize as a revoked client = %d, want 400; body: %s", rec.Code, rec.Body)
		}
		if location := rec.Header().Get("Location"); location != "" {
			t.Errorf("the refusal redirected to %q", location)
		}
	})
}

func TestOIDCRevocationStopsIssuedTokens(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	tokens := f.roundTrip(t, client)
	accessToken, _ := tokens["access_token"].(string)

	before := newResponse(serveRecorder(f.handler, newRequestWithBearer(http.MethodGet, oidc.PathUserinfo, accessToken)))
	if before.Code != http.StatusOK {
		t.Fatalf("userinfo before the revocation = %d, want 200; body: %s", before.Code, before.Body)
	}

	f.revoke(t, client)

	after := newResponse(serveRecorder(f.handler, newRequestWithBearer(http.MethodGet, oidc.PathUserinfo, accessToken)))
	if after.Code == http.StatusOK {
		t.Errorf("userinfo after the revocation = 200, want a refusal; the token is still live:\n%s", after.Body)
	}
}

func TestOIDCLoginStateMustMatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		presented string
		dropCookie bool
	}{
		{name: "a state from a different flow", presented: "oidc.not-the-one-that-was-issued"},
		{name: "an empty state", presented: ""},
		{name: "a state with no provider prefix", presented: "some-random-value"},
		{name: "no cookie at all", dropCookie: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newOIDCFixture(t)
			client := f.registerClient(t)

			_, challenge := codeVerifier(t)
			loginURL := f.authorize(t, client, challenge, "state-csrf", "nonce-csrf", nil)

			f.signOut()
			form := f.do(t, http.MethodGet, loginURL, "", nil)
			mustRedirectToLoginUI(t, form)
			interactionState(t, form)

			presented := tt.presented
			if presented == "" && !tt.dropCookie {
				presented = "oidx.something-else-entirely"
			}

			jar := &cookieJar{}
			if !tt.dropCookie {
				jar.absorb(form.Result().Cookies())
			}

			post := url.Values{
				"state":    []string{presented},
				"email":    []string{client.Email},
				"password": []string{passwordFor(client)},
			}
			req := newRequestForm(http.MethodPost, loginURL, post)
			if cookie := jar.header(); cookie != "" {
				req.Header.Set("Cookie", cookie)
			}

			rec := newResponse(serveRecorder(f.handler, req))
			mustRedirectToLoginUI(t, rec)
			if code := mustCodeIfPresent(rec.Header().Get("Location")); code != "" {
				t.Fatalf("a state that does not verify still completed the flow, carrying "+
					"an authorization code: %s", rec.Header().Get("Location"))
			}
			if got := rec.Header().Get("Location"); strings.Contains(got, oidcTestRedirect) {
				t.Errorf("the refusal pointed at the client (%q); a completed request is "+
					"exactly what the attack wanted", got)
			}
			query := interactionParams(t, rec)
			if got := query.Get(oidc.LoginParamError); got != oidc.LoginErrorInteractionExpired {
				t.Errorf("%s = %q, want %q", oidc.LoginParamError, got, oidc.LoginErrorInteractionExpired)
			}
			if query.Get(oidc.LoginParamErrorDetail) == "" {
				t.Error("the refusal carried no sentence; a login UI that cannot say why " +
					"shows the user a form that will fail the same way")
			}
			if fresh := query.Get(oidc.LoginParamState); fresh == "" || fresh == presented {
				t.Errorf("%s = %q, want a freshly minted one", oidc.LoginParamState, fresh)
			}
		})
	}
}

func passwordFor(registered) string { return oidcTestPassword }

func TestOIDCLoginStateIsOauthPackageState(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	_, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-reuse", "nonce-reuse", nil)

	f.signOut()
	form := f.do(t, http.MethodGet, loginURL, "", nil)
	mustRedirectToLoginUI(t, form)
	sealed := interactionState(t, form)

	cookies := form.Result().Cookies()
	var found *http.Cookie
	for _, c := range cookies {
		if c.Name == OIDCStateCookiePrefix+interactionParams(t, form).Get(oidc.LoginParamRequestID) {
			found = c
		}
	}
	if found == nil {
		t.Fatalf("the redirect set no %s* cookie; cookies: %v", OIDCStateCookiePrefix, cookieNames(cookies))
	}
	if found.Value != sealed {
		t.Errorf("the cookie holds %q and the redirect carried %q; they must be the same value",
			found.Value, sealed)
	}
	if !found.HttpOnly {
		t.Error("the state cookie is not HttpOnly, so a script on the login UI's origin could read it")
	}
	if found.SameSite != http.SameSiteNoneMode {
		t.Errorf("the state cookie is SameSite=%v; the login form is a cross-site POST and a "+
			"Lax cookie is not sent on one, so every sign-in would be refused", found.SameSite)
	}

	if !strings.HasPrefix(sealed, OIDCStateProvider+oauthStateSeparator) {
		t.Errorf("the state %q is not one oauth.NewState(%q) could have minted", sealed, OIDCStateProvider)
	}
	if !oauthVerifyState(OIDCStateProvider, sealed, sealed) {
		t.Error("the service's own state does not satisfy oauth.VerifyState against itself")
	}
	if oauthVerifyState(OIDCStateProvider, sealed, sealed+"x") {
		t.Error("a state one character longer verifies; the comparison is not exact")
	}
}

func cookieNames(cookies []*http.Cookie) []string {
	names := make([]string, 0, len(cookies))
	for _, c := range cookies {
		names = append(names, c.Name)
	}
	sortStrings(names)
	return names
}

func TestAnInteractionCodeThatHasAProblemCodeTwinIsTheSameString(t *testing.T) {
	t.Parallel()

	if oidc.LoginErrorAccountLocked != CodeAccountLocked {
		t.Errorf("the lockout is %q on the interaction and %q in the problem envelope; "+
			"one lockout has one name", oidc.LoginErrorAccountLocked, CodeAccountLocked)
	}

	problemCodes := map[string]bool{
		CodeUnauthorized:     true,
		CodeForbidden:        true,
		CodeValidationFailed: true,
		CodeConflict:         true,
		CodeNotFound:         true,
		CodeInvalidRequest:   true,
		CodeAccountLocked:    true,
		CodeGone:             true,
	}
	for _, code := range []string{
		oidc.LoginErrorInteractionExpired,
		oidc.LoginErrorMissingCredentials,
		oidc.LoginErrorInvalidCredentials,
		oidc.LoginErrorChallengeRejected,
		oidc.LoginErrorAccountLocked,
	} {
		if code == "" {
			t.Error("an interaction code in this list is empty")
		}
	}
	for _, code := range []string{
		oidc.LoginErrorInteractionExpired,
		oidc.LoginErrorMissingCredentials,
		oidc.LoginErrorInvalidCredentials,
		oidc.LoginErrorChallengeRejected,
	} {
		if problemCodes[code] {
			t.Errorf("the interaction code %q collides with a problem code of the same "+
				"spelling that means something else; a login UI switching on it would "+
				"render the wrong sentence", code)
		}
	}
}

func TestTheLoginRedirectCarriesNoBodyAndTheTwoHeadersThatEarnedTheirPlace(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	_, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-redirect-shape", "nonce-redirect-shape", nil)

	f.signOut()
	rec := f.do(t, http.MethodGet, loginURL, "", nil)
	redirect := mustRedirectToLoginUI(t, rec)

	query := redirect.Query()
	if got := query.Get(oidc.LoginParamRequestID); got == "" {
		t.Fatalf("the redirect carried no %s: %s", oidc.LoginParamRequestID, redirect)
	}
	if got := mustParseID(t, query.Get(oidc.LoginParamRequestID)).String(); got != requestIDOf(t, loginURL) {
		t.Errorf("%s = %q, want the id in the URL the browser was redirected to (%q)",
			oidc.LoginParamRequestID, got, requestIDOf(t, loginURL))
	}
	if got := query.Get(oidc.LoginParamClientName); got != "Anytalk" {
		t.Errorf("%s = %q, want the product asking", oidc.LoginParamClientName, got)
	}
	if got := query.Get(oidc.LoginParamStep); got != oidc.LoginStepPassword {
		t.Errorf("%s = %q, want %q", oidc.LoginParamStep, got, oidc.LoginStepPassword)
	}
	if query.Get(oidc.LoginParamError) != "" {
		t.Errorf("a fresh step carried an %s (%q); an absent error and an empty one must "+
			"not both read as success", oidc.LoginParamError, query.Get(oidc.LoginParamError))
	}

	if body := rec.Body.String(); body != "" {
		t.Errorf("the redirect carried a %d-byte body; identity renders nothing:\n%s", len(body), body)
	}
	if got := rec.Header().Get("Content-Type"); got != "" {
		t.Errorf("Content-Type = %q, want none: a response with no body has nothing to declare", got)
	}

	for header, want := range map[string]string{
		"Referrer-Policy": "no-referrer",
		"Cache-Control":   "no-store",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	for _, header := range []string{"X-Frame-Options", "X-Content-Type-Options"} {
		if got := rec.Header().Get(header); got != "" {
			t.Errorf("%s = %q; it protected a document, and there is no document", header, got)
		}
	}
}

func TestTheAuthorizeRedirectCarriesNoBody(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	_, challenge := codeVerifier(t)
	rec := f.do(t, http.MethodGet, oidc.PathAuthorize+"?"+url.Values{
		"client_id":             []string{client.ClientID},
		"redirect_uri":          []string{oidcTestRedirect},
		"response_type":         []string{"code"},
		"scope":                 []string{"openid email"},
		"state":                 []string{"state-no-body"},
		"nonce":                 []string{"nonce-no-body"},
		"code_challenge":        []string{challenge},
		"code_challenge_method": []string{"S256"},
	}.Encode(), "", nil)

	if rec.Code != http.StatusFound {
		t.Fatalf("GET /oidc/authorize = %d, want 302; body: %s", rec.Code, rec.Body)
	}
	if !strings.HasPrefix(rec.Header().Get("Location"), oidc.PathLogin+"/") {
		t.Errorf("the browser was sent to %q, want the login endpoint", rec.Header().Get("Location"))
	}
	if body := rec.Body.String(); body != "" {
		t.Errorf("the redirect carried a %d-byte body; net/http's redirect fallback is "+
			"HTML and identity serves none:\n%s", len(body), body)
	}
	if got := rec.Header().Get("Content-Type"); got != "" {
		t.Errorf("Content-Type = %q, want none", got)
	}
}

func requestIDOf(t *testing.T, loginURL string) string {
	t.Helper()

	trimmed := strings.TrimPrefix(loginURL, oidc.PathLogin+"/")
	trimmed, _, _ = strings.Cut(trimmed, "?")
	if trimmed == "" {
		t.Fatalf("the login URL %q carries no request id", loginURL)
	}
	return trimmed
}

func octxTime() time.Time { return time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC) }

func TestTheInteractionCookiesAreNoneAndTheFlowAndSessionCookiesAreNot(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	_, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-cookies", "nonce-cookies", nil)

	authorize := f.do(t, http.MethodGet, oidc.PathAuthorize+"?"+url.Values{
		"client_id":             []string{client.ClientID},
		"redirect_uri":          []string{oidcTestRedirect},
		"response_type":         []string{"code"},
		"scope":                 []string{"openid email"},
		"state":                 []string{"state-cookies"},
		"nonce":                 []string{"nonce-cookies"},
		"code_challenge":        []string{challenge},
		"code_challenge_method": []string{"S256"},
	}.Encode(), "", nil)
	if authorize.Code != http.StatusFound {
		t.Fatalf("GET /oidc/authorize = %d, want 302; body: %s", authorize.Code, authorize.Body)
	}

	flow := cookieNamed(authorize.ResponseRecorder, OIDCFlowCookieName)
	if flow == nil {
		t.Fatalf("/oidc/authorize set no %s; cookies: %v", OIDCFlowCookieName,
			cookieNames(authorize.Result().Cookies()))
	}
	if flow.SameSite != http.SameSiteLaxMode {
		t.Errorf("the flow cookie is SameSite=%v, want Lax. It is only ever read on a "+
			"TOP-LEVEL GET, which is the one case Lax still permits, and it is the "+
			"cookie D5's login-CSRF defense rests on.", flow.SameSite)
	}
	if !flow.Secure || !flow.HttpOnly {
		t.Errorf("the flow cookie is Secure=%t HttpOnly=%t, want both true", flow.Secure, flow.HttpOnly)
	}

	login := f.do(t, http.MethodPost, "/v1/session",
		`{"email":"`+f.email+`","password":"`+oidcTestPassword+`"}`, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("POST /v1/session = %d, want 200; body: %s", login.Code, login.Body)
	}
	session := cookieNamed(login.ResponseRecorder, SessionCookieName)
	if session == nil || session.Value == "" {
		t.Fatalf("the sign-in set no %s; cookies: %v", SessionCookieName,
			cookieNames(login.Result().Cookies()))
	}
	if session.SameSite != http.SameSiteLaxMode {
		t.Errorf("the session cookie is SameSite=%v, want Lax. It is only ever SET on a "+
			"top-level response and read on a top-level GET, so it does not need to "+
			"survive a cross-site POST.", session.SameSite)
	}

	f.signOut()
	form := f.do(t, http.MethodGet, loginURL, "", nil)
	mustRedirectToLoginUI(t, form)
	requestID := interactionParams(t, form).Get(oidc.LoginParamRequestID)

	state := cookieNamed(form.ResponseRecorder, OIDCStateCookiePrefix+requestID)
	if state == nil {
		t.Fatalf("the redirect set no state cookie; cookies: %v", cookieNames(form.Result().Cookies()))
	}
	if state.SameSite != http.SameSiteNoneMode {
		t.Errorf("the state cookie is SameSite=%v, want None. The login form is a "+
			"cross-site POST and a Lax cookie is not sent on one, so every sign-in "+
			"would be refused at the CSRF check.", state.SameSite)
	}
	if !state.Secure {
		t.Error("the state cookie is not Secure, and the __Host- prefix requires it")
	}
	if !state.HttpOnly {
		t.Error("the state cookie is not HttpOnly, so a script on the login UI's origin " +
			"could read the CSRF token")
	}
	if got := oidcChallengeCookie(requestID, "a-token", octxTime()); got.SameSite != http.SameSiteNoneMode {
		t.Errorf("the challenge cookie is SameSite=%v, want None; the code form is a "+
			"cross-site POST too", got.SameSite)
	}
}

func TestOIDCUnknownScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		scope string
		want string
	}{
		{name: "a standard scope identity does not implement", scope: "openid phone", want: `unknown scope "phone"`},
		{name: "address", scope: "openid address", want: `unknown scope "address"`},
		{name: "offline_access, which needs a refresh token store", scope: "openid offline_access", want: `unknown scope "offline_access"`},
		{name: "a plural of one of ours", scope: "openid profiles", want: `unknown scope "profiles"`},
		{name: "no openid", scope: "email profile", want: "openid scope is required"},
		{name: "no scope at all", scope: "", want: "openid scope is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newOIDCFixture(t)
			client := f.registerClient(t)

			_, challenge := codeVerifier(t)
			query := url.Values{
				"client_id":             []string{client.ClientID},
				"redirect_uri":          []string{oidcTestRedirect},
				"response_type":         []string{"code"},
				"state":                 []string{"state-scope"},
				"nonce":                 []string{"nonce-scope"},
				"code_challenge":        []string{challenge},
				"code_challenge_method": []string{"S256"},
			}
			if tt.scope != "" {
				query.Set("scope", tt.scope)
			}

			rec := f.do(t, http.MethodGet, oidc.PathAuthorize+"?"+query.Encode(), "", nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("authorize with scope %q = %d, want 400; body: %s", tt.scope, rec.Code, rec.Body)
			}
			if rec.Header().Get("Content-Type") != "application/problem+json" {
				t.Errorf("Content-Type = %q, want application/problem+json", rec.Header().Get("Content-Type"))
			}
			p := decodeProblem(t, rec.ResponseRecorder)
			if !strings.Contains(p.Detail, tt.want) {
				t.Errorf("detail = %q, want it to mention %q", p.Detail, tt.want)
			}
			if p.Code != CodeInvalidRequest {
				t.Errorf("code = %q, want %q", p.Code, CodeInvalidRequest)
			}
			if p.Status != http.StatusBadRequest {
				t.Errorf("status field = %d, want 400", p.Status)
			}
			if p.Type != "https://docs.anywaye.com/errors/"+CodeInvalidRequest {
				t.Errorf("type = %q, want the anywaye error URI for %q", p.Type, CodeInvalidRequest)
			}
			if p.TraceID == "" {
				t.Error("the problem has no trace_id; core requires it on every non-2xx")
			}
		})
	}
}

func TestOIDCAcceptedScopeIsClippedToTheRegistration(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)

	body := fmt.Sprintf(`{"name":"Anytalk","redirect_uris":[%q],"grant_types":["authorization_code"],`+
		`"scopes":["openid","email"]}`, oidcTestRedirect)
	rec := f.do(t, http.MethodPost, "/v1/accounts/"+f.account.String()+"/oidc-clients", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering a client: %d; body: %s", rec.Code, rec.Body)
	}
	var created oidcClientCreatedResponse
	mustJSON(t, rec.Body.Bytes(), &created)
	client := registered{ID: created.ID, ClientID: created.ClientID, ClientSecret: created.ClientSecret, Email: f.email, Password: oidcTestPassword}

	verifier, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-clip", "nonce-clip", nil)
	rec2 := f.login(t, loginURL, client.Email, client.Password)
	code := mustCode(t, rec2.Header().Get("Location"))

	tokens := f.exchange(t, client, code, verifier, oidcTestRedirect)
	if tokens.Code != http.StatusOK {
		t.Fatalf("the exchange = %d, want 200; body: %s", tokens.Code, tokens.Body)
	}

	var body2 map[string]any
	mustJSON(t, tokens.Body.Bytes(), &body2)
	idToken, _ := body2["id_token"].(string)
	claims := f.verify(t, idToken)
	if _, present := claims[oidc.ClaimAccounts]; present {
		t.Errorf("the id_token carries an accounts claim from a scope the client never registered:\n%v", claims)
	}
	if claims["email"] != f.email {
		t.Errorf("the registered email scope was not granted: %v", claims["email"])
	}
}

func TestOIDCUnimplementedParametersAreRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		extra      url.Values
		wantDetail string
	}{
		{
			name:       "prompt=login",
			extra:      url.Values{"prompt": []string{"login"}},
			wantDetail: `prompt=login is not implemented`,
		},
		{
			name:       "prompt=consent",
			extra:      url.Values{"prompt": []string{"consent"}},
			wantDetail: `prompt=consent is not implemented`,
		},
		{
			name:       "max_age",
			extra:      url.Values{"max_age": []string{"300"}},
			wantDetail: "max_age is not implemented",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newOIDCFixture(t)
			client := f.registerClient(t)

			_, challenge := codeVerifier(t)
			query := url.Values{
				"client_id":             []string{client.ClientID},
				"redirect_uri":          []string{oidcTestRedirect},
				"response_type":         []string{"code"},
				"scope":                 []string{"openid email"},
				"state":                 []string{"state-params"},
				"nonce":                 []string{"nonce-params"},
				"code_challenge":        []string{challenge},
				"code_challenge_method": []string{"S256"},
			}
			for key, values := range tt.extra {
				query[key] = values
			}

			got := f.do(t, http.MethodGet, oidc.PathAuthorize+"?"+query.Encode(), "", nil)
			if got.Code != http.StatusBadRequest {
				t.Fatalf("authorize with %v = %d, want 400; body: %s", tt.extra, got.Code, got.Body)
			}
			if !strings.Contains(got.Body.String(), tt.wantDetail) {
				t.Errorf("the detail does not mention %q:\n%s", tt.wantDetail, got.Body)
			}
		})
	}
}

func TestOIDCPromptNoneIsLoginRequired(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	_, challenge := codeVerifier(t)
	query := url.Values{
		"client_id":             []string{client.ClientID},
		"redirect_uri":          []string{oidcTestRedirect},
		"response_type":         []string{"code"},
		"scope":                 []string{"openid email"},
		"state":                 []string{"state-none"},
		"nonce":                 []string{"nonce-none"},
		"prompt":                []string{"none"},
		"code_challenge":        []string{challenge},
		"code_challenge_method": []string{"S256"},
	}

	rec := f.do(t, http.MethodGet, oidc.PathAuthorize+"?"+query.Encode(), "", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize with prompt=none = %d, want 302; body: %s", rec.Code, rec.Body)
	}

	redirect, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("the redirect is not a URL: %v", err)
	}
	if got := redirect.Scheme + "://" + redirect.Host + redirect.Path; got != oidcTestRedirect {
		t.Errorf("the error went to %q, want the registered %q", got, oidcTestRedirect)
	}
	if err := redirect.Query().Get("error"); err != "login_required" {
		t.Errorf("error = %q, want login_required", err)
	}
	if got := redirect.Query().Get("state"); got != "state-none" {
		t.Errorf("state = %q, want the client's own value echoed back", got)
	}
}

func TestOIDCWellKnownDocuments(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)

	t.Run("discovery", func(t *testing.T) {
		t.Parallel()

		for _, path := range []string{oidc.PathDiscovery, oidc.PathOAuthAuthorizationServer} {
			rec := f.do(t, http.MethodGet, path, "", nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200; body: %s", path, rec.Code, rec.Body)
			}
			if rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
				t.Errorf("%s Content-Type = %q", path, rec.Header().Get("Content-Type"))
			}
			if rec.JSON["issuer"] != oidcTestIssuer {
				t.Errorf("%s issuer = %v, want %q", path, rec.JSON["issuer"], oidcTestIssuer)
			}
			if rec.JSON["jwks_uri"] != oidcTestIssuer+oidc.PathJWKS {
				t.Errorf("%s jwks_uri = %v, want the path gateway hardcodes", path, rec.JSON["jwks_uri"])
			}
		}
	})

	t.Run("the key set", func(t *testing.T) {
		t.Parallel()

		rec := f.do(t, http.MethodGet, oidc.PathJWKS, "", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET the jwks = %d, want 200; body: %s", rec.Code, rec.Body)
		}
		if got := rec.JSON["keys"]; got == nil {
			t.Fatal("the key set has no keys array; gateway's isKeySet refuses an empty one")
		}
		keys, _ := rec.JSON["keys"].([]any)
		if len(keys) != 1 {
			t.Fatalf("the key set has %d keys, want exactly 1", len(keys))
		}
		first, _ := keys[0].(map[string]any)
		if first["kid"] != oidcTestKeyID {
			t.Errorf("kid = %v, want %q; the id in the document has to be the one the token header carries", first["kid"], oidcTestKeyID)
		}
		if first["alg"] != "RS256" {
			t.Errorf("alg = %v, want RS256", first["alg"])
		}
		if first["use"] != "sig" {
			t.Errorf("use = %v, want sig", first["use"])
		}
		if _, present := first["d"]; present {
			t.Error("the published key set carries the private exponent")
		}
		if rec.Header().Get("Cache-Control") == "" {
			t.Error("the key set has no Cache-Control; every edge in the platform re-fetches it")
		}
	})
}

func TestOIDCUnmountedEndpointsAre404(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)

	for _, target := range []string{"/oidc/introspect", "/oidc/revoke", "/oidc/end-session", "/oidc/device_authorization"} {
		rec := f.do(t, http.MethodPost, target, "", nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("POST %s = %d, want 404", target, rec.Code)
		}
		if rec.Header().Get("Content-Type") != "application/problem+json" {
			t.Errorf("POST %s Content-Type = %q, want the anywaye problem envelope rather than the library's",
				target, rec.Header().Get("Content-Type"))
		}
	}
}

func TestOIDCLoginSkipsTheFormForASignedInUser(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	verifier, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-silent", "nonce-silent", nil)

	rec := f.do(t, http.MethodGet, loginURL, "", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("GET the login page while signed in = %d, want 302 straight to the client; body: %s", rec.Code, rec.Body)
	}
	redirect, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("the redirect is not a URL: %v", err)
	}
	code := redirect.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in the redirect: %s", redirect)
	}
	if got := f.exchange(t, client, code, verifier, oidcTestRedirect).Code; got != http.StatusOK {
		t.Errorf("the exchange after a silent login = %d, want 200", got)
	}
}

func TestOIDCNonceIsEchoedUnchanged(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	const nonce = "a-nonce-a-client-generated-and-would-recognize"
	verifier, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-nonce", nonce, nil)
	rec := f.login(t, loginURL, client.Email, client.Password)
	code := mustCode(t, rec.Header().Get("Location"))

	tokens := f.exchange(t, client, code, verifier, oidcTestRedirect)
	if tokens.Code != http.StatusOK {
		t.Fatalf("the exchange = %d, want 200; body: %s", tokens.Code, tokens.Body)
	}
	var body map[string]any
	mustJSON(t, tokens.Body.Bytes(), &body)
	claims := f.verify(t, body["id_token"].(string))

	if claims["nonce"] != nonce {
		t.Errorf("id_token nonce = %v, want %q", claims["nonce"], nonce)
	}
}

func TestOIDCWrongCodeVerifierIsRefused(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	_, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-verifier", "nonce-verifier", nil)
	rec := f.login(t, loginURL, client.Email, client.Password)
	code := mustCode(t, rec.Header().Get("Location"))

	wrong, _ := codeVerifier(t)
	refused := f.exchange(t, client, code, wrong, oidcTestRedirect)
	if refused.Code != http.StatusBadRequest {
		t.Fatalf("the exchange with the wrong verifier = %d, want 400; body: %s", refused.Code, refused.Body)
	}
	if err, _ := refused.JSON["error"].(string); err != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", err)
	}
}

func TestOIDCLoginWithNoCredentials(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	_, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-empty", "nonce-empty", nil)

	f.signOut()
	form := f.do(t, http.MethodGet, loginURL, "", nil)
	mustRedirectToLoginUI(t, form)
	sealed := interactionState(t, form)

	jar := &cookieJar{}
	jar.absorb(form.Result().Cookies())

	req := newRequestForm(http.MethodPost, loginURL, url.Values{
		"state":    []string{sealed},
		"email":    []string{""},
		"password": []string{""},
	})
	req.Header.Set("Cookie", jar.header())

	rec := newResponse(serveRecorder(f.handler, req))
	mustRedirectToLoginUI(t, rec)
	query := interactionParams(t, rec)
	if got := query.Get(oidc.LoginParamError); got != oidc.LoginErrorMissingCredentials {
		t.Errorf("%s = %q, want %q", oidc.LoginParamError, got, oidc.LoginErrorMissingCredentials)
	}
	if cookie := cookieNamed(rec.ResponseRecorder, SessionCookieName); cookie != nil && cookie.Value != "" {
		t.Error("an empty form produced a session")
	}
}

func TestOIDCLoginDoesNotEnumerateAccounts(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	_, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-enum", "nonce-enum", nil)

	type answer struct {
		status int
		code   string
		detail string
		step   string
	}
	submit := func(email, password string) answer {
		t.Helper()

		f.signOut()
		form := f.do(t, http.MethodGet, loginURL, "", nil)
		mustRedirectToLoginUI(t, form)
		jar := &cookieJar{}
		jar.absorb(form.Result().Cookies())

		req := newRequestForm(http.MethodPost, loginURL, url.Values{
			"state":    []string{interactionState(t, form)},
			"email":    []string{email},
			"password": []string{password},
		})
		req.Header.Set("Cookie", jar.header())
		rec := newResponse(serveRecorder(f.handler, req))
		mustRedirectToLoginUI(t, rec)
		query := rec.Header().Get("Location")
		parsed, err := url.Parse(query)
		if err != nil {
			t.Fatalf("the redirect is not a URL: %v", err)
		}
		return answer{
			status: rec.Code,
			code:   parsed.Query().Get(oidc.LoginParamError),
			detail: parsed.Query().Get(oidc.LoginParamErrorDetail),
			step:   parsed.Query().Get(oidc.LoginParamStep),
		}
	}

	wrongPassword := submit(f.email, "not the password at all")
	noSuchUser := submit("nobody-at-all@example.com", "not the password at all")

	if wrongPassword.status != noSuchUser.status {
		t.Errorf("a wrong password answered %d and an unknown address %d; the two must be one",
			wrongPassword.status, noSuchUser.status)
	}
	if wrongPassword.code != noSuchUser.code {
		t.Errorf("the two answers name different failures: wrong password %q, unknown address %q",
			wrongPassword.code, noSuchUser.code)
	}
	if wrongPassword.detail != noSuchUser.detail {
		t.Errorf("the two sentences differ:\n  wrong password: %q\n  unknown address: %q",
			wrongPassword.detail, noSuchUser.detail)
	}
	if wrongPassword.step != noSuchUser.step {
		t.Errorf("the two answers land on different steps: %q and %q",
			wrongPassword.step, noSuchUser.step)
	}
	if wrongPassword.code != oidc.LoginErrorInvalidCredentials {
		t.Errorf("the refusal code is %q, want %q", wrongPassword.code, oidc.LoginErrorInvalidCredentials)
	}
	if wrongPassword.status != http.StatusFound {
		t.Errorf("status = %d, want 302 back to the login UI", wrongPassword.status)
	}
}

func TestOIDCLoginWithAnUnknownRequestIs404(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)

	for _, target := range []string{oidc.PathLogin + "/00000000-0000-4000-8000-000000000000", oidc.PathLogin + "/not-an-id"} {
		rec := f.do(t, http.MethodGet, target, "", nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404; body: %s", target, rec.Code, rec.Body)
		}
		if p := decodeProblem(t, rec.ResponseRecorder); p.Code != CodeNotFound {
			t.Errorf("GET %s code = %q, want %q", target, p.Code, CodeNotFound)
		}
	}
}

func TestOIDCDiscoveryOverHTTP(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)

	rec := f.do(t, http.MethodGet, oidc.PathDiscovery, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET discovery = %d, want 200", rec.Code)
	}
	for _, field := range []string{
		"issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri",
		"scopes_supported", "response_types_supported", "grant_types_supported", "subject_types_supported",
		"id_token_signing_alg_values_supported", "token_endpoint_auth_methods_supported",
		"claims_supported", "code_challenge_methods_supported",
	} {
		if _, present := rec.JSON[field]; !present {
			t.Errorf("the document served at %s has no %q", oidc.PathDiscovery, field)
		}
	}
}

func TestOIDCUnknownPathIsTheAnywayeProblemEnvelope(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)

	for _, target := range []string{"/oidc/nope", "/oidc/authorize/extra", "/.well-known/nope"} {
		rec := f.do(t, http.MethodGet, target, "", nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", target, rec.Code)
			continue
		}
		if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
			t.Errorf("GET %s Content-Type = %q, want application/problem+json", target, got)
		}
	}
}

func TestTheLoginRefusalCarriesItsReasonToTheLoginUI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		form url.Values
		wantCode string
		wantStep string
	}{
		{
			name:     "a wrong password",
			form:     url.Values{"email": {f0Email}, "password": {"not the password at all"}},
			wantCode: oidc.LoginErrorInvalidCredentials,
			wantStep: oidc.LoginStepPassword,
		},
		{
			name:     "an address nobody has",
			form:     url.Values{"email": {f0Email}, "password": {oidcTestPassword}},
			wantCode: oidc.LoginErrorInvalidCredentials,
			wantStep: oidc.LoginStepPassword,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newOIDCFixture(t)
			client := f.registerClient(t)

			_, challenge := codeVerifier(t)
			loginURL := f.authorize(t, client, challenge, "state-refusal", "nonce-refusal", nil)

			f.signOut()
			form := f.do(t, http.MethodGet, loginURL, "", nil)
			mustRedirectToLoginUI(t, form)

			post := url.Values{"state": {interactionState(t, form)}}
			for key, values := range tt.form {
				post[key] = values
			}
			rec := f.do(t, http.MethodPost, loginURL, "", post)

			redirect := mustRedirectToLoginUI(t, rec)
			query := redirect.Query()

			if got := query.Get(oidc.LoginParamError); got != tt.wantCode {
				t.Errorf("%s = %q, want %q; a refusal the UI cannot switch on is a refusal "+
					"the user sees as nothing happening", oidc.LoginParamError, got, tt.wantCode)
			}
			if got := query.Get(oidc.LoginParamStep); got != tt.wantStep {
				t.Errorf("%s = %q, want %q", oidc.LoginParamStep, got, tt.wantStep)
			}
			if detail := query.Get(oidc.LoginParamErrorDetail); detail == "" {
				t.Error("the refusal carried no sentence to show a person")
			}
			if got, sealed := query.Get(oidc.LoginParamState), post.Get("state"); got == "" || got == sealed {
				t.Errorf("%s = %q, want a fresh one (%q was just spent)", oidc.LoginParamState, got, sealed)
			}
			if got := mustCodeIfPresent(rec.Header().Get("Location")); got != "" {
				t.Errorf("the refusal minted an authorization code: %s", got)
			}
			if cookie := cookieNamed(rec.ResponseRecorder, SessionCookieName); cookie != nil && cookie.Value != "" {
				t.Error("the refusal set a session cookie")
			}
		})
	}
}

const f0Email = "nobody-at-all@example.com"

func TestOIDCRegistrationEvents(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)

	var before, after int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM outbox_events WHERE type = $1`,
		"identity.oidc_client.created").Scan(&before); err != nil {
		t.Fatalf("counting the created events: %v", err)
	}
	if before != 0 {
		t.Fatalf("there are %d created events before any registration", before)
	}

	client := f.registerClient(t)

	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM outbox_events WHERE type = $1`,
		"identity.oidc_client.created").Scan(&after); err != nil {
		t.Fatalf("counting the created events: %v", err)
	}
	if after != 1 {
		t.Fatalf("a registration wrote %d created events, want 1", after)
	}

	var envelope []byte
	if err := f.pool.QueryRow(t.Context(),
		`SELECT envelope FROM outbox_events WHERE type = $1`, "identity.oidc_client.created").Scan(&envelope); err != nil {
		t.Fatalf("reading the envelope: %v", err)
	}
	for _, forbidden := range []string{"secret", "digest", client.ClientSecret} {
		if strings.Contains(string(envelope), forbidden) {
			t.Errorf("the created envelope mentions %q:\n%s", forbidden, envelope)
		}
	}

	f.revoke(t, client)

	var revoked int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM outbox_events WHERE type = $1`,
		"identity.oidc_client.revoked").Scan(&revoked); err != nil {
		t.Fatalf("counting the revoked events: %v", err)
	}
	if revoked != 1 {
		t.Errorf("a revocation wrote %d revoked events, want 1", revoked)
	}
}

func TestOIDCRevokingTwiceIs409(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	first := f.do(t, http.MethodDelete, "/v1/accounts/"+f.account.String()+"/oidc-clients/"+client.ID, "", nil)
	if first.Code != http.StatusNoContent {
		t.Fatalf("the first revocation = %d, want 204; body: %s", first.Code, first.Body)
	}

	second := f.do(t, http.MethodDelete, "/v1/accounts/"+f.account.String()+"/oidc-clients/"+client.ID, "", nil)
	if second.Code != http.StatusConflict {
		t.Fatalf("the second revocation = %d, want 409; body: %s", second.Code, second.Body)
	}
	if p := decodeProblem(t, second.ResponseRecorder); p.Code != CodeConflict {
		t.Errorf("code = %q, want %q", p.Code, CodeConflict)
	}
}

func TestOIDCClientSecretIsReturnedOnce(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	list := f.do(t, http.MethodGet, "/v1/accounts/"+f.account.String()+"/oidc-clients", "", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("listing clients = %d, want 200; body: %s", list.Code, list.Body)
	}
	if strings.Contains(list.Body.String(), client.ClientSecret) {
		t.Error("the list carries the client secret")
	}
	if strings.Contains(list.Body.String(), "secret_digest") {
		t.Error("the list carries the secret digest")
	}

	detail := f.do(t, http.MethodGet, "/v1/accounts/"+f.account.String()+"/oidc-clients/"+client.ID, "", nil)
	if detail.Code != http.StatusOK {
		t.Fatalf("reading a client = %d, want 200; body: %s", detail.Code, detail.Body)
	}
	for _, forbidden := range []string{client.ClientSecret, "secret_digest"} {
		if strings.Contains(detail.Body.String(), forbidden) {
			t.Errorf("the detail carries %q", forbidden)
		}
	}

	var digest string
	if err := f.pool.QueryRow(t.Context(),
		`SELECT secret_digest FROM oidc_clients WHERE id = $1`, mustParseID(t, client.ID)).Scan(&digest); err != nil {
		t.Fatalf("reading the stored digest: %v", err)
	}
	if digest == client.ClientSecret {
		t.Error("the row holds the secret in plaintext")
	}
	if len(digest) != 64 {
		t.Errorf("the stored digest is %d characters, want 64", len(digest))
	}
}

func TestOIDCClientIsScopedToItsAccount(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	other, otherSession := f.otherAccount(t)

	rec := f.doAs(t, otherSession, http.MethodGet, "/v1/accounts/"+other.String()+"/oidc-clients/"+client.ID, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("reading another account's client = %d, want 404; body: %s", rec.Code, rec.Body)
	}
	if p := decodeProblem(t, rec.ResponseRecorder); p.Code != CodeNotFound {
		t.Errorf("code = %q, want %q", p.Code, CodeNotFound)
	}

	revoked := f.doAs(t, otherSession, http.MethodDelete, "/v1/accounts/"+other.String()+"/oidc-clients/"+client.ID, "")
	if revoked.Code != http.StatusNotFound {
		t.Errorf("revoking another account's client = %d, want 404; body: %s", revoked.Code, revoked.Body)
	}
}

func TestOIDCClientRegistrationValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		body      string
		wantField string
	}{
		{
			name: "no name",
			body: fmt.Sprintf(`{"redirect_uris":[%q],"grant_types":["authorization_code"],"scopes":["openid"]}`,
				oidcTestRedirect),
			wantField: "name",
		},
		{
			name: "no redirect URIs",
			body: `{"name":"Anytalk","redirect_uris":[],"grant_types":["authorization_code"],"scopes":["openid"]}`,
			wantField: "redirect_uris",
		},
		{
			name: "a plain-http origin",
			body: `{"name":"Anytalk","redirect_uris":["http://app.example.com/cb"],` +
				`"grant_types":["authorization_code"],"scopes":["openid"]}`,
			wantField: "redirect_uris",
		},
		{
			name: "a wildcard origin",
			body: `{"name":"Anytalk","redirect_uris":["https://*.example.com/cb"],` +
				`"grant_types":["authorization_code"],"scopes":["openid"]}`,
			wantField: "redirect_uris",
		},
		{
			name: "a grant this service does not implement",
			body: fmt.Sprintf(`{"name":"Anytalk","redirect_uris":[%q],"grant_types":["client_credentials"],`+
				`"scopes":["openid"]}`, oidcTestRedirect),
			wantField: "grant_types",
		},
		{
			name: "scopes with no openid",
			body: fmt.Sprintf(`{"name":"Anytalk","redirect_uris":[%q],"grant_types":["authorization_code"],`+
				`"scopes":["email"]}`, oidcTestRedirect),
			wantField: "scopes",
		},
		{
			name: "an unknown field",
			body: fmt.Sprintf(`{"name":"Anytalk","redirect_uris":[%q],"grant_types":["authorization_code"],`+
				`"scopes":["openid"],"is_admin":true}`, oidcTestRedirect),
			wantField: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newOIDCFixture(t)
			rec := f.do(t, http.MethodPost, "/v1/accounts/"+f.account.String()+"/oidc-clients", tt.body, nil)

			if tt.wantField == "" {
				if rec.Code != http.StatusUnprocessableEntity {
					t.Fatalf("= %d, want 422; body: %s", rec.Code, rec.Body)
				}
				return
			}

			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("= %d, want 422; body: %s", rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec.ResponseRecorder)
			if len(p.Errors) != 1 || p.Errors[0].Field != tt.wantField {
				t.Errorf("errors = %+v, want one entry on %q", p.Errors, tt.wantField)
			}
		})
	}
}

func TestOIDCClientRegistrationResponse(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	rec := f.do(t, http.MethodGet, "/v1/accounts/"+f.account.String()+"/oidc-clients/"+client.ID, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("= %d, want 200; body: %s", rec.Code, rec.Body)
	}

	want := []string{"id", "client_id", "name", "redirect_uris", "grant_types", "scopes", "created_at"}
	if len(rec.JSON) != len(want) {
		t.Errorf("the body has %d fields (%v), want exactly %d", len(rec.JSON), sortedKeys(rec.JSON), len(want))
	}
	for _, field := range want {
		if _, present := rec.JSON[field]; !present {
			t.Errorf("the body has no %q", field)
		}
	}
	if rec.JSON["name"] != "Anytalk" {
		t.Errorf("name = %v, want Anytalk", rec.JSON["name"])
	}
	if uris, _ := rec.JSON["redirect_uris"].([]any); len(uris) != 1 || uris[0] != oidcTestRedirect {
		t.Errorf("redirect_uris = %v, want the one registered", rec.JSON["redirect_uris"])
	}
	if grants, _ := rec.JSON["grant_types"].([]any); len(grants) != 1 || grants[0] != "authorization_code" {
		t.Errorf("grant_types = %v, want [authorization_code]", rec.JSON["grant_types"])
	}
	if scopes, _ := rec.JSON["scopes"].([]any); !slices.Contains(scopes, "openid") {
		t.Errorf("scopes = %v, want them to include openid", rec.JSON["scopes"])
	}
}

func TestOIDCClientListIsAnArrayNotNull(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)

	rec := f.do(t, http.MethodGet, "/v1/accounts/"+f.account.String()+"/oidc-clients", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("= %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if trimmed := strings.TrimSpace(rec.Body.String()); trimmed != "[]" {
		t.Errorf("body = %s, want []", trimmed)
	}
}


func (f *oidcFixture) revoke(t *testing.T, client registered) {
	t.Helper()

	rec := f.do(t, http.MethodDelete, "/v1/accounts/"+f.account.String()+"/oidc-clients/"+client.ID, "", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoking a client = %d, want 204; body: %s", rec.Code, rec.Body)
	}
}

func (f *oidcFixture) otherAccount(t *testing.T) (id.UUID, string) {
	t.Helper()

	email := dbtest.UniqueEmail(t)
	rec := f.do(t, http.MethodPost, "/v1/users", `{"email":"`+email+`","password":"`+oidcTestPassword+`"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering a second user: %d; body: %s", rec.Code, rec.Body)
	}
	var created userResponse
	mustJSON(t, rec.Body.Bytes(), &created)

	login := f.do(t, http.MethodPost, "/v1/session", `{"email":"`+email+`","password":"`+oidcTestPassword+`"}`, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("signing the second user in: %d; body: %s", login.Code, login.Body)
	}
	var session sessionResponse
	mustJSON(t, login.Body.Bytes(), &session)

	owner := mustParseID(t, created.ID)
	created2, err := f.tenantAccount(t, owner)
	if err != nil {
		t.Fatalf("creating a second account: %v", err)
	}
	return created2, session.Token
}

func (f *oidcFixture) doAs(t *testing.T, token, method, target, body string) *oidcResponse {
	t.Helper()

	return f.doWithSession(t, token, method, target, body, nil)
}
