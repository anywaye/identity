package httpapi


import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/platform/dbtest"
)

type oidcFlowBindingFixture struct {
	*oidcFixture
	attackerJar *cookieJar
}

func (f *oidcFlowBindingFixture) authorizeAnonymous(t *testing.T, client registered, challenge, state, nonce string) string {
	t.Helper()

	query := url.Values{
		"client_id":             []string{client.ClientID},
		"redirect_uri":          []string{oidcTestRedirect},
		"response_type":         []string{"code"},
		"scope":                 []string{"openid email profile accounts"},
		"state":                 []string{state},
		"nonce":                 []string{nonce},
		"code_challenge":        []string{challenge},
		"code_challenge_method": []string{"S256"},
	}

	req := newRequestNoCookie(http.MethodGet, oidc.PathAuthorize+"?"+query.Encode())
	rec := newResponse(serveRecorder(f.handler, req))
	if rec.Code != http.StatusFound {
		t.Fatalf("GET /oidc/authorize = %d, want 302; body: %s", rec.Code, rec.Body)
	}

	location := rec.Header().Get("Location")
	if !hasPrefixPath(location, oidc.PathLogin+"/") {
		t.Fatalf("the browser was sent to %q, want the login page", location)
	}
	return location
}

func hasPrefixPath(got, prefix string) bool {
	return len(got) >= len(prefix) && got[:len(prefix)] == prefix
}

func TestAnAuthorizationRequestIsNotSpendableByABrowserThatDidNotStartIt(t *testing.T) {
	t.Parallel()

	f := &oidcFlowBindingFixture{oidcFixture: newOIDCFixture(t), attackerJar: &cookieJar{}}

	client := f.registerClient(t)

	_, challenge := codeVerifier(t)
	attackerLoginURL := f.authorizeAnonymous(t, client, challenge, "state-attacker", "nonce-attacker")

	_ = f.attackerJar

	rec := f.do(t, http.MethodGet, attackerLoginURL, "", nil)

	if code := mustCodeIfPresent(rec.Header().Get("Location")); code != "" {
		t.Fatalf("a browser that never started this flow completed it: GET %s answered %d "+
			"carrying an authorization code to %s. The victim's session signed an "+
			"authorization request whose client, secret, PKCE verifier and redirect_uri "+
			"all belong to whoever sent them this link",
			attackerLoginURL, rec.Code, oidcTestRedirect)
	}
	if strings.Contains(rec.Header().Get("Location"), oidcTestRedirect) {
		t.Fatalf("the victim's browser was handed to the attacker's redirect_uri: %s",
			rec.Header().Get("Location"))
	}

	switch rec.Code {
	case http.StatusForbidden:
	case http.StatusFound:
		redirect := mustRedirectToLoginUI(t, rec)
		if redirect.Query().Get(oidc.LoginParamRequestID) != requestIDOf(t, attackerLoginURL) {
			t.Errorf("the redirect names %q rather than the request in the URL; a login UI "+
				"that posts back the wrong id would complete a different request",
				redirect.Query().Get(oidc.LoginParamRequestID))
		}
	default:
		t.Errorf("the victim's browser got %d, want 403 or a redirect to the login UI; "+
			"body:\n%s", rec.Code, rec.Body)
	}
}

func mustCodeIfPresent(location string) string {
	if location == "" {
		return ""
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return ""
	}
	return parsed.Query().Get("code")
}

func (f *oidcFixture) signInASecondUser(t *testing.T) (email string, token string) {
	t.Helper()

	email = uniqueEmailForFlowTest(t)

	rec := f.do(t, http.MethodPost, "/v1/users",
		`{"email":"`+email+`","password":"`+oidcTestPassword+`"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering the second user: %d; body: %s", rec.Code, rec.Body)
	}

	login := f.do(t, http.MethodPost, "/v1/session",
		`{"email":"`+email+`","password":"`+oidcTestPassword+`"}`, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("signing the second user in: %d; body: %s", login.Code, login.Body)
	}

	var session sessionResponse
	mustJSON(t, login.Body.Bytes(), &session)
	if session.Token == "" {
		t.Fatal("the second user's login carried no session token")
	}
	return email, session.Token
}

func uniqueEmailForFlowTest(t *testing.T) string { return dbtest.UniqueEmail(t) }

func TestAnAttackerExchangesACodeTheVictimsBrowserMintedForThem(t *testing.T) {
	t.Parallel()

	f := &oidcFlowBindingFixture{oidcFixture: newOIDCFixture(t), attackerJar: &cookieJar{}}

	attackerClient := f.registerClient(t)
	attackerID := f.owner

	verifier, challenge := codeVerifier(t)
	loginURL := f.authorizeAnonymous(t, attackerClient, challenge, "state-attacker", "nonce-attacker")

	_, victimSession := f.signInASecondUser(t)

	jar := &cookieJar{}
	jar.set(victimSession)

	req := newRequestNoCookie(http.MethodGet, loginURL)
	req.Header.Set("Cookie", jar.header())
	rec := newResponse(serveRecorder(f.handler, req))

	code := mustCodeIfPresent(rec.Header().Get("Location"))

	if code == "" {
		if rec.Code != http.StatusForbidden {
			t.Errorf("the victim's browser was refused with %d, want 403 — a refusal is the "+
				"right answer but an unexplained one, and this file asserts the status so a "+
				"future change cannot quietly turn it into something else", rec.Code)
		}
		return
	}

	tokens := f.exchange(t, attackerClient, code, verifier, oidcTestRedirect)
	if tokens.Code != http.StatusOK {
		t.Fatalf("the victim's browser minted a code for the attacker's client, and the "+
			"attacker then could not redeem it: %d; body: %s", tokens.Code, tokens.Body)
	}

	idToken, _ := tokens.JSON["id_token"].(string)
	if idToken == "" {
		t.Fatal("the token response carried no id_token")
	}

	claims := f.verify(t, idToken)
	sub, _ := claims["sub"].(string)
	if sub == attackerID.String() {
		t.Fatalf("sub = the attacker; the victim contributed nothing to this token, so the " +
			"browser binding is not what this test was checking")
	}

	t.Fatalf("the attack completed: a browser holding only the VICTIM's session minted an "+
		"authorization code for the ATTACKER's client, and the attacker exchanged it for an "+
		"id_token whose subject is %s — a user who never started this flow, never saw its "+
		"login page and never typed a password for it. The attacker now holds the victim's "+
		"identity at a relying party they registered themselves", sub)
}
