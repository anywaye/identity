package oauthtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/anywaye/identity/internal/oauth"
)

// Email is one entry of GitHub's /user/emails response.
type Email struct {
	Address  string
	Primary  bool
	Verified bool
}

// Server is a fake provider serving a token endpoint, an identity endpoint and —
// because GitHub's identity endpoint does not always carry one — an emails
// endpoint.
//
// Every method is safe to call before the first request; the knobs are read under
// a mutex when a handler runs, and go test runs tests within a package in
// sequence unless they call t.Parallel.
type Server struct {
	URL string

	closer func()

	Code string
	AccessToken  string
	RefreshToken string
	ExpiresIn int

	ProviderUID string
	Email       string
	Name        string

	Emails []Email

	OmitEmail bool

	UnverifiedEmail bool

	appleKey *ecdsa.PrivateKey
	appleKeyID string
	unpublishedKey *ecdsa.PrivateKey
	unpublishedKeyID string
	useUnpublishedKey bool

	clientID string

	tokenStatus    int
	userInfoStatus int
	emailsStatus   int

	mu        sync.Mutex
	calls     []string
	tokenForm url.Values
	authz     string
}

// NewServer starts a fake provider and stops it when the test ends.
func NewServer(t *testing.T) *Server {
	t.Helper()

	appleKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the fake's ES256 key: %v", err)
	}
	unpublishedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the fake's unpublished ES256 key: %v", err)
	}

	s := &Server{
		Code:             "the-authorization-code",
		AccessToken:      "an-access-token",
		RefreshToken:     "a-refresh-token",
		ExpiresIn:        3600,
		ProviderUID:      "107346492749283471920",
		Email:            "kaka@example.com",
		Name:             "Kaka",
		appleKey:         appleKey,
		appleKeyID:       "test-key-id",
		unpublishedKey:   unpublishedKey,
		unpublishedKeyID: "unpublished-key-id",
		clientID:         "test-client-id",
	}

	server := httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(server.Close)
	s.URL = server.URL
	s.closer = server.Close

	return s
}

// Close stops the server, so a test can prove what a caller sees when the provider
// cannot be reached at all.
func (s *Server) Close() { s.closer() }

// Person sets what the identity endpoint reports.
func (s *Server) Person(uid, email, name string) *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ProviderUID, s.Email, s.Name = uid, email, name
	return s
}

// WithoutEmail makes the identity endpoint report no address. Combined with
// Emails, it is the GitHub case where the address has to come from a second call.
func (s *Server) WithoutEmail() *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.OmitEmail = true
	return s
}

// WithEmails sets the /user/emails payload.
func (s *Server) WithEmails(emails ...Email) *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Emails = emails
	return s
}

// WithoutVerifiedEmail makes the provider report the address as NOT verified. It is
// the case the client must refuse, and it is a distinct knob from WithoutEmail: one
// is "the provider said nothing usable", the other is "the provider said something
// and it is not good enough".
func (s *Server) WithoutVerifiedEmail() *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.UnverifiedEmail = true
	return s
}

// WithoutExpiry makes the token endpoint return a token that does not expire.
func (s *Server) WithoutExpiry() *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ExpiresIn = 0
	return s
}

// WithUnpublishedKey makes the fake sign id_tokens with a key it does NOT
// publish in its JWKS — the forged-token case.
//
// It exists because the client's Apple path verifies the id_token's signature
// against the provider's JWKS, and a fake that only ever signed with the
// published key would make that verification untestable in the direction that
// matters: a token signed by a key the JWKS does not publish must be refused,
// and a verifier that accepted it would be an authentication bypass. The knob
// is the negative control for the whole id_token path.
func (s *Server) WithUnpublishedKey() *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.useUnpublishedKey = true
	return s
}

// FailToken makes the token endpoint answer with this status and an RFC 6749 error
// body. 500 is "the provider is broken"; 400 is "your code was no good", and the
// two mean different things to the caller.
func (s *Server) FailToken(status int) *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenStatus = status
	return s
}

// FailUserInfo makes the identity endpoint answer with this status.
func (s *Server) FailUserInfo(status int) *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.userInfoStatus = status
	return s
}

// FailEmails makes the emails endpoint answer with this status.
func (s *Server) FailEmails(status int) *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.emailsStatus = status
	return s
}

// Calls returns the endpoints that were hit, in order, so a test can assert that
// the flow stopped where it should.
func (s *Server) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// LastTokenForm returns the form the last token request carried. The code and the
// redirect_uri are the two fields a test needs to check that the right code was
// exchanged for the right callback.
func (s *Server) LastTokenForm() url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokenForm
}

// LastAuthorization returns the Authorization header the last identity request
// carried. A test asserting the access token is presented — rather than a
// remembered session id, or nothing at all — is what catches an implementation
// that fetched the profile before exchanging the code.
func (s *Server) LastAuthorization() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authz
}

// Provider returns base with every endpoint pointed at this server.
//
// It is how a test gets a real Provider value — a real one, with real scopes and a
// real client id — into a flow whose network calls land in this process.
func (s *Server) Provider(t *testing.T, base oauth.Provider) oauth.Provider {
	t.Helper()

	base.AuthorizeURL = s.URL + "/authorize"
	base.TokenURL = s.URL + "/token"
	base.UserInfoURL = s.URL + "/userinfo"
	base.EmailsURL = s.URL + "/emails"
	base.JWKSURL = s.URL + "/keys"
	base.ClientID = s.clientID
	base.ClientSecret = "test-client-secret"
	return base
}

// Providers returns a Registry holding every provider pointed at this server, so a
// test can exercise the 404 path for a provider it has deliberately not
// configured.
func (s *Server) Providers(t *testing.T) []oauth.Provider {
	t.Helper()

	return []oauth.Provider{
		s.Provider(t, oauth.Google()),
		s.Provider(t, oauth.GitHub()),
		s.Provider(t, oauth.Microsoft()),
		s.Provider(t, oauth.Apple()),
	}
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.record(r.URL.Path)

	if status := s.tokenStatus; status != 0 && r.URL.Path == "/token" {
		s.serveTokenError(w, status)
		return
	}
	if status := s.userInfoStatus; status != 0 && r.URL.Path == "/userinfo" {
		http.Error(w, `{"error":"server_error"}`, status)
		return
	}
	if status := s.emailsStatus; status != 0 && r.URL.Path == "/emails" {
		http.Error(w, `{"message":"server error"}`, status)
		return
	}

	switch r.URL.Path {
	case "/token":
		s.serveToken(w, r)
	case "/userinfo":
		s.serveUserInfo(w, r)
	case "/emails":
		s.serveEmails(w, r)
	case "/keys":
		s.serveJWKS(w)
	case "/authorize":
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>authorize</body></html>"))
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) record(path string) {
	s.calls = append(s.calls, path)
}

func (s *Server) authorizes(r *http.Request) bool {
	return r.Header.Get("Authorization") == "Bearer "+s.AccessToken
}

func (s *Server) serveToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	s.tokenForm = r.PostForm

	if r.PostForm.Get("code") != s.Code {
		s.serveTokenError(w, http.StatusBadRequest)
		return
	}

	body := map[string]any{
		"access_token": s.AccessToken,
		"token_type":   "Bearer",
	}
	if s.RefreshToken != "" {
		body["refresh_token"] = s.RefreshToken
	}
	if s.ExpiresIn > 0 {
		body["expires_in"] = s.ExpiresIn
	}
	body["redirect_uri"] = r.PostForm.Get("redirect_uri")

	idToken, err := s.mintIDToken()
	if err != nil {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}
	body["id_token"] = idToken

	writeJSON(w, http.StatusOK, body)
}

func (s *Server) mintIDToken() (string, error) {
	key := s.appleKey
	kid := s.appleKeyID
	if s.useUnpublishedKey {
		key = s.unpublishedKey
		kid = s.unpublishedKeyID
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", kid),
	)
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := map[string]any{
		"iss":            "https://appleid.apple.com",
		"sub":            s.ProviderUID,
		"aud":            s.clientID,
		"email":          s.Email,
		"email_verified": !s.UnverifiedEmail,
		"iat":            now.Unix(),
		"exp":            now.Add(time.Hour).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

func (s *Server) serveJWKS(w http.ResponseWriter) {
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       &s.appleKey.PublicKey,
		KeyID:     s.appleKeyID,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}}}
	writeJSON(w, http.StatusOK, jwks)
}

func (s *Server) serveTokenError(w http.ResponseWriter, status int) {
	code := "server_error"
	if status < 500 {
		code = "invalid_grant"
	}
	writeJSON(w, status, map[string]string{"error": code})
}

func (s *Server) serveUserInfo(w http.ResponseWriter, r *http.Request) {
	if !s.authorizes(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	s.authz = r.Header.Get("Authorization")

	body := map[string]any{
		"name":  s.Name,
		"login": s.ProviderUID,
	}
	if s.OmitEmail {
		body["email"] = nil
	} else {
		body["email"] = s.Email
	}

	body["sub"] = s.ProviderUID
	if _, err := strconv.ParseInt(s.ProviderUID, 10, 64); err == nil {
		body["id"] = json.Number(s.ProviderUID)
	}
	body["email_verified"] = !s.UnverifiedEmail

	writeJSON(w, http.StatusOK, body)
}

func (s *Server) serveEmails(w http.ResponseWriter, r *http.Request) {
	if !s.authorizes(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	s.authz = r.Header.Get("Authorization")

	out := make([]map[string]any, 0, len(s.Emails))
	for _, e := range s.Emails {
		out = append(out, map[string]any{
			"email": e.Address,
			"primary":  e.Primary,
			"verified": e.Verified && !s.UnverifiedEmail,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

const (
	TokenEndpointPath    = "/token"
	UserInfoEndpointPath = "/userinfo"
	EmailsEndpointPath   = "/emails"
	JWKSPath             = "/keys"
)

// RequireCalls fails the test unless the endpoints were hit in this order. A flow
// that calls the identity endpoint before the token endpoint is a flow that
// authenticates nobody, and this is how that is caught.
func RequireCalls(t *testing.T, s *Server, want ...string) {
	t.Helper()

	got := s.Calls()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("the provider was called %v, want %v", got, want)
	}
}
