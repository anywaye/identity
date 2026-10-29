package client


import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// APITokenPrefix is identity's `apikeys.Prefix`, read as the discriminator exactly
// as identity reads it.
//
// Duplicated rather than imported: `internal/apikeys` is an `internal/` package and
// this one is not — a client that cannot be imported by a consumer is not a client
// — and the whole module is the service, whose binary must not depend on a client.
// `TestThePrefixIsTheOneIdentityUses` states the two must agree, so the copy
// cannot drift silently.
const APITokenPrefix = "anywaye_"

// SessionCookieName is identity's `httpapi.SessionCookieName`.
//
// The `__Host-` prefix is not cosmetic: it is a browser-enforced contract
// requiring `Secure`, `Path=/` and no `Domain`, and a request that names the cookie
// wrongly is a request that looks authenticated and is not.
const SessionCookieName = "__Host-session"

// CredentialKind is what a credential is, which decides where it may be sent.
type CredentialKind int

const (
	KindSession CredentialKind = iota
	KindAPIToken
	KindJWT
)

// String names the kind, and deliberately names the DISCRIMINATOR rather than the
// internal value: "apiToken" is what a reader of a log line or a support ticket
// needs, and an integer index would be meaningless to them and would change meaning
// if a constant were ever inserted.
func (k CredentialKind) String() string {
	switch k {
	case KindAPIToken:
		return "apiToken"
	case KindJWT:
		return "jwt"
	case KindSession:
		return "session"
	}
	return "unknown"
}

// ErrInvalidCredential is returned for a credential this package refuses to send.
//
// A sentinel so a caller can match it with `errors.Is` and decide, which is the
// same shape `internal/config`'s sentinels take in the service half of this
// repository.
var ErrInvalidCredential = errors.New("invalid credential")

var forbiddenInCredential = regexp.MustCompile(`[\x00-\x20\x7f]`)

// ClassifyCredential decides what a credential is, and refuses one that could
// break a header.
//
// It returns a `CredentialKind` and an error rather than panicking, because the
// caller is a library: a credential from an operator's configuration file is not a
// programming mistake, and taking a process down over one is worse than refusing
// the request.
//
// **The offending value is never quoted back in the error.** A credential that
// reached an error message has leaked, and this is one of the two places that has
// to be true for that not to have happened — the other is the error type's own
// `Error()`.
func ClassifyCredential(token string) (CredentialKind, error) {
	if token == "" || forbiddenInCredential.MatchString(token) {
		return KindSession, fmt.Errorf("%w: a anywaye credential must be a non-empty string "+
			"containing no control characters, spaces, CR or LF. Refusing it here rather "+
			"than sending it, because a value carrying CR or LF would be a header-injection "+
			"attempt and a blank one is a configuration mistake that would otherwise surface "+
			"as a 401 from a service hours later", ErrInvalidCredential)
	}

	if strings.HasPrefix(token, APITokenPrefix) {
		return KindAPIToken, nil
	}
	if isJWSCompact(token) {
		return KindJWT, nil
	}
	return KindSession, nil
}

const jwsCompact = "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$"

func isJWSCompact(token string) bool {
	if !regexp.MustCompile(jwsCompact).MatchString(token) {
		return false
	}

	first, _, _ := strings.Cut(token, ".")
	raw, err := base64URLDecode(first)
	if err != nil {
		return false
	}

	var header struct {
		Alg string `json:"alg"`
	}
	if err := jsonUnmarshal(raw, &header); err != nil {
		return false
	}
	return header.Alg != ""
}

// AttachCredential puts the credential on a request, in the one place that does it.
//
// Three rules, all of them load-bearing:
//
//   - A session contributes BOTH the bearer header and the cookie, for the reason
//     in the file header: identity prefers the header when both are present, so
//     the pair is unambiguous by the server's own rule and one credential works
//     against every service in the fleet.
//
//   - An apiToken and a jwt contribute the bearer header ONLY. core's conventions
//     reserve cookies for browser sessions, and a machine credential in a cookie is
//     one a browser attaches without the holder intending it.
//
//   - An existing header is never overwritten. The generated client applies the
//     same rule to the same problem (`checkForExistence` in its own utils), and
//     matching it means a caller passing their own `Authorization` per request
//     gets theirs rather than a surprise about which of two values won.
//
// The cookie is set with `Header.Set` rather than `http.Cookie` because a `Cookie`
// request header is exactly one line and `http.Cookie.String()` adds `Path=/`,
// which is wrong for a request header and is the sort of detail that gets a cookie
// silently ignored.
func AttachCredential(req *http.Request, token string) error {
	kind, err := ClassifyCredential(token)
	if err != nil {
		return err
	}

	if req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	if kind == KindSession && req.Header.Get("Cookie") == "" {
		req.Header.Set("Cookie", SessionCookieName+"="+token)
	}

	return nil
}

func base64URLDecode(segment string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(segment)
}

func jsonUnmarshal(raw []byte, into any) error {
	return json.Unmarshal(raw, into)
}
