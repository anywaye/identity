package oidc

import (
	"errors"
	"fmt"
	"net/url"
)


// LoginUIEnvVar is the variable that names the login UI.
//
// It is exported so the refusal an operator reads names the variable they have
// to set, which is the same reason `LinkTemplateVariable` is exported and for a
// narrower reason: there is one login UI, so there is nothing to walk.
const LoginUIEnvVar = "OIDC_LOGIN_UI_URL"

var (
	ErrNoLoginUI = errors.New("no OIDC login UI configured")

	ErrInvalidLoginUI = errors.New("the OIDC login UI URL is not usable")
)

const (
	LoginParamRequestID = "request_id"
	LoginParamState = "state"
	LoginParamStep = "step"
	LoginParamClientName = "client_name"
	LoginParamLoginHint = "login_hint"
	LoginParamError = "error"
	LoginParamErrorDetail = "error_detail"
	LoginParamRetryAfter = "retry_after"
)

const (
	LoginStepPassword = "password"
	LoginStepChallenge = "challenge"
)

const (
	LoginErrorInteractionExpired = "interaction_expired"
	LoginErrorMissingCredentials = "missing_credentials"
	LoginErrorInvalidCredentials = "invalid_credentials"
	LoginErrorChallengeRejected = "challenge_rejected"
	LoginErrorAccountLocked = "account_locked"
)

// LoginRedirectParams is one redirect to the login UI.
//
// A struct rather than a url.Values at the call site because the parameter NAMES
// are a contract with another repository and a bag of strings is where a
// contract goes to be misspelled. Every field is optional except RequestID, State
// and Step, and an empty optional field is omitted rather than sent empty — an
// absent `error` and an empty `error` must not both be readable as "no error",
// because a login UI that renders `if (params.error)` would show an empty
// failure banner.
type LoginRedirectParams struct {
	RequestID string
	State string
	Step string
	ClientName string
	LoginHint string
	Error string
	ErrorDetail string
	RetryAfter string
}

// Values is the query this service adds, as url.Values.
//
// Exported through the type rather than kept private because the two tests that
// hold the contract — the one in this package and the one in `internal/httpapi`
// that asserts on a real response — should both read the names from here rather
// than from a list of literals that happens to match.
func (p LoginRedirectParams) Values() url.Values {
	out := url.Values{}
	out.Set(LoginParamRequestID, p.RequestID)
	out.Set(LoginParamState, p.State)
	out.Set(LoginParamStep, p.Step)
	for name, value := range map[string]string{
		LoginParamClientName:  p.ClientName,
		LoginParamLoginHint:   p.LoginHint,
		LoginParamError:       p.Error,
		LoginParamErrorDetail: p.ErrorDetail,
		LoginParamRetryAfter:  p.RetryAfter,
	} {
		if value != "" {
			out.Set(name, value)
		}
	}
	return out
}

// ValidateLoginUIURL refuses a login UI address this service cannot send a
// browser to.
//
// IT IS EXPORTED AND CALLED BY BOTH SIDES — `NewProvider` here and
// `internal/config` at boot — rather than duplicated, and the reason is stated
// because the courier's boot rule IS duplicated and the contrast is the
// argument. `internal/courier` is a platform adapter that has to be correct on
// its own whether or not this service validated anything, so the rule is written
// twice and a test holds the copies in step. `internal/oidc` is not an adapter:
// it is what the provider IS, the same way `internal/recovery` is what a mailer
// implements. One rule in one place, and the two callers cannot disagree because
// there is only one to disagree with.
//
// # THE REFUSALS, AND WHY EACH IS THE FAILURE DIRECTION
//
//	empty        an authorization server with nowhere to send a browser is a
//	             provider that cannot complete a flow. Construction failure.
//	not a URL    a typo. Found at boot, it costs one log line; found by the first
//	             user, it costs an afternoon.
//	wrong scheme a `javascript:` or `data:` login UI is an injection primitive
//	             aimed at a redirect this service issues, and the value it would
//	             carry is an authorization request id.
//	no host      same class: not an address.
//	userinfo     `https://parlor@evil.example.com/login` reads as a login UI and
//	             resolves to an attacker's host. Refused for the same reason
//	             `validateLinkTemplate` refuses one.
//	fragment     a fragment is not sent to a server, so a login UI that expected
//	             to read the request id from one would never see it.
//	query        THE ONE THAT LOOKS HARMLESS. This service MERGES its parameters
//	             into the query rather than appending to it, so a configured
//	             query would be preserved rather than mangled — and a preserved
//	             query is a query this service did not write appearing in a URL
//	             that also carries an authorization request id, a CSRF state and
//	             whatever a client put in `login_hint`. `internal/config` refuses
//	             COURIER_BASE_URL for exactly this reason, and the rule is the
//	             same here. A deployment that needs a tenant or a variant in the
//	             path puts it in the path.
func ValidateLoginUIURL(raw string) error {
	if raw == "" {
		return ErrNoLoginUI
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: it is not a URL: %w", ErrInvalidLoginUI, err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("%w: its scheme is %q, want http or https", ErrInvalidLoginUI, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: it has no host, so there is nowhere to send a browser", ErrInvalidLoginUI)
	}
	if parsed.RawQuery != "" {
		return fmt.Errorf("%w: it carries a query (%q). This service adds its own parameters to "+
			"the query, and a configured one would be preserved — so the URL would carry an "+
			"authorization request id, a CSRF state and a client's login_hint alongside a "+
			"string this service did not write. Put a tenant or a variant in the PATH instead",
			ErrInvalidLoginUI, parsed.RawQuery)
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("%w: it carries a fragment, which is not sent to a server", ErrInvalidLoginUI)
	}
	if parsed.User != nil {
		return fmt.Errorf("%w: it has a userinfo section, so the host in it is not the host it "+
			"resolves to", ErrInvalidLoginUI)
	}
	return nil
}

// LoginRedirect is the absolute URL a browser is sent to in order to authenticate
// for one authorization request.
//
// It is a method on *Provider rather than a free function because the URL is
// configuration the provider already validated, and re-parsing a configured
// string at every redirect would be a second answer to "where does a browser go
// to sign in" that nothing holds in step with the first.
//
// The base is COPIED and the query is MERGED rather than appended, so a caller
// cannot mutate the provider's own configuration by holding on to the result and
// the output is deterministic: url.Values.Encode sorts by key, so the same
// interaction always produces byte-identical Location headers, which is what
// makes a test able to assert on one and a reviewer able to read one.
func (p *Provider) LoginRedirect(params LoginRedirectParams) string {
	target := *p.loginUI
	target.RawQuery = params.Values().Encode()
	return target.String()
}
