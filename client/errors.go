package client


import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/anywaye/identity/client/generated"
)

// ProblemContentType is the media type every non-2xx response carries.
const ProblemContentType = "application/problem+json"

// RetryAfterHeader carries the wait a 423 asks for. The document puts it on the 423
// responses and nowhere else, and says the value is "seconds until the account may be
// tried again, never negative".
const RetryAfterHeader = "Retry-After"

// ProblemError is every failure that carried an RFC 9457 problem document.
//
// An interface, and the reasoning is in the file header: a base STRUCT cannot be
// caught with `errors.As` from a type that embeds it, so a hierarchy of structs
// would invert the one property this package exists to provide.
//
// `Problem` and `FieldError` are NOT declared here — `client/generated` declares both
// from `openapi/v1.yaml`, and using the generated ones means the code is a
// compile-time enum rather than a string somebody can typo, and there is exactly one
// `Problem` in this module.
type ProblemError interface {
	error

	Code() string

	HTTPStatus() int

	Document() generated.Problem

	TraceID() string
}

type problem struct {
	operation string
	status    int
	document  generated.Problem
	redactor  Redactor

	retryAfter int
}

func (p *problem) Code() string                { return string(p.document.Code) }
func (p *problem) HTTPStatus() int             { return p.status }
func (p *problem) Document() generated.Problem { return p.document }
func (p *problem) TraceID() string             { return p.document.TraceID }

func (p *problem) render(kind string) string {
	where := ""
	if p.operation != "" {
		where = p.operation + ": "
	}

	code := p.document.Code
	if code == "" {
		code = generated.ProblemCode(kind)
	}

	msg := fmt.Sprintf("%sHTTP %d %s: %s", where, p.status, code,
		p.redactor.String(p.document.Title))

	if detail := p.redactor.String(p.document.Detail); detail != "" {
		msg += ": " + detail
	}
	if p.document.TraceID != "" {
		msg += " (trace_id " + p.document.TraceID + ")"
	}
	return p.redactor.String(msg)
}


// UnauthenticatedError is 401: the credential was absent, unknown, expired or
// revoked. identity answers all four with one body, and so does this.
type UnauthenticatedError struct{ problem }

func (e *UnauthenticatedError) Error() string { return e.render("unauthorized") }

// ForbiddenError is 403: the credential is valid and not enough.
type ForbiddenError struct{ problem }

func (e *ForbiddenError) Error() string { return e.render("forbidden") }

// NotFoundError is 404, and core is careful about it: "Never 404 for authorization
// failures on a resource the caller cannot see". So a 404 from identity can mean "not
// a member of that account" and not only "no such account", and a caller must not
// read it either way.
type NotFoundError struct{ problem }

func (e *NotFoundError) Error() string { return e.render("not_found") }

// ConflictError is 409.
type ConflictError struct{ problem }

func (e *ConflictError) Error() string { return e.render("conflict") }

// ValidationError is 422, and the only code that carries `errors[]`.
type ValidationError struct{ problem }

func (e *ValidationError) Error() string { return e.render("validation_failed") }

// RateLimitedError is 429.
type RateLimitedError struct{ problem }

func (e *RateLimitedError) Error() string { return e.render("rate_limited") }

// AccountLockedError is 423, identity's extension to core's reserved list, and the
// one code whose correct client behavior is to WAIT.
//
// A distinct type rather than a field on the base because the action differs: every
// other 4xx here is "do not retry", and a client that treats 423 like 403 will hammer
// an account the lockout exists to protect.
type AccountLockedError struct{ problem }

func (e *AccountLockedError) Error() string { return e.render("account_locked") }

// RetryAfterSeconds is the remaining window, rounded up, from the `Retry-After`
// header. Never negative, and never retried here — see IsRetryable.
//
// Zero means "no readable header", NOT "retry now": the document says the value is
// "never negative" and a literal `0` is a real answer the service could give, so the
// two are told apart by `-1` in the unexported field and a caller that cares should
// read the header itself. Stated rather than smoothed over because a client that
// treats "unknown" as "now" is how an account gets locked harder.
func (e *AccountLockedError) RetryAfterSeconds() int {
	if e.retryAfter < 0 {
		return 0
	}
	return e.retryAfter
}

// HasRetryAfter reports whether the response carried a readable `Retry-After`. A
// caller that needs to distinguish "retry immediately" from "do not know" asks this
// rather than reading zero and guessing.
func (e *AccountLockedError) HasRetryAfter() bool { return e.retryAfter >= 0 }

// UnknownProblemError is THE FALLBACK: a problem document whose `code` this build has
// never heard of.
//
// It is a real, exported, `errors.As`-able type rather than a nil and rather than a
// bare error, and that is the whole point. The brief's requirement is that a client
// "breaks silently" if it cannot represent a code it has not seen; this type is what
// it represents them with. A caller can therefore always write
//
//	var problem client.ProblemError
//	if errors.As(err, &problem) { … }
//
// and have it work against every failure this package can produce, including every
// code identity adds after this client was generated.
//
// identity's document already lists four codes core does not have, and flags them as
// a proposal rather than a fait accompli — so this is not a shape of failure that
// happens eventually. It is a shape this service is already in.
type UnknownProblemError struct{ problem }

func (e *UnknownProblemError) Error() string { return e.render("unknown") }

// ProblemCode returns the code verbatim, which is the only way a caller can act on a
// code this build has no type for — by matching the string, with a default that does
// something sensible rather than nothing.
func (e *UnknownProblemError) ProblemCode() string { return e.Code() }

// CallError is a failure that did NOT carry a problem document.
//
// Two cases, both of them judgement calls worth naming:
//
//   - A transport failure: no HTTP response at all. `net/http`'s own text is kept,
//     redacted, because `dial tcp … connection refused` is the single most useful line
//     in a network error and there is nothing to redact in it.
//
//   - A response that broke the contract: a proxy's HTML 502, a WAF's challenge, a
//     `/readyz` 503 which this repository's own document records as known gap 4. There
//     is a status and there is no problem document, so producing a `ProblemError`
//     would be a lie about `type` and `title`.
type CallError struct {
	Operation string
	Status int

	message string

	snippet string

	contentType string

	redactor Redactor
}

// Error renders the failure.
//
// Redacted again here even though `message` arrived redacted. Two passes look
// redundant; the second is what makes the type safe if a future caller constructs one
// with a raw string, which is exactly the mistake a single redaction site invites.
func (e *CallError) Error() string {
	msg := e.Operation + ": "
	if e.Status > 0 {
		msg += "HTTP " + itoa(e.Status) + " "
	}
	msg += e.redactor.String(e.message)

	if e.snippet != "" && e.snippet != Redacted {
		msg += " Body began: " + e.snippet
	}
	return e.redactor.String(msg)
}

// Unwrap returns nil so `errors.Is` and `errors.As` stop here rather than walking a
// chain this package did not build.
//
// Present as an explicit method rather than omitted so the intent is on the page: the
// generated client returns `*http.Response` and an `error` from `net/http`, and the
// temptation to unwrap into the transport error is exactly the path by which a URL
// with a query string, or a header dump, reaches a log line.
func (e *CallError) Unwrap() error { return nil }

// MFARequiredError is the 202 from `POST /v1/session`: a correct password, an
// unfinished authentication, and nothing else.
//
// **There is no session.** The document says so in as many words — "there is no
// `token` field in this schema, and that is deliberate: a client that looks for one
// must handle its absence rather than treat an empty string as a value" — and this
// type is that handling made unavoidable. It is an error rather than a result
// precisely so a caller cannot hold a `*Session` containing no session: the zero value
// of a `Session` has an empty token, which is credential-shaped and is not a
// credential, and returning it would be the bug the document warns about.
//
// The challenge is carried rather than fetched by a second call, because it is
// single-use and expires in ten minutes. A caller that had to collect it separately
// would have to cache it, and a cached single-use credential is a liability.
type MFARequiredError struct {
	CallError

	Challenge generated.MFAChallenge
}

func (e *MFARequiredError) Error() string {
	return e.redactor.String(e.Operation +
		": the credential was accepted and this account has a second factor, so no session " +
		"exists. Answer POST /v1/session/mfa with the challenge to get one.")
}

// MFARequiredFrom builds the 202 error from a body, for the operations that have to
// read the status themselves.
//
// `CreateSession` reads its own status because a 200 and a 202 are both success
// and both go through the shared `call`, which assumes one JSON shape per success.
// `completeSocialLogin` is the second operation in that position and would
// otherwise open-code the same four lines — build the error, set the status, keep
// the challenge, redact the message — and a second copy of that is a second thing
// to keep in step.
//
// A body that will not decode as a challenge is a `CallError` rather than a
// challenge with empty fields, because an `*MFARequiredError` whose challenge is
// the zero value is a caller that will present nothing to `/v1/session/mfa` and be
// told 404, having been told in the meantime that a second factor is waiting.
func MFARequiredFrom(operation string, body []byte, redact Redactor) error {
	var challenge generated.MFAChallenge
	if err := json.Unmarshal(body, &challenge); err != nil {
		return &CallError{
			Operation: operation, Status: http.StatusAccepted, redactor: redact,
			message: redact.String("a 202 from this operation did not carry a usable " +
				"challenge, so the login cannot be finished: " + err.Error()),
		}
	}
	if challenge.Challenge == "" {
		return &CallError{
			Operation: operation, Status: http.StatusAccepted, redactor: redact,
			message: "a 202 from this operation carried no challenge. The document promises " +
				"one, and an error carrying an empty one would send a caller to " +
				"POST /v1/session/mfa with nothing to present.",
		}
	}
	return &MFARequiredError{
		CallError: CallError{
			Operation: operation, Status: http.StatusAccepted, redactor: redact,
		},
		Challenge: challenge,
	}
}

// ProblemFrom builds the right error for a problem document.
//
// `body` is the raw response body, `contentType` what the service said it was, and
// `retryAfter` the raw header value. The body is decoded HERE rather than by the
// caller so that "this was not a problem document" is one decision this package
// makes, with a stated consequence, rather than a branch twenty call sites write
// differently.
//
// `redact` is the client's redactor, already bound to its credential. It is passed
// rather than a `[]string` of secrets so no caller assembles the credential list, and
// so no slice of secrets travels through this package where one could read it back
// out.
//
// Kept a pure function of its arguments — no `*http.Response`, no transport — which
// is what lets the per-code table below be a table rather than a fixture.
func ProblemFrom(operation string, status int, contentType, retryAfter string, body []byte, redact Redactor) error {
	if status >= 200 && status < 300 {
		return &CallError{
			Operation: operation, Status: status, redactor: redact,
			message: "the service answered 2xx with an application/problem+json body. " +
				"core's conventions reserve that media type for failures, so treating it " +
				"as a success would hand the caller a problem where its types promised a " +
				"result. The service is not following its own contract.",
		}
	}

	var decoded generated.Problem
	if err := json.Unmarshal(body, &decoded); err != nil {
		return notAProblem(operation, status, contentType, body, redact)
	}

	if decoded.Type == "" && decoded.Title == "" {
		return notAProblem(operation, status, contentType, body, redact)
	}

	decoded = sanitiseProblem(decoded, redact)
	if decoded.Status == 0 {
		decoded.Status = status
	}

	built := &problem{
		operation:  operation,
		status:     status,
		document:   decoded,
		redactor:   redact,
		retryAfter: parseRetryAfter(retryAfter),
	}

	if constructor, known := problemTypes[built.Code()]; known {
		return constructor(*built)
	}
	if constructor, known := statusTypes[decoded.Status]; known {
		return constructor(*built)
	}

	return &UnknownProblemError{problem: *built}
}

func notAProblem(operation string, status int, contentType string, body []byte, redact Redactor) error {
	shown := contentType
	if shown == "" {
		shown = "no Content-Type"
	}

	return &CallError{
		Operation: operation, Status: status, contentType: contentType, redactor: redact,
		message: "the response did not carry an RFC 9457 problem document (Content-Type: " +
			shown + "). Something between this client and identity answered — a proxy, a " +
			"gateway, a rate limiter — so there is no anywaye code to branch on.",
		snippet: redact.String(truncate(strings.TrimSpace(string(body)), 200)),
	}
}

var problemTypes = map[string]func(problem) error{
	"unauthorized":      func(p problem) error { return &UnauthenticatedError{p} },
	"forbidden":         func(p problem) error { return &ForbiddenError{p} },
	"not_found":         func(p problem) error { return &NotFoundError{p} },
	"conflict":          func(p problem) error { return &ConflictError{p} },
	"validation_failed": func(p problem) error { return &ValidationError{p} },
	"rate_limited":      func(p problem) error { return &RateLimitedError{p} },
	"account_locked":    func(p problem) error { return &AccountLockedError{p} },
}

var statusTypes = map[int]func(problem) error{
	http.StatusUnauthorized:        func(p problem) error { return &UnauthenticatedError{p} },
	http.StatusForbidden:           func(p problem) error { return &ForbiddenError{p} },
	http.StatusNotFound:            func(p problem) error { return &NotFoundError{p} },
	http.StatusConflict:            func(p problem) error { return &ConflictError{p} },
	http.StatusUnprocessableEntity: func(p problem) error { return &ValidationError{p} },
	http.StatusTooManyRequests:     func(p problem) error { return &RateLimitedError{p} },
}

func sanitiseProblem(p generated.Problem, r Redactor) generated.Problem {
	out := p
	out.Type = r.String(p.Type)
	out.Title = r.String(p.Title)
	out.Detail = r.String(p.Detail)
	out.Instance = r.String(p.Instance)
	out.Code = generated.ProblemCode(r.String(string(p.Code)))


	if p.Errors != nil {
		fields := make([]generated.FieldError, len(*p.Errors))
		for i, field := range *p.Errors {
			fields[i] = generated.FieldError{
				Field: r.String(field.Field),
				Code:  r.String(field.Code),
			}
		}
		out.Errors = &fields
	}
	return out
}

func parseRetryAfter(raw string) int {
	if raw == "" {
		return -1
	}

	seconds, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || seconds < 0 {
		return -1
	}
	return seconds
}

// IsRetryable reports whether waiting could plausibly succeed.
//
// A deliberately small set: 429 and 503. A 409 is not here even though it is
// sometimes transient, because a conflict means the request conflicts with current
// state and repeating it unchanged repeats the conflict — that is a decision for
// whoever holds the domain, not for a transport.
//
// **No retry is attempted by this package at all.** A client library that retries
// hides a caller's own deadline and error handling behind its own, and MD6 gives this
// client four responsibilities — credentials, base URLs, RFC 9457 mapping, and being
// the public surface — and retrying is not one of them.
func IsRetryable(err error) bool {
	var rate *RateLimitedError
	if errors.As(err, &rate) {
		return true
	}
	return errors.Is(err, ErrUnavailable)
}

// ErrUnavailable is returned for a 503 with no anywaye problem body, which is what
// `GET /readyz` answers when a dependency is down.
//
// This repository's document calls that response out as the one non-2xx in the
// service that is not a problem document — recorded as known gap 4 and escalated as
// a conflict with core's conventions. It is matched by status rather than by code
// precisely because there is no code to match.
var ErrUnavailable = errors.New("identity is not ready: a dependency did not answer")
