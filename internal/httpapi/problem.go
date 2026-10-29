package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

const errorTypeBase = "https://docs.anywaye.com/errors/"

const (
	CodeUnauthorized     = "unauthorized"
	CodeForbidden        = "forbidden"
	CodeValidationFailed = "validation_failed"
	CodeConflict         = "conflict"
	CodeNotFound         = "not_found"
	CodeInternal         = "internal"

	CodeGone = "gone"

	CodeAccountLocked    = "account_locked"
	CodeMethodNotAllowed = "method_not_allowed"
	CodeInvalidJSON      = "invalid_json"
	CodePayloadTooLarge  = "payload_too_large"

	CodeRateLimited = "rate_limited"

	CodeEmailNotVerified = "email_not_verified"

	CodeAccountOwnershipConflict = "account_ownership_conflict"

	CodeInvalidRequest = "invalid_request"

	CodeAgentUnclaimed = "agent_unclaimed"

	CodeServiceUnavailable = "service_unavailable"
)

var titles = map[string]string{
	CodeUnauthorized:     "Unauthorized",
	CodeForbidden:        "Forbidden",
	CodeValidationFailed: "Validation failed",
	CodeConflict:         "Conflict",
	CodeNotFound:         "Not found",
	CodeInternal:         "Internal server error",
	CodeGone:             "Gone",

	CodeAccountLocked:      "Account locked",
	CodeServiceUnavailable: "Service unavailable",
	CodeMethodNotAllowed:   "Method not allowed",
	CodeInvalidJSON:        "Malformed request body",
	CodePayloadTooLarge:    "Request body too large",
	CodeInvalidRequest:     "Invalid request",
	CodeRateLimited:        "Too many requests",
	CodeEmailNotVerified:   "Email not verified",

	CodeAccountOwnershipConflict: "Account ownership conflict",
	CodeAgentUnclaimed:           "Agent unclaimed",
}

func titleFor(code string) string {
	if title, ok := titles[code]; ok {
		return title
	}
	return "Request failed"
}

// FieldError is one entry of a problem's `errors[]`, present only on a 422.
//
// It has exactly the two fields core's example shows. A `message` is tempting and
// wrong: it duplicates `detail` per field, it is not in the contract, and clients
// that render it end up showing an untranslated server string to a user.
type FieldError struct {
	Field string `json:"field"`
	Code  string `json:"code"`
}

// Problem is the anywaye error envelope: RFC 9457 (application/problem+json) plus
// core's `code` and `trace_id` extensions.
//
// core sets no additionalProperties rule on the error body, so the seven fields
// below are the whole document.
type Problem struct {
	Type     string       `json:"type"`
	Title    string       `json:"title"`
	Status   int          `json:"status"`
	Detail   string       `json:"detail"`
	Instance string       `json:"instance"`
	Code     string       `json:"code"`
	TraceID  string       `json:"trace_id"`
	Errors   []FieldError `json:"errors,omitempty"`
}

func newProblem(status int, code string) Problem {
	return Problem{
		Type:   errorTypeBase + code,
		Title:  titleFor(code),
		Status: status,
		Code:   code,
	}
}

func (p Problem) withDetail(detail string) Problem {
	p.Detail = detail
	return p
}

func (p Problem) withFieldErrors(errs []FieldError) Problem {
	p.Errors = errs
	return p
}

func writeProblem(w http.ResponseWriter, r *http.Request, p Problem) {
	p.Instance = r.URL.Path
	p.TraceID = traceIDFrom(r.Context())

	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set(TraceHeader, p.TraceID)
	w.WriteHeader(p.Status)
	if err := json.NewEncoder(w).Encode(p); err != nil {
		slog.Default().Warn("writing a problem response failed", "code", p.Code, "error", err)
	}
}

func problemFor(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	writeProblem(w, r, newProblem(status, code).withDetail(detail))
}

func unauthorized(w http.ResponseWriter, r *http.Request) {
	problemFor(w, r, http.StatusUnauthorized, CodeUnauthorized,
		"authentication is required to access this resource")
}

func unexpected(w http.ResponseWriter, r *http.Request, logger *slog.Logger, err error) {
	CaptureError(err, r)
	if logger != nil {
		logger.Error("request failed",
			"error", err,
			"trace_id", traceIDFrom(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
		)
	}
	problemFor(w, r, http.StatusInternalServerError, CodeInternal,
		"the request could not be completed. Quote the trace id when reporting this.")
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func noContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

func bodyTooLarge(err error) bool {
	var tooLarge *http.MaxBytesError
	return errors.As(err, &tooLarge)
}
