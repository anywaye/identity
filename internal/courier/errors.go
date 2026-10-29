package courier

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

type problem struct {
	Status  int          `json:"status"`
	Code    string       `json:"code"`
	TraceID string       `json:"trace_id"`
	Errors  []FieldError `json:"errors"`
}

const codeUnreadable = "unreadable_problem"

func classify(op string, status int, header http.Header, raw []byte) error {
	var doc problem
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &doc)
	}

	code := doc.Code
	if code == "" {
		code = codeUnreadable
	}
	trace := doc.TraceID
	if trace == "" {
		trace = header.Get("x-trace-id")
	}

	refused := &Error{
		Op:      op,
		Status:  status,
		Code:    code,
		TraceID: trace,
		Fields:  doc.Errors,
		retry:   retryable(status, code),
	}

	switch {
	case status == http.StatusConflict && code == "conflict":
		refused.sentinel = ErrSuppressed
	case status == http.StatusConflict:
		refused.sentinel = ErrRefused
	case status == http.StatusUnprocessableEntity && hasField(doc.Errors, FieldPreferencesDisabled):
		refused.sentinel = ErrDeclined
	case status == http.StatusUnprocessableEntity:
		refused.sentinel = ErrRefused
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		refused.sentinel = ErrUnauthenticated
	case status == http.StatusServiceUnavailable, status == http.StatusInternalServerError,
		status == http.StatusBadGateway, status == http.StatusGatewayTimeout:
		refused.sentinel = ErrUnavailable
	default:
		refused.sentinel = ErrRefused
	}
	return refused
}

func retryable(status int, code string) bool {
	switch {
	case status == http.StatusServiceUnavailable, status == http.StatusInternalServerError,
		status == http.StatusBadGateway, status == http.StatusGatewayTimeout:
		return true
	case status == http.StatusConflict, status == http.StatusUnprocessableEntity,
		status == http.StatusUnauthorized, status == http.StatusForbidden:
		return false
	case code == codeUnreadable:
		return false
	default:
		return false
	}
}

func hasField(fields []FieldError, code string) bool {
	for _, f := range fields {
		if f.Code == code {
			return true
		}
	}
	return false
}

func statusText(status int) string {
	if text := http.StatusText(status); text != "" {
		return text + " (" + strconv.Itoa(status) + ")"
	}
	return strconv.Itoa(status)
}

func fieldsString(fields []FieldError) string {
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		parts = append(parts, f.Field+"="+f.Code)
	}
	return strings.Join(parts, ",")
}
