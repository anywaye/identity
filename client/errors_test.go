package client


import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/anywaye/identity/client/generated"
)

func problemBody(code string, status int) []byte {
	document := map[string]any{
		"type":     "https://docs.anywaye.com/errors/" + code,
		"title":    "A fixed summary for " + code,
		"status":   status,
		"detail":   "something specific to this occurrence",
		"instance": "/v1/me",
		"code":     code,
		"trace_id": "0af7651916cd43dd8448eb211c80319c",
	}
	if status == http.StatusUnprocessableEntity {
		document["errors"] = []map[string]string{
			{"field": "password", "code": "too_short"},
		}
	}

	body, err := json.Marshal(document)
	if err != nil {
		panic("fixture problem body: " + err.Error())
	}
	return body
}


func TestEveryProblemCodeMapsToItsOwnType(t *testing.T) {
	for _, tc := range []struct {
		code   string
		status int
		assert func(*testing.T, error) bool
	}{
		{
			code: "unauthorized", status: http.StatusUnauthorized,
			assert: func(t *testing.T, err error) bool { return isType[*UnauthenticatedError](err) },
		},
		{
			code: "forbidden", status: http.StatusForbidden,
			assert: func(t *testing.T, err error) bool { return isType[*ForbiddenError](err) },
		},
		{
			code: "not_found", status: http.StatusNotFound,
			assert: func(t *testing.T, err error) bool { return isType[*NotFoundError](err) },
		},
		{
			code: "conflict", status: http.StatusConflict,
			assert: func(t *testing.T, err error) bool { return isType[*ConflictError](err) },
		},
		{
			code: "validation_failed", status: http.StatusUnprocessableEntity,
			assert: func(t *testing.T, err error) bool { return isType[*ValidationError](err) },
		},
		{
			code: "rate_limited", status: http.StatusTooManyRequests,
			assert: func(t *testing.T, err error) bool { return isType[*RateLimitedError](err) },
		},
		{
			code: "account_locked", status: http.StatusLocked,
			assert: func(t *testing.T, err error) bool { return isType[*AccountLockedError](err) },
		},
	} {
		t.Run(tc.code, func(t *testing.T) {
			err := ProblemFrom("getCurrentUser", tc.status, ProblemContentType, "",
				problemBody(tc.code, tc.status), NewRedactor())

			var problem ProblemError
			if !errorsAs(err, &problem) {
				t.Fatalf("%s produced %T, which does not satisfy client.ProblemError.\n"+
					"This is the catch a caller writes once. If it fails here it would "+
					"fail in their code too, and only for codes this build knows.",
					tc.code, err)
			}

			if problem.Code() != tc.code {
				t.Errorf("Code() is %q, want %q.\n"+
					"`code` is the contract — core says `type` is a stable URI and `code` "+
					"is its last segment — so it has to survive onto the error rather "+
					"than being consumed by the mapping.", problem.Code(), tc.code)
			}

			if problem.HTTPStatus() != tc.status {
				t.Errorf("HTTPStatus() is %d, want %d", problem.HTTPStatus(), tc.status)
			}

			if problem.TraceID() != "0af7651916cd43dd8448eb211c80319c" {
				t.Errorf("TraceID() is %q.\n"+
					"Support starts from the trace id, and the redactor deliberately does "+
					"not touch it — a scrubber that ate it would make every unsupported "+
					"failure harder to report.", problem.TraceID())
			}

			if !tc.assert(t, err) {
				t.Errorf("%s did not produce its own concrete type: %T.\n"+
					"Each code a caller may branch on gets its own type, because a "+
					"`switch` on a status or a string is what this replaces.",
					tc.code, err)
			}
		})
	}
}

func isType[T error](err error) bool {
	var target T
	return errors.As(err, &target)
}

func TestAnUnknownProblemCodeStillProducesATypedError(t *testing.T) {
	const unknownCode = "quantum_entanglement_revoked"

	err := ProblemFrom("getCurrentUser", http.StatusTeapot, ProblemContentType, "",
		problemBody(unknownCode, http.StatusTeapot), NewRedactor())

	var problem ProblemError
	if !errorsAs(err, &problem) {
		t.Fatalf("an unknown code produced %T, which does not satisfy client.ProblemError.\n"+
			"This is the failure the brief names: \"a client that returns ok, false on "+
			"an unknown problem type breaks the day the API grows, and it breaks "+
			"silently.\" There is no `ok` in this signature, so the equivalent failure is "+
			"an error a caller cannot catch.", err)
	}

	if got := problem.Code(); got != unknownCode {
		t.Errorf("Code() is %q, want the code verbatim.\n"+
			"A caller that wants to act on a code this build has no type for has exactly "+
			"one thing to match on, and losing it would leave the fallback able to say "+
			"\"something failed\" and nothing more.", got)
	}

	if problem.HTTPStatus() != http.StatusTeapot {
		t.Errorf("HTTPStatus() is %d, want %d", problem.HTTPStatus(), http.StatusTeapot)
	}

	var unknown *UnknownProblemError
	if !errorsAs(err, &unknown) {
		t.Errorf("the error is %T, not *UnknownProblemError.\n"+
			"A caller may reasonably want to tell \"a code I have a type for\" from \"a "+
			"code this build does not\" — that is the difference between handling it and "+
			"logging it and moving on.", err)
	}

	if rendered := err.Error(); !strings.Contains(rendered, unknownCode) {
		t.Errorf("the message does not name the code: %s", rendered)
	}
}

func TestTheCodeChoosesTheTypeAndTheStatusOnlyBreaksTies(t *testing.T) {
	t.Run("the code wins over a drifted status", func(t *testing.T) {
		err := ProblemFrom("getCurrentUser", http.StatusUnauthorized, ProblemContentType, "",
			problemBody("forbidden", http.StatusUnauthorized), NewRedactor())

		if !isType[*ForbiddenError](err) {
			t.Errorf("a `forbidden` code on a 401 produced %T, want *ForbiddenError.\n"+
				"`code` is the documented machine-readable contract; `status` is one "+
				"response's opinion about itself.", err)
		}
	})

	t.Run("the status is used when the code is absent", func(t *testing.T) {
		body := []byte(`{"type":"https://docs.anywaye.com/errors/","title":"Unauthorized",` +
			`"status":401,"detail":"","instance":"/v1/me","trace_id":"abc"}`)

		err := ProblemFrom("getCurrentUser", http.StatusUnauthorized, ProblemContentType, "",
			body, NewRedactor())

		if !isType[*UnauthenticatedError](err) {
			t.Errorf("a 401 with no code produced %T, want *UnauthenticatedError.\n"+
				"RFC 9457 makes `code` a anywaye extension rather than a required member, "+
				"so a service may omit it. Falling back to the status is what keeps a "+
				"conforming-but-terse service from landing on the fallback type.", err)
		}
	})
}

func TestAResponseThatIsNotAProblemDocumentIsNotAProblemError(t *testing.T) {
	t.Run("a proxy's html 502", func(t *testing.T) {
		err := ProblemFrom("getCurrentUser", http.StatusBadGateway, "text/html", "",
			[]byte("<html><body>502 Bad Gateway</body></html>"), NewRedactor())

		var problem ProblemError
		if errorsAs(err, &problem) {
			t.Errorf("an HTML 502 produced a ProblemError: %T.\n"+
				"There is no problem document here, so `type` and `title` would both be a "+
				"lie. The excerpt is kept because a proxy's HTML 502 is otherwise "+
				"undiagnosable from the client side.", err)
		}
		if !isType[*CallError](err) {
			t.Errorf("an HTML 502 produced %T, want *CallError", err)
		}
		if !strings.Contains(err.Error(), "502 Bad Gateway") {
			t.Errorf("the excerpt was dropped, so a proxy failure is undiagnosable: %s", err)
		}
	})

	t.Run("a 2xx carrying a problem document", func(t *testing.T) {
		err := ProblemFrom("getCurrentUser", http.StatusOK, ProblemContentType, "",
			problemBody("internal", http.StatusInternalServerError), NewRedactor())

		if err == nil {
			t.Fatal("a 200 carrying a problem document returned no error.\n" +
				"core reserves application/problem+json for failures, so treating this as " +
				"a success would hand the caller a Problem where its types promised a " +
				"result. A typed client that quietly returns the wrong shape produces a " +
				"TypeError three frames from the mistake.")
		}
		if !isType[*CallError](err) {
			t.Errorf("produced %T, want *CallError", err)
		}
	})
}

func TestAccountLockedCarriesTheRetryAfter(t *testing.T) {
	body := problemBody("account_locked", http.StatusLocked)

	t.Run("a readable header", func(t *testing.T) {
		err := ProblemFrom("createSession", http.StatusLocked, ProblemContentType, "900",
			body, NewRedactor())

		var locked *AccountLockedError
		if !errorsAs(err, &locked) {
			t.Fatalf("produced %T, want *AccountLockedError", err)
		}
		if locked.RetryAfterSeconds() != 900 {
			t.Errorf("RetryAfterSeconds() is %d, want 900", locked.RetryAfterSeconds())
		}
		if !locked.HasRetryAfter() {
			t.Error("HasRetryAfter() is false for a response carrying `Retry-After: 900`")
		}
	})

	t.Run("a zero header means retry now, not unknown", func(t *testing.T) {
		err := ProblemFrom("createSession", http.StatusLocked, ProblemContentType, "0",
			body, NewRedactor())

		var locked *AccountLockedError
		if !errorsAs(err, &locked) {
			t.Fatalf("produced %T, want *AccountLockedError", err)
		}
		if !locked.HasRetryAfter() {
			t.Error("HasRetryAfter() is false for `Retry-After: 0`.\n" +
				"The document says the value is never negative, so 0 is a real answer — " +
				"\"retry immediately\" — and it is not the same as no header at all.")
		}
	})

	t.Run("an absent header is reported as absent", func(t *testing.T) {
		err := ProblemFrom("createSession", http.StatusLocked, ProblemContentType, "",
			body, NewRedactor())

		var locked *AccountLockedError
		if !errorsAs(err, &locked) {
			t.Fatalf("produced %T, want *AccountLockedError", err)
		}
		if locked.HasRetryAfter() {
			t.Error("HasRetryAfter() is true with no header at all")
		}
		if locked.RetryAfterSeconds() != 0 {
			t.Errorf("RetryAfterSeconds() is %d; an unknown wait must read as 0 so a "+
				"caller that ignores HasRetryAfter backs off rather than hammering.",
				locked.RetryAfterSeconds())
		}
	})

	t.Run("an http-date is reported as absent rather than guessed at", func(t *testing.T) {
		err := ProblemFrom("createSession", http.StatusLocked, ProblemContentType,
			"Wed, 30 Sep 2026 12:15:00 GMT", body, NewRedactor())

		var locked *AccountLockedError
		if !errorsAs(err, &locked) {
			t.Fatalf("produced %T, want *AccountLockedError", err)
		}
		if locked.HasRetryAfter() {
			t.Error("an HTTP-date was parsed as delta-seconds.\n" +
				"RFC 9110 allows both forms; identity's document says its value is whole " +
				"seconds, so the date form comes from something else in the chain. A wrong " +
				"retry time is worse than a caller falling back to its own policy.")
		}
	})
}

func TestValidationCarriesTheFieldErrors(t *testing.T) {
	err := ProblemFrom("registerUser", http.StatusUnprocessableEntity, ProblemContentType, "",
		problemBody("validation_failed", http.StatusUnprocessableEntity), NewRedactor())

	var problem ProblemError
	if !errorsAs(err, &problem) {
		t.Fatalf("produced %T, want a ProblemError", err)
	}

	fields := problem.Document().Errors
	if fields == nil {
		t.Fatal("Errors is nil; the document says `errors[]` is present on a 422")
	}
	if len(*fields) != 1 || (*fields)[0].Field != "password" || (*fields)[0].Code != "too_short" {
		t.Errorf("Errors is %v, want one entry of {password, too_short}", *fields)
	}
}

func TestIsRetryableIsNarrow(t *testing.T) {
	retryable := ProblemFrom("getCurrentUser", http.StatusTooManyRequests,
		ProblemContentType, "", problemBody("rate_limited", http.StatusTooManyRequests),
		NewRedactor())
	if !IsRetryable(retryable) {
		t.Error("a 429 is not reported as retryable")
	}

	for _, tc := range []struct {
		name string
		err  error
	}{
		{"a 409", ProblemFrom("x", http.StatusConflict, ProblemContentType, "",
			problemBody("conflict", http.StatusConflict), NewRedactor())},
		{"a 403", ProblemFrom("x", http.StatusForbidden, ProblemContentType, "",
			problemBody("forbidden", http.StatusForbidden), NewRedactor())},
		{"a 422", ProblemFrom("x", http.StatusUnprocessableEntity, ProblemContentType, "",
			problemBody("validation_failed", http.StatusUnprocessableEntity), NewRedactor())},
		{"nil", nil},
	} {
		if IsRetryable(tc.err) {
			t.Errorf("%s is reported as retryable.\n"+
				"Retrying a request that cannot succeed is how a client turns a "+
				"conflict into an incident.", tc.name)
		}
	}
}

func TestProblemFieldsAreRedacted(t *testing.T) {
	leaky, marshalErr := json.Marshal(map[string]any{
		"type":     "https://docs.anywaye.com/errors/validation_failed",
		"title":    "Validation failed",
		"status":   422,
		"detail":   "the token " + apiCredential + " was rejected",
		"instance": "/v1/me",
		"code":     "validation_failed",
		"trace_id": "0af7651916cd43dd8448eb211c80319c",
		"errors":   []map[string]string{{"field": "token", "code": "invalid_format"}},
		"an_extension_member_nobody_declared": apiCredential,
	})
	if marshalErr != nil {
		t.Fatalf("building the fixture: %v", marshalErr)
	}

	err := ProblemFrom("getCurrentUser", http.StatusUnprocessableEntity, ProblemContentType, "",
		leaky, NewRedactor(apiCredential))

	var problem ProblemError
	if !errorsAs(err, &problem) {
		t.Fatalf("produced %T, want a ProblemError", err)
	}

	document := problem.Document()
	for name, value := range map[string]string{
		"detail":    document.Detail,
		"type":      document.Type,
		"title":     document.Title,
		"instance":  document.Instance,
		"the error": err.Error(),
	} {
		if strings.Contains(value, apiCredential) {
			t.Errorf("the credential appears in the problem's %s:\n%s", name, value)
		}
	}

	if document.TraceID != "0af7651916cd43dd8448eb211c80319c" {
		t.Errorf("TraceID is %q; it must survive redaction", document.TraceID)
	}
}

func TestTheGeneratedProblemTypeIsTheOneUsed(t *testing.T) {
	var document generated.Problem
	document.Code = generated.ProblemCodeUnauthorized

	if string(document.Code) != "unauthorized" {
		t.Fatalf("the generated ProblemCode enum does not carry %q; this test is "+
			"checking a shape the document no longer has", "unauthorized")
	}
}
