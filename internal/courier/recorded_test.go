package courier

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)


type recordedCase struct {
	name    string
	status  int
	headers map[string]string
	body    string
	request MessageRequest
	wantType   string
	wantErrIs  error
	wantCode   string
	wantTrace  string
	wantFields []FieldError
	wantRetry  bool
}

func TestAgainstInteractionsRecordedFromRealCourier(t *testing.T) {
	const userID = "1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9"

	cases := []recordedCase{
		{
			name:   "a password reset is accepted, and courier names the send and its event",
			status: http.StatusOK,
			headers: map[string]string{
				"content-type": "application/json; charset=utf-8",
			},
			body: `{"data":{"status":"accepted","user_id":"` + userID + `",` +
				`"message_id":"courier-16c22f7a-deda-443c-bdac-d7dcf2405b70",` +
				`"event_id":"0f1d27fc-47ed-4547-aba6-3e98aeaaa198",` +
				`"notification_type":"password_reset"}}`,
			wantType: TypePasswordReset,
			wantCode: "accepted",
		},
		{
			name:   "the current-address half of an email change is accepted with its link",
			status: http.StatusOK,
			headers: map[string]string{
				"content-type": "application/json; charset=utf-8",
				"x-trace-id":   "b17533f1-5a5c-478d-9ec3-c21ebb935fdf",
			},
			request: MessageRequest{
				Type:   TypeEmailChangeCurrent,
				UserID: userID,
				To:     "identity-e2e-change-current@example.com",
				URL:    "https://app.example.com/confirm-change?token=K7dQm2xR9vTb4nLpZcHs1JfWy6AeUi0O",
			},
			body: `{"data":{"status":"accepted","user_id":"` + userID + `",` +
				`"event_id":"be852c34-7286-43ba-b728-04d506415959",` +
				`"notification_type":"email_change_current",` +
				`"message_id":"courier-db7a1cef-510d-45da-9d0e-e66bb27de573"}}`,
			wantType: TypeEmailChangeCurrent,
			wantCode: "accepted",
		},
		{
			name:   "the new-address half of an email change is accepted with its previous address",
			status: http.StatusOK,
			headers: map[string]string{
				"content-type": "application/json; charset=utf-8",
				"x-trace-id":   "25196fc2-511a-49e2-b883-6276347b7f45",
			},
			request: MessageRequest{
				Type:          TypeEmailChangeNew,
				UserID:        userID,
				To:            "identity-e2e-change-new@example.com",
				PreviousEmail: "kaka@example.com",
			},
			body: `{"data":{"status":"accepted","user_id":"` + userID + `",` +
				`"event_id":"e37a02de-a50e-4581-b428-09cea0661057",` +
				`"notification_type":"email_change_new",` +
				`"message_id":"courier-be8e0269-9c79-40e9-bfd6-421ea08a04a1"}}`,
			wantType: TypeEmailChangeNew,
			wantCode: "accepted",
		},
		{
			name:   "a hard-bounced mailbox is a 409 that does not echo the address",
			status: http.StatusConflict,
			headers: map[string]string{
				"content-type":   "application/problem+json; charset=utf-8",
				"x-trace-id":     "1cd5f880-fc3a-428d-923c-71866c488ea6",
				"x-request-id":   "GNp5D6lNg6uySL0AAALC",
				"content-length": "358",
			},
			body: `{"code":"conflict","detail":"That mailbox does not exist: it ` +
				`hard-bounced a previous message, and courier does not write to a ` +
				`mailbox that has said it is gone.","instance":"/v1/messages",` +
				`"status":409,"title":"Conflict",` +
				`"trace_id":"1cd5f880-fc3a-428d-923c-71866c488ea6",` +
				`"type":"https://docs.anywaye.com/errors/conflict"}`,
			wantErrIs: ErrSuppressed,
			wantCode:  "conflict",
			wantTrace: "1cd5f880-fc3a-428d-923c-71866c488ea6",
		},
		{
			name:   "a spam complaint is the same 409 and the same refusal",
			status: http.StatusConflict,
			headers: map[string]string{
				"content-type": "application/problem+json; charset=utf-8",
				"x-trace-id":   "d1f22bfb-7948-443b-bb39-2eb87882f860",
			},
			body: `{"code":"conflict","detail":"That recipient reported a ` +
				`previous message as spam. courier does not write to someone who ` +
				`has asked not to be written to.","instance":"/v1/messages",` +
				`"status":409,"title":"Conflict",` +
				`"trace_id":"d1f22bfb-7948-443b-bb39-2eb87882f860",` +
				`"type":"https://docs.anywaye.com/errors/conflict"}`,
			wantErrIs: ErrSuppressed,
			wantCode:  "conflict",
			wantTrace: "d1f22bfb-7948-443b-bb39-2eb87882f860",
		},
		{
			name:   "a declined preference is a 422 and is NOT a suppression",
			status: http.StatusUnprocessableEntity,
			headers: map[string]string{
				"content-type": "application/problem+json; charset=utf-8",
				"x-trace-id":   "c5eb7c00-76a4-46cc-82bd-afc067babfe8",
			},
			body: `{"code":"validation_failed","detail":"The recipient has asked ` +
				`not to receive this notification by email. Read or change it ` +
				`through GET or PUT /v1/notification_preferences/{user_id}.",` +
				`"errors":[{"code":"notification_preferences_disabled",` +
				`"field":"type"}],"instance":"/v1/messages","status":422,` +
				`"title":"Validation failed",` +
				`"trace_id":"c5eb7c00-76a4-46cc-82bd-afc067babfe8",` +
				`"type":"https://docs.anywaye.com/errors/validation_failed"}`,
			wantErrIs: ErrDeclined,
			wantCode:  "validation_failed",
			wantTrace: "c5eb7c00-76a4-46cc-82bd-afc067babfe8",
			wantFields: []FieldError{
				{Field: "type", Code: FieldPreferencesDisabled},
			},
		},
		{
			name:   "a type courier does not send is a 422 naming the field",
			status: http.StatusUnprocessableEntity,
			headers: map[string]string{
				"content-type": "application/problem+json; charset=utf-8",
				"x-trace-id":   "2226cc75-4b8c-4a24-8dc5-5fceba01e4be",
			},
			body: `{"code":"validation_failed","detail":"The message was not ` +
				`valid.","errors":[{"code":"unknown_notification_type",` +
				`"field":"type"}],"instance":"/v1/messages","status":422,` +
				`"title":"Validation failed",` +
				`"trace_id":"2226cc75-4b8c-4a24-8dc5-5fceba01e4be",` +
				`"type":"https://docs.anywaye.com/errors/validation_failed"}`,
			wantErrIs: ErrRefused,
			wantCode:  "validation_failed",
			wantTrace: "2226cc75-4b8c-4a24-8dc5-5fceba01e4be",
			wantFields: []FieldError{
				{Field: "type", Code: "unknown_notification_type"},
			},
		},
		{
			name:   "a field courier does not have is a 422 naming it",
			status: http.StatusUnprocessableEntity,
			headers: map[string]string{
				"content-type": "application/problem+json; charset=utf-8",
				"x-trace-id":   "baa4918d-f58a-4b78-bc56-9514d64ce7ee",
			},
			body: `{"code":"validation_failed","detail":"The message was not ` +
				`valid.","errors":[{"code":"unknown_field","field":"subject"}],` +
				`"instance":"/v1/messages","status":422,"title":"Validation failed",` +
				`"trace_id":"baa4918d-f58a-4b78-bc56-9514d64ce7ee",` +
				`"type":"https://docs.anywaye.com/errors/validation_failed"}`,
			wantErrIs: ErrRefused,
			wantCode:  "validation_failed",
			wantTrace: "baa4918d-f58a-4b78-bc56-9514d64ce7ee",
			wantFields: []FieldError{
				{Field: "subject", Code: "unknown_field"},
			},
		},
		{
			name:   "a user id that is not a uuid is a 422",
			status: http.StatusUnprocessableEntity,
			headers: map[string]string{
				"content-type": "application/problem+json; charset=utf-8",
				"x-trace-id":   "cfd5fdca-17a7-4298-8a8c-d031bef8f3a2",
			},
			body: `{"code":"validation_failed","detail":"The message was not ` +
				`valid.","errors":[{"code":"invalid_format","field":"user_id"}],` +
				`"instance":"/v1/messages","status":422,"title":"Validation failed",` +
				`"trace_id":"cfd5fdca-17a7-4298-8a8c-d031bef8f3a2",` +
				`"type":"https://docs.anywaye.com/errors/validation_failed"}`,
			wantErrIs: ErrRefused,
			wantCode:  "validation_failed",
			wantTrace: "cfd5fdca-17a7-4298-8a8c-d031bef8f3a2",
			wantFields: []FieldError{
				{Field: "user_id", Code: "invalid_format"},
			},
		},
		{
			name:   "a password reset with no link is a 422 naming url",
			status: http.StatusUnprocessableEntity,
			headers: map[string]string{
				"content-type": "application/problem+json; charset=utf-8",
				"x-trace-id":   "5e8c6f7d-dc5a-44a0-897d-140c4cf2d564",
			},
			body: `{"code":"validation_failed","detail":"The message was not ` +
				`valid.","errors":[{"code":"invalid_format","field":"url"}],` +
				`"instance":"/v1/messages","status":422,"title":"Validation failed",` +
				`"trace_id":"5e8c6f7d-dc5a-44a0-897d-140c4cf2d564",` +
				`"type":"https://docs.anywaye.com/errors/validation_failed"}`,
			wantErrIs: ErrRefused,
			wantCode:  "validation_failed",
			wantTrace: "5e8c6f7d-dc5a-44a0-897d-140c4cf2d564",
			wantFields: []FieldError{
				{Field: "url", Code: "invalid_format"},
			},
		},
		{
			name:   "an Idempotency-Key that is not a uuid is a 422 — courier's own rule",
			status: http.StatusUnprocessableEntity,
			headers: map[string]string{
				"content-type": "application/problem+json; charset=utf-8",
				"x-trace-id":   "4f54da8d-6453-474c-8a04-5a9aa69de187",
			},
			body: `{"code":"validation_failed","detail":"The Idempotency-Key is ` +
				`not valid.","errors":[{"code":"invalid_format","detail":"It must ` +
				`be a uuid, chosen by the client.","field":"Idempotency-Key"}],` +
				`"instance":"/v1/messages","status":422,"title":"Validation failed",` +
				`"trace_id":"4f54da8d-6453-474c-8a04-5a9aa69de187",` +
				`"type":"https://docs.anywaye.com/errors/validation_failed"}`,
			wantErrIs: ErrRefused,
			wantCode:  "validation_failed",
			wantTrace: "4f54da8d-6453-474c-8a04-5a9aa69de187",
			wantFields: []FieldError{
				{Field: "Idempotency-Key", Code: "invalid_format"},
			},
		},
		{
			name:   "a reused key with a different body is a 409 that is NOT a suppression",
			status: http.StatusConflict,
			headers: map[string]string{
				"content-type": "application/problem+json; charset=utf-8",
				"x-trace-id":   "328ebc5c-dab5-4f5d-93c4-4fc573ca1f0c",
			},
			body: `{"code":"idempotency_key_reused","detail":"That Idempotency-Key ` +
				`was already used for a different request body on this endpoint. ` +
				`Reuse the original body to get the original response, or send a ` +
				`new key.","instance":"/v1/messages","status":409,` +
				`"title":"Idempotency key reused",` +
				`"trace_id":"328ebc5c-dab5-4f5d-93c4-4fc573ca1f0c",` +
				`"type":"https://docs.anywaye.com/errors/idempotency_key_reused"}`,
			wantErrIs: ErrRefused,
			wantCode:  "idempotency_key_reused",
			wantTrace: "328ebc5c-dab5-4f5d-93c4-4fc573ca1f0c",
		},
		{
			name:   "no authenticated caller is a 401 — courier master's shipped default",
			status: http.StatusUnauthorized,
			headers: map[string]string{
				"content-type": "application/problem+json; charset=utf-8",
				"x-trace-id":   "4adb7daa-a480-48d1-bbe8-e6a6f9c5db6f",
			},
			body: `{"code":"unauthorized","detail":"This request needs an ` +
				`authenticated caller.","instance":"/v1/messages","status":401,` +
				`"title":"Unauthorized",` +
				`"trace_id":"4adb7daa-a480-48d1-bbe8-e6a6f9c5db6f",` +
				`"type":"https://docs.anywaye.com/errors/unauthorized"}`,
			wantErrIs: ErrUnauthenticated,
			wantCode:  "unauthorized",
			wantTrace: "4adb7daa-a480-48d1-bbe8-e6a6f9c5db6f",
		},
		{
			name:   "a provider that refused is a 503 and the outbox stayed empty",
			status: http.StatusServiceUnavailable,
			headers: map[string]string{
				"content-type": "application/problem+json; charset=utf-8",
				"x-trace-id":   "5c0f0b3a-1f9d-4c0e-9c1e-2f3a4b5c6d7e",
			},
			body: `{"code":"unavailable","detail":"The mail provider did not ` +
				`accept the message. Nothing was sent and nothing was recorded, so ` +
				`this request is safe to retry with the same Idempotency-Key.",` +
				`"instance":"/v1/messages","status":503,` +
				`"title":"Service unavailable",` +
				`"trace_id":"5c0f0b3a-1f9d-4c0e-9c1e-2f3a4b5c6d7e",` +
				`"type":"https://docs.anywaye.com/errors/unavailable"}`,
			wantErrIs: ErrUnavailable,
			wantCode:  "unavailable",
			wantTrace: "5c0f0b3a-1f9d-4c0e-9c1e-2f3a4b5c6d7e",
			wantRetry: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := newRecordedServer(t, tc)
			defer server.Close()

			client := newTestClient(t, server.URL, "service-token-value")
			request := tc.request
			if request.Type == "" {
				request = validRecordedRequest(userID)
			}
			got, err := client.SendMessage(context.Background(), request)

			if tc.wantErrIs == nil {
				if err != nil {
					t.Fatalf("SendMessage: %v", err)
				}
				assertRecordedAccepted(t, got, tc)
				return
			}

			if err == nil {
				t.Fatalf("a real courier %d was reported as a successful send", tc.status)
			}
			if !isError(err, tc.wantErrIs) {
				t.Fatalf("error = %v, want one matching %v", err, tc.wantErrIs)
			}
			if got := Retryable(err); got != tc.wantRetry {
				t.Errorf("Retryable = %t, want %t", got, tc.wantRetry)
			}

			var refused *Error
			if !errorsAs(err, &refused) {
				t.Fatalf("error is not a *courier.Error: %v", err)
			}
			if refused.Status != tc.status {
				t.Errorf("Status = %d, want courier's %d", refused.Status, tc.status)
			}
			if refused.Code != tc.wantCode {
				t.Errorf("Code = %q, want %q", refused.Code, tc.wantCode)
			}
			if tc.wantTrace != "" && refused.TraceID != tc.wantTrace {
				t.Errorf("TraceID = %q, want courier's %q", refused.TraceID, tc.wantTrace)
			}
			if len(refused.Fields) != len(tc.wantFields) {
				t.Errorf("Fields = %v, want %v", refused.Fields, tc.wantFields)
			} else {
				for i, want := range tc.wantFields {
					if refused.Fields[i] != want {
						t.Errorf("Fields[%d] = %+v, want %+v", i, refused.Fields[i], want)
					}
				}
			}
		})
	}
}

func TestTheIdempotencyKeyIsAUuidCourierWillAccept(t *testing.T) {
	const token = "s3cr3t-recovery-token-value-0123456789abcdef"
	const user = "1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9"
	const reset = TypePasswordReset
	const welcome = TypeWelcome

	first, err := idempotencyKeyFor(reset, user, token)
	if err != nil {
		t.Fatalf("idempotencyKeyFor: %v", err)
	}
	second, err := idempotencyKeyFor(reset, user, token)
	if err != nil {
		t.Fatalf("idempotencyKeyFor: %v", err)
	}

	if first != second {
		t.Error("the same send produced two keys, so a retry would be a second send")
	}
	if !isUUID(first) {
		t.Errorf("the derived key %q is not a uuid; courier answers 422 for one", first)
	}
	if strings.Contains(first, token) {
		t.Error("the derived key contains the token; it is a credential")
	}

	differing := []struct {
		name            string
		purpose         string
		user            string
		token           string
		whyItMustDiffer string
	}{
		{
			name: "another token", purpose: reset, user: user, token: "another-token",
			whyItMustDiffer: "two people's resets would share an idempotency slot and " +
				"the second would be answered with the first one's message id",
		},
		{
			name: "another user", purpose: reset, user: "00000000-0000-4000-8000-000000000000",
			token:           token,
			whyItMustDiffer: "the key would no longer identify WHICH send it names",
		},
		{
			name: "another purpose", purpose: welcome, user: user, token: token,
			whyItMustDiffer: "a verification and a reset of one token would be answered " +
				"with each other's stored response",
		},
	}
	for _, tc := range differing {
		t.Run(tc.name, func(t *testing.T) {
			other, err := idempotencyKeyFor(tc.purpose, tc.user, tc.token)
			if err != nil {
				t.Fatalf("idempotencyKeyFor: %v", err)
			}
			if other == first {
				t.Errorf("changing %s produced the same key, so %s", tc.name, tc.whyItMustDiffer)
			}
		})
	}

	raw, err := newUUIDv4()
	if err != nil {
		t.Fatalf("newUUIDv4: %v", err)
	}
	if !isUUID(raw) {
		t.Errorf("newUUIDv4 produced %q, which is not a uuid", raw)
	}
	if _, err := idempotencyKeyFor(reset, user, ""); err == nil {
		t.Error("an empty token produced an idempotency key")
	}
}

func TestAReplayedSendIsOneSend(t *testing.T) {
	const userID = "1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9"
	const first = `{"data":{"status":"accepted","user_id":"` + userID + `",` +
		`"message_id":"courier-16c22f7a-deda-443c-bdac-d7dcf2405b70",` +
		`"event_id":"0f1d27fc-47ed-4547-aba6-3e98aeaaa198",` +
		`"notification_type":"password_reset"}}`

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(first))
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Idempotency-Replayed", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(first))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "service-token-value")
	req := validRecordedRequest(userID)

	one, err := client.SendMessage(context.Background(), req)
	if err != nil {
		t.Fatalf("the first send: %v", err)
	}
	two, err := client.SendMessage(context.Background(), req)
	if err != nil {
		t.Fatalf("the replayed send: %v", err)
	}

	if one != two {
		t.Errorf("the replay answered differently:\n first: %+v\nsecond: %+v", one, two)
	}
	if one.MessageID != "courier-16c22f7a-deda-443c-bdac-d7dcf2405b70" {
		t.Errorf("MessageID = %q, want the recorded one", one.MessageID)
	}
	if calls != 2 {
		t.Errorf("courier was called %d times, want 2 (the second being a replay)", calls)
	}
}

func TestCouriersTypesAgreeWithCouriersDocument(t *testing.T) {
	document := findCourierOpenAPI(t)
	raw, err := os.ReadFile(document)
	if err != nil {
		t.Fatalf("reading courier's document: %v", err)
	}
	courierTypes, err := extractNotificationTypes(raw)
	if err != nil {
		t.Fatalf("parsing the NotificationType enum out of %s: %v", document, err)
	}

	identity := make(map[string]struct{}, len(identityTypes))
	for _, one := range identityTypes {
		identity[one] = struct{}{}
	}
	courier := make(map[string]struct{}, len(courierTypes))
	for _, one := range courierTypes {
		courier[one] = struct{}{}
	}

	for _, one := range courierTypes {
		if _, declared := identity[one]; !declared {
			t.Errorf("courier sends %q (read from %s) and this package has no "+
				"constant for it; add the Type* constant and the IsType case, and "+
				"re-check whether any flow should send it", one, document)
		}
	}
	for _, one := range identityTypes {
		if _, sent := courier[one]; !sent {
			t.Errorf("this package declares %q, which courier's document (read "+
				"from %s) does not send; the client would send it and courier "+
				"would answer 422", one, document)
		}
	}
	t.Logf("courier's NotificationType enum in %s equals this package's %d Type* constants",
		document, len(identityTypes))
}

var identityTypes = []string{
	TypeWelcome,
	TypePasswordReset,
	TypeTeamInvitation,
	TypeAccountSecurity,
	TypeEmailChangeCurrent,
	TypeEmailChangeNew,
}

func extractNotificationTypes(raw []byte) ([]string, error) {
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != "NotificationType:" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		for _, rest := range lines[i+1:] {
			trimmed := strings.TrimSpace(rest)
			if trimmed == "" {
				continue
			}
			if len(rest)-len(strings.TrimLeft(rest, " ")) <= indent {
				break
			}
			if strings.HasPrefix(trimmed, "enum:") {
				values := enumValues(trimmed)
				if len(values) == 0 {
					return nil, errors.New("courier's NotificationType enum is empty")
				}
				return values, nil
			}
		}
		return nil, errors.New("courier's NotificationType schema declares no enum")
	}
	return nil, errors.New("courier's document has no NotificationType schema")
}

func enumValues(line string) []string {
	values := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "enum:"))
	values = strings.TrimPrefix(values, "[")
	values = strings.TrimSuffix(values, "]")
	var out []string
	for _, one := range strings.Split(values, ",") {
		if one = strings.TrimSpace(one); one != "" {
			out = append(out, one)
		}
	}
	return out
}

func newRecordedServer(t *testing.T, tc recordedCase) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for key, value := range tc.headers {
			w.Header().Set(key, value)
		}
		w.WriteHeader(tc.status)
		_, _ = w.Write([]byte(tc.body))
	}))
}

func validRecordedRequest(userID string) MessageRequest {
	return MessageRequest{
		Type:   TypePasswordReset,
		UserID: userID,
		To:     "kaka@example.com",
		URL:    "https://app.example.com/reset?token=abc",
	}
}

func assertRecordedAccepted(t *testing.T, got MessageResult, tc recordedCase) {
	t.Helper()
	if got.Status != StatusAccepted {
		t.Errorf("Status = %q, want %q", got.Status, StatusAccepted)
	}
	wantType := tc.wantType
	if wantType == "" {
		wantType = TypePasswordReset
	}
	if got.Type != wantType {
		t.Errorf("Type = %q, want %q", got.Type, wantType)
	}
	if got.MessageID == "" {
		t.Error("MessageID is empty; courier always returns one and a bounce is tied to it")
	}
	if got.EventID == "" {
		t.Error("EventID is empty; it is the outbox row a subscriber will see")
	}
}

func findCourierOpenAPI(t *testing.T) string {
	t.Helper()
	if document, ok := sourceCheckoutCourier(t); ok {
		return document
	}
	candidates := []string{
		filepath.Join("..", "..", "courier", "openapi.yaml"),
		filepath.Join("..", "..", "..", "courier", "openapi.yaml"),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	t.Fatalf("courier's openapi.yaml is not beside this checkout (looked in %v). "+
		"This test could not check that the Type* constants still match courier's "+
		"vocabulary, and reporting that is better than passing silently.",
		candidates)
	return ""
}

func sourceCheckoutCourier(t *testing.T) (string, bool) {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "git", "rev-parse", "--git-common-dir").Output()
	if err != nil {
		return "", false
	}
	common := strings.TrimSpace(string(out))
	if common == "" {
		return "", false
	}
	root, err := filepath.Abs(common)
	if err != nil {
		return "", false
	}
	document := filepath.Join(filepath.Dir(root), "..", "courier", "openapi.yaml")
	if _, err := os.Stat(document); err != nil {
		return "", false
	}
	return document, true
}
