package courier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/recovery"
)


func recoveryMessage(subject, to, body string) recovery.Message {
	return recovery.Message{To: to, Subject: subject, Body: body}
}

func resetMessageFor(email, token string) recovery.Message {
	message := recoveryMessage(kindPasswordReset, email,
		resetBody(token, email, time.Date(2026, 10, 1, 12, 30, 0, 0, time.UTC)))
	message.UserID = testUserID
	return message
}

func verificationMessage(token string) recovery.Message {
	message := recoveryMessage(kindVerifyEmail, "kaka@example.com",
		"Confirm the address kaka@example.com for your anywaye account.\n\n"+
			"Your confirmation code is:\n\n    "+token+"\n")
	message.UserID = testUserID
	return message
}

func changeCurrentMessage(token string) recovery.Message {
	message := recoveryMessage(kindChangeCurrent, "kaka@example.com",
		"Somebody signed in to the anywaye account on kaka@example.com and asked to\n"+
			"change the address it uses.\n\nIf that was you, confirm it with this code:\n\n    "+
			token+"\n")
	message.UserID = testUserID
	return message
}

func changeNewMessage(token string) recovery.Message {
	message := recoveryMessage(kindChangeNew, "new@example.com",
		"Somebody asked to move the anywaye account on kaka@example.com to this address.\n\n"+
			"Confirm it with this code:\n\n    "+token+"\n")
	message.UserID = testUserID
	return message
}

var testUserID = id.MustNew()

func resetBody(token, email string, expiry time.Time) string {
	return "Somebody asked to reset the password for the account registered to " + email + ".\n" +
		"\nYour reset code is:\n" +
		"\n    " + token + "\n" +
		"\nEnter it where you sign in to choose a new password. It works once, and only\n" +
		"until " + expiry.UTC().Format(time.RFC1123) + ".\n" +
		"\nIf this was not you, nothing has changed. Nobody can sign in with this code\n" +
		"without it, and it stops working as soon as it is used or when it expires.\n"
}

const testToken = "K7dQm2xR9vTb4nLpZcHs1JfWy6AeUi0O"


func TestEveryRecoverableMessageReachesCourier(t *testing.T) {
	deliverable := make([]string, 0, len(courierTypeFor))
	for subject := range courierTypeFor {
		deliverable = append(deliverable, subject)
	}
	sort.Strings(deliverable)

	if len(deliverable) != 4 {
		t.Errorf("%d messages are deliverable, want 4: %v. identity's address "+
			"verification maps onto courier's `welcome`, its password reset onto "+
			"courier's `password_reset`, and the two halves of an email change onto "+
			"the two types courier built for them", len(deliverable), deliverable)
	}
	if len(knownSubjects)-len(deliverable) != 0 {
		t.Errorf("%d of %d messages are refused, want 0: courier has carried both "+
			"email-change types since 20373bf and this adapter now uses them, so a "+
			"refusal here is a mapping somebody forgot to update",
			len(knownSubjects)-len(deliverable), len(knownSubjects))
	}

	for _, subject := range deliverable {
		t.Run(subject, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":{"status":"accepted",` +
					`"user_id":"6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",` +
					`"message_id":"courier-1","event_id":"e1",` +
					`"notification_type":"` + courierTypeFor[subject] + `"}}`))
			}))
			defer server.Close()

			mailer := testMailer(t, server.URL, nil)
			var message recovery.Message
			switch subject {
			case kindPasswordReset:
				message = resetMessageFor("kaka@example.com", testToken)
			case kindVerifyEmail:
				message = verificationMessage(testToken)
			case kindChangeCurrent:
				message = changeCurrentMessage(testToken)
			case kindChangeNew:
				message = changeNewMessage(testToken)
			default:
				t.Fatalf("no fixture for %q; add one or remove it from courierTypeFor", subject)
			}

			if err := mailer.Send(context.Background(), message); err != nil {
				t.Fatalf("a message courier CAN render was refused: %v", err)
			}
		})
	}
}

func TestAMessageCourierHasNoTypeForIsRefused(t *testing.T) {
	cases := []struct {
		name    string
		message recovery.Message
		why     string
	}{
		{
			name: "a two-factor enrolment notice",
			message: recoveryMessage("Confirm your new security key", "kaka@example.com",
				"Somebody added a security key to your anywaye account.\n\n    "+testToken+"\n"),
			why: "courier's NotificationType has no security-key type, and inventing " +
				"one would mean identity owning a template courier renders",
		},
		{
			name: "a subject that is almost a real one",
			message: recoveryMessage("Reset your anywaye password.", "kaka@example.com",
				"Somebody asked to reset the password for the account registered to "+
					"kaka@example.com.\n\n    "+testToken+"\n"),
			why: "the match on the subject is exact and not a normalisation: a subject " +
				"with a trailing period is a different message, and a fuzzy match " +
				"would deliver it onto the reset type",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("courier was called for a message it should never have been "+
					"sent: %s %s", r.Method, r.URL.Path)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			mailer, err := NewRecoveryMailer(RecoveryMailerConfig{
				Client:        newTestClient(t, server.URL, "service-token-value"),
				LinkTemplates: testLinkTemplates(),
			})
			if err != nil {
				t.Fatalf("NewRecoveryMailer: %v", err)
			}

			err = mailer.Send(context.Background(), tc.message)
			if err == nil {
				t.Fatalf("Send accepted a message courier cannot render, because %s", tc.why)
			}
			if !isError(err, ErrUnsupportedMessage) {
				t.Errorf("error = %v, want one matching ErrUnsupportedMessage", err)
			}
			if Retryable(err) {
				t.Error("a message courier cannot render was reported as retryable")
			}
		})
	}
}

func TestAMessageWithNoAccountIsRefusedRatherThanGuessedAt(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		t.Errorf("courier was called for a message with no account: %s", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var log bytes.Buffer
	mailer := testMailer(t, server.URL, slog.New(slog.NewTextHandler(&log, nil)))

	anonymous := recoveryMessage(kindPasswordReset, "kaka@example.com",
		resetBody(testToken, "kaka@example.com", time.Date(2026, 10, 1, 12, 30, 0, 0, time.UTC)))
	if !anonymous.UserID.IsZero() {
		t.Fatal("the fixture is supposed to have no account")
	}

	err := mailer.Send(context.Background(), anonymous)
	if !isError(err, ErrUnsupportedMessage) {
		t.Fatalf("Send = %v, want ErrUnsupportedMessage", err)
	}
	if calls != 0 {
		t.Errorf("courier was called %d times", calls)
	}
	if !strings.Contains(log.String(), "no account") {
		t.Errorf("the refusal was not logged:\n%s", log.String())
	}
	if strings.Contains(log.String(), testToken) {
		t.Error("the log carries the live token of a message that was not sent")
	}
}


func TestTheRequestCarriesExactlyWhatCouriersVocabularyHas(t *testing.T) {
	var body map[string]any
	var header http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header = r.Header.Clone()
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"status":"accepted",` +
			`"user_id":"6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",` +
			`"message_id":"courier-1","event_id":"e1","notification_type":"password_reset"}}`))
	}))
	defer server.Close()

	mailer := testMailer(t, server.URL, nil)

	client, err := New(Config{BaseURL: server.URL, Token: "service-token-value"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.SendMessage(context.Background(), MessageRequest{
		Type:   TypePasswordReset,
		UserID: "6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",
		To:     "kaka@example.com",
		URL:    "https://app.example.com/reset?token=" + testToken,
	}); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	for _, forbidden := range []string{"from", "subject", "text", "html", "body", "account_id"} {
		if _, present := body[forbidden]; present {
			t.Errorf("the request carried %q; courier's vocabulary is closed and has no such field",
				forbidden)
		}
	}
	for _, required := range []string{"type", "user_id", "to", "url"} {
		if _, present := body[required]; !present {
			t.Errorf("the request has no %q; courier requires it", required)
		}
	}
	if body["type"] != TypePasswordReset {
		t.Errorf("type = %v, want %q", body["type"], TypePasswordReset)
	}
	if got := stringOf(body["url"]); !strings.Contains(got, testToken) {
		t.Errorf("url = %q, want the token in it", got)
	}
	key := header.Get("Idempotency-Key")
	if !isUUID(key) {
		t.Errorf("Idempotency-Key = %q, which is not a uuid; courier answers 422", key)
	}
	if strings.Contains(key, testToken) {
		t.Error("the idempotency key carries the token")
	}
	if got := stringOf(body["url"]); got != "https://app.example.com/reset?token="+testToken {
		t.Errorf("url = %q, want the configured template rendered with the token", got)
	}

	_ = mailer
}

func TestTheLinkTemplateIsRefusedWhenItCannotMakeAWorkingLink(t *testing.T) {
	cases := []struct {
		name     string
		template string
		wantErr  bool
	}{
		{
			name:     "an absolute https URL with the placeholder",
			template: "https://app.example.com/reset?token={token}",
		},
		{
			name:     "the token in a path segment rather than a query",
			template: "https://app.example.com/reset/{token}",
		},
		{
			name:     "an http URL, which is legitimate for a local product",
			template: "http://localhost:3000/reset?token={token}",
		},
		{name: "empty", template: "", wantErr: true},
		{name: "blank", template: "   ", wantErr: true},
		{
			name:     "no placeholder at all, so the link carries no token",
			template: "https://app.example.com/reset",
			wantErr:  true,
		},
		{
			name:     "a relative URL, which cannot be rendered in a mail",
			template: "/reset?token={token}",
			wantErr:  true,
		},
		{
			name:     "a scheme courier's schema would not accept",
			template: "javascript:alert({token})",
			wantErr:  true,
		},
		{
			name:     "a fragment, which mail clients do not send to a server",
			template: "https://app.example.com/reset#/{token}",
			wantErr:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateLinkTemplate(tc.template)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ValidateLinkTemplate(%q) accepted it", tc.template)
				}
				if got != "" {
					t.Errorf("a refused template returned %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateLinkTemplate(%q): %v", tc.template, err)
			}
			rendered, err := got.render(testToken)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if !strings.Contains(rendered, testToken) {
				t.Errorf("the rendered link %q has no token in it", rendered)
			}
			if strings.Contains(rendered, TokenPlaceholder) {
				t.Errorf("the rendered link %q still has the placeholder in it", rendered)
			}
		})
	}
}

func TestRenderRefusesATokenlessLink(t *testing.T) {
	template, err := ValidateLinkTemplate("https://app.example.com/reset?token={token}")
	if err != nil {
		t.Fatalf("ValidateLinkTemplate: %v", err)
	}
	if _, err := template.render(""); !isError(err, errNoToken) {
		t.Errorf("render(\"\") = %v, want a refusal", err)
	}
}

func TestReadyAnswersTheDeploymentQuestionAndNotCouriersOwn(t *testing.T) {
	t.Run("an up courier is ready", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != readyzPath {
				t.Errorf("Ready probed %s, want %s", r.URL.Path, readyzPath)
			}
			if r.Header.Get("Authorization") == "" {
				t.Error("Ready sent no credential; the path courier may later need one has none")
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		}))
		defer server.Close()

		mailer := testMailer(t, server.URL, nil)
		if err := mailer.Ready(context.Background()); err != nil {
			t.Errorf("Ready = %v, want nil", err)
		}
	})

	t.Run("a courier that is not answering is ErrNoMailer", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		mailer := testMailer(t, server.URL, nil)
		err := mailer.Ready(context.Background())
		if !isError(err, recovery.ErrNoMailer) {
			t.Fatalf("Ready = %v, want one matching recovery.ErrNoMailer", err)
		}
		if !isError(err, ErrUnavailable) {
			t.Errorf("the courier reason is gone from the chain: %v", err)
		}
	})
}


func TestTheMailerNeverPrintsACredentialOrAToken(t *testing.T) {
	const credential = "svc-7f3a9c1e4b8d2056-the-credential"

	leaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]any
		body, _ := readAllString(r)
		_ = json.Unmarshal([]byte(body), &raw)
		echo := map[string]any{
			"code":          "unauthorized",
			"detail":        "the credential " + credential + " was not accepted for " + raw["url"].(string),
			"trace_id":      "0af7651916cd43dd8448eb211c80319c",
			"echoed_auth":   r.Header.Get("Authorization"),
			"echoed_key":    r.Header.Get("Idempotency-Key"),
			"echoed_cook":   r.Header.Get("Cookie"),
			"echoed_repeat": credential,
		}
		encoded, _ := json.Marshal(echo)
		w.Header().Set("Content-Type", "application/problem+json")
		w.Header().Set("X-Echo-Auth", r.Header.Get("Authorization"))
		w.Header().Set("X-Echo-Key", r.Header.Get("Idempotency-Key"))
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write(encoded)
	}))
	defer leaky.Close()

	var log bytes.Buffer
	mailer := testMailer(t, leaky.URL, slog.New(slog.NewTextHandler(&log, nil)))

	clientErr := courierSend(t, leaky.URL, credential)

	things := map[string]any{
		"error string":     clientErr.Error(),
		"error %v":         clientErr,
		"error %+v":        clientErr,
		"error %#v":        clientErr,
		"mailer String":    mailer.String(),
		"mailer %v":        mailer,
		"mailer %#v":       mailer,
		"client String":    mailer.client.String(),
		"client %#v":       mailer.client,
		"log output":       log.String(),
		"retryable":        Retryable(clientErr),
		"serialized error": serialize(t, clientErr),
	}

	for what, thing := range things {
		rendered := renderAll(t, thing)
		if strings.Contains(rendered, credential) {
			t.Errorf("%s carries the service credential:\n%s", what, rendered)
		}
	}
	if !isError(clientErr, ErrUnauthenticated) {
		t.Errorf("the echoed 401 is not an authentication refusal: %v", clientErr)
	}
}

func TestTheLogNeverCarriesTheTokenOrTheRecipient(t *testing.T) {
	const email = "kaka-privacy@example.com"
	const token = "K7dQm2xR9vTb4nLpZcHs1JfWy6AeUi0O"

	cases := []struct {
		name   string
		status int
		body   string
		wantLog string
	}{
		{
			name:   "courier refused the credential",
			status: http.StatusUnauthorized,
			body:   `{"code":"unauthorized","detail":"no","trace_id":"t1"}`,
			wantLog: "",
		},
		{
			name:   "the mailbox is suppressed",
			status: http.StatusConflict,
			body: `{"code":"conflict","detail":"That mailbox does not exist: it ` +
				`hard-bounced a previous message.","trace_id":"t2"}`,
			wantLog: "t2",
		},
		{
			name:    "the provider refused",
			status:  http.StatusServiceUnavailable,
			body:    `{"code":"unavailable","detail":"Nothing was sent.","trace_id":"t3"}`,
			wantLog: "t3",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var log bytes.Buffer
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			mailer := testMailer(t, server.URL, slog.New(slog.NewTextHandler(&log, nil)))
			err := mailer.Send(context.Background(), resetMessageFor(email, token))
			if err == nil {
				t.Fatal("the send succeeded against a courier that refused")
			}

			written := log.String()
			if strings.Contains(written, token) {
				t.Errorf("the log carries the live token:\n%s", written)
			}
			if strings.Contains(written, email) {
				t.Errorf("the log carries the recipient:\n%s", written)
			}
			for _, want := range []string{"status=", "code=", "retryable="} {
				if !strings.Contains(written, want) {
					t.Errorf("the log line has no %s:\n%s", want, written)
				}
			}
			if tc.wantLog != "" && !strings.Contains(written, tc.wantLog) {
				t.Errorf("the log has no handle on courier's own logs (%s):\n%s", tc.wantLog, written)
			}
		})
	}
}

func TestASuccessfulSendLogsCouriersIdentifiersAndNothingElse(t *testing.T) {
	const email = "kaka-privacy@example.com"
	const token = "K7dQm2xR9vTb4nLpZcHs1JfWy6AeUi0O"
	var log bytes.Buffer

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"status":"accepted",` +
			`"user_id":"6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",` +
			`"message_id":"courier-16c22f7a","event_id":"0f1d27fc",` +
			`"notification_type":"password_reset"}}`))
	}))
	defer server.Close()

	mailer := testMailer(t, server.URL, slog.New(slog.NewTextHandler(&log, nil)))
	if err := mailer.Send(context.Background(), resetMessageFor(email, token)); err != nil {
		t.Fatalf("the send: %v", err)
	}

	written := log.String()
	if !strings.Contains(written, "courier-16c22f7a") {
		t.Errorf("the log has no message_id, so a bounce cannot be tied back:\n%s", written)
	}
	if strings.Contains(written, token) || strings.Contains(written, email) {
		t.Errorf("the log carries the token or the recipient:\n%s", written)
	}
}


func TestTheOnlyPlaceBothVocabulariesMeet(t *testing.T) {
	if got := reflectMessageFields(); got != "To Subject Body UserID" {
		t.Errorf("recovery.Message carries %q, want exactly To, Subject, Body and "+
			"UserID. A fifth field is a courier decision leaking into identity unless "+
			"it is another fact about the recipient, and the reasoning belongs there.",
			got)
	}

	if tokenFromBody("no marker here") != "" {
		t.Error("tokenFromBody found a token in a body with no marker in it")
	}

}

func TestEveryMessageRecoveryRendersIsAccountedFor(t *testing.T) {
	// recovery's own subjects, read from its source. The set is small and the
	// alternative — importing an unexported constant — is not possible, and adding
	// an export purely for a test would be a worse change than reading the file.
	recoverySubjects := subjectsInRecoverySource(t)

	for subject := range recoverySubjects {
		if _, known := knownSubjects[subject]; !known {
			t.Errorf("internal/recovery renders a subject this package has never heard "+
				"of (%q); add it to knownSubjects and decide whether courier can send it", subject)
		}
	}
	for subject := range knownSubjects {
		if _, rendered := recoverySubjects[subject]; !rendered {
			t.Errorf("this package knows a subject internal/recovery does not render (%q)", subject)
		}
	}
}

func TestNoRecoverySubjectCarriesAToken(t *testing.T) {
	for subject := range knownSubjects {
		lowered := strings.ToLower(subject)
		for _, forbidden := range []string{"token", "code", "=", "{", "}"} {
			if strings.Contains(lowered, forbidden) {
				t.Errorf("the subject %q contains %q; a subject is this adapter's "+
					"discriminator and it must be a constant", subject, forbidden)
			}
		}
	}
}


func testMailer(t *testing.T, baseURL string, logger *slog.Logger) *RecoveryMailer {
	t.Helper()
	client, err := New(Config{BaseURL: baseURL, Token: "service-token-value"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mailer, err := NewRecoveryMailer(RecoveryMailerConfig{
		Client:        client,
		LinkTemplates: testLinkTemplates(),
		Logger:        logger,
	})
	if err != nil {
		t.Fatalf("NewRecoveryMailer: %v", err)
	}
	return mailer
}

func courierSend(t *testing.T, baseURL, credential string) error {
	t.Helper()
	client, err := New(Config{BaseURL: baseURL, Token: credential})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = client.SendMessage(context.Background(), MessageRequest{
		Type:   TypePasswordReset,
		UserID: "6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",
		To:     "kaka@example.com",
		URL:    "https://app.example.com/reset?token=" + testToken,
	})
	return err
}

func readAllString(r *http.Request) (string, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(r.Body)
	return buf.String(), err
}

func renderAll(t *testing.T, thing any) string {
	t.Helper()
	var out strings.Builder
	out.WriteString(sprint(t, thing, "%v"))
	out.WriteString(sprint(t, thing, "%+v"))
	out.WriteString(sprint(t, thing, "%#v"))
	out.WriteString(sprint(t, thing, "%s"))
	out.WriteString(sprint(t, thing, "%q"))
	return out.String()
}

func serialize(t *testing.T, err error) string {
	t.Helper()
	encoded, marshalErr := json.Marshal(map[string]any{"error": err.Error()})
	if marshalErr != nil {
		t.Fatalf("marshaling the error: %v", marshalErr)
	}
	return string(encoded)
}

var _ = errors.Is
