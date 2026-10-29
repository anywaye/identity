package courier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/anywaye/identity/internal/recovery"
)


type sentRequest struct {
	method string
	path   string
	header http.Header
	body   map[string]any
}

func recordingCourier(t *testing.T) (*httptest.Server, *[]sentRequest) {
	t.Helper()

	var mu sync.Mutex
	var seen []sentRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)

		mu.Lock()
		seen = append(seen, sentRequest{
			method: r.Method,
			path:   r.URL.Path,
			header: r.Header.Clone(),
			body:   body,
		})
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"status":"accepted",` +
			`"user_id":"6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",` +
			`"message_id":"courier-1","event_id":"e1","notification_type":"password_reset"}}`))
	}))
	t.Cleanup(server.Close)

	return server, &seen
}

func TestOneSendCarriesOneStableKey(t *testing.T) {
	server, seen := recordingCourier(t)
	mailer := testMailer(t, server.URL, nil)

	for range 2 {
		if err := mailer.Send(context.Background(), resetMessageFor("kaka@example.com", testToken)); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}

	if len(*seen) != 2 {
		t.Fatalf("courier saw %d requests, want 2 — the sends that reach courier are what "+
			"the key is for", len(*seen))
	}

	first, second := (*seen)[0], (*seen)[1]
	firstKey, secondKey := first.header.Get("Idempotency-Key"), second.header.Get("Idempotency-Key")

	if firstKey == "" {
		t.Fatal("no Idempotency-Key on the wire; courier's :idempotent pipeline scopes the " +
			"key to the principal, so a keyless send cannot be deduplicated at all")
	}
	if firstKey != secondKey {
		t.Errorf("two sends of ONE message carried different keys (%q then %q), so a user who\n"+
			"asked twice for one reset link would be sent two mails. The key must be derived\n"+
			"from the send, not minted per attempt.", firstKey, secondKey)
	}
	if !isUUID(firstKey) {
		t.Errorf("Idempotency-Key = %q, which is not a uuid; courier answers 422 for one", firstKey)
	}
	if strings.Contains(firstKey, testToken) {
		t.Error("the Idempotency-Key carries the recovery token, and a live credential in " +
			"somebody else's store is a credential the next reader can redeem")
	}

	if !reflect.DeepEqual(first.body, second.body) {
		t.Errorf("the two sends of one message carried different bodies:\n%v\n%v",
			first.body, second.body)
	}
}

func TestTheAdapterPutsCouriersRequestOnTheWire(t *testing.T) {
	server, seen := recordingCourier(t)
	mailer := testMailer(t, server.URL, nil)

	if err := mailer.Send(context.Background(), resetMessageFor("kaka@example.com", testToken)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(*seen) != 1 {
		t.Fatalf("courier saw %d requests, want 1", len(*seen))
	}
	got := (*seen)[0]

	if got.method != http.MethodPost {
		t.Errorf("method = %q, want POST; %s is the only door into courier's send path",
			got.method, messagesPath)
	}
	if got.path != messagesPath {
		t.Errorf("path = %q, want %q", got.path, messagesPath)
	}

	authorization := got.header.Values("Authorization")
	if len(authorization) != 1 {
		t.Errorf("Authorization appears %d times; courier reads the first and a repeated "+
			"header is ambiguous", len(authorization))
	} else if scheme, value, _ := strings.Cut(authorization[0], " "); scheme != "Bearer" || value == "" {
		t.Errorf("Authorization = %q, want a bearer credential and nothing else", authorization[0])
	}
	if got.header.Get("Cookie") != "" {
		t.Error("a machine credential was sent in a cookie; courier's surface is not a browser")
	}

	for _, forbidden := range []string{"from", "subject", "text", "html", "body", "account_id"} {
		if _, present := got.body[forbidden]; present {
			t.Errorf("the request carried %q; courier's vocabulary is closed and has no such field. "+
				"A caller that could choose the sender or the body would make courier an open relay "+
				"with a config file attached", forbidden)
		}
	}
	for _, required := range []string{"type", "user_id", "to", "url"} {
		if _, present := got.body[required]; !present {
			t.Errorf("the request has no %q; courier requires it", required)
		}
	}

	if got.body["type"] != TypePasswordReset {
		t.Errorf("type = %v, want %q", got.body["type"], TypePasswordReset)
	}
	if got.body["to"] != "kaka@example.com" {
		t.Errorf("to = %v, want the recipient recovery rendered", got.body["to"])
	}
	if got.body["user_id"] != testUserID.String() {
		t.Errorf("user_id = %v, want the account the message concerns (%s). courier keys the "+
			"recipient's notification preferences by it and attributes the delivered event to it",
			got.body["user_id"], testUserID)
	}

	url, _ := got.body["url"].(string)
	if want := "https://app.example.com/reset?token=" + testToken; url != want {
		t.Errorf("url = %q, want %q — the configured template rendered with the token", url, want)
	}
}

func TestTheTwoEmailChangeHalvesPutTheirOwnFieldsOnTheWire(t *testing.T) {
	cases := []struct {
		name     string
		message  recovery.Message
		wantType string
		wantURL string
		wantPrevious string
	}{
		{
			name:     "the current-address half carries the link and no previous address",
			message:  changeCurrentMessage(testToken),
			wantType: TypeEmailChangeCurrent,
			wantURL:  "https://app.example.com/confirm-change?token=" + testToken,
		},
		{
			name:         "the new-address half carries the previous address and no link",
			message:      changeNewMessage(testToken),
			wantType:     TypeEmailChangeNew,
			wantPrevious: "kaka@example.com",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, seen := recordingCourier(t)
			mailer := testMailer(t, server.URL, nil)

			if err := mailer.Send(context.Background(), tc.message); err != nil {
				t.Fatalf("Send: %v", err)
			}
			if len(*seen) != 1 {
				t.Fatalf("courier saw %d requests, want 1", len(*seen))
			}
			got := (*seen)[0]

			if got.body["type"] != tc.wantType {
				t.Errorf("type = %v, want %q", got.body["type"], tc.wantType)
			}
			if got.body["to"] != tc.message.To {
				t.Errorf("to = %v, want the recipient recovery rendered", got.body["to"])
			}
			if got.body["user_id"] != testUserID.String() {
				t.Errorf("user_id = %v, want the account the message concerns", got.body["user_id"])
			}

			if tc.wantURL != "" {
				url, _ := got.body["url"].(string)
				if url != tc.wantURL {
					t.Errorf("url = %q, want %q — the configured template rendered with the token",
						url, tc.wantURL)
				}
			} else if _, present := got.body["url"]; present {
				t.Error("the request carried a url; courier's email_change_new declares no " +
					"such field, so this is a 422 against a real courier")
			}

			if tc.wantPrevious != "" {
				previous, _ := got.body["previous_email"].(string)
				if previous != tc.wantPrevious {
					t.Errorf("previous_email = %q, want %q — the address the account is "+
						"moving from", previous, tc.wantPrevious)
				}
			} else if _, present := got.body["previous_email"]; present {
				t.Error("the request carried previous_email; courier's " +
					"email_change_current declares no such field, so this is a 422 " +
					"against a real courier")
			}
		})
	}
}

func TestTheResetLinkComesFromConfigurationAndNotFromARequest(t *testing.T) {
	t.Run("no Host header can change the link", func(t *testing.T) {
		server, seen := recordingCourier(t)
		mailer := testMailer(t, server.URL, nil)

		attacker := "identity.attacker.example"
		probe := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/password-resets", nil)
		probe.Host = attacker
		probe.Header.Set("X-Forwarded-Host", attacker)

		if err := mailer.Send(context.Background(),
			resetMessageFor("kaka@example.com", testToken)); err != nil {
			t.Fatalf("Send: %v", err)
		}
		if len(*seen) != 1 {
			t.Fatalf("courier saw %d requests, want 1", len(*seen))
		}

		url, _ := (*seen)[0].body["url"].(string)
		if strings.Contains(url, attacker) {
			t.Errorf("the reset link carries %q, which came from a request header rather than "+
				"from configuration. A reset link is the one URL that carries a live credential "+
				"and grants it: a link whose host an attacker can choose is a credential "+
				"typed into a form they wrote.\n  link: %s", attacker, url)
		}
		if !strings.HasPrefix(url, "https://app.example.com/") {
			t.Errorf("the reset link is %q, want the configured base URL", url)
		}
	})

	t.Run("neither the adapter nor the client can reach a request", func(t *testing.T) {
		for _, typ := range []reflect.Type{
			reflect.TypeOf(RecoveryMailer{}),
			reflect.TypeOf(Client{}),
			reflect.TypeOf(LinkTemplate("")),
		} {
			if typ.Kind() != reflect.Struct {
				if typ.Kind() == reflect.String {
					continue
				}
				t.Errorf("%s is a %s rather than a struct or a string, so this walk no "+
					"longer covers it; the reflection here is asserting an absence and an "+
					"unwalked type would pass it for the wrong reason", typ.Name(), typ.Kind())
				continue
			}
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if strings.Contains(field.Type.String(), "net/http") {
					t.Errorf("%s.%s is a %s, so this type can hold a request and a "+
						"`Host` header with it. The reset link must come from configuration.",
						typ.Name(), field.Name, field.Type)
				}
			}
		}
	})
}

func TestARefusedMessageNeverReachesTheWire(t *testing.T) {
	message := recoveryMessage("Confirm your new security key", "kaka@example.com",
		"Somebody added a security key to your anywaye account.\n\n    "+testToken+"\n")

	server, seen := recordingCourier(t)
	mailer := testMailer(t, server.URL, nil)

	err := mailer.Send(context.Background(), message)
	if !isError(err, ErrUnsupportedMessage) {
		t.Fatalf("Send = %v, want ErrUnsupportedMessage", err)
	}

	if len(*seen) != 0 {
		t.Errorf("a message courier has no type for reached the wire %d time(s). The "+
			"token in it is a live credential, and the refusal has to happen before "+
			"the wire rather than as a 422 after it.", len(*seen))
	}
}
