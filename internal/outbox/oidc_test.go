package outbox

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)


func TestOIDCClientEventsValidateAgainstCoreSchema(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 4, 19, 0, 0, time.UTC)
	clientRow := id.MustNew()
	account := id.MustNew()
	actor := id.MustNew()

	tests := []struct {
		name string
		give func() (Envelope, error)
	}{
		{
			name: "a client is registered",
			give: func() (Envelope, error) {
				return NewOIDCClientCreated(now, clientRow, account, "anytalk-web", []string{"https://app.anytalk.test/cb"},
					[]string{"authorization_code"}, []string{"openid", "email", "profile", "accounts"}, actor)
			},
		},
		{
			name: "a client is revoked",
			give: func() (Envelope, error) {
				return NewOIDCClientRevoked(now, clientRow, account, "anytalk-web", actor)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := tt.give()
			if err != nil {
				t.Fatalf("building the envelope: %v", err)
			}
			if err := got.Validate(); err != nil {
				t.Errorf("the envelope does not satisfy core's schema: %v", err)
			}
			if got.Source != SourceIdentity {
				t.Errorf("source = %q, want %q", got.Source, SourceIdentity)
			}
			if !strings.HasPrefix(got.Type, SourceIdentity+".") {
				t.Errorf("type = %q, want the %q prefix", got.Type, SourceIdentity)
			}
			if got.Subject != clientRow.String() {
				t.Errorf("subject = %q, want the client row id %q", got.Subject, clientRow)
			}
			if !got.Time.Equal(now) {
				t.Errorf("time = %s, want the injected instant %s", got.Time, now)
			}
		})
	}
}

func TestOIDCClientCreatedPayload(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 4, 19, 0, 0, time.UTC)
	clientRow, account, actor := id.MustNew(), id.MustNew(), id.MustNew()
	redirects := []string{"https://app.anytalk.test/cb"}

	e, err := NewOIDCClientCreated(now, clientRow, account, "anytalk-web", redirects,
		[]string{"authorization_code"}, []string{"openid", "email"}, actor)
	if err != nil {
		t.Fatalf("building the envelope: %v", err)
	}

	var data struct {
		ClientID     string   `json:"client_id"`
		AccountID    string   `json:"account_id"`
		RedirectURIs []string `json:"redirect_uris"`
		Scopes       []string `json:"scopes"`
		GrantTypes   []string `json:"grant_types"`
		RegisteredBy string   `json:"registered_by"`
	}
	if err := json.Unmarshal(e.Data, &data); err != nil {
		t.Fatalf("the payload is not JSON: %v", err)
	}

	if data.ClientID != "anytalk-web" {
		t.Errorf("client_id = %q, want anytalk-web", data.ClientID)
	}
	if data.AccountID != account.String() {
		t.Errorf("account_id = %q, want %q", data.AccountID, account)
	}
	if data.RegisteredBy != actor.String() {
		t.Errorf("registered_by = %q, want %q", data.RegisteredBy, actor)
	}
	if len(data.RedirectURIs) != 1 || data.RedirectURIs[0] != redirects[0] {
		t.Errorf("redirect_uris = %v, want %v", data.RedirectURIs, redirects)
	}
	if len(data.Scopes) != 2 || len(data.GrantTypes) != 1 {
		t.Errorf("scopes = %v, grant_types = %v; want the registered values", data.Scopes, data.GrantTypes)
	}
}

func TestOIDCEventsCarryNoClientSecret(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 4, 19, 0, 0, time.UTC)
	clientRow, account, actor := id.MustNew(), id.MustNew(), id.MustNew()

	created, err := NewOIDCClientCreated(now, clientRow, account, "anytalk-web",
		[]string{"https://app.anytalk.test/cb"}, []string{"authorization_code"}, []string{"openid"}, actor)
	if err != nil {
		t.Fatalf("building the created envelope: %v", err)
	}
	revoked, err := NewOIDCClientRevoked(now, clientRow, account, "anytalk-web", actor)
	if err != nil {
		t.Fatalf("building the revoked envelope: %v", err)
	}

	for _, e := range []Envelope{created, revoked} {
		for _, forbidden := range []string{"secret", "digest", "client_secret", "password"} {
			if strings.Contains(string(e.Data), forbidden) {
				t.Errorf("%s payload %s mentions %q", e.Type, e.Data, forbidden)
			}
		}
	}
}
