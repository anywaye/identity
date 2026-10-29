package recovery

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
)


type sessionLinkFor struct {
	token  string
	rowID  id.UUID
	digest string
}

func mintLink(t *testing.T, h *harness, who account, ttl time.Duration) sessionLinkFor {
	t.Helper()

	token, digest, err := sessions.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	created, err := NewStore(h.pool).Create(t.Context(), h.pool, NewToken{
		UserID:    who.id,
		Purpose:   PurposeSessionLink,
		Digest:    digest,
		CreatedAt: h.now(),
		ExpiresAt: h.now().Add(ttl),
	})
	if err != nil {
		t.Fatalf("Create(%s): %v", PurposeSessionLink, err)
	}
	return sessionLinkFor{token: token, rowID: created.ID, digest: digest}
}

func TestASessionLinkIsOneRowOfTheMachineAndNothingElse(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()
	link := mintLink(t, h, who, SessionLinkTTL)

	row := h.storedTokenRow(link.rowID)

	if got := row["purpose"]; got != string(PurposeSessionLink) {
		t.Errorf("purpose = %v, want %q", got, PurposeSessionLink)
	}
	if got := row["token_digest"]; got != link.digest {
		t.Errorf("token_digest = %v, want the digest it was handed", got)
	}
	if row["target_email"] != nil {
		t.Errorf("a session link row carries a target address: %v", row["target_email"])
	}
	if row["target_token_digest"] != nil {
		t.Errorf("a session link row carries a second token: %v", row["target_token_digest"])
	}
	if row["token_consumed_at"] != nil || row["target_consumed_at"] != nil {
		t.Error("a freshly minted link is already spent")
	}

	for column := range row {
		switch column {
		case "id", "user_id", "purpose", "token_digest", "target_email",
			"target_token_digest", "created_at", "expires_at",
			"token_consumed_at", "target_consumed_at":
		default:
			t.Errorf("the table grew a column this file has never heard of: %q; read it here "+
				"and say what a session link is doing in it", column)
		}
	}
}

func TestThePlaintextIsNowhereInTheLinkRow(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()
	link := mintLink(t, h, who, SessionLinkTTL)

	for column, value := range h.storedTokenRow(link.rowID) {
		text, ok := value.(string)
		if !ok {
			continue
		}
		if strings.Contains(text, link.token) {
			t.Errorf("the session link plaintext is in column %q", column)
		}
	}

	if link.digest == link.token {
		t.Fatal("the stored digest IS the token; every assertion in this file about " +
			"what the row does not hold is now meaningless")
	}
}

func TestASessionLinkIsSpentOnceUnderConcurrency(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()
	rowID := mintLink(t, h, who, SessionLinkTTL).rowID

	const racers = 8
	type outcome struct {
		won bool
		err error
	}
	results := make(chan outcome, racers)
	start := make(chan struct{})

	var wg sync.WaitGroup
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			won, err := NewStore(h.pool).Consume(t.Context(), h.pool, rowID, h.now())
			results <- outcome{won: won, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	winners := 0
	for got := range results {
		if got.err != nil {
			t.Fatalf("Consume: %v", got.err)
		}
		if got.won {
			winners++
		}
	}
	if winners != 1 {
		t.Errorf("%d of %d concurrent spends of one link succeeded, want exactly 1", winners, racers)
	}
}

func TestALinkAnswersIdenticallyForEveryWayOfBeingWrong(t *testing.T) {
	cases := []struct {
		name string
		mint func(t *testing.T, h *harness, who account) (digest string, purpose Purpose)
		presented Purpose
		elapsed  time.Duration
		wantLive bool
	}{
		{
			name: "a token that never existed",
			mint: func(t *testing.T, _ *harness, _ account) (string, Purpose) {
				_, digest, err := sessions.NewToken()
				if err != nil {
					t.Fatalf("NewToken: %v", err)
				}
				return digest, PurposeSessionLink
			},
			presented: PurposeSessionLink,
			wantLive:  false,
		},
		{
			name: "an expired link",
			mint: func(t *testing.T, h *harness, who account) (string, Purpose) {
				link := mintLink(t, h, who, SessionLinkTTL)
				return link.digest, PurposeSessionLink
			},
			presented: PurposeSessionLink,
			elapsed:   SessionLinkTTL + time.Second,
			wantLive:  false,
		},
		{
			name: "a link that has been spent",
			mint: func(t *testing.T, h *harness, who account) (string, Purpose) {
				link := mintLink(t, h, who, SessionLinkTTL)
				spent, err := NewStore(h.pool).Consume(t.Context(), h.pool, link.rowID, h.now())
				if err != nil || !spent {
					t.Fatalf("spending the link in its own fixture: won=%v err=%v", spent, err)
				}
				return link.digest, PurposeSessionLink
			},
			presented: PurposeSessionLink,
			wantLive:  false,
		},
		{
			name: "a password reset token presented as a link",
			mint: func(t *testing.T, h *harness, who account) (string, Purpose) {
				_, digest, err := sessions.NewToken()
				if err != nil {
					t.Fatalf("NewToken: %v", err)
				}
				if _, err := NewStore(h.pool).Create(t.Context(), h.pool, NewToken{
					UserID: who.id, Purpose: PurposePasswordReset, Digest: digest,
					CreatedAt: h.now(), ExpiresAt: h.now().Add(PasswordResetTTL),
				}); err != nil {
					t.Fatalf("Create(password_reset): %v", err)
				}
				return digest, PurposePasswordReset
			},
			presented: PurposeSessionLink,
			wantLive:  false,
		},
		{
			name: "CONTROL: a live link presented as a link",
			mint: func(t *testing.T, h *harness, who account) (string, Purpose) {
				link := mintLink(t, h, who, SessionLinkTTL)
				return link.digest, PurposeSessionLink
			},
			presented: PurposeSessionLink,
			wantLive:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, false)
			who := h.registerSimple()

			digest, minted := tc.mint(t, h, who)
			if tc.wantLive && minted != tc.presented {
				t.Fatalf("the control row is a %s token read as a %s; the row cannot be the "+
					"one under test", minted, tc.presented)
			}
			if tc.elapsed > 0 {
				h.clk.Advance(tc.elapsed)
			}

			_, err := NewStore(h.pool).Live(t.Context(), h.pool, digest, tc.presented, h.now())
			switch {
			case tc.wantLive && err != nil:
				t.Fatalf("Live on a live link = %v, want the row", err)
			case !tc.wantLive && !errors.Is(err, ErrTokenNotFound):
				t.Errorf("Live = %v, want exactly ErrTokenNotFound", err)
			}
		})
	}
}

func TestALinkIsGoneWithItsUser(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()
	link := mintLink(t, h, who, SessionLinkTTL)

	if got := countRows(t, h, `SELECT count(*) FROM recovery_tokens WHERE id = $1`, link.rowID); got != 1 {
		t.Fatalf("%d rows before the user is deleted, want 1", got)
	}
	if _, err := h.pool.Exec(t.Context(), `DELETE FROM users WHERE id = $1`, who.id); err != nil {
		t.Fatalf("deleting the user: %v", err)
	}
	if got := countRows(t, h, `SELECT count(*) FROM recovery_tokens WHERE id = $1`, link.rowID); got != 0 {
		t.Errorf("the link survived its user: %d rows remain", got)
	}
}

func TestTheSchemaKnowsTheLinkPurposeAndStillRefusesOneItDoesNot(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	_, digest, err := sessions.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if _, err := NewStore(h.pool).Create(t.Context(), h.pool, NewToken{
		UserID: who.id, Purpose: PurposeSessionLink, Digest: digest,
		CreatedAt: h.now(), ExpiresAt: h.now().Add(SessionLinkTTL),
	}); err != nil {
		t.Errorf("the schema refused a purpose this build implements: %v", err)
	}

	_, other, err := sessions.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if _, err := h.pool.Exec(t.Context(), `
		INSERT INTO recovery_tokens (user_id, purpose, token_digest, created_at, expires_at)
		VALUES ($1, 'open_the_vault', $2, $3, $4)`,
		who.id, other, h.now(), h.now().Add(time.Hour)); err == nil {
		t.Error("the database accepted a purpose this build does not implement")
	}
}

func TestTheLinkWindowIsShortAndBounded(t *testing.T) {
	if SessionLinkTTL >= PasswordResetTTL {
		t.Errorf("SessionLinkTTL (%s) is not shorter than the mailed reset window (%s); a link "+
			"is not delivered to an inbox and has nothing to survive a delay in one",
			SessionLinkTTL, PasswordResetTTL)
	}
	if MaxSessionLinkTTL < SessionLinkTTL {
		t.Errorf("MaxSessionLinkTTL (%s) is under the default (%s), so a caller could not even "+
			"ask for the default", MaxSessionLinkTTL, SessionLinkTTL)
	}
	if MaxSessionLinkTTL > time.Hour {
		t.Errorf("MaxSessionLinkTTL is %s; the maximum is the thing that decides how long a "+
			"delivered link stays live, and an hour is the ceiling this service publishes",
			MaxSessionLinkTTL)
	}
	if TTLFor(PurposeSessionLink) != SessionLinkTTL {
		t.Errorf("TTLFor(%s) = %s, want the default link window %s",
			PurposeSessionLink, TTLFor(PurposeSessionLink), SessionLinkTTL)
	}
}

func TestNoPurposeInheritsAnotherPurposesWindow(t *testing.T) {
	for _, p := range allPurposes() {
		if p != PurposePasswordReset && TTLFor(p) == PasswordResetTTL {
			t.Errorf("TTLFor(%s) falls through to the password reset window; a purpose with "+
				"no case of its own inherits the wrong window silently", p)
		}
	}
}
