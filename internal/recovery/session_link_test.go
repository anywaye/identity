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

// THE SESSION LINK, AT THE STORE.
//
// These tests are about the token MACHINE and nothing about the route that will
// mint one. The claim being made here is narrow and it is the one the whole feature
// rests on: a delegated session link is a fourth purpose on the existing
// `recovery_tokens` table — one insert, one digest-only column, one conditional
// UPDATE — and every property the three mailed flows hold (spend once, expire,
// wrong purpose is indistinguishable from unknown) comes from the statements those
// flows already use rather than from a second implementation of them.
//
// A test that asserted those properties through a new method could not tell "the
// machine was extended" from "a fourth machine was added behind the same type", so
// every test below drives `Store` directly: `Create`, `Live` and `Consume`, with
// the purpose as the only thing that differs.

// sessionLinkFor is one minted link token: the plaintext the caller would deliver,
// and the row the machine wrote about it.
type sessionLinkFor struct {
	token  string
	rowID  id.UUID
	digest string
}

// mintLink mints a session-link row over the store, which is what the mint route
// will do — so a test that passes here and fails at the route is a route problem,
// not a machine one.
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

// TestASessionLinkIsOneRowOfTheMachineAndNothingElse is the claim the feature rests
// on, asserted at the shape level: a session link is a row of the same table, with
// the same columns, carrying the same digest construction.
//
// IT ALSO PINS WHAT A LINK ROW DOES NOT CARRY, because the temptation on this
// feature is to make the token describe the thing it is for — a redirect, a landing
// page, a project. Every one of those would be a field that outlives the click, and
// the caller owns both delivery and landing. The test reads every column through
// the map, for the reason `storedTokenRow` documents: a struct that deliberately has
// no field for them would hide their absence.
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
	// The target half belongs to an email change and to nothing else, and the
	// schema's CHECK says so; a link carrying one would be a row that could confirm
	// a second address nobody asked about.
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

// TestThePlaintextIsNowhereInTheLinkRow: the link's plaintext is handed straight
// back to the caller in the mint response and never travels again inside this
// process, so the row is the only place it could have been kept by accident.
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

	// The negative control: if the digest contained the token, the loop above would
	// pass vacuously, so the two are shown to be different values.
	if link.digest == link.token {
		t.Fatal("the stored digest IS the token; every assertion in this file about " +
			"what the row does not hold is now meaningless")
	}
}

// TestASessionLinkIsSpentOnceUnderConcurrency is the single-use property at the
// only place it can be wrong, and it is asserted as a SUM: exactly one winner.
//
// The same shape as TestOneTokenSpentOnceUnderConcurrency and the same reason for
// the word "exactly" — "at least one succeeded" is passed by a machine that lets
// every racer through, which is the failure this exists to catch.
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

// TestALinkAnswersIdenticallyForEveryWayOfBeingWrong is the existence-leak claim,
// and it is a TABLE because the four cases have to be COMPARED rather than each
// asserted separately: "each is ErrTokenNotFound" is satisfiable by four different
// errors a caller could still tell apart.
//
//   - a token that never existed     -> a well-formed digest no row holds
//   - an expired one                 -> past expires_at, on a moved clock
//   - one that has been spent        -> token_consumed_at set
//   - one minted for another purpose -> a password reset token, presented as a link
//
// The fifth row is the control: the same presentation against the RIGHT purpose
// must succeed, or the four refusals prove nothing.
func TestALinkAnswersIdenticallyForEveryWayOfBeingWrong(t *testing.T) {
	cases := []struct {
		name string
		// mint writes the row this case presents, and says which purpose it is for.
		mint func(t *testing.T, h *harness, who account) (digest string, purpose Purpose)
		// presented is the purpose the caller asks about, which is deliberately
		// another one on the wrong-purpose row.
		presented Purpose
		// elapsed is how far the clock moves before the read, so "expired" is a
		// fixture rather than a sleep.
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

// TestALinkIsGoneWithItsUser, because the link's whole value is that it mints a
// session: a row outliving the account is a credential with nothing left to open.
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

// TestTheSchemaKnowsTheLinkPurposeAndStillRefusesOneItDoesNot is the database half
// of the closed-set pair, and both halves matter: a CHECK widened to accept anything
// passes the first assertion and fails the second.
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

// TestTheLinkWindowIsShortAndBounded is the arithmetic the mint route depends on,
// and every assertion is about a CONSTANT rather than about behavior — which is
// what makes them worth pinning, because a well-meaning "let the caller choose an
// hour" would satisfy every other test in this file.
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

// TestNoPurposeInheritsAnotherPurposesWindow: TTLFor answers with a switch, and a
// purpose added without a case of its own lands in the reset window by default —
// which is a link living thirty minutes because nobody opened a file.
func TestNoPurposeInheritsAnotherPurposesWindow(t *testing.T) {
	for _, p := range allPurposes() {
		if p != PurposePasswordReset && TTLFor(p) == PasswordResetTTL {
			t.Errorf("TTLFor(%s) falls through to the password reset window; a purpose with "+
				"no case of its own inherits the wrong window silently", p)
		}
	}
}
