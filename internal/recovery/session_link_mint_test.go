package recovery

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
	"github.com/anywaye/identity/internal/users"
)

// THE MINT, AT THE USE CASE.
//
// The machine's own tests (session_link_test.go) drive `Store` directly, because the
// claim there is that a link is a fourth purpose on the existing table. This file
// is the other claim: that the USE CASE refuses the right things in the right
// order, and refuses them before a credential exists.
//
// EVERY REFUSAL IS ASSERTED AGAINST THE TABLE, not just the returned error, because
// "it returned an error" and "it left no live row behind" are different facts and
// only the second one is the security property. A mint that refused after inserting
// would pass every test that reads the error.

// isErr matches a sentinel, however it was wrapped.
func isErr(sentinel error) func(error) bool {
	return func(err error) bool { return errors.Is(err, sentinel) }
}

// isWindowError matches a `*users.FieldError` on the `window` field with one code.
//
// It is a separate matcher rather than a general field-error matcher because the
// FIELD is half of what is being asserted: an error naming some other field would
// tell a caller to fix a field this request does not have, and the 422 would say so.
func isWindowError(code string) func(error) bool {
	return func(err error) bool {
		var fieldErr *users.FieldError
		return errors.As(err, &fieldErr) && fieldErr.Field == "window" && fieldErr.Code == code
	}
}

func TestAMintedLinkIsOneLiveRowAndThePlaintextIsOnlyTheReturnValue(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	link, err := h.svc.MintSessionLink(t.Context(), MintSessionLinkInput{UserID: who.id})
	if err != nil {
		t.Fatalf("MintSessionLink: %v", err)
	}
	if link.Token == "" {
		t.Fatal("the mint returned no token, so the route would hand a caller an empty credential")
	}
	if link.ExpiresAt != h.now().Add(SessionLinkTTL) {
		t.Errorf("expires_at = %s, want the default link window %s from now",
			link.ExpiresAt, h.now().Add(SessionLinkTTL))
	}

	live, err := NewStore(h.pool).Live(t.Context(), h.pool, sessions.Digest(link.Token), PurposeSessionLink, h.now())
	if err != nil {
		t.Fatalf("the minted link does not read back as live: %v", err)
	}
	if live.UserID != who.id {
		t.Errorf("the link names user %s, want %s", live.UserID, who.id)
	}
	if live.TargetEmail != "" || live.TargetMinted {
		t.Errorf("a minted link carries an email-change half: target=%q minted=%v",
			live.TargetEmail, live.TargetMinted)
	}

	// The plaintext is in no column. TestASessionLinkIsOneRowOfTheMachineAndNothingElse
	// proves this at the store level; this is the same property seen from the use case,
	// because the use case is where the value exists and a future field could hold it.
	for column, value := range h.storedTokenRow(live.ID) {
		if text, ok := value.(string); ok && strings.Contains(text, link.Token) {
			t.Errorf("the minted plaintext is in column %q", column)
		}
	}
}

// TestTheMintRefusesBeforeItWritesAnything is the table above turned into the
// property it exists for: every refusal is a refusal of a REQUEST, so there is no
// row for a caller to find afterwards.
//
// THE COUNT IS A SUM OVER THE TABLE, not over the returned errors. Four refusals
// that each returned an error and each wrote a row would pass an error-shaped test
// completely, and a live row for a refused subject is a live credential.
func TestTheMintRefusesBeforeItWritesAnything(t *testing.T) {
	cases := []struct {
		name string
		// arrange sets the fixture up, so a refusal that depends on the subject's
		// state can be expressed as a fixture rather than as a branch in the test.
		arrange func(t *testing.T, h *harness) MintSessionLinkInput
		// want says what the mint must fail with. It is a PREDICATE rather than a
		// sentinel because two of the five refusals are `*users.FieldError`, and
		// `errors.Is` on a pointer to a struct with no `Is` method is pointer
		// identity: a table written as `want: &users.FieldError{...}` would compare
		// two different allocations and fail while the behavior was correct.
		want func(error) bool
	}{
		{
			name:    "a subject that is not a user",
			arrange: func(*testing.T, *harness) MintSessionLinkInput { return MintSessionLinkInput{UserID: id.MustNew()} },
			want:    isErr(ErrSubjectNotFound),
		},
		{
			name: "a subject with a second factor",
			arrange: func(t *testing.T, h *harness) MintSessionLinkInput {
				h.secondFactor.enrolled = true
				return MintSessionLinkInput{UserID: h.registerSimple().id}
			},
			want: isErr(ErrSubjectHasSecondFactor),
		},
		{
			name: "a window over the ceiling",
			arrange: func(t *testing.T, h *harness) MintSessionLinkInput {
				return MintSessionLinkInput{
					UserID: h.registerSimple().id,
					Window: MaxSessionLinkTTL + time.Second,
				}
			},
			want: isWindowError(users.CodeTooLong),
		},
		{
			name: "a negative window",
			arrange: func(t *testing.T, h *harness) MintSessionLinkInput {
				return MintSessionLinkInput{UserID: h.registerSimple().id, Window: -time.Second}
			},
			want: isWindowError(users.CodeInvalidFormat),
		},
		{
			// THE SEAM THAT CANNOT ANSWER. A deployment with no way to say whether
			// anybody has a second factor must mint nothing, because the alternative
			// is minting on an assumption and the assumption is the control this route
			// has.
			name: "a deployment that cannot ask about second factors",
			arrange: func(t *testing.T, h *harness) MintSessionLinkInput {
				h.secondFactor.err = ErrMFAUnavailable
				return MintSessionLinkInput{UserID: h.registerSimple().id}
			},
			want: isErr(ErrMFAUnavailable),
		},
		{
			name: "a nil second-factor seam",
			arrange: func(t *testing.T, h *harness) MintSessionLinkInput {
				// A service constructed without the seam at all, which the required
				// constructor argument makes a wiring fault rather than a supported
				// configuration — and a fault must fail closed rather than read as
				// "nobody has a second factor".
				h.svc.secondFactor = nil
				return MintSessionLinkInput{UserID: h.registerSimple().id}
			},
			want: isErr(ErrMFAUnavailable),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, false)
			in := tc.arrange(t, h)
			before := countRows(t, h,
				`SELECT count(*) FROM recovery_tokens WHERE purpose = 'session_link'`)

			_, err := h.svc.MintSessionLink(t.Context(), in)
			if err == nil {
				t.Fatalf("the mint accepted this request; the row names a refusal it must answer")
			}
			if !tc.want(err) {
				t.Errorf("mint error = %v, which is not the refusal this row names", err)
			}

			after := countRows(t, h,
				`SELECT count(*) FROM recovery_tokens WHERE purpose = 'session_link'`)
			if after != before {
				t.Errorf("a refused mint left %d session-link row(s) behind. A row for a "+
					"refused subject is a live credential, and the caller was told no", after-before)
			}
		})
	}
}

// TestAMintForAnEnrolledSubjectIsRefusedRatherThanServedWithAChallenge is the MFA
// decision, asserted as the two things it could have been and was not.
//
// THE CLAIM IS A REFUSAL, so this test cannot be satisfied by a mint that succeeds
// with a challenge attached: the first assertion is that the call fails. The second
// is the reason — that the refusal is about the SUBJECT and is therefore only
// available to a caller holding `sessions:write`, which is what makes a 409 here
// safe in a way the same status on a stranger-facing route would not be.
func TestAMintForAnEnrolledSubjectIsRefusedRatherThanServedWithAChallenge(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()
	h.secondFactor.enrolled = true

	_, err := h.svc.MintSessionLink(t.Context(), MintSessionLinkInput{UserID: who.id})
	if !errors.Is(err, ErrSubjectHasSecondFactor) {
		t.Fatalf("minting for an enrolled subject = %v, want ErrSubjectHasSecondFactor", err)
	}
	if errors.Is(err, ErrTokenNotFound) {
		t.Error("the MFA refusal reused ErrTokenNotFound. That error is deliberately " +
			"indistinguishable from an unknown token for the REDEMPTION's four cases, and " +
			"reusing it here would make one sentinel carry two different meanings")
	}

	// The negative control on the fixture: with the seam saying "not enrolled" the
	// very same call succeeds, so the refusal above is about the answer and not about
	// the subject or the route.
	h.secondFactor.enrolled = false
	if _, err := h.svc.MintSessionLink(t.Context(), MintSessionLinkInput{UserID: who.id}); err != nil {
		t.Fatalf("the same mint with no second factor enrolled = %v, want a link", err)
	}
}

// TestTheWindowIsARefusedBoundAndNotAClamp: a caller that asked for more than the
// ceiling learns so, rather than receiving the ceiling and believing it got what it
// asked for.
//
// THE COMPARISON IS ON THE ERROR AND ON THE ABSENCE OF A ROW, because a clamp that
// still wrote a row would answer 422 and leave a live credential — the worst of the
// two shapes, and the one a test reading only the error would pass.
func TestTheWindowIsARefusedBoundAndNotAClamp(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	for _, requested := range []time.Duration{MaxSessionLinkTTL + time.Nanosecond, 24 * time.Hour} {
		before := countRows(t, h,
			`SELECT count(*) FROM recovery_tokens WHERE purpose = 'session_link'`)

		_, err := h.svc.MintSessionLink(t.Context(), MintSessionLinkInput{
			UserID: who.id,
			Window: requested,
		})
		var fieldErr *users.FieldError
		if !errors.As(err, &fieldErr) || fieldErr.Field != "window" {
			t.Fatalf("a window of %s = %v, want a field error naming `window`", requested, err)
		}
		if after := countRows(t, h,
			`SELECT count(*) FROM recovery_tokens WHERE purpose = 'session_link'`); after != before {
			t.Errorf("a window of %s was refused with a %s AND a row was written", requested, fieldErr.Code)
		}
	}

	// And the ceiling itself is a legal request, which is what makes the refusal a
	// bound rather than a rejection of the field.
	atCeiling, err := h.svc.MintSessionLink(t.Context(), MintSessionLinkInput{
		UserID: who.id,
		Window: MaxSessionLinkTTL,
	})
	if err != nil {
		t.Fatalf("asking for exactly the ceiling = %v, want a link", err)
	}
	if want := h.now().Add(MaxSessionLinkTTL); !atCeiling.ExpiresAt.Equal(want) {
		t.Errorf("expires_at = %s, want %s", atCeiling.ExpiresAt, want)
	}
}

// TestAShorterWindowIsHonoured, because a ceiling nobody may approach is a constant
// and not a policy: the caller is allowed to ask for less than the default, and the
// value it asked for is the value that is written.
func TestAShorterWindowIsHonoured(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	link, err := h.svc.MintSessionLink(t.Context(), MintSessionLinkInput{
		UserID: who.id,
		Window: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("MintSessionLink: %v", err)
	}
	if want := h.now().Add(30 * time.Second); !link.ExpiresAt.Equal(want) {
		t.Errorf("expires_at = %s, want %s", link.ExpiresAt, want)
	}
}
