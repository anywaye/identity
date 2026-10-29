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


func isErr(sentinel error) func(error) bool {
	return func(err error) bool { return errors.Is(err, sentinel) }
}

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

	for column, value := range h.storedTokenRow(live.ID) {
		if text, ok := value.(string); ok && strings.Contains(text, link.Token) {
			t.Errorf("the minted plaintext is in column %q", column)
		}
	}
}

func TestTheMintRefusesBeforeItWritesAnything(t *testing.T) {
	cases := []struct {
		name string
		arrange func(t *testing.T, h *harness) MintSessionLinkInput
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

	h.secondFactor.enrolled = false
	if _, err := h.svc.MintSessionLink(t.Context(), MintSessionLinkInput{UserID: who.id}); err != nil {
		t.Fatalf("the same mint with no second factor enrolled = %v, want a link", err)
	}
}

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
