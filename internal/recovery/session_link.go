package recovery

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
	"github.com/anywaye/identity/internal/users"
)


var (
	ErrSubjectNotFound = errors.New("no such user to mint a session link for")

	ErrSubjectHasSecondFactor = errors.New("that account has a second factor, which a session link cannot answer")

	ErrSubjectDisabled = errors.New("that account is disabled and cannot be minted a session for")
)

// ErrMFAUnavailable means this deployment cannot answer whether anybody has a
// second factor, and the mint refuses rather than assume.
//
// IT IS A SENTINEL RATHER THAN A BOOLEAN `canAsk` FOR THE SAME REASON ErrNoMailer
// is: a seam that fails is honest about what it knows, and a `false` from a
// deployment that cannot look is indistinguishable from a real "this user has no
// second factor". Assuming "no" there would make the refusal above the one control
// this route has.
var ErrMFAUnavailable = errors.New("this deployment cannot say whether an account has a second factor")

// SecondFactorState is the one question the mint asks about a subject.
//
// IT IS `mfa.Service.Enabled` BY SIGNATURE AND DECLARED HERE RATHER THAN IMPORTED,
// for the reason SessionRevoker and AccessTokenRevoker are: `recovery_tokens` and
// `mfa_credentials` are two tables with nothing to say to each other, and the RULE
// this package states is that a link must not outlive the account's ability to sign
// in — not anything about how a TOTP secret is sealed. An import in both
// directions would be an edge between two tables for one boolean.
type SecondFactorState interface {
	Enabled(ctx context.Context, q db.Querier, userID id.UUID) (bool, error)
}

// MintSessionLinkInput is a named subject and an optional window.
//
// The subject is a USER and not an account: what a session belongs to is the user,
// and the accounts a user belongs to are a question the caller already has a route
// for. Naming an account here would be a second way to express tenancy, and this
// service has exactly one.
type MintSessionLinkInput struct {
	UserID id.UUID
	Email string
	Window time.Duration
}

// SessionLink is the minted pair: the plaintext the CALLER delivers, and when it
// stops working.
//
// Token is here, and it is here because the route's whole contract is to hand the
// value back exactly once. It is a return value rather than a field on a row for
// the reason Token carries no plaintext: the digest goes in and the plaintext goes
// out, and there is no object in between that could hold both.
type SessionLink struct {
	Token     string
	ExpiresAt time.Time
}

// MintSessionLink writes one row of the token machine for a named subject and hands
// back the plaintext.
//
// THE ORDER IS THE SECURITY PROPERTY, and each step is where a decision that would
// otherwise be made after a credential exists is made before one does:
//
//  1. resolve the window       a caller that asked for too long is told so before
//     anything is written
//  2. resolve the subject      404 for a user that is not there. Ahead of the MFA
//     question on purpose, and specifically rather than
//     generally: answering 409 ("that account has a second
//     factor") for an id that is not an account at all would
//     make the 409 a probe for which uuids are enrolled and the
//     404 a probe for which are real. One lookup, one answer per
//     outcome. DECISIONS.md D12 is why the 404 is safe HERE and
//     is a 202 on every self-service route in this service
//  3. ask about the second     409 for an enrolled subject. Ahead of the mint, so a
//     factor                   refused link leaves no row at all
//  4. mint and store           one insert, the digest only
//
// # WHAT IS NOT CHECKED HERE, AND WHY IT IS NOT AN OVERSIGHT
//
// It is checked, as of packet identity-disabled-01 (step 2b above): `users` grew
// `disabled_at` on 2026-10-05 and the mint now refuses a disabled subject.
//
// WHAT IS STILL NOT HERE IS THE REDEMPTION'S REFUSAL, and that is the next packet
// rather than an oversight. The redeem route does not exist yet, so there is
// nothing to refuse today and no link can currently become a session at all — which
// is why the mint is the right half to wire first and why wiring the other one
// without a route to wire it into would be code with no caller.
//
// # WHERE THAT REFUSAL BELONGS WHEN IT IS WRITTEN, because the file said so and
// the sentence is still true
//
// It must be the SHAPE OF AN UNKNOWN TOKEN and not its own status. On the redeem
// route the token IS the credential (`security: []`), so the caller is the owner or
// whoever took the link, and an answer that named the account's state would publish
// it to exactly the person the operator acted about. `TestTheSubjectDisabledRefusalIsItsOwnErrorAndNotA404`
// above is the other half of that pair: on THIS surface the caller is a machine
// credential and naming the state is correct, so the two answers differ and neither
// is the other's.
func (s *Service) MintSessionLink(ctx context.Context, in MintSessionLinkInput) (SessionLink, error) {
	window := in.Window
	switch {
	case window == 0:
		window = SessionLinkTTL
	case window < 0:
		return SessionLink{}, &users.FieldError{Field: "window", Code: users.CodeInvalidFormat}
	case window > MaxSessionLinkTTL:
		return SessionLink{}, &users.FieldError{Field: "window", Code: users.CodeTooLong}
	}

	now := s.clk.Now()

	if in.UserID.IsZero() && in.Email == "" {
		return SessionLink{}, &users.FieldError{Field: "user_id", Code: users.CodeRequired}
	}

	var user users.User
	var err error
	if in.Email != "" {
		if in.UserID.IsZero() == false {
			return SessionLink{}, &users.FieldError{Field: "user_id", Code: users.CodeInvalidFormat}
		}
		user, err = s.resolveSubjectByEmail(ctx, in.Email, now)
		if err != nil {
			return SessionLink{}, err
		}
	} else {
		q := s.read.Queryer()
		user, err = s.users.ByID(ctx, q, in.UserID)
		if err != nil {
			if errors.Is(err, users.ErrNotFound) {
				return SessionLink{}, ErrSubjectNotFound
			}
			return SessionLink{}, fmt.Errorf("recovery: looking up the subject for a session link: %w", err)
		}
	}

	if user.IsDisabled() {
		return SessionLink{}, ErrSubjectDisabled
	}

	q := s.read.Queryer()

	if s.secondFactor == nil {
		return SessionLink{}, ErrMFAUnavailable
	}
	enrolled, err := s.secondFactor.Enabled(ctx, q, user.ID)
	if err != nil {
		if errors.Is(err, ErrMFAUnavailable) {
			return SessionLink{}, ErrMFAUnavailable
		}
		return SessionLink{}, fmt.Errorf("recovery: asking whether the subject has a second factor: %w", err)
	}
	if enrolled {
		return SessionLink{}, ErrSubjectHasSecondFactor
	}

	token, digest, err := sessions.NewToken()
	if err != nil {
		return SessionLink{}, fmt.Errorf("recovery: minting a session link: %w", err)
	}

	expiresAt := now.Add(window)
	if err := s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		_, err := s.tokens.Create(ctx, q, NewToken{
			UserID:    user.ID,
			Purpose:   PurposeSessionLink,
			Digest:    digest,
			CreatedAt: now,
			ExpiresAt: expiresAt,
		})
		return err
	}); err != nil {
		return SessionLink{}, err
	}

	return SessionLink{Token: token, ExpiresAt: expiresAt}, nil
}

func (s *Service) resolveSubjectByEmail(ctx context.Context, raw string, now time.Time) (users.User, error) {
	email := users.NormalizeEmail(raw)
	if err := users.ValidateEmail(email); err != nil {
		return users.User{}, &users.FieldError{Field: "email", Code: users.CodeInvalidFormat}
	}

	q := s.read.Queryer()
	u, err := s.users.ByEmail(ctx, q, email)
	if err == nil {
		if u.IsDisabled() {
			return users.User{}, ErrSubjectDisabled
		}
		return u, nil
	}
	if !errors.Is(err, users.ErrNotFound) {
		return users.User{}, fmt.Errorf("recovery: looking up the subject by email: %w", err)
	}

	digest, err := s.hasher.Hash(randomUnusablePassword())
	if err != nil {
		return users.User{}, fmt.Errorf("recovery: hashing the placeholder password: %w", err)
	}

	var created users.User
	err = s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		u, err := s.users.Create(ctx, q, users.CreateParams{Email: email, PasswordDigest: digest})
		if err != nil {
			if errors.Is(err, users.ErrEmailTaken) {
				u2, err2 := s.users.ByEmail(ctx, q, email)
				if err2 != nil {
					return fmt.Errorf("recovery: re-reading a concurrently created user: %w", err2)
				}
				created = u2
				return nil
			}
			return fmt.Errorf("recovery: creating the subject: %w", err)
		}
		created = u
		return nil
	})
	if err != nil {
		return users.User{}, err
	}
	_ = now
	return created, nil
}

func randomUnusablePassword() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Errorf("recovery: reading randomness for a placeholder password: %w", err))
	}
	return base64.StdEncoding.EncodeToString(b)
}
