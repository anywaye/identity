package mfa

import (
	"errors"
	"net/netip"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)

const (
	MethodTOTP = "totp"

	MethodRecoveryCode = "recovery_code"
)

const (
	Digits = 6

	Period = 30 * time.Second

	SkewSteps = 1

	SecretSize = 20
)

// RecoveryCodeCount is how many recovery codes a credential is issued with.
//
// Ten, and the argument is arithmetic: ten single-use codes is a code the user
// can keep in a drawer, a code they can print, and a code they can be trusted to
// have not already used. Five is the number most products ship, and it is a
// number a user reuses — the same code written on two pieces of paper in two
// places, both of which are then in an attacker's hands.
const RecoveryCodeCount = 10

// RecoveryCodeBytes is the entropy in one recovery code.
//
// TEN BYTES, EIGHTY BITS, and this is a floor rather than a round number.
//
// The codes are compared by SHA-256, not by argon2id, and that is only safe
// because of this constant. A six-digit recovery code would be 10^6 candidates,
// and a SHA-256 of one is walked in microseconds — a database dump would then
// contain ten working second factors. At eighty bits the same search is
// 2^80 ≈ 1.2 × 10^24 candidates, which is not a computation rather than an
// intractable one. See the column comment on mfa_recovery_codes.code_digest.
const RecoveryCodeBytes = 10

// ChallengeTTL is how long a login's challenge is worth completing.
//
// Ten minutes, the same window as the OIDC login form's sealed state and the
// same reasoning: a challenge is something somebody is typing six digits into
// right now, and one that outlives the interruption it was created by is a
// credential sitting in a log waiting to be found.
const ChallengeTTL = 10 * time.Minute

// EnrollmentTTL is how long an unconfirmed secret is worth keeping.
//
// Ten minutes, and it is a bound rather than a courtesy because an unconfirmed
// credential authenticates nothing — it is a secret at rest for as long as the
// row survives, and a row with no deadline is a table that grows by one per
// abandoned setup. It is also about right for the task: reading a QR code,
// opening an authenticator app, and typing six digits.
const EnrollmentTTL = 10 * time.Minute

// CodeTTL is the de facto lifetime of a TOTP code, and the window an attacker's
// copy of it is good for. It is Period times the two-sided skew plus the step
// itself, and it exists so the value is stated once instead of being
// re-derived in prose and in a pruning query.
var CodeTTL = time.Duration(SkewSteps*2+1) * Period

var (
	ErrNotFound = errors.New("mfa credential not found")

	ErrNotEnabled = errors.New("multi-factor authentication is not enabled for this user")

	ErrAlreadyEnabled = errors.New("multi-factor authentication is already enabled for this user")

	ErrEnrollmentNotFound = errors.New("no pending enrollment with that id")

	ErrChallengeNotFound = errors.New("no live sign-in challenge matches that token")

	ErrInvalidFactor = errors.New("that code was not accepted")

	ErrNoVault = errors.New("this deployment has no MFA_ENCRYPTION_KEY, so it cannot verify a second factor")

	ErrNoIssuer = errors.New("the MFA issuer label is required")
)

const (
	CodeRequired = "required"

	CodeInvalidFormat = "invalid_format"
)

// FieldError is a per-field validation failure on an enrollment request.
type FieldError struct {
	Field string
	Code  string
}

func (e *FieldError) Error() string {
	return e.Field + ": " + e.Code
}

// Credential is a row in mfa_credentials.
//
// SecretCiphertext is carried because every read of this row needs it, and
// because the shape of the row is the shape of the decision. It is never
// rendered, never logged, and never leaves this package except as a base32
// string handed to the user exactly once at enrollment.
type Credential struct {
	ID     id.UUID
	UserID id.UUID
	Method string
	SecretCiphertext string
	Digits           int
	PeriodSeconds    int
	Algorithm        string
	Label            string
	ConfirmedAt *time.Time
	ExpiresAt *time.Time
	FailedAttempts int
	LockedUntil    *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// IsConfirmed reports whether the credential is live. The login path reads only
// rows where this is true, which is what makes "stored but never confirmed"
// mean "authenticates nothing" rather than "authenticates, eventually".
func (c Credential) IsConfirmed() bool { return c.ConfirmedAt != nil }

// IsLocked reports whether the credential's own counter has locked the second
// factor as of now. Expiry is decided on read, so no sweeper has to clear it.
func (c Credential) IsLocked(now time.Time) bool {
	return c.LockedUntil != nil && c.LockedUntil.After(now)
}

// RetryAfter is how much longer the caller must wait on the second factor. It is
// zero once the window has closed and never negative.
func (c Credential) RetryAfter(now time.Time) time.Duration {
	if !c.IsLocked(now) {
		return 0
	}
	return c.LockedUntil.Sub(now)
}

// Challenge is a row in mfa_challenges: a correct password, and no session yet.
type Challenge struct {
	ID         id.UUID
	UserID     id.UUID
	UserAgent  string
	IP         *netip.Addr
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt *time.Time
}

// Live reports whether the challenge may still be answered as of now.
func (c Challenge) Live(now time.Time) bool {
	if c.ConsumedAt != nil {
		return false
	}
	return c.ExpiresAt.After(now)
}
