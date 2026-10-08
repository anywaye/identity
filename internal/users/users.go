// Package users owns the user aggregate: the row, the credential, and the rules
// about what a valid email and password are.
//
// It knows nothing about HTTP. Handlers translate domain errors into the cafaye
// error envelope; they do not define the rules.
package users

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// Errors returned by the store and the validators. Callers match them with
// errors.Is; nothing here is compared by string.
var (
	// ErrNotFound means no such user. It is deliberately indistinguishable from
	// "no such user" in every other sense: the HTTP layer renders it as a
	// generic 401 so the response cannot be used to enumerate accounts.
	ErrNotFound = errors.New("user not found")
	// ErrEmailTaken means the address is already registered. A registration
	// endpoint is the one place this is safe to reveal, and it maps to 409.
	ErrEmailTaken = errors.New("email already registered")
)

// Field validation codes. These land verbatim in the `errors[]` array of the
// cafaye error envelope (core: docs/openapi-conventions.md), so they are part of
// the contract and clients may switch on them.
const (
	CodeRequired      = "required"
	CodeInvalidFormat = "invalid_format"
	CodeTooShort      = "too_short"
	CodeTooLong       = "too_long"
)

// MaxEmailLength is the RFC 5321 limit on a full address. It is also the upper
// bound on the bytes that reach the UNIQUE index on users.email.
const MaxEmailLength = 320

// MaxDisplayNameLength bounds a display name. It is a person's name, not an
// identifier and not a password: nothing is looked up by it, so the bound is
// about what a profile screen can render and what a log line can carry, not
// about an index. 64 is generous for any name a human will actually answer to
// and short enough that a name is never a vector for stuffing a response.
const MaxDisplayNameLength = 64

// MinPasswordLength is the floor the brief sets. There is deliberately no
// composition rule: requiring a mix of character classes reliably produces
// "Password1!" and reliably rejects passphrases. Length is the property that
// actually tracks entropy.
const MinPasswordLength = 8

// MaxPasswordLength bounds what argon2id will be asked to hash. The cost of an
// argon2id call is fixed in memory, but its input is not bounded, so without
// this an unauthenticated caller can choose the size of every login's work.
const MaxPasswordLength = 1024

// FieldError is a per-field validation failure. The HTTP layer turns one of
// these into a single entry of `errors[]` without needing to know which rules
// produced it.
type FieldError struct {
	Field string
	Code  string
}

func (e *FieldError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Code)
}

func fieldErr(field, code string) error {
	return &FieldError{Field: field, Code: code}
}

// User is the row as the domain sees it. PasswordDigest is carried because
// login has to read it; it is never rendered and never leaves this package in a
// response body.
type User struct {
	ID id.UUID
	// Email is stored normalized: lower case and trimmed. See NormalizeEmail.
	Email string
	// DisplayName is what the person is called, and nil means nobody has set
	// one. A POINTER WITH NO `false`, for the reason EmailVerifiedAt and
	// DisabledAt have one: "no name" and "a name that is the empty string" are
	// the same state, and the column is NULL for both — a second way to say it
	// is a second thing to disagree with this one.
	DisplayName *string
	// Preferences is the profile's settings document (00027). A struct value
	// rather than a pointer because the column is NOT NULL DEFAULT '{}'::jsonb:
	// every row has a document, and "no preferences" is the empty document
	// rather than a NULL. See Preferences for the one key it carries and why.
	Preferences Preferences
	// PasswordDigest is an argon2id encoded digest, never a plaintext password.
	PasswordDigest      string
	FailedLoginAttempts int
	// LockedUntil is nil when the account is not locked. A pointer, not a zero
	// time, because "never locked" and "locked until 1970" are different answers
	// and only one of them is true.
	LockedUntil *time.Time
	// EmailVerifiedAt is when somebody proved they can read the address on this
	// row, by following a link delivered to it. nil means nobody has.
	//
	// A POINTER WITH NO `false`, and the absence is the whole of the design: there
	// is no state in which an address is "known to be bad", because the only thing
	// a verification proves is that somebody read a message at this address at this
	// instant. The way to stop trusting it is to change the address, and
	// Store.SetEmail clears this in the same transaction that moves it.
	EmailVerifiedAt *time.Time
	// DisabledAt is when somebody deliberately turned this account off. nil means
	// nobody ever has.
	//
	// IT IS NOT LockedUntil AND THE TWO MUST NOT BE MERGED, which is the whole of
	// migrations/00021's first three lines. A lock is automatic, temporary and
	// expires by itself; a disable is a person's decision with no expiry. So there
	// is no `now` parameter here and no expiry to check: an account disabled in
	// 2019 is disabled today, and the only thing that changes that is somebody
	// calling Store.Enable.
	//
	// A POINTER WITH NO `false`, for the reason EmailVerifiedAt has one: null is
	// the positive statement "nobody has decided this", and a second way to say
	// "active" is a second thing to disagree with this one.
	DisabledAt *time.Time
	// IsStaff marks a platform operator: a human who may use the staff surface
	// (`/v1/operator/*`).
	//
	// IT IS NOT A ROLE, and the difference is the whole of DECISIONS.md D17. A
	// role is re-read per account on every request and answers "what may this
	// person do HERE"; this answers "is this person staff anywhere", and no
	// tenant-admin API may write it — the only writer is `Store.SetStaff`, which
	// the `identity-staff` operator command calls and no HTTP route does. False
	// on every row until an operator grants it (migrations/00030), and a session
	// carries it because `Authenticate` returns the row.
	IsStaff   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// DisabledError is a credential refused because the account was turned off by a
// person.
//
// # IT IS A TYPE AND NOT A SENTINEL, and it is the mirror of LockedError for the
// same reason LockedError is a type
//
// LockedError carries a RetryAfter, so it has to be a value with a field. This one
// carries nothing: there is no window, no count, no deadline. It is a type anyway,
// for the reason that matters on the other side — `errors.As` matches on
// assignability, and the HTTP layer has to be able to tell "disabled" from "wrong
// password" and from "locked" without inspecting a string. A sentinel would work
// for errors.Is and would lose the ability to say anything else about it, and the
// one thing this concept needs to be able to say is that it is NOT the lockout.
//
// # IT IS NOT ErrInvalidCredentials, AND THAT IS A DECISION
//
// The caller reached it by presenting a correct password. Answering 401 would tell
// somebody that their password is wrong when it is not, send them round a reset
// loop that cannot help them, and make the account's state invisible to the only
// person who can act on it. See DECISIONS.md D13 for the enumeration reasoning,
// which is that the check runs AFTER the password is verified — so this error
// reaches a caller who has already proved they hold the credential and therefore
// already knows the account exists.
//
// The sentence is fixed in the HTTP layer for the same reason the lockout's is:
// a detail that varied would be a detail that leaked.
type DisabledError struct{}

func (e *DisabledError) Error() string { return "this account is disabled" }

// IsDisabled reports whether this account has been turned off by a person.
//
// IT TAKES NO CLOCK, and the absence is the decision rather than an oversight: a
// disable does not expire, so there is no instant to compare against. IsLocked
// takes one because a lock does expire, and the two methods reading alike while
// meaning opposite things is the exact confusion migrations/00021 exists to stop —
// so the name says the difference rather than leaving it to a caller to remember
// which column it had.
func (u User) IsDisabled() bool { return u.DisabledAt != nil }

// IsVerified reports whether the address on this row has been proved.
//
// It is a method rather than a comparison against nil at every call site because
// the two answers callers want from it are "may I say verified" and "may I say
// NOT verified", and a caller that forgets the second has made a claim about an
// address nobody checked.
func (u User) IsVerified() bool { return u.EmailVerifiedAt != nil }

// IsLocked reports whether the account is locked as of now. A lock whose instant
// has arrived is not a lock: expiry is checked on read rather than by a sweeper,
// so there is no window where the row says "locked" and the answer is "yes,
// sorry" for a window that already closed.
func (u User) IsLocked(now time.Time) bool {
	return u.LockedUntil != nil && u.LockedUntil.After(now)
}

// RetryAfter is how much longer the caller must wait. It never returns a
// negative or zero-but-locked answer: a body saying "retry in 0s" on a 423 is a
// busy loop written by whoever reads it.
func (u User) RetryAfter(now time.Time) time.Duration {
	if !u.IsLocked(now) {
		return 0
	}
	return u.LockedUntil.Sub(now)
}

// NormalizeEmail is the single definition of what "the same address" means.
//
// Registration, login and every lookup run it, so an address typed as
// "Kaka@Example.com" finds the row stored as "kaka@example.com". The database
// enforces the same invariant with a CHECK constraint; this is where it is
// established.
//
// Inner whitespace is preserved rather than stripped: "ka ka@example.com" is a
// typo, and silently repairing it would create a second account for what the
// caller believes is one address. Validation rejects it instead.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// emailPattern is deliberately stricter than RFC 5322. It requires at least one
// dot in the domain, rejects empty adjacent labels, and rejects domains whose
// labels start or end with a hyphen. The goal is not "any string mail clients
// accept" — it is "an address that could be delivered to by a real MTA", which
// rules out the shapes that make header injection and typo-typos useful.
var emailPattern = regexp.MustCompile(`^[a-z0-9!#$%&'*+/=?^_` + "`" + `{|}~.-]{1,64}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidateEmail checks an already-normalized address. Passing a raw address is a
// bug: it would reject "Kaka@Example.com" and read as a format problem rather
// than a missing normalization step.
func ValidateEmail(normalized string) error {
	if normalized == "" {
		return fieldErr("email", CodeRequired)
	}
	if len(normalized) > MaxEmailLength {
		return fieldErr("email", CodeTooLong)
	}
	if !emailPattern.MatchString(normalized) {
		return fieldErr("email", CodeInvalidFormat)
	}
	return nil
}

// ValidatePassword enforces the length rules and nothing else. See
// MinPasswordLength for why there is no composition rule.
func ValidatePassword(password string) error {
	switch {
	case password == "":
		return fieldErr("password", CodeRequired)
	case len(password) < MinPasswordLength:
		return fieldErr("password", CodeTooShort)
	case len(password) > MaxPasswordLength:
		return fieldErr("password", CodeTooLong)
	}
	return nil
}

// ValidateDisplayName checks an already-trimmed name. Passing an untrimmed one
// is a bug: "  Kaka  " and "Kaka" are the same name, and a caller that let the
// first through would store a value the owner did not type.
//
// EMPTY IS LEGAL, and that is the rule rather than an oversight: an empty name
// is how a caller clears the one they have, and the column it writes is NULL —
// the same "no name" every user who never set one has. There is deliberately no
// minimum length and no format rule. A display name is not an identifier, so
// there is nothing to validate it against: it can be a handle, a nickname, a
// full name, or an emoji, and the only property that matters is that it fits.
func ValidateDisplayName(name string) error {
	if len(name) > MaxDisplayNameLength {
		return fieldErr("display_name", CodeTooLong)
	}
	return nil
}

// Preferences is the jsonb document in users.preferences (00027).
//
// EXACTLY ONE FIELD, because the reference has exactly one: the theme. The
// document is a container for the profile's settings, and the closed set of keys
// is a code fact — the same reasoning migrations/00011 gives for an api key's
// scopes and 00012 for an audit log's action: adding a key is one Go change and
// one UPDATE, not one migration, and a migration per key would be a schema that
// drifts from the code that reads it. The day a second key lands, this struct
// gains a field and nothing else moves.
//
// Theme is a pointer with no `false`, for the reason DisplayName is one: the
// document is a map, and "the key is absent" and "the key is present and null"
// are the same state — the system theme, which is the reference's
// `theme.blank?`. The JSON tag is omitempty so a cleared theme marshals to the
// empty document rather than to {"theme":null}, and the two stop being two
// spellings of one answer.
type Preferences struct {
	Theme *string `json:"theme,omitempty"`
}

// ValidateTheme checks a theme against the closed set the reference defines:
// "light" and "dark", and nothing else. The reference's system theme is a BLANK
// one (User::Theme#system_theme? is theme.blank?), and the JSON API's blank is
// not a value but an ABSENCE — the key omitted from the preferences document —
// which PATCH /v1/me expresses by omitting the field. So the empty string is
// refused here like any other non-theme: it is not one of the two themes, and
// the state it might have meant already has a representation.
//
// EVERYTHING ELSE IS REFUSED, and the refusal is invalid_format rather than a
// code of its own: the existing codes are the contract (they land verbatim in
// the errors[] array of the 422), and "a value outside the closed set" is a
// format problem in exactly the sense a malformed address is. "blue", "DARK"
// and "system" are not themes. A number never reaches this function at all —
// the JSON decoder refuses it first, as a 400 rather than a 422: the request
// was not understood, rather than understood and unacceptable.
func ValidateTheme(theme string) error {
	switch theme {
	case "light", "dark":
		return nil
	default:
		return fieldErr("theme", CodeInvalidFormat)
	}
}
