// Package auth is the identity use cases: register, log in, log out, and resolve
// a token to the user it belongs to.
//
// It sits between the HTTP layer and the three aggregates that own the data
// (users, sessions, outbox) because the interesting part of authentication is
// not any one of them — it is the ordering, and the transactions. Checking the
// lock before the password, counting a failure even though the login is refused,
// and writing a session and its clearing of the failure counter together are all
// properties of the use case, not of a handler and not of a table.
//
// Nothing here knows about HTTP. The handlers translate the errors below into the
// cafaye error envelope (core: docs/openapi-conventions.md).
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/mfa"
	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/sessions"
	"github.com/cafaye/identity/internal/tenancy"
	"github.com/cafaye/identity/internal/useraudit"
	"github.com/cafaye/identity/internal/users"
)

// Errors the HTTP layer maps onto status codes.
//
// The two credential errors are the important ones. They are distinct values so
// that the code says what happened, but ErrInvalidCredentials is deliberately the
// *same* value for "no such account" and "wrong password", and its message is
// deliberately identical in both cases. Anything that distinguishes them — a
// different status, a different detail string, a different response time — is an
// account-enumeration oracle.
var (
	// ErrInvalidCredentials is a refused login. The caller cannot tell why.
	ErrInvalidCredentials = errors.New("invalid email or password")

	// ErrUnauthenticated is a request with no usable credential: no token, an
	// unknown one, an expired one, or a revoked one. One value for all four.
	ErrUnauthenticated = errors.New("authentication required")
)

// LockedError is a login refused because the account is locked.
//
// It is an ALIAS, not a type of its own. The type lives in internal/sessions
// because the second factor's lockout is the same shape — same policy, same
// response, one 423 — and the HTTP layer matches the type rather than the source
// so that a caller who exhausts five TOTP guesses and a caller who exhausts five
// passwords are told the same thing. Declaring it here as well would give the
// layer two types to match and a bug the day it matched the wrong one.
type LockedError = sessions.LockedError

// DisabledError is a login refused because somebody turned the account off.
//
// It is the ALIAS's counterpart and the same argument applies, pointing the other
// way: the type lives in internal/users because the state is a column on that row
// and `users` is where its meaning is defined. Declaring a second type here would
// give the HTTP layer two things to match and a bug the day it matched the wrong
// one — and "disabled" and "locked" are exactly the two it must never confuse.
type DisabledError = users.DisabledError

// DefaultSessionTTL is how long a session lasts when nothing overrides it.
const DefaultSessionTTL = 30 * 24 * time.Hour

// UnitOfWork runs a function inside a transaction. db.TxRunner implements it; the
// interface is what lets the lockout matrix be tested without Postgres.
type UnitOfWork interface {
	Do(ctx context.Context, fn func(ctx context.Context, q db.Querier) error) error
}

// UserStore is the part of users.Store that login and registration need.
type UserStore interface {
	Create(ctx context.Context, q db.Querier, p users.CreateParams) (users.User, error)
	ByEmail(ctx context.Context, q db.Querier, email string) (users.User, error)
	ByID(ctx context.Context, q db.Querier, id id.UUID) (users.User, error)
	RecordFailedLogin(ctx context.Context, q db.Querier, userID id.UUID, attempts int, lockedUntil *time.Time) error
	ClearFailures(ctx context.Context, q db.Querier, userID id.UUID) error
	// Disable and Enable are the concept's two directions and they are here because
	// Disable has to do more than write a column — see Service.Disable, which is the
	// only thing in this repository that should call them.
	Disable(ctx context.Context, q db.Querier, userID id.UUID, at time.Time) error
	Enable(ctx context.Context, q db.Querier, userID id.UUID) error
	// UpdateName is here because PATCH /v1/me is a session surface and this is the
	// package that owns the session's user — the handler resolves the caller
	// through Authenticate and then writes the one column the profile screen
	// owns, and a second path to the table would be a second thing to keep in
	// step with the first.
	UpdateName(ctx context.Context, q db.Querier, userID id.UUID, name *string) error
	// UpdateTheme is here for the reason UpdateName is: it is the second column
	// the profile screen owns, and the same boundary applies.
	UpdateTheme(ctx context.Context, q db.Querier, userID id.UUID, theme *string) error
}

// SessionStore is the part of sessions.Store that login, logout and resolution
// need.
type SessionStore interface {
	Create(ctx context.Context, q db.Querier, n sessions.NewSession) (sessions.Session, error)
	ByToken(ctx context.Context, q db.Querier, token string, now time.Time) (sessions.Session, error)
	Revoke(ctx context.Context, q db.Querier, sessionID id.UUID) error
	// RevokeAllForUser ends every session a user holds. It is on this interface
	// because a disable is not a column write: see Service.Disable.
	RevokeAllForUser(ctx context.Context, q db.Querier, userID id.UUID) error
	// ListLiveForUser and RevokeOneForUser are the two halves of "sign out of one
	// of these", and they are BOTH on this interface rather than being reached for
	// through a store the handlers hold separately. The reason is that the user id
	// they are given comes from the presented credential, and a use case is the
	// only place in this service where "who is asking" is a fact rather than a
	// parameter — see Service.ListSessions and Service.RevokeSession.
	//
	// A hypothetical `*sessions.Store` on the HTTP layer would work and be wrong:
	// it would hand every handler a query that takes a user id, and the day one of
	// them read that id from a path parameter instead of from the session the
	// tenant boundary would be a comment. Here it is a parameter of a method on a
	// service that resolved the caller first.
	ListLiveForUser(ctx context.Context, q db.Querier, userID id.UUID, now time.Time) ([]sessions.Session, error)
	RevokeOneForUser(ctx context.Context, q db.Querier, userID, sessionID id.UUID) (bool, error)
}

// SecondFactor is the part of internal/mfa that login needs, and it is REQUIRED.
//
// It is an interface declared here, at the consumer, for the same reason
// UserStore and SessionStore are, and it is the fourth thing Login cannot work
// without. The alternative — a nil check, or a default that answers "no" — is how
// a service ends up issuing single-factor sessions for users whose accounts have
// a second factor, and that failure is silent by construction: every login works,
// every login is one factor short, and nothing in the logs says so. NewService
// refuses a nil one, and Login refuses to mint a session without it.
//
// Three methods, and each one is a decision rather than a lookup:
//
//	Enabled          is this user's account two-factor right now
//	CreateChallenge  record a correct password with no session behind it
//	VerifyChallenge  check a code and claim what it spent
//	Commit           finish the acceptance, inside the session's transaction
type SecondFactor interface {
	Enabled(ctx context.Context, q db.Querier, userID id.UUID) (bool, error)
	CreateChallenge(ctx context.Context, in mfa.CreateChallengeInput) (mfa.NewChallenge, error)
	VerifyChallenge(ctx context.Context, token, code string, now time.Time) (mfa.Claim, error)
	Commit(ctx context.Context, q db.Querier, claim mfa.Claim, now time.Time) error
}

// AccessTokenRevoker ends every OpenID Connect access token a user holds.
//
// IT IS `internal/recovery`'s `AccessTokenRevoker` with the same signature, and it
// is declared here rather than imported from there for the reason recovery's is
// declared at the consumer: the RULE is this package's and the TABLE is
// `internal/oidc`'s, and an import in both directions would be an edge between two
// tables with nothing to say to each other. Two declarations of the same one-method
// interface is a real cost — a type satisfying one satisfies the other, silently —
// and it is paid here rather than paid as an edge.
//
// `*oidc.Store` satisfies it by signature. So does a test's recording double, which
// is how "the sweep is asked for" is separated from "the sweep reaches the rows":
// the latter is proven in disabled_integration_test.go against the real store.
type AccessTokenRevoker interface {
	RevokeAccessTokensForUser(ctx context.Context, q db.Querier, userID id.UUID, at time.Time) error
}

// ErrNoAccessTokenRevoker means this auth service has no access-token sweep wired,
// so `Disable` cannot revoke the OpenID Connect tokens a user holds.
//
// It is an error and not a degraded "revoked the sessions, left the tokens", and the
// direction of the refusal is the whole point — the same argument
// ErrNoSecondFactor makes, with the credential on the other side of it. That
// sentinel exists because a login proceeding without being able to ask about a
// second factor IS the bypass MFA exists to prevent; here the bypass is the one
// users:disable exists to prevent, and "revoked the sessions, left the tokens"
// would answer an operator's disable with success while a fifteen-minute JWT keeps
// authenticating in every third party that holds one. That is a caller told their
// disable succeeded while it did not, which is worse than a 500 because nothing
// looks wrong.
//
// main wires the real sweep whenever it has a database, so reaching this is a
// wiring bug at a call site rather than a supported configuration.
//
// # WHY IT IS A 500 AND NOT RECOVERY'S 503
//
// `recovery.ErrNoMailer` and `recovery.ErrMFAUnavailable` are 503s, and this
// deliberately is not. Both of those describe a DEPLOYMENT CAPABILITY that can be
// absent in a steady state — a deployment with no SMTP, a deployment with no MFA
// provider mounted — so "come back later" is a true contract. This one has no such
// state: `oidc.NewStore(pool)` is constructed from a pool, so any process that has
// a database can wire it, and a nil here means a call site forgot rather than a
// deployment lacks. 503 would tell a client to retry a request whose failure is
// permanent, and the operator surface's documented refusal table has no 503 arm to
// widen for a wiring bug.
var ErrNoAccessTokenRevoker = errors.New("disabling a user: no access token revoker is configured")

// UserAuditRecorder writes the one row saying who turned a person off, and on.
//
// IT IS DECLARED HERE RATHER THAN IMPORTED AS A CONCRETE STORE, for the same reason
// AccessTokenRevoker is: the RULE that a disable is recorded belongs to this package,
// and the TABLE belongs to internal/useraudit. `*useraudit.Store` satisfies it by
// signature, and so does a recording double, which is how "the record was asked for"
// is separated from "the record reached the table" — the latter is proven against the
// real store in disabled_integration_test.go.
//
// IT TAKES A db.Querier RATHER THAN OPENING ITS OWN TRANSACTION, and that signature
// IS the same-transaction guarantee rather than a convenience: a writer that opened
// its own would put the audit row in a second transaction, so a disable could commit
// its revocations and its column write and then fail to leave a record, with nothing
// anywhere reporting that anything went wrong. Both writes would have "succeeded".
type UserAuditRecorder interface {
	Append(ctx context.Context, q db.Querier, e useraudit.Entry) (useraudit.Record, error)
}

// ErrNoUserAuditRecorder means this auth service has no audit writer wired, so a
// disable would revoke a person's credentials and change the column without recording
// who asked.
//
// It is an error and not a degraded "revoked everything, wrote nothing", and the
// direction is the whole point — the same argument ErrNoAccessTokenRevoker makes with
// a different credential on the other side of it. That sentinel exists because a
// disable proceeding without a token sweep leaves a JWT authenticating; this one
// exists because a disable that records nothing cannot be reviewed at all, and the
// first question of any incident review reaching this service is "who turned this
// person off, and when". A caller told their disable succeeded while it left no trace
// is a caller whose complaint ("nobody can tell me why I was locked out") cannot even
// be investigated, and unlike the token sweep there is no second mechanism that would
// catch it: the trail is the whole answer, so its absence is not degraded, it is
// silent.
//
// main wires the real writer whenever it has a database, so reaching this is a wiring
// bug at a call site rather than a supported configuration.
var ErrNoUserAuditRecorder = errors.New("disabling or enabling a user: no audit recorder is configured")

// EventAppender is the part of outbox.Store that registration needs.
type EventAppender interface {
	Append(ctx context.Context, q db.Querier, e outbox.Envelope) error
}

// PersonalAccountProvisioner is the part of the accounts service that
// registration needs: the personal account a new user gets, and the ownership
// that makes it theirs.
//
// It is an interface declared here, at the consumer, for the same reason
// UserStore and SessionStore are. It is also the reason its two methods take a
// db.Querier rather than opening their own transaction: they run inside the
// registration's, and a user who exists with no account is a state nothing
// downstream can repair.
//
// It is a required dependency rather than an optional one. A nil provisioner
// would mean a service that registers users into a void, and the failure would
// show up as a user with an empty account list rather than as a startup error —
// which is the worse of the two by a long way.
type PersonalAccountProvisioner interface {
	// Provision creates the personal account for a user.
	Provision(ctx context.Context, q db.Querier, userID id.UUID, email string) (accounts.Account, error)
	// AddOwner makes that user the account's owner, and announces the account.
	AddOwner(ctx context.Context, q db.Querier, accountID, userID id.UUID) (accounts.Membership, error)
}

// Service is the identity use cases.
type Service struct {
	uow        UnitOfWork
	read       db.QuerierSource
	users      UserStore
	sessions   SessionStore
	events     EventAppender
	tenancy    PersonalAccountProvisioner
	mfa        SecondFactor
	access     AccessTokenRevoker
	auditor    UserAuditRecorder
	hasher     *users.Hasher
	clock      clock.Clock
	sessionTTL time.Duration
	// requireEmailVerification gates sign-in on a proved address, and it is
	// OFF BY DEFAULT. See Config.RequireEmailVerification in internal/config
	// for the whole of it: the default preserves parity with the reference
	// this fleet matches (Jumpstart Pro does not use Devise's
	// :confirmable), and the flag exists so a deployment that wants
	// confirmation-gated sign-in can turn it on.
	requireEmailVerification bool
}

// EmailNotVerifiedError is a login refused because the account's email address
// has not been verified, when REQUIRE_EMAIL_VERIFICATION is on.
//
// IT IS ANCHORED IN startLogin, AFTER THE PASSWORD, and that placement is the
// security property: a caller who is refused has already proved they hold the
// credential and already knew the account existed. A refusal placed before the
// password is a one-request existence oracle for every unverified account on
// the service. See DECISIONS.md D13 for the same ruling on the disabled flag,
// which is the precedent for how carefully these refusals are told apart.
type EmailNotVerifiedError struct{}

func (e *EmailNotVerifiedError) Error() string { return "this account's email address is not verified" }

// ErrNoSecondFactor means this auth service has no second-factor dependency
// wired, so it cannot answer the question "does this user's account have a second
// factor" and therefore cannot know whether a correct password may mint a
// session.
//
// It is an error and not a degraded single-factor mode, and the direction of the
// refusal is the whole point: a login that proceeds without being able to check is
// exactly the bypass MFA exists to prevent. main wires the real dependency
// whenever it has a database, so reaching this is a wiring bug at a call site
// rather than a supported configuration.
var ErrNoSecondFactor = errors.New("logging in: no second-factor service is configured")

// NewService wires the use cases. A non-positive sessionTTL means
// DefaultSessionTTL.
//
// uow is used for the writes that must be atomic with each other — the user, its
// personal account, the ownership and the two events; and the session, the
// challenge it answers and the two failure counters it clears. read is used for
// everything else, so those lookups do not pay for a transaction.
//
// secondFactor, access and auditor are all required. See ErrNoSecondFactor,
// ErrNoAccessTokenRevoker and ErrNoUserAuditRecorder — none of them has a supported
// "absent" configuration, and a nil that reads as "there is nothing to sweep" or
// "there is nothing to record" is the failure none of them can detect from the
// inside.
func NewService(
	uow UnitOfWork,
	read db.QuerierSource,
	userStore UserStore,
	sessionStore SessionStore,
	events EventAppender,
	tenancy PersonalAccountProvisioner,
	secondFactor SecondFactor,
	access AccessTokenRevoker,
	auditor UserAuditRecorder,
	hasher *users.Hasher,
	clk clock.Clock,
	sessionTTL time.Duration,
	// requireEmailVerification gates sign-in on a proved address. It is a
	// parameter rather than a setter because it is a deployment decision made
	// once at boot, and a setter would make it a fact that could be changed
	// after the service is built — which is the one thing a security flag
	// must never be. The default is false (parity); see
	// Config.RequireEmailVerification in internal/config.
	requireEmailVerification bool,
) *Service {
	if sessionTTL <= 0 {
		sessionTTL = DefaultSessionTTL
	}
	return &Service{
		uow:                      uow,
		read:                     read,
		users:                    userStore,
		sessions:                 sessionStore,
		events:                   events,
		tenancy:                  tenancy,
		mfa:                      secondFactor,
		access:                   access,
		auditor:                  auditor,
		hasher:                   hasher,
		clock:                    clk,
		sessionTTL:               sessionTTL,
		requireEmailVerification: requireEmailVerification,
	}
}

// RegisterInput is a registration request.
type RegisterInput struct {
	Email    string
	Password string
}

// RegisteredUser is what a successful registration returns: the public projection
// of the user and nothing else.
//
// It is its own type rather than users.User so that the digest cannot reach a
// response body by accident. Adding a field to users.User does not add it here.
type RegisteredUser struct {
	ID    id.UUID
	Email string
}

// Register creates a user, their personal account, and announces both.
//
// The five writes — user, account, owner membership, `identity.user.created` and
// `identity.account.created` — are one transaction. That is the whole reason the
// outbox exists and the whole reason the provisioner takes a Querier: a user
// without its event would never be announced, an event without its user would
// announce a registration that did not happen, and a user without an account is
// somebody who has signed up and can do nothing at all.
//
// Does not create a session. Sign in separately.
func (s *Service) Register(ctx context.Context, in RegisterInput) (RegisteredUser, error) {
	email := users.NormalizeEmail(in.Email)
	if err := validateRegistration(email, in.Password); err != nil {
		return RegisteredUser{}, err
	}

	// Hashed before the transaction opens. Validation has already passed, so this
	// cannot fail for a request-shaped reason, and doing it outside keeps a ~100ms
	// memory-hard operation from holding a database connection and a transaction
	// open.
	digest, err := s.hasher.Hash(in.Password)
	if err != nil {
		return RegisteredUser{}, fmt.Errorf("hashing the password: %w", err)
	}

	now := s.clock.Now()

	var created users.User
	err = s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		u, err := s.users.Create(ctx, q, users.CreateParams{Email: email, PasswordDigest: digest})
		if err != nil {
			return err
		}

		// The tenancy comes before the events, because an event about an account
		// that does not exist is exactly the drift the outbox is supposed to
		// prevent. The user id is needed for both the slug and the ownership, so
		// this is the first point at which it can happen at all.
		if err := s.provisionTenancy(ctx, q, u); err != nil {
			return err
		}

		// The event is about this user, so it is built after the insert: the
		// subject is an id that now exists.
		event, err := outbox.NewUserCreated(now, u.ID, u.Email)
		if err != nil {
			return err
		}
		if err := s.events.Append(ctx, q, event); err != nil {
			return err
		}

		created = u
		return nil
	})
	if err != nil {
		return RegisteredUser{}, err
	}

	return RegisteredUser{ID: created.ID, Email: created.Email}, nil
}

// provisionTenancy creates the personal account and makes the user its owner,
// inside the registration's transaction.
//
// The two steps are separate rather than one call because the packet's ordering
// is the point: the account's slug is derived from the user id, and the ownership
// is what makes the account administrable. A service that created the membership
// first would have no account to attach it to.
//
// # THE ONE REQUEST WITH NO ACCOUNT THAT STILL WRITES ACCOUNT-SCOPED ROWS
//
// BETWEEN Provision AND AddOwner IS WHERE begin_account HAPPENS, and it is here
// rather than in the transaction runner because a registration has no account to
// resolve at all: the caller is anonymous, there is no session, and the account
// does not exist until Provision returns it. So the identity cannot come from the
// request — it comes from the row that was just created.
//
// WITHOUT IT the owner membership INSERT meets
// `with check (account_id = (select cafaye.current_account_id()))` with a NULL
// identity, NULL is not true, and Postgres refuses the write with SQLSTATE 42501.
// That is the substrate working: it is refusing an account-scoped write that
// claims no account. The symptom it produced was `POST /v1/users` answering 500,
// which is how this branch shipped red.
//
// The alternative — leaving it NULL and letting the INSERT fail — is not a
// choice, it is the bug. The alternative of writing the membership BEFORE the
// account exists would have no account_id to write, which is the ordering
// constraint the paragraph above already explains.
func (s *Service) provisionTenancy(ctx context.Context, q db.Querier, u users.User) error {
	if s.tenancy == nil {
		// NewService requires a provisioner, so this is a wiring bug rather than a
		// supported configuration. It is said out loud rather than defaulted,
		// because the alternative — registering a user into an account-less void —
		// is a failure that would not surface until somebody complained that the
		// product was empty.
		return errors.New("registering: no personal account provisioner is configured")
	}

	account, err := s.tenancy.Provision(ctx, q, u.ID, u.Email)
	if err != nil {
		return fmt.Errorf("creating the personal account: %w", err)
	}

	// Before AddOwner and on the SAME transaction, because begin_account is
	// transaction-local and the membership write is the account-scoped statement
	// that needs it. On a different transaction it would have expired.
	if err := tenancy.BeginAccount(ctx, q, account.ID); err != nil {
		return fmt.Errorf("beginning as the new personal account: %w", err)
	}

	if _, err := s.tenancy.AddOwner(ctx, q, account.ID, u.ID); err != nil {
		return fmt.Errorf("granting ownership of the personal account: %w", err)
	}
	return nil
}

// LoginInput is a login request.
type LoginInput struct {
	Email    string
	Password string
	// UserAgent and IP are recorded against the session for the incident trail.
	// Neither is trusted for any decision.
	UserAgent string
	IP        *netip.Addr
}

// LoginResult is what a successful login returns.
//
// It is one type with three shapes rather than three types, and the shape is
// decided by MFARequired and by nothing else:
//
//	MFARequired false  Token is a session token, Challenge is nil
//	MFARequired true   Token is EMPTY, Challenge is not nil
//
// THE EMPTY TOKEN IS THE POINT, and it is the shape of the mistake this whole
// package exists to prevent. A caller that ignores MFARequired and reads Token
// gets the empty string, which authenticates nothing, rather than a working
// credential. There is no field of this struct from which a session can be
// obtained without the second factor having been presented, and
// TestAResultThatRequiresASecondFactorCarriesNoSessionToken is the assertion.
type LoginResult struct {
	User RegisteredUser
	// Token and ExpiresAt are the SESSION's, and both are zero unless
	// MFARequired is false.
	Token     string
	ExpiresAt time.Time

	// MFARequired says the password was correct and this account has a second
	// factor. No session exists yet, and ExpiresAt is the CHALLENGE's expiry
	// rather than a session's, which is why it is repeated here rather than left
	// confusing: a client that reads ExpiresAt without reading MFARequired is
	// holding a challenge's deadline, and the only honest thing it can do with it
	// is nothing until it has the second factor.
	MFARequired bool
	// Challenge is the login that is halfway through. nil whenever a session was
	// minted.
	Challenge *Challenge
}

// Challenge is a login waiting on its second factor.
type Challenge struct {
	// Token is presented once, at the end of the challenge, and is stored only as
	// a digest. The same reasoning as an OIDC client secret: a secret this service
	// can produce again is a secret this service is storing.
	Token     string
	ExpiresAt time.Time
}

// Login authenticates an email and password.
//
// The order of the checks is the security property, so it is spelled out:
//
//  1. Validate the shape of the request. A malformed address never reaches argon2id.
//  2. Look the account up. A miss costs a dummy hash and returns
//     ErrInvalidCredentials — the same error, from the same path, in the same time
//     as a wrong password.
//  3. If the account is locked, return LockedError *before* verifying anything.
//     There is no reason to spend a memory-hard hash on an account nobody may log
//     into, and it means a locked account cannot be probed.
//  4. Verify the password.
//  5. On a mismatch, count the failure, persist it, and return
//     ErrInvalidCredentials.
//  6. On a match: refuse a DISABLED account. DisabledError, and it comes HERE —
//     after the password and before anything is minted. See below.
//  7. On a match and not disabled: ask whether this account has a CONFIRMED
//     second factor. If it does, mint a CHALLENGE and return MFARequired — no
//     session, no token, nothing that authenticates anything.
//  8. Otherwise mint the session and clear the password's failure run in one
//     transaction.
//
// # STEP 6 IS AFTER THE PASSWORD, AND THAT IS THE ENUMERATION REASONING
//
// A disabled answer NAMES the state rather than pretending the password was wrong,
// and the only thing that makes that free is that this check sits after step 4. A
// caller who is told "this account is disabled" has already proved they hold the
// right password, so they already know the account exists and the answer reveals
// nothing. Move it above the password and it becomes a one-request existence
// oracle for every disabled account on the service — strictly worse than the
// lockout's 423, which costs a stranger six requests and is measured in
// DECISIONS.md D9.
//
// The same reasoning says the social callback gets it too, and gets it for a
// better reason still: there the caller has proved control of a provider account
// whose address this service believes. See startLogin, which is where that check
// actually lives, because Login cannot be the only door that has it.
//
// # AND IT IS NOT 423, EVER
//
// The lock is above it and stays there. A 423 in this service means "retry at",
// with a Retry-After, and a client that knows the code renders it as a wait. A
// disabled account is not coming back at any time, so answering 423 would be a
// promise nothing keeps — and it would be precisely the conflation
// migrations/00021 exists to prevent. The other order (disabled above locked) is
// worse than wrong: a user whose account is merely locked would be told to contact
// an administrator and would have no reason to try again in fifteen minutes.
//
// STEP 7 IS THE LINE THE PREVIOUS PACKET WAS ABOUT, and it sits where it does on purpose:
// after the password has been verified and before the session is created. A
// challenge is not a session, and a session created here for an account with a
// second factor is a login with one factor where there should be two — which is
// not a weaker version of MFA, it is the absence of it.
//
// Note what step 6 does NOT do: it does not clear the password's failure run. The
// password was right, but the login is not finished, and the run is cleared in
// CompleteSecondFactor, in the transaction that mints the session. Clearing it
// here would let five wrong passwords cost an attacker nothing while they work on
// the second factor.
func (s *Service) Login(ctx context.Context, in LoginInput) (LoginResult, error) {
	email := users.NormalizeEmail(in.Email)
	if err := validateLogin(email, in.Password); err != nil {
		return LoginResult{}, err
	}

	now := s.clock.Now()

	user, err := s.users.ByEmail(ctx, s.read.Queryer(), email)
	if err != nil {
		if !errors.Is(err, users.ErrNotFound) {
			return LoginResult{}, fmt.Errorf("looking up a user: %w", err)
		}
		// No such account. Do the same memory-hard work a real account would cost
		// and return the same error, so neither the response nor its timing says
		// whether this address is registered. Nothing is written: there is no row
		// to count against, and creating one would let anyone lock any address out
		// simply by guessing at it.
		s.hasher.VerifyDummy(in.Password)
		return LoginResult{}, ErrInvalidCredentials
	}

	lock := sessions.Lockout{FailedAttempts: user.FailedLoginAttempts, LockedUntil: user.LockedUntil}
	if lock.Locked(now) {
		return LoginResult{}, &LockedError{RetryAfter: lock.RetryAfter(now)}
	}

	if !s.hasher.Verify(user.PasswordDigest, in.Password) {
		// The failure is counted even though the login is refused, and the count
		// is persisted. A lockout that is not written down is not a lockout.
		next := lock.Failed(now)
		if err := s.recordFailure(ctx, user.ID, next); err != nil {
			// Surfaced, not reported as invalid credentials: a store failure that
			// looks like a wrong password stops the counter climbing, and the
			// brute-force protection silently stops existing.
			return LoginResult{}, fmt.Errorf("recording a failed login: %w", err)
		}
		return LoginResult{}, ErrInvalidCredentials
	}

	// Step 6. The password was right, so this is a refusal about the ACCOUNT and
	// not about the credential — which is why it is its own error and why saying
	// so is safe here rather than only in the comment above.
	if user.IsDisabled() {
		return LoginResult{}, &DisabledError{}
	}

	return s.startLogin(ctx, user, in, now)
}

// startLogin is the tail of Login: the second-factor decision, and then whichever
// of a challenge or a session the account's own state calls for.
//
// It is a function rather than the last six lines of Login because a social callback
// has to ask the SAME question at the same point — internal/auth/social.go calls it
// after it has resolved which local user a provider identity belongs to — and a
// caller that had to reimplement it would be reimplementing "does this account have
// a second factor", which is the one line that must never be optional. Naming it
// also means there is exactly one place in this package where a session is minted
// without a password having been verified, and it is this one.
//
// # THE DISABLED CHECK IS HERE AND NOT IN Login, and that placement IS THE POINT
//
// Login refuses a disabled account too, one line earlier, and it would be redundant
// if this were the only caller. It is not the only caller: `internal/auth/social.go`
// resolves a provider identity to a local user and comes straight here, with no
// password anywhere in the request.
//
// So a check written in Login would leave the social door open, and the way that
// defect stays invisible is that a social sign-in for a disabled account WORKS —
// it mints a session, tests are green, and nothing in the logs says the account
// was turned off. Putting the gate here means there is one line that both doors
// pass through, which is what makes the second door's coverage a fact about the
// code rather than about whether somebody remembered.
//
// The social path's answer is safe on the same terms as the password one and for a
// stronger reason: the caller proved control of a provider account whose address
// this service already believes (internal/oauth refuses an unverified one), so
// they already knew the local account existed.
func (s *Service) startLogin(ctx context.Context, user users.User, in LoginInput, now time.Time) (LoginResult, error) {
	if user.IsDisabled() {
		return LoginResult{}, &DisabledError{}
	}

	// THE VERIFICATION GATE, anchored here and not in Login for the same reason
	// the disabled check is: a social callback arrives here with no password, and
	// a check in Login would leave that door open. The caller has already proved
	// they hold the credential (or control of a provider account whose address
	// this service already believes), so the refusal is about the ACCOUNT and
	// not about the credential — which is why it is its own error and why saying
	// so is safe here rather than only in the comment above.
	//
	// It is OFF BY DEFAULT, and the default is parity: the reference this fleet
	// matches does not gate sign-in on verification. See
	// Config.RequireEmailVerification in internal/config.
	if s.requireEmailVerification && !user.IsVerified() {
		return LoginResult{}, &EmailNotVerifiedError{}
	}

	required, err := s.requiresSecondFactor(ctx, user.ID)
	if err != nil {
		return LoginResult{}, err
	}
	if required {
		return s.startChallenge(ctx, user, in, now)
	}

	return s.startSession(ctx, user, in, now)
}

// requiresSecondFactor asks internal/mfa whether this account has a live second
// factor, and refuses to guess.
func (s *Service) requiresSecondFactor(ctx context.Context, userID id.UUID) (bool, error) {
	if s.mfa == nil {
		return false, ErrNoSecondFactor
	}
	required, err := s.mfa.Enabled(ctx, s.read.Queryer(), userID)
	if err != nil {
		return false, fmt.Errorf("checking whether this account has a second factor: %w", err)
	}
	return required, nil
}

// startChallenge records a correct password with no session behind it.
//
// It is a separate function from startSession rather than a branch inside one,
// because the two write different things and a merge would make "which of these
// ran" a question about a boolean.
func (s *Service) startChallenge(ctx context.Context, user users.User, in LoginInput, now time.Time) (LoginResult, error) {
	challenge, err := s.mfa.CreateChallenge(ctx, mfa.CreateChallengeInput{
		UserID:    user.ID,
		UserAgent: in.UserAgent,
		IP:        in.IP,
	})
	if err != nil {
		return LoginResult{}, fmt.Errorf("creating a second-factor challenge: %w", err)
	}

	// No session. No token. Nothing that authenticates anything.
	//
	// ExpiresAt IS SET, to the CHALLENGE's expiry. It is the same field a session
	// uses, so leaving it zero would be a second, subtler version of the same bug —
	// a client reading `expires_at` would see the epoch and have to special-case it.
	// Repeating the challenge's deadline here means a client that reads only
	// ExpiresAt is holding a value it can use, and the value it can use is the
	// honest one: when this login has to be finished.
	return LoginResult{
		User:        RegisteredUser{ID: user.ID, Email: user.Email},
		ExpiresAt:   challenge.ExpiresAt,
		MFARequired: true,
		Challenge:   &Challenge{Token: challenge.Token, ExpiresAt: challenge.ExpiresAt},
	}, nil
}

// CompleteSecondFactorInput is a challenge token and the code that answers it.
type CompleteSecondFactorInput struct {
	// ChallengeToken is the token from the Login that returned MFARequired.
	ChallengeToken string
	// Code is a TOTP code or a recovery code. One field for both, because the
	// consequence of being wrong is identical and two fields would invite a client
	// to put a recovery code in the TOTP field and be told it was malformed rather
	// than not accepted.
	Code string
}

// CompleteSecondFactor answers a challenge and, only then, mints the session.
//
// THE ORDER IS THE WHOLE THING:
//
//  1. VerifyFactor (through mfa) matches the code and CLAIMS what it spent,
//     counting a failure and writing the counter itself if it does not match.
//  2. One transaction: consume the challenge, create the session, clear BOTH
//     failure counters.
//
// There is no branch, and there is no path through this method that returns a
// session without step 1 having succeeded. That is what makes the service's
// second factor a second factor.
//
// The two counters clear together and in this transaction for the reason the
// password's clears with the session in startSession: a counter that clears
// without the login it was counting towards completing hands an attacker a free
// reset every time they get it wrong. The second factor's counter lives on a
// different row from the password's, and both are cleared here — a successful
// two-factor login restarts both runs and neither one survives on its own.
//
// # AND THE DISABLED CHECK IS HERE TOO, BECAUSE THIS DOOR DOES NOT GO THROUGH
// startLogin
//
// A challenge was minted by startLogin, ten minutes ago, while the account was
// still enabled. Ten minutes is a long time for an administrator to act inside,
// and this method is reached by a TOKEN rather than by a user row — so the gate
// that covered the first half of the login does not cover the second. A user
// disabled midway through their own two-factor login is a real window, and closing
// it is the reason a disable is worth more than a flag on the row.
//
// It is INSIDE the transaction, which is what makes the refusal cost nothing: the
// session insert above and this read are the same transaction, so a refusal rolls
// the session back rather than minting one and then declining to hand it over.
func (s *Service) CompleteSecondFactor(ctx context.Context, in CompleteSecondFactorInput) (LoginResult, error) {
	if s.mfa == nil {
		return LoginResult{}, ErrNoSecondFactor
	}
	if in.ChallengeToken == "" {
		return LoginResult{}, ErrUnauthenticated
	}

	now := s.clock.Now()

	// Outside the transaction, and deliberately: this writes the second factor's
	// failure counter when the code is wrong, and a counter rolled back along with
	// the refusal it provoked is not a counter.
	claim, err := s.mfa.VerifyChallenge(ctx, in.ChallengeToken, in.Code, now)
	if err != nil {
		return LoginResult{}, err
	}

	token, digest, err := sessions.NewToken()
	if err != nil {
		return LoginResult{}, fmt.Errorf("minting a session token: %w", err)
	}
	expiresAt := now.Add(s.sessionTTL)

	err = s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		// BEFORE the session, and the reason is the same as Login's: a refusal
		// that minted a session first would have to be rolled back to be honest,
		// and the two orders differ in exactly one respect — this one cannot leave
		// a row behind even if a later statement in this transaction misbehaves.
		user, err := s.users.ByID(ctx, q, claim.UserID())
		if err != nil {
			return err
		}
		if user.IsDisabled() {
			return &DisabledError{}
		}

		// The session is created first, for the reason startSession gives: if it
		// fails the transaction rolls back and the challenge is still live, so the
		// user can press "try again" rather than being told their login has
		// expired. The order of the other two is not load-bearing — they are both
		// accounting and the transaction covers all three.
		if _, err := s.sessions.Create(ctx, q, sessions.NewSession{
			UserID:      claim.UserID(),
			TokenDigest: digest,
			ExpiresAt:   expiresAt,
		}); err != nil {
			return err
		}
		// Consumes the challenge and clears the second factor's failure run.
		if err := s.mfa.Commit(ctx, q, claim, now); err != nil {
			return err
		}
		return s.users.ClearFailures(ctx, q, claim.UserID())
	})
	if err != nil {
		return LoginResult{}, err
	}

	user, err := s.users.ByID(ctx, s.read.Queryer(), claim.UserID())
	if err != nil {
		return LoginResult{}, fmt.Errorf("loading the user behind a second-factor login: %w", err)
	}

	return LoginResult{
		User:      RegisteredUser{ID: user.ID, Email: user.Email},
		Token:     token,
		ExpiresAt: expiresAt,
	}, nil
}

// startSession mints the session and clears the failure run together.
func (s *Service) startSession(ctx context.Context, user users.User, in LoginInput, now time.Time) (LoginResult, error) {
	token, digest, err := sessions.NewToken()
	if err != nil {
		return LoginResult{}, fmt.Errorf("minting a session token: %w", err)
	}
	expiresAt := now.Add(s.sessionTTL)

	err = s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		// The session is created first. If it fails, the transaction rolls back
		// and the counter is untouched — which is the safe direction, because a
		// reset with no session would hand an attacker five free attempts per
		// attempt.
		if _, err := s.sessions.Create(ctx, q, sessions.NewSession{
			UserID:      user.ID,
			TokenDigest: digest,
			ExpiresAt:   expiresAt,
			UserAgent:   in.UserAgent,
			IP:          in.IP,
		}); err != nil {
			return err
		}
		return s.users.ClearFailures(ctx, q, user.ID)
	})
	if err != nil {
		return LoginResult{}, err
	}

	return LoginResult{
		User:      RegisteredUser{ID: user.ID, Email: user.Email},
		Token:     token,
		ExpiresAt: expiresAt,
	}, nil
}

// recordFailure persists the new lockout state for an account.
func (s *Service) recordFailure(ctx context.Context, userID id.UUID, next sessions.Lockout) error {
	return s.users.RecordFailedLogin(ctx, s.read.Queryer(), userID, next.FailedAttempts, next.LockedUntil)
}

// Disable turns an account off and ends every session it holds, in ONE
// transaction.
//
// # WHY THIS LIVES HERE AND NOT IN internal/admin, SAID OUT LOUD
//
// `internal/admin` is the house's operator surface and this is the operation an
// operator will eventually want there, but that surface is ACCOUNT-scoped: its
// audit rows carry an account_id, its privilege boundary is one sentence about
// account admins and invitations, and a user is not an account — the same person
// belongs to several. Putting this behind that boundary would widen a boundary
// DECISIONS.md D2–D5 spent five entries drawing, in a packet whose subject is
// something else entirely.
//
// So the enforcement ships here, in the package that owns "which sessions may
// exist", and the ROUTE does not ship at all. What is deliberately NOT here: an
// HTTP surface, a scope, an audit record, a permission. `Enable` exists because
// re-enabling has to be testable for the concept to be honest, not because an
// operator can reach it yet. **This is a foundation, not a feature**, and the
// operator surface is the next packet — see HANDOFF-identity-disabled-01.md.
//
// # WHY THE REVOCATION IS IN THE SAME TRANSACTION, AND WHY THAT IS NOT OPTIONAL
//
// Two statements, two tables, one transaction. The alternative — a column write
// and a later sweep — is a window in which a disabled account holds live sessions,
// and its length is not a number anybody chose: it is however long the sweep is
// late. A request already in flight dies at its NEXT store read, because the
// sessions table is the thing it reads and the row is gone.
//
// The direction of the ordering matters for the same reason it does in
// startSession: the session DELETE first, then the column. If the column write
// fails, the transaction rolls back and nothing is lost; if it were the other way
// round and the DELETE failed, an account marked disabled would still be holding
// sessions with no record of why.
//
// This is the same rule MFA and a password reset already follow with their own
// RevokeAllForUser calls, and the reasoning is theirs: a credential minted before
// a change is not a credential after it.
//
// # AND THE THIRD STATEMENT IS AN OIDC ACCESS TOKEN, BECAUSE A ROW IS NOT A
// RECALL FOR A JWT
//
// disabled-01 shipped this as two statements and named the gap in its own commit
// message: the session DELETE and the column, with "no sweep of
// `oidc_access_tokens`" written down as something the packet did not do. That gap
// is why there are three statements here, and the middle one is not optional in the
// way a reader might assume.
//
// Every other credential this service issues can be recalled by deleting a row,
// because resolving it means reading that row. An OpenID Connect access token
// cannot: it is a JWT, verified by whoever holds it against the published JWKS from
// the moment it is minted until `exp`, and this service is not the verifier. So the
// row behind the token is not the credential — it is the only place this service
// can record that the credential is meant to be dead, and a third party checking
// the token locally has no way to ask. Without the sweep a disable leaves a
// credential valid for up to fifteen more minutes in the hands of every relying
// party that took it, and no amount of column-writing brings that window down.
//
// This is the SAME call `internal/recovery` makes in the SAME transaction shape for
// a password reset (`recovery.Service.revokeEveryCredential`), and it is one rule
// with two tables under it rather than two rules that happen to agree: "a
// credential minted before this moment is not a credential after it" does not get
// to have a session-shaped half and a token-shaped half.
//
// # THE ORDER, AND IT IS THE SAME ORDER `startSession` USES FOR THE SAME REASON
//
// Revocations first, state change last, record very last: sessions, then access
// tokens, then the column, then the audit row. Every failure mode of that order rolls
// back, and the one that matters most is the reverse — a column write before the
// sweeps would leave an account that reads as turned off to an operator inspecting the
// table while its tokens are still live, which is the half-applied state nothing else
// in this service models.
//
// The record goes last rather than first for a related reason: a trail that says a
// disable happened while the revocations were still being attempted is a trail
// asserting something untrue, and it is the one ordering here where the surviving
// evidence would be the misleading one. Last also means it cannot fail after the work
// is done and leave it done — there is nothing after it.
//
// # AND THE FOURTH STATEMENT IS THE AUDIT ROW, WHICH IS THE POINT OF disabled-04
//
// The three above revoke and stamp. None of them says WHO. Until this packet a
// disable was unattributable: the first question of any incident review reaching this
// service — "who turned this person off, and when" — had no answer in the database
// at all.
//
// It is written to `user_audit_log` (migrations/00022) and NOT to
// `account_audit_log`, and that is not a preference. The account-scoped table is
// `account_id NOT NULL` because its actions are account actions, and a disable names
// no account: `users:disable` is its own scope with no account in its path precisely
// because its subject is a person rather than one of their memberships (DECISIONS.md
// D14). A user belongs to as many accounts as they like, so hanging the record on
// "the caller's own account" would grant one tenant that authority once per
// membership, and would put a tenancy fiction into the one table whose whole value is
// that it is true.
//
// So it is a second table, scoped to a user, carrying the twin's discipline: an
// append-only trigger rather than a Go convention, two unconstrained actor ids so the
// record outlives both, and a closed set validated here rather than by the schema.
//
// # AND `Authenticate` STILL DOES NOT READ disabled_at, ON PURPOSE
//
// disabled-01 left that check out with the argument that revocation is the stronger
// guarantee because it deletes the rows. That argument now HOLDS for OpenID Connect
// as well as for sessions, which is the only reason it was ever safe to make: as of
// this commit, revocation covers every credential this service has issued, so a
// revoked-but-present row is no longer a way in. Adding a `disabled_at` check here
// would be a second mechanism for one fact, and the row is already the answer —
// except for a token whose revocation failed, and that transaction rolled back
// nothing at all rather than writing the column.
func (s *Service) Disable(ctx context.Context, in DisableInput) error {
	// BEFORE the transaction, not inside it. A wiring bug should not open a
	// transaction and abort it, and — the reason this ordering is load-bearing
	// rather than tidiness — a nil check that ran after the session DELETE would
	// have ended every session the user holds and then reported failure, which is
	// a signed-out user who is not disabled and cannot sign back in.
	if s.access == nil {
		return ErrNoAccessTokenRevoker
	}
	// The same ordering, for the same reason, about a different dependency. A nil
	// auditor checked after the sweeps would have revoked every credential the user
	// holds and then reported failure — which is the more damaging of the two,
	// because the person is signed out everywhere and cannot sign back in, and the
	// operator is told the disable did not happen so they do not know to look for
	// it.
	if s.auditor == nil {
		return ErrNoUserAuditRecorder
	}

	return s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		// First, as above.
		if err := s.sessions.RevokeAllForUser(ctx, q, in.UserID); err != nil {
			return fmt.Errorf("ending a disabled user's sessions: %w", err)
		}
		// Second: the credential that deleting a row cannot recall.
		if err := s.access.RevokeAccessTokensForUser(ctx, q, in.UserID, in.At); err != nil {
			return fmt.Errorf("ending a disabled user's access tokens: %w", err)
		}
		// Third, and only if both of the above held.
		if err := s.users.Disable(ctx, q, in.UserID, in.At); err != nil {
			return fmt.Errorf("marking the user disabled: %w", err)
		}
		// Last: the record of it, in the SAME transaction as the three writes above.
		//
		// This is the fourth statement rather than a fourth transaction, and that is
		// the whole of the property. A disable that revokes without recording is the
		// gap this closes; a disable that RECORDS without revoking is the same gap
		// wearing a different hat — an audit trail claiming an event that did not
		// happen is worse than no trail, because an investigator who finds the row
		// stops looking. So the record is written by the transaction that does the
		// work: there is no interleaving in which the revocations are visible and the
		// record is not, and none in which the record is visible and the revocations
		// are not.
		//
		// The action is named HERE rather than passed in, so there is no caller that
		// can write a disable's record under another action's name.
		if _, err := s.auditor.Append(ctx, q, useraudit.Entry{
			UserID: in.UserID,
			Action: useraudit.ActionUserDisabled,
			Actor: useraudit.Actor{
				UserID:  in.ActorUserID,
				KeyID:   in.ActorKeyID,
				TraceID: in.TraceID,
			},
			OccurredAt: in.At,
		}); err != nil {
			return fmt.Errorf("recording the disable: %w", err)
		}
		return nil
	})
}

// DisableInput is a request to turn a person off.
//
// It is a struct rather than a fourth and fifth positional argument because the actor
// is not optional information: `Disable(ctx, userID, at)` had nowhere to put the two
// ids and the trace id, and a method that cannot be told who is asking cannot record
// who asked. Adding them positionally would have put a user id where the compiler
// cannot tell it from the subject, and the two are exactly the kind of uuid that gets
// them the wrong way round.
type DisableInput struct {
	// UserID is the SUBJECT: the person being turned off.
	UserID id.UUID
	// ActorUserID and ActorKeyID are the caller — the operator's own user and the
	// api key row. Both required, on useraudit.Actor's argument: this surface is
	// machine-credential-only (D14), so every recorded event names a token.
	ActorUserID id.UUID
	ActorKeyID  id.UUID
	// TraceID joins the audit row to the request's log line.
	TraceID string
	// At is the service's clock, used for the revocation stamps, the column and the
	// audit row alike — one instant for the whole event, so the three cannot disagree
	// about when it happened.
	At time.Time
}

// Enable lifts a disable.
//
// IT RESTORES NOTHING BUT THE COLUMN, and that is worth stating because "enable"
// reads like the inverse of everything Disable did. The sessions it ended are gone
// and do not come back: the owner signs in again like anybody else. A re-enable
// that resurrected the sessions would hand back credentials minted before the
// account was turned off, which is the thing the revocation exists to prevent.
//
// # AND IT RECORDS, IN A TRANSACTION, DESPITE HAVING BEEN ONE STATEMENT
//
// Until disabled-04 this was one statement and needed no transaction because there
// was no second write to make atomic with it. There is now: the audit row. So it
// opens one, and the reason it must is the mirror of Disable's — a re-enable that
// lifts the column without recording it leaves the trail saying the person is still
// disabled, which is the one conclusion an investigator must never draw from a trail
// that is silent about the event that would have corrected it.
//
// A re-enable is a decision by an operator with authority over a person who has no
// authority over themselves, and it is the second half of the pair "who turned this
// off and when". A trail holding only the first half answers neither half of a
// question that is always asked together: an operator who disabled a user in error
// and re-enabled them an hour later has, in the trail's terms, disabled them with no
// end.
//
// IT DOES NOT NEED THE ACCESS-TOKEN REVOKER, and its absence from Enable's preamble
// is not an oversight. A re-enable mints nothing and revokes nothing — the column is
// what the sessions already honour — so the only thing that can fail here is the two
// writes, and ErrNoUserAuditRecorder is the same refusal Disable makes.
func (s *Service) Enable(ctx context.Context, in EnableInput) error {
	// Same ordering as Disable and the same reason: after the column write, a nil
	// here would have lifted the disable and then reported failure, so the operator
	// believes the person is still disabled while the service has let them straight
	// back in.
	if s.auditor == nil {
		return ErrNoUserAuditRecorder
	}

	return s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		if err := s.users.Enable(ctx, q, in.UserID); err != nil {
			return fmt.Errorf("marking the user enabled: %w", err)
		}
		if _, err := s.auditor.Append(ctx, q, useraudit.Entry{
			UserID: in.UserID,
			Action: useraudit.ActionUserEnabled,
			Actor: useraudit.Actor{
				UserID:  in.ActorUserID,
				KeyID:   in.ActorKeyID,
				TraceID: in.TraceID,
			},
			OccurredAt: in.At,
		}); err != nil {
			return fmt.Errorf("recording the enable: %w", err)
		}
		return nil
	})
}

// EnableInput is a request to lift a disable. Same shape as DisableInput and for the
// same reason: the actor is not optional, and the two ids must not be
// interchangeable with the subject's.
type EnableInput struct {
	UserID      id.UUID
	ActorUserID id.UUID
	ActorKeyID  id.UUID
	TraceID     string
	At          time.Time
}

// Authenticate resolves a presented token to its user.
//
// A missing, unknown, expired or revoked token are one error. So is a token whose
// user has since been deleted: the session rows go with the user, so the lookup
// misses for a reason the caller has no way to distinguish.
func (s *Service) Authenticate(ctx context.Context, token string) (users.User, error) {
	if token == "" {
		return users.User{}, ErrUnauthenticated
	}

	session, err := s.sessions.ByToken(ctx, s.read.Queryer(), token, s.clock.Now())
	if err != nil {
		if errors.Is(err, sessions.ErrNotFound) {
			return users.User{}, ErrUnauthenticated
		}
		return users.User{}, fmt.Errorf("resolving a session: %w", err)
	}

	user, err := s.users.ByID(ctx, s.read.Queryer(), session.UserID)
	if err != nil {
		if errors.Is(err, users.ErrNotFound) {
			return users.User{}, ErrUnauthenticated
		}
		return users.User{}, fmt.Errorf("loading the session's user: %w", err)
	}

	return user, nil
}

// UpdateDisplayName sets the caller's display name, or clears it.
//
// IT IS THE WRITE HALF OF /v1/me, and it lives here rather than in the handler
// because the handler has no querier and no business having one: the read half
// (Authenticate) is here, the column is the users table's, and a handler that
// reached for a pool to write one field would be a second composition root for
// the same row.
//
// name is a pointer for the reason users.UpdateName's is: nil clears, and an
// empty display name is the same state as no display name. The value is
// expected to be trimmed and length-checked by then — the rules are
// users.ValidateDisplayName's, and this method is the use case that applies
// them, not the place they are defined.
//
// NO TRANSACTION, and that is a decision rather than an oversight: this is one
// UPDATE against one row the caller has already been resolved to, and the
// transaction runner exists for writes that must be atomic WITH each other.
// recordFailure is the same shape for the same reason.
func (s *Service) UpdateDisplayName(ctx context.Context, userID id.UUID, name *string) error {
	if err := s.users.UpdateName(ctx, s.read.Queryer(), userID, name); err != nil {
		return fmt.Errorf("setting a display name: %w", err)
	}
	return nil
}

// UpdateTheme sets the caller's theme, or clears it.
//
// IT IS THE WRITE HALF OF /v1/me's second field, and it lives here for the
// reason UpdateDisplayName does: the handler has no querier and no business
// having one, and a handler that reached for a pool to write one column would
// be a second composition root for the same row.
//
// theme is a pointer for the reason UpdateDisplayName's is: nil clears, and a
// cleared theme is the same state as a never-set one — the key is absent from
// the document. The value is expected to be already checked against the closed
// set by then; the rules are users.ValidateTheme's, and this method is the use
// case that applies them, not the place they are defined.
//
// NO TRANSACTION, for the reason UpdateDisplayName gives: one UPDATE against
// one row the caller has already been resolved to.
func (s *Service) UpdateTheme(ctx context.Context, userID id.UUID, theme *string) error {
	if err := s.users.UpdateTheme(ctx, s.read.Queryer(), userID, theme); err != nil {
		return fmt.Errorf("setting a theme: %w", err)
	}
	return nil
}

// Logout revokes the session a token belongs to.
//
// A token that resolves to nothing is a success, not an error. A client retrying
// a logout, or a browser presenting a cookie that has already expired, should get
// an answer; answering 500 would make a retry look like a failure and would make
// the natural client behaviour (retry) pathological.
func (s *Service) Logout(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}

	session, err := s.sessions.ByToken(ctx, s.read.Queryer(), token, s.clock.Now())
	if err != nil {
		if errors.Is(err, sessions.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("resolving a session to revoke: %w", err)
	}

	if err := s.sessions.Revoke(ctx, s.read.Queryer(), session.ID); err != nil {
		return fmt.Errorf("revoking a session: %w", err)
	}
	return nil
}

// Session is one row of GET /v1/sessions: a session a caller can recognise and
// name, with nothing on it that is a credential.
//
// # WHY IT IS NOT sessions.Session
//
// The domain type carries the two things this response must never carry, and
// neither is removed rather than renamed: it has the row's id, which is fine, but
// the store is the thing that knows how to turn that row back into a credential
// only through `token_digest`, and `sessions.Session` does not carry the digest
// — so the type is nearly safe already. What it does carry is `UserID`, and
// `UserID` is not a secret but it IS somebody else's business on a shared
// surface: a route that renders the caller's own user id back to them has told
// them nothing, and a route that renders it from a row has made the row the
// authority on whose session this is.
//
// So this is a dedicated projection rather than a struct tag. The rule this
// service keeps elsewhere is that a response shape is a type of its own so a field
// cannot reach a body by being added to a domain struct (see `userResponse` in
// internal/httpapi), and this is that rule applied to a list.
//
// `Current` is the only field here that is not in the row, and it is computed
// rather than stored because it is a fact about THIS REQUEST — which session the
// caller is holding — and a column would be true for exactly one request at a time
// and wrong for all the others.
type Session struct {
	ID        id.UUID
	ExpiresAt time.Time
	CreatedAt time.Time
	// UserAgent is the caller's own header as recorded at sign-in. It is shown
	// because it is the only thing in the row a person recognises — "Chrome on my
	// laptop" — and it is shown raw rather than parsed because a device label this
	// service invents is a label that can be wrong, and a UI that trusts a
	// server-side label shows somebody the wrong laptop. The caller parses it.
	//
	// It is also caller-supplied text: anything can be in a User-Agent header, so
	// a front end rendering it has the same obligation as every other untrusted
	// string in this service (see the login-redirect argument in AGENTS.md).
	UserAgent string
	// IP is recorded, never trusted, and shown for the same reason. It is behind a
	// proxy in most deployments, so it is frequently the proxy's address — which
	// is a reason to present it as evidence rather than as a location.
	IP *netip.Addr
	// Current marks the session the request itself authenticated with, so a
	// client can render "this device" without comparing a token it does not have.
	Current bool
}

// ListSessions returns the caller's live sessions, newest first.
//
// IT TAKES THE TOKEN, NOT A USER ID, and that is the whole reason the boundary
// holds. Every other method on this service that acts on somebody's data either
// takes a subject and an actor (Disable, Enable — where the distinction is the
// audit row's business) or takes no subject at all. This one takes the
// credential, resolves the user from it, and asks only about that user's rows. A
// handler cannot pass anybody else's id because there is no parameter to pass one
// in, and the alternative signature — `ListSessions(ctx, userID)` — would put the
// tenant boundary in the discipline of every call site.
//
// A token that resolves to nothing is ErrUnauthenticated, the same as
// Authenticate's: an expired session is not a session the caller may enumerate,
// and treating it as an empty list would answer a 200 to a credential that is
// dead, which is a client told its session is fine.
func (s *Service) ListSessions(ctx context.Context, token string) ([]Session, error) {
	session, err := s.sessions.ByToken(ctx, s.read.Queryer(), token, s.clock.Now())
	if err != nil {
		if errors.Is(err, sessions.ErrNotFound) {
			return nil, ErrUnauthenticated
		}
		return nil, fmt.Errorf("resolving the caller's own session: %w", err)
	}

	rows, err := s.sessions.ListLiveForUser(ctx, s.read.Queryer(), session.UserID, s.clock.Now())
	if err != nil {
		return nil, err
	}

	out := make([]Session, 0, len(rows))
	for _, row := range rows {
		out = append(out, Session{
			ID:        row.ID,
			ExpiresAt: row.ExpiresAt,
			CreatedAt: row.CreatedAt,
			UserAgent: row.UserAgent,
			IP:        row.IP,
			Current:   row.ID == session.ID,
		})
	}

	return out, nil
}

// ErrSessionNotFound means the caller named a session that is not one of theirs, or
// is one that has already ended.
//
// FOUR CASES, ONE ERROR, and the reason is the same one sessions.ErrNotFound gives:
// the caller is already authenticated, so nothing here is protected by hiding it —
// and the two cases that WOULD be protected by hiding it are "that session id is
// somebody else's" and "that session id does not exist", which a 403 against a 404
// would tell apart. A user may name their own session ids; they may not learn
// anybody else's.
//
// It is NOT auth.ErrUnauthenticated. That one is about the caller's credential and
// this one is about a row in the caller's own account, and a client that saw 401
// here would go looking for a login problem it does not have.
var ErrSessionNotFound = errors.New("session not found")

// RevokeSession revokes one of the caller's own sessions by id.
//
// # IT TAKES THE TOKEN FOR THE SAME REASON ListSessions DOES
//
// The user id is resolved from the credential and the session id is the only thing
// the caller supplies, so "is this session mine" is asked of the database with the
// owner in the predicate (see `Store.RevokeOneForUser`) rather than asked here and
// then acted on. There is no code path in which a resolved user id and a
// caller-supplied session id meet without the ownership clause between them.
//
// # REVOKING THE SESSION YOU ARE USING IS ALLOWED, AND HERE IS WHY
//
// The packet offered two answers and this is the first: a caller may revoke the
// session that authenticated this very request. The consequence is stated rather
// than prevented — the response is a 204 and the caller is signed out, so the next
// request with that credential is a 401 and the browser must clear its cookie.
//
// The alternative — refusing the current session with a 409 — was rejected for a
// reason that is about the API rather than about security. `DELETE /v1/session`
// already revokes the caller's current session with no complaint; a route that
// refuses to do the same thing when the id is spelled out is a route whose refusal
// is a puzzle. "Sign out everywhere" is a separate operation and this is not it: the
// other sessions are untouched, and the response says which one is gone.
//
// There is no third refusal here — an expired or already-revoked session is the
// same 404 as somebody else's, and a session belonging to another user never
// reaches a DELETE at all.
func (s *Service) RevokeSession(ctx context.Context, token string, sessionID id.UUID) error {
	present, err := s.sessions.ByToken(ctx, s.read.Queryer(), token, s.clock.Now())
	if err != nil {
		if errors.Is(err, sessions.ErrNotFound) {
			return ErrUnauthenticated
		}
		return fmt.Errorf("resolving the caller's own session: %w", err)
	}

	revoked, err := s.sessions.RevokeOneForUser(ctx, s.read.Queryer(), present.UserID, sessionID)
	if err != nil {
		return err
	}
	if !revoked {
		return ErrSessionNotFound
	}

	return nil
}

// validateRegistration checks the request before anything is hashed or written.
func validateRegistration(email, password string) error {
	if err := users.ValidateEmail(email); err != nil {
		return err
	}
	return users.ValidatePassword(password)
}

// validateLogin checks the shape of a login without requiring a strong password:
// an existing account may predate any rule, and a login that failed validation
// because the password is short would be a way to probe which passwords are in
// use. The length bounds still apply, because they bound the work argon2id is
// asked to do.
func validateLogin(email, password string) error {
	if err := users.ValidateEmail(email); err != nil {
		return err
	}
	if password == "" {
		return &users.FieldError{Field: "password", Code: users.CodeRequired}
	}
	if len(password) > users.MaxPasswordLength {
		return &users.FieldError{Field: "password", Code: users.CodeTooLong}
	}
	return nil
}
