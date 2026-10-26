package accounts

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/tenancy"
	"github.com/anywaye/identity/internal/users"
)

// The use cases. Everything a client can do to an account, a membership or an
// invitation, and the rules that govern each of them.
//
// It sits above the store because the interesting part of tenancy is not any one
// table — it is the ordering and the transactions. Creating an account writes
// three rows and an event; accepting an invitation creates a membership, marks
// the invitation and announces the membership, and any two of the three without
// the third is a bug rather than a state. Those are properties of the use case,
// not of a handler and not of a schema.
//
// NOTHING HERE KNOWS ABOUT HTTP. The handlers translate the errors below into
// the anywaye error envelope; they do not define the rules.

// UnitOfWork runs a function inside a transaction. db.TxRunner implements it;
// the interface is the seam that lets these rules be tested without Postgres.
type UnitOfWork interface {
	Do(ctx context.Context, fn func(ctx context.Context, q db.Querier) error) error
}

// AccountStore is the slice of Store the use cases need.
//
// It is declared here rather than taking *Store so a test can program a failure
// at the exact write that matters — a slug conflict, a pending invitation, a
// membership that is already there — without standing up a database.
type AccountStore interface {
	Create(ctx context.Context, q db.Querier, p CreateParams) (Account, error)
	ByID(ctx context.Context, q db.Querier, id id.UUID) (Account, error)
	Rename(ctx context.Context, q db.Querier, id id.UUID, name string) (Account, error)
	Delete(ctx context.Context, q db.Querier, id id.UUID) error
	AddMember(ctx context.Context, q db.Querier, m Membership) (Membership, error)
	Member(ctx context.Context, q db.Querier, accountID, userID id.UUID) (Membership, error)
	Members(ctx context.Context, q db.Querier, accountID id.UUID) ([]MemberSummary, error)
	CountOwners(ctx context.Context, q db.Querier, accountID id.UUID) (int, error)
	SetRole(ctx context.Context, q db.Querier, accountID, userID id.UUID, role Role) (Membership, error)
	RemoveMember(ctx context.Context, q db.Querier, accountID, userID id.UUID) error
	ListForUser(ctx context.Context, q db.Querier, userID id.UUID) ([]MemberSummary, error)
	// Search is the staff directory's read over the accounts table: a bounded
	// substring match on name and slug. It authorizes nothing on its own.
	Search(ctx context.Context, q db.Querier, query string, limit int) ([]Account, error)
	CreateInvitation(ctx context.Context, q db.Querier, n NewInvitation) (Invitation, error)
	InvitationByToken(ctx context.Context, q db.Querier, digest string) (Invitation, error)
	MarkInvitationAccepted(ctx context.Context, q db.Querier, id id.UUID, at time.Time) error
}

// EventAppender is the slice of outbox.Store the tenancy use cases need. Every
// event this service emits about an account is written inside the transaction
// that changed the account, which is the entire reason the outbox exists.
type EventAppender interface {
	Append(ctx context.Context, q db.Querier, e outbox.Envelope) error
}

// UserEmailReader reads the address a registered user holds.
//
// IT IS A NARROW INTERFACE AND NOT users.Store because the use case needs one
// field from one row and the table belongs to the users package — the same seam
// internal/recovery declares as its own UserStore, for the same reason. accounts
// already imports users for the address rules, so there is no cycle to route
// around; the narrowness is about the dependency saying what it is for, which a
// whole-store parameter does not.
type UserEmailReader interface {
	ByID(ctx context.Context, q db.Querier, userID id.UUID) (users.User, error)
}

// CredentialRevoker withdraws the machine credentials a user holds in an account.
//
// IT IS A DEPENDENCY RATHER THAN AN IMPORT because internal/apikeys imports this
// package for accounts.Role, and a direct import back would be a cycle that exists
// only because a role is a type on both sides. Declaring the one method here is the
// same seam internal/mfa uses for its session sweep, and for the same reason: the
// RULE lives in the use case that makes the change, and the table that holds the
// rows is somebody else's.
//
// IT MAY BE NIL, and then a member removal changes only the membership. That is
// supported rather than broken — a deployment with no api key table has no
// credentials to revoke — and it is why the sweep is a separate statement rather
// than part of the membership delete: a revocation that fails must not leave the
// membership half-removed either.
type CredentialRevoker interface {
	RevokeAllForMember(ctx context.Context, q db.Querier, accountID, userID id.UUID, at time.Time) error
}

// InvitationMailer delivers the invitation email for one pending invitation.
//
// IT IS A SEAM RATHER THAN A COURIER CLIENT because the send is a fact about the
// invite use case — it happens after the invitation commits, it carries the
// invitation's one-time token, and its failure is the invite's failure — while
// courier's vocabulary is courier's. internal/courier satisfies it, exactly as
// it satisfies recovery.Mailer, and neither package imports the other: the
// interface is declared here and satisfied in cmd/identity/main.go, the one
// place that knows both.
//
// IT MAY BE NIL, and then an invitation is created with no mail — a deployment
// with no mail path, which is a supported state rather than a broken one (the
// same shape CredentialRevoker has). A mailer that is PRESENT and fails is a
// different thing: that failure is returned to the caller, never swallowed.
type InvitationMailer interface {
	SendInvitation(ctx context.Context, invitation OutgoingInvitation) error
}

// OutgoingInvitation is the invitation email waiting to be sent.
//
// IT CARRIES THE ONE-TIME TOKEN, which is why it is built inside Invite and
// never stored: the token exists once, in the row's digest and in this value,
// and the mail is the only thing that takes it out of the process. The same
// rule the Invitation struct's comment states.
type OutgoingInvitation struct {
	// ID is the invitation's id. It is the key the send's idempotency is
	// derived from, and the value courier's own consumer uses as the mail's
	// user_id — an invitee has no user, because the invitation exists
	// precisely because they have not signed up.
	ID id.UUID
	// Email is the invitee's address — the recipient.
	Email string
	// Token is the one-time acceptance token, rendered into the link.
	Token string
	// AccountName is the account the invitee is invited to, which courier's
	// template renders after "invited you to join".
	AccountName string
	// InvitedBy is who the mail says sent it: the inviter's display name when
	// they have one, and their address when they do not.
	InvitedBy string
	// Role is the role the invitation offers, rendered after "as".
	Role string
}

// Service is the tenancy use cases.
type Service struct {
	uow     UnitOfWork
	store   AccountStore
	users   UserEmailReader
	events  EventAppender
	revokes CredentialRevoker
	mailer  InvitationMailer
	clock   clock.Clock
	read    db.QuerierSource
}

// NewService wires the use cases.
//
// revokes may be nil — see CredentialRevoker. mailer may be nil — see
// InvitationMailer.
func NewService(
	uow UnitOfWork,
	store AccountStore,
	users UserEmailReader,
	events EventAppender,
	revokes CredentialRevoker,
	clk clock.Clock,
	read db.QuerierSource,
	mailer InvitationMailer,
) *Service {
	return &Service{uow: uow, store: store, users: users, events: events, revokes: revokes, mailer: mailer, clock: clk, read: read}
}

// CreateInput is a request to create an account.
type CreateInput struct {
	// Name is what a human sees; the slug is derived from it.
	Name string
	// Owner is the user creating it, who becomes its first and (for now) only
	// owner. It is the caller's authenticated user, never something from a body.
	Owner id.UUID
}

// Created is a new account and the caller's membership in it.
type Created struct {
	Account    Account
	Membership Membership
}

// Create provisions an account and makes the caller its owner.
//
// Three rows and an event, in one transaction. The account without its owner
// membership is an account nobody can administer, and the event without the
// account announces a tenant that does not exist, so none of the three is
// written unless all of them are.
func (s *Service) Create(ctx context.Context, in CreateInput) (Created, error) {
	name := NormalizeName(in.Name)
	if err := ValidateName(name); err != nil {
		return Created{}, err
	}
	if in.Owner.IsZero() {
		return Created{}, ErrNotAMember
	}

	now := s.clock.Now()
	var out Created

	err := s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		account, err := s.store.Create(ctx, q, CreateParams{
			Name: name,
			Slug: Slugify(name),
		})
		if err != nil {
			return err
		}

		// Begin as the account that was just created, for the same reason
		// registration does (internal/auth's provisionTenancy): the membership
		// write below is account-scoped and the account did not exist when the
		// request arrived, so there is nothing on the context to resolve. Without
		// this the INSERT is refused with SQLSTATE 42501 and the route 500s.
		if err := tenancy.BeginAccount(ctx, q, account.ID); err != nil {
			return fmt.Errorf("beginning as the new account: %w", err)
		}

		membership, err := s.addOwner(ctx, q, account, in.Owner)
		if err != nil {
			return err
		}

		event, err := outbox.NewAccountCreated(now, account.ID, account.Name, account.Slug, false, in.Owner)
		if err != nil {
			return err
		}
		if err := s.events.Append(ctx, q, event); err != nil {
			return err
		}

		out = Created{Account: account, Membership: membership}
		return nil
	})
	if err != nil {
		return Created{}, err
	}
	return out, nil
}

// Provision creates the account a registration gives its user, and
// AddOwner gives that user the owner role in it.
//
// Neither opens a transaction and neither may: they run inside the
// registration's, which is what makes "the personal account and the user exist
// together or not at all" true rather than aspirational. A registration that
// commits a user with no account is a user who cannot do anything, and it is
// exactly the half-written state a later packet would have to repair.
//
// The slug is derived from the user id rather than the name, because two people
// can share an email local part and the second must still be able to sign up.
// See PersonalSlug.
func (s *Service) Provision(ctx context.Context, q db.Querier, userID id.UUID, email string) (Account, error) {
	if userID.IsZero() {
		return Account{}, ErrNotAMember
	}

	name := PersonalName(email)
	if name == "" {
		name = "Personal"
	}
	if err := ValidateName(name); err != nil {
		// A local part that cannot be a name — "東京", or one over the limit — is
		// repaired rather than refused, because refusing here would fail a
		// registration over the *name* of an account the user never chose. The
		// fallback is the address, which is always sluggable and always unique
		// once the id is folded in.
		name = truncateName(email)
	}

	return s.store.Create(ctx, q, CreateParams{
		Name:     name,
		Slug:     PersonalSlug(email, userID),
		Personal: true,
	})
}

// AddOwner creates an owner's membership and announces the account. It pairs
// with Provision inside a registration's transaction.
func (s *Service) AddOwner(ctx context.Context, q db.Querier, accountID, userID id.UUID) (Membership, error) {
	account, err := s.store.ByID(ctx, q, accountID)
	if err != nil {
		return Membership{}, err
	}
	membership, err := s.addOwner(ctx, q, account, userID)
	if err != nil {
		return Membership{}, err
	}
	// The event belongs to the registration, not to the membership: there is one
	// identity.account.created for the account, and writing it here rather than in
	// Provision is what keeps it next to the row it announces.
	event, err := outbox.NewAccountCreated(s.clock.Now(), account.ID, account.Name, account.Slug, account.Personal, userID)
	if err != nil {
		return Membership{}, err
	}
	if err := s.events.Append(ctx, q, event); err != nil {
		return Membership{}, err
	}
	return membership, nil
}

// addOwner creates a membership with the owner role, inside the caller's
// transaction.
func (s *Service) addOwner(ctx context.Context, q db.Querier, account Account, userID id.UUID) (Membership, error) {
	return s.store.AddMember(ctx, q, Membership{
		AccountID: account.ID,
		UserID:    userID,
		Role:      RoleOwner,
	})
}

// ListMine returns every account the user belongs to, with their role in each.
//
// Scoped by the authenticated user's id and nothing else. A query scoped by an
// account id from the request body is how one tenant's data reaches another's.
//
// # WHY THIS IS THE ONE CALL SITE OF tenancy.BeginUser
//
// `account_users` carries two policies after migration 00018 and this query needs
// the second one. The first is `anywaye.protect_table`'s — `account_id = (select
// anywaye.current_account_id())` — and it answers "which members belong to the
// account I am standing in", which is a different question from this one. A caller
// who has signed in and has not yet chosen an account is not standing in one;
// that is what makes them a caller rather than a tenant.
//
// So this query ran under the account policy alone and returned nothing. Not an
// error, not a 401, not a red assertion anywhere: the join was correct, the
// membership row was in the table, and the answer was `[]` for a user who owned
// an account. The product rendered "you are not a member of any account".
//
// The fix is `anywaye.begin_user/1`, and it needs a TRANSACTION to live in —
// `begin_user` is `is_local = true`, exactly as `begin_account` is, so on a
// pooled connection outside a transaction it expires at the end of the statement
// that set it. That is why this opens one through the same `s.uow` every write in
// this service already uses rather than reading on `s.read.Queryer()`.
//
// It opens its own rather than relying on TxRunner having set it, and that is a
// deliberate trade rather than an oversight. TxRunner's argument is that EVERY
// account-scoped write passes through it, so "every write runs under an identity"
// is a property of one type; that argument does not carry over to a read one
// endpoint makes, and paying a statement on every transaction of every request to
// satisfy it is the cost scope.go explicitly declines for the account seam's own
// empty case.
func (s *Service) ListMine(ctx context.Context, userID id.UUID) ([]MemberSummary, error) {
	if userID.IsZero() {
		return nil, ErrNotAMember
	}

	var out []MemberSummary
	err := s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		if err := tenancy.BeginUser(ctx, q, userID); err != nil {
			return fmt.Errorf("naming the caller for the account list: %w", err)
		}
		rows, err := s.store.ListForUser(ctx, q, userID)
		if err != nil {
			return fmt.Errorf("listing the caller's accounts: %w", err)
		}
		out = rows
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Never nil, so a JSON encoder renders `[]` rather than `null` for a user
	// with no accounts. The store guarantees that already; it is restated because
	// this method now hands back whatever the callback captured, and a nil slice
	// captured there is a `null` one level out with nothing left to turn it back.
	if out == nil {
		out = []MemberSummary{}
	}
	return out, nil
}

// Get returns an account and the caller's membership in it.
//
// It returns ErrNotAMember for both "you are not in this account" and "there is
// no such account", and that is the security property rather than a
// convenience: a 403 for the first and a 404 for the second is an existence
// oracle for anybody who can guess an id.
//
// The second return value is the caller's own Role, which the handler needs to
// render "you are an admin of this" without a second query.
//
// # WHY IT OPENS ITS OWN TRANSACTION
//
// This read runs BEFORE a request has chosen an account — `requireAccountRole`
// calls it to decide whether the account in the path is this caller's at all — so
// nothing has set `anywaye.account_id` and the four account policies on
// `account_users` cannot let this row through. Migration 00018 added the fifth,
// `account_users_anywaye_members`, which filters on
// `user_id = anywaye.current_user_id()`, and `anywaye.begin_user` is what puts the
// caller there.
//
// So without the transaction below this returns ErrNotAMember to the OWNER of
// the account, which the handler renders as `404 Account not found`: the
// database filtered the row out rather than any assertion refusing it, and
// nothing anywhere went red. `begin_user` is `is_local`, so on a pooled
// connection outside a transaction it expires at the end of the statement that
// set it, which is why this opens one through the same `s.uow` every write here
// already uses rather than reading on `s.read.Queryer()`.
//
// It is the SECOND call site of `tenancy.BeginUser`, not the first, and that is
// the defect's real shape: `ListMine` above had the reasoning in a comment and
// `Get` did not, so the rule lived in the doc comment of the one function that
// happened to be fixed. `get_rls_test.go` is what holds it now.
// SearchAccounts returns the accounts whose name or slug contains query,
// bounded by limit. It authorizes nothing on its own — the staff gate is the
// route's — for the same reason auth.Service.SearchUsers does.
func (s *Service) SearchAccounts(ctx context.Context, query string, limit int) ([]Account, error) {
	entries, err := s.store.Search(ctx, s.read.Queryer(), query, limit)
	if err != nil {
		return nil, fmt.Errorf("searching accounts: %w", err)
	}
	return entries, nil
}

func (s *Service) Get(ctx context.Context, accountID, userID id.UUID) (Account, Role, error) {
	var out Account
	var role Role

	err := s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		if err := tenancy.BeginUser(ctx, q, userID); err != nil {
			return fmt.Errorf("naming the caller for the account read: %w", err)
		}

		membership, err := s.store.Member(ctx, q, accountID, userID)
		if err != nil {
			if errors.Is(err, ErrNotAMember) {
				return ErrNotAMember
			}
			return fmt.Errorf("looking up a membership: %w", err)
		}

		account, err := s.store.ByID(ctx, q, accountID)
		if err != nil {
			// A membership with no account is not a state the foreign keys allow, so
			// this is a database problem rather than a caller one. It is mapped to
			// the same error anyway: the caller learns nothing about the account's
			// existence either way.
			return ErrNotAMember
		}

		out, role = account, membership.Role
		return nil
	})
	if err != nil {
		return Account{}, "", err
	}

	return out, role, nil
}

// Members lists an account's memberships.
//
// It does not check the caller's own role. Authorization is
// RequireAccountRole's job in the HTTP layer, and duplicating it here would give
// the service two answers to the same question. This is a use case for the
// authorized caller, and the tests above prove the middleware calls it in the
// right order.
//
// # WHY IT OPENS A TRANSACTION, AND WHY THAT IS THE WHOLE FIX
//
// `account_users` is scoped by the ACCOUNT — `account_users_anywaye_select` from
// 00016, `account_id = (select anywaye.current_account_id())` — so listing an
// account's members needs the ACCOUNT identity, and `begin_account` is
// `is_local`: on a bare pooled connection it expires at the end of the statement
// that set it. Reading on `s.read.Queryer()` therefore saw no identity at all,
// every predicate was false, and the DATABASE filtered every membership row out.
//
// There is no error to notice. `Members` returned `[]` and a nil error for an
// account with two real members, so `GET /v1/accounts/:id/members` answered
// `200 []`, and an owner watching a member list render empty had no signal that
// it was wrong. It is the silent half of the defect `Get` had: `Get` at least
// mapped the miss to a 404 the caller could report.
//
// `tenancy.TxRunner` sets the account from the CONTEXT, and
// `requireAccountRole` is the one place in this service that puts an account
// there — after a membership read has established that the account is the
// caller's. So the identity this read runs under is a fact rather than the
// caller's argument, which is the only reason the account seam is the right one
// here: naming the account from `accountID` instead would hand the policy a
// value no membership check ever approved.
//
// WHICH IS WHY IT REFUSES A CONTEXT THAT NAMES NOTHING, or names something
// else. Both cases leave the same two questions in the query and no predicate
// true, so both answer `[]` — and an empty member list is a real answer as far
// as any caller can tell. `tenancy.BeginUser` refuses the nil caller for
// precisely this reason ("a membership read with no membership to find is not a
// thing anybody meant to ask for"), and this is the same rule about the other
// half of the identity. The HTTP layer renders an unrecognized error as a 500
// with a trace id, which is the right answer for a route reached without the
// middleware that is supposed to have authorized it.
func (s *Service) Members(ctx context.Context, accountID id.UUID) ([]MemberSummary, error) {
	scoped, ok := tenancy.AccountFrom(ctx)
	if !ok {
		return nil, fmt.Errorf("%w: listing the members of %s with no account on the context. "+
			"A request chooses its account in requireAccountRole, which is also what "+
			"authorizes the caller for it; reaching this without one is a wiring bug, and "+
			"answering [] instead would say the account has nobody in it",
			tenancy.ErrNoIdentity, accountID)
	}
	if scoped != accountID {
		return nil, fmt.Errorf("%w: listing the members of %s while the request is standing in %s. "+
			"The two have to be one account — the rows are filtered by both, so a mismatch "+
			"returns neither account's members and says [] about the one that was asked for",
			tenancy.ErrNoIdentity, accountID, scoped)
	}

	var out []MemberSummary
	err := s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := s.store.Members(ctx, q, accountID)
		if err != nil {
			return err
		}
		out = rows
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Never nil, so a JSON encoder renders `[]` rather than `null`. The store
	// already guarantees it on both of its returns; restated for the same reason
	// ListMine restates it — this method hands back whatever the callback
	// captured, and a nil slice captured there is a `null` one level out.
	if out == nil {
		out = []MemberSummary{}
	}
	return out, nil
}

// Member returns one user's membership, for the assertions above and for the
// removal path. A miss is ErrNotAMember, not ErrNotFound.
//
// IT OPENS A TRANSACTION AND NAMES THE CALLER for the reason Get gives, and it is
// here rather than not because `TransferOwnership` reads the membership to
// authorize its actor on an account nobody has stood in yet. Left on
// `s.read.Queryer()` it refuses the owner who asked for the transfer with
// ErrNotOwner — indistinguishable from an admin being correctly refused, so the
// only symptom would have been a transfer that 403s its own owner.
func (s *Service) Member(ctx context.Context, accountID, userID id.UUID) (Membership, error) {
	var out Membership
	err := s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		if err := tenancy.BeginUser(ctx, q, userID); err != nil {
			return fmt.Errorf("naming the caller for the membership read: %w", err)
		}
		m, err := s.store.Member(ctx, q, accountID, userID)
		if err != nil {
			return err
		}
		out = m
		return nil
	})
	if err != nil {
		return Membership{}, err
	}
	return out, nil
}

// Account returns an account without any authorization check, for the handlers
// that have already established the caller's role.
func (s *Service) Account(ctx context.Context, accountID id.UUID) (Account, error) {
	return s.store.ByID(ctx, s.read.Queryer(), accountID)
}

// Rename changes an account's name.
//
// It does not re-derive the slug, and it cannot conflict: a slug is set once, at
// creation, and a rename is therefore never a 409. See accounts.Account.Slug.
func (s *Service) Rename(ctx context.Context, accountID id.UUID, name string) (Account, error) {
	normalized := NormalizeName(name)
	if err := ValidateName(normalized); err != nil {
		return Account{}, err
	}
	return s.store.Rename(ctx, s.read.Queryer(), accountID, normalized)
}

// Delete removes an account. Its memberships and pending invitations go with it
// through the ON DELETE CASCADE the migrations declare.
func (s *Service) Delete(ctx context.Context, accountID id.UUID) error {
	return s.store.Delete(ctx, s.read.Queryer(), accountID)
}

// InviteInput is a request to invite somebody to an account.
type InviteInput struct {
	AccountID id.UUID
	Email     string
	Role      Role
	// InvitedBy is the authenticated caller. The inviter's own role is resolved
	// from the database rather than taken from a request, and it decides whether
	// an admin may be invited.
	InvitedBy id.UUID
}

// Invited is a new invitation and the one-time token that redeems it.
//
// The token is returned exactly once, here, and is never stored. A caller that
// loses it mints a new invitation; there is no way to recover it, which is the
// same rule that governs a session token and a password.
type Invited struct {
	Invitation Invitation
	Token      string
}

// Invite creates a pending membership and announces it.
//
// The inviter's own role is read here rather than assumed from the middleware,
// because the rule "only an owner may invite an admin" is about the *inviter*
// and there is one more hop between the request and this decision than there is
// for the caller's minimum role. Checking it in one place means the rule holds
// however the use case is reached.
//
// THE READ IS `s.Member`, and that is the whole fix for a defect that stopped
// anybody being invited at all. It used to be
// `s.store.Member(ctx, s.read.Queryer(), …)` — a bare pooled connection, no
// transaction, no `tenancy.BeginUser` — so the `account_users_anywaye_members`
// policy (00018, `user_id = anywaye.current_user_id()`) filtered the OWNER'S OWN
// membership row out, `ErrNotAMember` came back, and the mapping a few lines
// below turned it into ErrOwnerProtected. An owner could not invite anybody,
// and the error said something about owners, which is the hardest kind of wrong
// answer to notice from the outside.
//
// Reading it through `Member` rather than repeating the transaction here is what
// keeps that from being a fifth copy of the rule: there is one method that reads
// a membership for a caller, it knows the GUC has to be named on a transaction,
// and every caller of it inherits both.
func (s *Service) Invite(ctx context.Context, in InviteInput) (Invited, error) {
	email := users.NormalizeEmail(in.Email)
	if err := users.ValidateEmail(email); err != nil {
		// The address rules belong to users — one emailPattern, one
		// MaxEmailLength, one NormalizeEmail — and reusing them is why an
		// invitation address and a registered address cannot disagree about what
		// "the same address" means. The error is re-wrapped in this package's own
		// FieldError so that a caller of this service never has to know which
		// package a validation type came from; the field and code survive intact,
		// which is all a client reads.
		return Invited{}, asFieldError(err)
	}
	if !in.Role.Invitable() {
		return Invited{}, ErrRoleNotInvitable
	}

	inviter, err := s.Member(ctx, in.AccountID, in.InvitedBy)
	if err != nil {
		if errors.Is(err, ErrNotAMember) {
			return Invited{}, ErrOwnerProtected
		}
		return Invited{}, fmt.Errorf("looking up the inviter: %w", err)
	}
	if !inviter.Role.AtLeast(RoleAdmin) {
		return Invited{}, ErrOwnerProtected
	}
	// An admin may invite a member; only an owner may hand out admin. The
	// privilege has to be granted by somebody who already holds it, or an admin
	// can clone themselves into a second admin who answers to nobody.
	if in.Role == RoleAdmin && !inviter.Role.AtLeast(RoleOwner) {
		return Invited{}, ErrRoleNotInvitable
	}

	token, digest, err := NewToken()
	if err != nil {
		return Invited{}, err
	}
	now := s.clock.Now()

	var out Invited
	err = s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		invitation, err := s.store.CreateInvitation(ctx, q, NewInvitation{
			AccountID:   in.AccountID,
			Email:       email,
			Role:        in.Role,
			TokenDigest: digest,
			CreatedAt:   now,
			ExpiresAt:   now.Add(InvitationTTL),
			InvitedBy:   in.InvitedBy,
		})
		if err != nil {
			return err
		}

		event, err := outbox.NewMemberInvited(now, in.AccountID, invitation.ID, email, token, string(in.Role), in.InvitedBy)
		if err != nil {
			return err
		}
		if err := s.events.Append(ctx, q, event); err != nil {
			return err
		}

		out = Invited{Invitation: invitation, Token: token}
		return nil
	})
	if err != nil {
		return Invited{}, err
	}

	// THE MAIL, AFTER THE COMMIT — and the ordering is the whole of it.
	// A mail cannot be rolled back, so it cannot go inside the transaction: an
	// invitation that rolled back with its mail sent is a link to nothing, and
	// an invitation that committed with its mail unsent is an admin who can
	// revoke and re-invite. The second is recoverable and the first is not, so
	// the send is after the commit whatever the mailer does with it — the same
	// ordering internal/recovery's mintAndSend establishes.
	//
	// A NIL MAILER IS A DEPLOYMENT WITH NO MAIL PATH, not a failure: the
	// invitation row is the promise and the token in the response is the
	// one-time credential, exactly as it is for a deployment that cannot send
	// recovery mail. A PRESENT mailer whose send fails is RETURNED: the admin
	// is told the invite did not reach anybody, and the invitation row that
	// survived is revoked and re-invited rather than guessed about. The token
	// is not stored — only its digest is — so the failed link is gone for good
	// and re-inviting mints a new one; that is the honest failure semantics,
	// and it is why the error is not swallowed.
	if s.mailer != nil {
		outgoing, err := s.outgoingInvitation(ctx, out)
		if err != nil {
			return Invited{}, err
		}
		if err := s.mailer.SendInvitation(ctx, outgoing); err != nil {
			return Invited{}, err
		}
	}
	return out, nil
}

// outgoingInvitation gathers what the invitation email needs, after the commit.
//
// THE READS ARE AFTER THE COMMIT because the mail is: the transaction holds
// only the invitation's own writes, and everything the mail needs is gathered
// in the same post-commit block as the send it feeds. A failure here is a send
// that cannot be composed, and it is returned like a courier failure — the
// invitation row survives either way.
func (s *Service) outgoingInvitation(ctx context.Context, invited Invited) (OutgoingInvitation, error) {
	account, err := s.store.ByID(ctx, s.read.Queryer(), invited.Invitation.AccountID)
	if err != nil {
		return OutgoingInvitation{}, fmt.Errorf("reading the account for the invitation mail: %w", err)
	}
	inviter, err := s.users.ByID(ctx, s.read.Queryer(), invited.Invitation.InvitedBy)
	if err != nil {
		return OutgoingInvitation{}, fmt.Errorf("reading the inviter for the invitation mail: %w", err)
	}
	return OutgoingInvitation{
		ID:          invited.Invitation.ID,
		Email:       invited.Invitation.Email,
		Token:       invited.Token,
		AccountName: account.Name,
		InvitedBy:   displayNameOrEmail(inviter),
		Role:        string(invited.Invitation.Role),
	}, nil
}

// displayNameOrEmail is who the invitation mail says sent it.
//
// THE DISPLAY NAME WHEN THERE IS ONE AND THE ADDRESS WHEN THERE IS NOT,
// because courier's template renders the value immediately before "invited
// you to join": a blank there is a mail that does not say who invited them, and
// a uuid would be worse. Most users have no display name — the column is
// nullable and registration does not set it — so the address is the common
// case, and it is a value the invitee can recognize.
func displayNameOrEmail(u users.User) string {
	if u.DisplayName != nil && *u.DisplayName != "" {
		return *u.DisplayName
	}
	return u.Email
}

// InviteRole is Invite for a caller that has a role as a string, which is what a
// request body carries.
//
// It is a separate method rather than a ParseRole at the handler, so the owner
// restriction is applied on the same path however the use case is reached: a
// handler that parsed "owner" into accounts.RoleOwner and called Invite would
// otherwise skip nothing — Invite re-checks Invitable — but the two entry points
// would still be two places to keep in step.
func (s *Service) InviteRole(ctx context.Context, accountID id.UUID, email, role string, invitedBy id.UUID) (Invited, error) {
	parsed, err := ParseInvitableRole(role)
	if err != nil {
		return Invited{}, err
	}
	return s.Invite(ctx, InviteInput{
		AccountID: accountID,
		Email:     email,
		Role:      parsed,
		InvitedBy: invitedBy,
	})
}

// AcceptInput is a request to redeem an invitation.
type AcceptInput struct {
	// Token is the raw token from the invitation's 201 response.
	Token string
	// User is the authenticated caller redeeming it.
	User id.UUID
}

// Accept redeems an invitation: it creates the membership, marks the invitation
// accepted and announces the membership, in one transaction.
//
// The three are one fact. A membership with an invitation still pending is an
// invitation that can be redeemed again; an invitation marked accepted with no
// membership is a link that has been spent on nothing; and either without the
// event leaves a consumer's member list permanently one short with no way to
// notice.
//
// The token is not bound to the email it was sent to. Possession of a 256-bit
// token is the credential, the same rule as a session token, and binding it to an
// address would break the legitimate case of inviting somebody who already has
// an account under a different one. The consequence is that an admin can invite
// an address they do not control and the person who clicks the link is who joins
// — which is already true, because an admin can invite any address they like.
func (s *Service) Accept(ctx context.Context, in AcceptInput) (Membership, error) {
	if in.User.IsZero() {
		return Membership{}, ErrNotAMember
	}

	now := s.clock.Now()
	digest := Digest(in.Token)

	var out Membership
	err := s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		// Open the resolution FIRST, as the digest and nothing else. The
		// account is what this lookup is FOR, so there is no identity to run
		// it under — and a lookup on a bare connection reads zero rows under
		// the enforced boundary, which is how a fresh invitation came to 404
		// (migrations/00029). The transaction carries the digest the caller
		// presented, computed above before any query ran, and the policy
		// admits exactly the row carrying it.
		//
		// The account follows, AFTER the lookup, and it comes from the row
		// the caller presented rather than from the request: re-beginning as
		// the invitation's own account is what admits the membership INSERT
		// below. The union of the two policies inside this transaction is the
		// invitation's row plus its account's rows, which is the redemption's
		// own scope and nothing wider — a token still reveals only its own
		// invitation and grants no broader read or write.
		if err := tenancy.BeginCredential(ctx, q, digest); err != nil {
			return fmt.Errorf("opening the invitation resolution: %w", err)
		}
		invitation, err := s.store.InvitationByToken(ctx, q, digest)
		if err != nil {
			if errors.Is(err, ErrInvitationNotFound) {
				return ErrInvitationNotFound
			}
			return fmt.Errorf("looking up the invitation: %w", err)
		}

		// REVOKED FIRST, AND IT BECOMES ErrInvitationNotFound.
		//
		// This is the check whose absence made a revoked invitation redeemable
		// (identity-30), and both halves of how it fails are deliberate.
		//
		// It runs before the other two because a withdrawal is the strongest thing
		// known about the token: whatever else is true of this row, an admin decided
		// it must not work. It answers NotFound rather than ErrInvitationRevoked
		// because openapi/v1.yaml already promises that "an invitation an admin
		// revoked is also 404 — it is not redeemable and there is nothing to redeem",
		// and because a distinct status would tell whoever holds the token that this
		// invitation was once real — which is the one piece of an answer an
		// enumeration of stolen tokens is trying to extract.
		//
		// The account's own admin surface does not come through here and is entitled
		// to the distinction: it reads revocation state directly instead of by
		// redeeming.
		if invitation.RevokedAt != nil {
			return ErrInvitationNotFound
		}

		// Order matters and it is the order a client would want them in: used before
		// expired, because an invitation that was accepted and has since expired is
		// "used" — the caller's link was already spent, and telling them to request a
		// new one would be wrong advice.
		if invitation.AcceptedAt != nil {
			return ErrInvitationUsed
		}
		if !invitation.ExpiresAt.After(now) {
			return ErrInvitationExpired
		}

		// Begin as the account the invitation names. It is on the row rather than
		// on the request, because accepting an invitation is the one account-scoped
		// write a caller reaches WITHOUT being a member of the account yet — that
		// is what the invitation is for. So there is no membership to resolve and
		// nothing on the context, and the membership INSERT below would otherwise
		// be refused with SQLSTATE 42501.
		//
		// The account id comes from the invitation row the caller presented, not
		// from a request body, so it is not a tenancy the caller chose.
		if err := tenancy.BeginAccount(ctx, q, invitation.AccountID); err != nil {
			return fmt.Errorf("beginning as the invited account: %w", err)
		}

		membership, err := s.store.AddMember(ctx, q, Membership{
			AccountID: invitation.AccountID,
			UserID:    in.User,
			Role:      invitation.Role,
		})
		if err != nil {
			return err
		}

		// Conditional: a second redemption of the same token updates zero rows
		// and rolls the whole transaction back, so two concurrent redemptions
		// cannot both produce a membership.
		//
		// ErrInvitationRevoked is the same withdrawal the check above catches,
		// arriving late: an admin revoked this token between the read and this
		// statement, so the row said "live" when it was read. The transaction
		// rolls back either way — no membership is created — and the caller gets
		// the same 404 it would have got had the revocation landed a moment
		// earlier, which is the only answer that keeps "what this token's status
		// is" from depending on how fast the machine was.
		if err := s.store.MarkInvitationAccepted(ctx, q, invitation.ID, now); err != nil {
			if errors.Is(err, ErrInvitationRevoked) {
				return ErrInvitationNotFound
			}
			if errors.Is(err, ErrInvitationUsed) {
				return ErrInvitationUsed
			}
			return err
		}

		// The member's address, read here and inside the transaction because the
		// event below carries it: the consumer that mails the welcome cannot read
		// the user row, so the event has to bring the address with it. See
		// outbox.NewMemberAccepted for why it is the member's address and not the
		// invitation's.
		member, err := s.users.ByID(ctx, q, in.User)
		if err != nil {
			return err
		}

		event, err := outbox.NewMemberAccepted(now, invitation.AccountID, in.User, member.Email, string(invitation.Role))
		if err != nil {
			return err
		}
		if err := s.events.Append(ctx, q, event); err != nil {
			return err
		}

		out = membership
		return nil
	})
	if err != nil {
		return Membership{}, err
	}
	return out, nil
}

// ChangeRoleInput is a request to change a membership's role.
type ChangeRoleInput struct {
	AccountID id.UUID
	UserID    id.UUID
	Role      Role
	// Actor is the authenticated caller. It is separate from UserID because the
	// two roles in the decision are different: the caller's authority to change
	// roles, and whose role is changing.
	Actor id.UUID
}

// ChangeRole moves a membership to a new role.
//
// The last-owner check and the role change are in one transaction, and the count
// is taken under a row lock (see Store.CountOwners). Without the lock two owners
// demoting each other at the same moment both see two owners, both succeed, and
// the account is left with nobody who can administer it — a state no later
// request can repair, because every one of them now fails the role check.
func (s *Service) ChangeRole(ctx context.Context, in ChangeRoleInput) (Membership, error) {
	if !in.Role.Valid() {
		return Membership{}, &FieldError{Field: "role", Code: CodeUnknownRole}
	}

	now := s.clock.Now()
	var out Membership

	err := s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		target, err := s.store.Member(ctx, q, in.AccountID, in.UserID)
		if err != nil {
			return err
		}
		if target.Role == in.Role {
			// A no-op is still a fact worth recording as a no-op, but it is not
			// worth an event: "the role changed" would be false.
			return nil
		}

		if err := s.guardLastOwner(ctx, q, in.AccountID, target, in.Role); err != nil {
			// The caller is the owner who would be left with nothing to run. That
			// is the case a person hits by accident, so it gets its own error and
			// its own sentence.
			if errors.Is(err, ErrLastOwner) && target.UserID == in.Actor {
				return ErrSelfRoleChange
			}
			return err
		}

		updated, err := s.store.SetRole(ctx, q, in.AccountID, in.UserID, in.Role)
		if err != nil {
			return err
		}

		event, err := outbox.NewMemberRoleChanged(now, in.AccountID, in.UserID, string(target.Role), string(in.Role))
		if err != nil {
			return err
		}
		if err := s.events.Append(ctx, q, event); err != nil {
			return err
		}

		out = updated
		return nil
	})
	if err != nil {
		return Membership{}, err
	}
	return out, nil
}

// guardLastOwner refuses a change that would leave the account with no owner.
//
// The count is read through CountOwners, which takes a row lock on the owner
// rows, so a concurrent change to a *different* membership cannot interleave
// between the check and the write. That is the whole reason the check is inside
// the transaction rather than before it: two owners demoting each other at the
// same moment both see two owners, both succeed, and the account is left with
// nobody who can administer it — a state no later request can repair, because
// every one of them now fails the role check.
//
// It returns ErrLastOwner in every case. ChangeRole upgrades that to
// ErrSelfRoleChange when the caller is the owner being demoted, because "you
// cannot demote yourself out of the last account you run" is more use to the
// person who hit it than the general form.
func (s *Service) guardLastOwner(ctx context.Context, q db.Querier, accountID id.UUID, target Membership, next Role) error {
	// Only a demotion can lose an owner. Promoting one adds to the count, and a
	// change between admin and member does not touch it.
	if target.Role != RoleOwner || next == RoleOwner {
		return nil
	}

	owners, err := s.store.CountOwners(ctx, q, accountID)
	if err != nil {
		return err
	}
	if owners > 1 {
		return nil
	}
	return ErrLastOwner
}

// RemoveMemberInput is a request to remove a membership.
type RemoveMemberInput struct {
	AccountID id.UUID
	UserID    id.UUID
	Actor     id.UUID
}

// RemoveMember deletes a membership and announces it.
//
// Two rules beyond the minimum role, which the middleware checks: an owner is
// only removed by an owner, and the last owner is never removed. The first is
// about the target's role rather than the caller's minimum, so it belongs here;
// the second is the same invariant ChangeRole guards.
func (s *Service) RemoveMember(ctx context.Context, in RemoveMemberInput) error {
	now := s.clock.Now()

	return s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		target, err := s.store.Member(ctx, q, in.AccountID, in.UserID)
		if err != nil {
			return err
		}

		if target.Role == RoleOwner {
			actor, err := s.store.Member(ctx, q, in.AccountID, in.Actor)
			if err != nil {
				return err
			}
			// An admin may remove members and other admins; the owner's
			// membership is a different object and only an owner touches it.
			if !actor.Role.AtLeast(RoleOwner) {
				return ErrOwnerProtected
			}
			if err := s.guardLastOwner(ctx, q, in.AccountID, target, RoleMember); err != nil {
				return err
			}
		}

		if err := s.store.RemoveMember(ctx, q, in.AccountID, in.UserID); err != nil {
			return err
		}

		// A CREDENTIAL THE MEMBER HELD IN THIS ACCOUNT IS REVOKED IN THE SAME
		// TRANSACTION, and this is the rule that took two attempts to get right.
		//
		// The obvious design is that the token stores no role and the resolution
		// query joins the membership — so a removal stops it on the next request
		// with nothing to invalidate. That part works. What it does NOT do is stop
		// the token coming BACK: the same user re-invited to the same account at
		// the same role satisfies the join again, and a contractor's CI credential
		// that was supposed to have died at offboarding quietly starts working the
		// day somebody re-adds them. The test that caught it is
		// TestARemovedMembershipStopsTheTokenOnTheNextRequest, in internal/httpapi.
		//
		// So the removal revokes explicitly. The row is kept, `revoked_at` is set,
		// and the credential is dead for good: a re-invite is a NEW grant and starts
		// from nothing, which is the only outcome an operator who offboarded
		// somebody would recognize as correct.
		//
		// The alternative considered and rejected: keying the token on the
		// membership's `created_at` so a re-invite's new row does not match. It
		// fails on a clock — two removals and re-adds inside one second, or any test
		// with a frozen clock, produce the same value and the token revives anyway.
		if s.revokes != nil {
			if err := s.revokes.RevokeAllForMember(ctx, q, in.AccountID, in.UserID, now); err != nil {
				return err
			}
		}

		event, err := outbox.NewMemberRemoved(now, in.AccountID, in.UserID, string(target.Role))
		if err != nil {
			return err
		}
		return s.events.Append(ctx, q, event)
	})
}

// TransferInput is a request to hand an account to another member.
type TransferInput struct {
	AccountID id.UUID
	// ToUserID is the member who becomes the owner. It must ALREADY be a member:
	// a transfer is not an invitation, and it takes no token, has no expiry and
	// cannot be refused by the person it names. Someone who is not in the account
	// has to be invited first, by a route that says so.
	ToUserID id.UUID
	// Actor is the authenticated caller. It is the OWNER's id, resolved from the
	// request's credential and never from a body field, because "am I the owner"
	// is the first question and answering it from the request would answer it from
	// the requester's own sentence.
	Actor id.UUID
}

// Transferred is the result of a successful transfer: both memberships, at the
// roles they now hold.
//
// It returns both rather than only the new owner because the interesting half is
// the demotion, and a caller that receives only the heir cannot render "you are
// no longer the owner of this account" without a second request to find out what
// they are now.
type Transferred struct {
	// Account is the account that changed hands. Nothing about it changed — the
	// id, name, slug and personal flag are all untouched — and it is here so the
	// response does not have to be assembled from the path.
	Account Account
	// PreviousOwner is the former owner's membership, at RoleAdmin.
	PreviousOwner Membership
	// NewOwner is the heir's membership, at RoleOwner.
	NewOwner Membership
}

// TransferOwnership hands an account to another member.
//
// FOUR RULES, AND THE ORDER IS THE ARGUMENT.
//
// The caller's authority is settled FIRST, before anything is said about whether
// this account could be transferred at all. That order is what keeps the
// refusals from being an oracle: an admin who asks learns they are not the owner
// and nothing about the account itself — not whether it is personal, not how many
// members it has. Reordering these two checks would let any admin of an account
// interrogate its shape.
//
//  1. the caller holds RoleOwner on THIS account   ErrNotOwner
//  2. the account is not personal                  ErrNotTransferable
//  3. the account has at least two members         ErrNotTransferable
//  4. the target is not the caller                 ErrTransferToSelf
//     and then the target must already be a member, which is ErrNotAMember from the
//     membership read rather than a rule of its own.
//
// Rule 2 IS JUMPSTART'S `team?` and rule 3 IS ITS `users.size >= 2`, ported
// rather than invented. Both say the same thing from two directions: a personal
// account has exactly one member by construction, so the second rule subsumes the
// first — and it is kept anyway, because a personal account is refused with the
// reason a person can act on. "You can hand this account to somebody" is a
// different answer from "there is nobody else in here to hand it to", and a
// future packet that adds a second member to a personal account must not
// silently make personal accounts transferable.
//
// # THE PREVIOUS OWNER BECOMES AN ADMIN
//
// This is jumpstart's "previous owner roles are unchanged", and it is the one
// place where its model and this one disagree about what unchanged MEANS.
// jumpstart stores ownership as a boolean on the account alongside a separate
// `admin` boolean on the membership, so an owner who was also an admin keeps the
// admin flag. Here a membership is exactly one of three ordered roles, so
// "everything they had except ownership" is precisely RoleAdmin: every
// capability owner carries over admin, and admin is the weakest role that has all
// of them.
//
// Choosing RoleMember instead would be a real loss of authority on the day of the
// handoff, and it is the reason transferring stays reversible: an heir who turns
// out to be unavailable is a problem, and a previous owner who can no longer
// rename the account, invite a member or remove one cannot fix it.
//
// # THE PROMOTION HAPPENS FIRST
//
// Inside one transaction the heir is promoted and only then is the previous owner
// demoted, and guardLastOwner is never consulted because it does not have to be:
// at every instant between the two statements the account has either one owner or
// two, and the transaction's commit is what makes the two-owner state unobservable
// from outside. Demoting first would pass through zero owners, and a concurrent
// request that read that state would conclude the account has nobody to administer
// it.
//
// The event is written in the same transaction as both role changes, which is the
// same rule every other use case in this file follows and the reason the event
// names both sides: see outbox.EventAccountOwnershipTransferred.
func (s *Service) TransferOwnership(ctx context.Context, in TransferInput) (Transferred, error) {
	if in.AccountID.IsZero() || in.ToUserID.IsZero() || in.Actor.IsZero() {
		return Transferred{}, ErrNotAMember
	}

	now := s.clock.Now()
	var out Transferred

	err := s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		// (1) The caller, on THIS account. Read from the membership table rather
		// than taken from the middleware's resolved role, for the same reason
		// Invite reads its inviter: the rule is about the use case, so it holds
		// however the use case is reached.
		actor, err := s.store.Member(ctx, q, in.AccountID, in.Actor)
		if err != nil {
			if errors.Is(err, ErrNotAMember) {
				// A stranger is refused the same way an admin is. Ownership is
				// per-account, so holding the owner role somewhere else is
				// nothing, and ErrNotOwner says nothing about this account.
				return ErrNotOwner
			}
			return err
		}
		if !actor.Role.AtLeast(RoleOwner) {
			return ErrNotOwner
		}

		account, err := s.store.ByID(ctx, q, in.AccountID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return ErrNotFound
			}
			return err
		}

		// (2) Personal accounts are the system's, not a team's.
		if account.Personal {
			return ErrNotTransferable
		}

		// (4) Before the member count, because it is the caller's own mistake and
		// the sentence that answers it is different. Checked here rather than
		// after the target read so that "you cannot transfer this to yourself" is
		// not gated behind whether the account had two members.
		if in.ToUserID == in.Actor {
			return ErrTransferToSelf
		}

		// (3) Two members, counted inside the transaction so a concurrent removal
		// cannot land between the count and the promotion.
		members, err := s.store.Members(ctx, q, in.AccountID)
		if err != nil {
			return err
		}
		if len(members) < 2 {
			return ErrNotTransferable
		}

		// The target must already be in the account. ErrNotAMember here is the
		// same sentinel a stranger gets, which is right: this request does not
		// admit anybody, so "not a member" is the whole of what it knows. The
		// membership is read for the role it holds today, which travels in no
		// response field and is here only so the promotion's precondition is a
		// read rather than an assumption.
		if _, err := s.store.Member(ctx, q, in.AccountID, in.ToUserID); err != nil {
			return err
		}

		// THE HEIR FIRST. See the method comment: at no point does the account
		// pass through a state with no owner.
		promoted, err := s.store.SetRole(ctx, q, in.AccountID, in.ToUserID, RoleOwner)
		if err != nil {
			return err
		}

		demoted, err := s.store.SetRole(ctx, q, in.AccountID, in.Actor, RoleAdmin)
		if err != nil {
			return err
		}

		event, err := outbox.NewAccountOwnershipTransferred(now, in.AccountID, actor.UserID, promoted.UserID, in.Actor)
		if err != nil {
			return err
		}
		if err := s.events.Append(ctx, q, event); err != nil {
			return err
		}

		out = Transferred{Account: account, PreviousOwner: demoted, NewOwner: promoted}
		return nil
	})
	if err != nil {
		return Transferred{}, err
	}
	return out, nil
}

// truncateName shortens an over-long personal account name to MaxNameLength.
//
// It exists for one case: a registration whose email local part is longer than a
// name may be. Refusing the registration over the name of an account the user
// never chose would be the wrong trade, and the name is the only field that has
// to be shortened — the slug is derived from the user id regardless.
func truncateName(name string) string {
	runes := []rune(name)
	if len(runes) <= MaxNameLength {
		return name
	}
	return string(runes[:MaxNameLength])
}

// asFieldError converts a users.FieldError into this package's own.
//
// The two types are structurally identical and deliberately separately declared:
// a shared one would put an edge between users and accounts for the sake of four
// fields, and the HTTP layer would then have to know that an accounts endpoint
// can fail with a users error. Everything that is not a *users.FieldError is
// returned unchanged, so a store failure does not come back as a 422.
func asFieldError(err error) error {
	var fe *users.FieldError
	if !errors.As(err, &fe) {
		return err
	}
	return &FieldError{Field: fe.Field, Code: fe.Code}
}
