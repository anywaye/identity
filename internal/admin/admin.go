package admin

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
)

// Action is one of the things the admin surface can do.
//
// IT IS A CLOSED SET IN GO AND NOT A CHECK IN THE SCHEMA, and the reason is the
// one 00011 gives for api_keys.scopes: a closed vocabulary is a code fact, and
// putting it in the schema would make adding an action a migration. A row holding
// an action this build does not know about is refused when it is read, which is
// the fail-closed direction — treating an unknown action as "and so anything
// goes" is the bug a future migration would otherwise introduce silently.
type Action string

const (
	ActionInvitationRevoked Action = "invitation.revoked"

	ActionInvitationsRevoked Action = "invitations.revoked"
)

// AllActions is the vocabulary, in a fixed order, for the same reason
// apikeys.AllScopes is: the order reaches a response and a map's iteration order
// would make two identical requests answer differently.
func AllActions() []Action {
	return []Action{ActionInvitationRevoked, ActionInvitationsRevoked}
}

// ErrUnknownAction is a row or a request naming an action this build does not
// implement.
var ErrUnknownAction = errors.New("not an action the admin surface performs")

func validateAction(action string) error {
	for _, known := range AllActions() {
		if string(known) == action {
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ErrUnknownAction, action)
}

var (
	ErrInvitationNotRevocable = errors.New("no revocable invitation with that id in this account")

	ErrNoInvitations = errors.New("a bulk revocation must name at least one invitation")

	ErrTooManyInvitations = errors.New("too many invitation ids in one bulk revocation")

	ErrBadCursor = errors.New("the page cursor is not one this service issued")

	ErrBadLimit = errors.New("page size is outside the range the audit trail accepts")
)

const (
	DefaultAuditLogLimit = 25

	MaxAuditLogLimit = 100

	MaxBulkInvitationIDs = 50

	maxTargetLength = 64
)

// Page is one page of the audit trail, as the route's query string spells it.
type Page struct {
	Limit int
	Before string
}

// Normalised resolves the page to a usable limit, or refuses it.
//
// It is exported because the HTTP layer validates the query string against it, so
// the 422 can name the field that was wrong. The use case calls it again on the
// way in, and the two agreeing is the point: the handler's check produces a good
// error, the use case's is the guarantee a caller cannot route around by calling
// the service directly.
func (p Page) Normalised() (int, error) {
	switch {
	case p.Limit < 0, p.Limit > MaxAuditLogLimit:
		return 0, fmt.Errorf("%w: %d is outside 1..%d", ErrBadLimit, p.Limit, MaxAuditLogLimit)
	case p.Limit == 0:
		return DefaultAuditLogLimit, nil
	default:
		return p.Limit, nil
	}
}

// Cursor decodes the opaque page token into the (instant, id) pair the keyset
// comparison needs. An empty cursor is the first page, and a malformed one is an
// error rather than a silent first page.
//
// It is exported so the HTTP layer can name `before` as the field that was wrong;
// the decoding itself is not reimplemented there.
//
// IT REFUSES RATHER THAN DEGRADES. A client that sends a cursor this build cannot
// read — a truncated one, one from a future build, a hand-typed value — gets
// ErrBadCursor. Answering it with the first page instead would look like data
// loss to an operator paging through a trail, and they would conclude the rows
// are missing rather than that their token was wrong.
func (p Page) Cursor() (time.Time, id.UUID, error) {
	if p.Before == "" {
		return time.Time{}, id.UUID{}, nil
	}

	raw, err := base64.RawURLEncoding.DecodeString(p.Before)
	if err != nil {
		return time.Time{}, id.UUID{}, fmt.Errorf("%w: not a cursor this build issued", ErrBadCursor)
	}

	instant, rowID, found := strings.Cut(string(raw), "|")
	if !found {
		return time.Time{}, id.UUID{}, fmt.Errorf("%w: not a cursor this build issued", ErrBadCursor)
	}
	parsed, err := time.Parse(time.RFC3339Nano, instant)
	if err != nil {
		return time.Time{}, id.UUID{}, fmt.Errorf("%w: not a cursor this build issued", ErrBadCursor)
	}
	uuid, err := id.Parse(rowID)
	if err != nil || uuid.IsZero() {
		return time.Time{}, id.UUID{}, fmt.Errorf("%w: not a cursor this build issued", ErrBadCursor)
	}
	return parsed, uuid, nil
}

func encodeCursor(occurredAt time.Time, rowID id.UUID) string {
	return base64.RawURLEncoding.EncodeToString(
		[]byte(occurredAt.UTC().Format(time.RFC3339Nano) + "|" + rowID.String()))
}

// Actor is who performed an admin action.
//
// TWO IDS AND A TRACE ID, and the absence of a third field is the design. Actor
// is what reaches account_audit_log, and the api key's VALUE must never reach a
// table an operator reads during an incident; its row id is what an operator
// needs anyway, because that is the id they revoke by.
type Actor struct {
	UserID id.UUID
	KeyID id.UUID
	TraceID string
}

func (a Actor) validate() error {
	if a.UserID.IsZero() || a.KeyID.IsZero() {
		return errors.New("an admin action must name both the user and the api key that performed it")
	}
	return nil
}

// Entry is a request to record one admin action. It is what an operation builds
// from its own inputs; Record is what comes back out of the table.
type Entry struct {
	AccountID id.UUID
	Action    Action
	Actor     Actor
	Target string
	Affected int
	OccurredAt time.Time
}

// Record is one row of account_audit_log.
type Record struct {
	ID          id.UUID
	AccountID   id.UUID
	Action      Action
	ActorUserID id.UUID
	ActorKeyID  id.UUID
	Target      string
	Affected    int
	TraceID     string
	OccurredAt  time.Time
	Next string
}

func (e Entry) validate() error {
	if e.AccountID.IsZero() {
		return errors.New("an audit record must name the account it was taken in")
	}
	if err := validateAction(string(e.Action)); err != nil {
		return err
	}
	if err := e.Actor.validate(); err != nil {
		return err
	}
	if strings.TrimSpace(e.Target) == "" {
		return errors.New("an audit record must name what the action was taken on")
	}
	if len(e.Target) > maxTargetLength {
		return fmt.Errorf("an audit record's target is %d characters, over the %d accepted", len(e.Target), maxTargetLength)
	}
	if e.Affected < 0 {
		return fmt.Errorf("an audit record's affected count is %d, which no action can report", e.Affected)
	}
	return nil
}

// UnitOfWork runs a function inside a transaction. db.TxRunner implements it; the
// interface is what lets the atomicity below be tested without Postgres, and
// store_test.go and the HTTP layer's integration test are what prove it against
// a real database.
type UnitOfWork interface {
	Do(ctx context.Context, fn func(ctx context.Context, q db.Querier) error) error
}

// AuditStore is the slice of the audit table these use cases need.
//
// APPEND AND LIST AND NOTHING ELSE. There is no Update and no Delete method, and
// that is not an omission waiting to be filled: the table refuses both at the
// database (migrations/00012), so a method here would be a function that can only
// ever return an error. The interface is the shape, and the trigger is the
// guarantee.
type AuditStore interface {
	Append(ctx context.Context, q db.Querier, e Entry) (Record, error)
	List(ctx context.Context, q db.Querier, accountID id.UUID, page Page) ([]Record, error)
}

// InvitationRevoker is the slice of the accounts store the two operations need.
//
// Declared here rather than taking *accounts.Store so a test can program a
// failure at the exact statement that matters — the mutation failing is how the
// "no audit record for an action that did not happen" test is written.
type InvitationRevoker interface {
	RevokePendingInvitation(ctx context.Context, q db.Querier, accountID, invitationID id.UUID) (int, error)
	RevokePendingInvitations(ctx context.Context, q db.Querier, accountID id.UUID, ids []id.UUID) (int, error)
}

// Service is the admin surface's use cases.
type Service struct {
	tx      UnitOfWork
	store   AuditStore
	revoker InvitationRevoker
	clock   clock.Clock
	reads db.QuerierSource
}

// NewService builds the admin use cases.
//
// reads is separate from tx on purpose, for the reason on the field: writes are
// transactional and reads are not, and a Service with one querier for both would
// have to open a transaction to serve a GET.
func NewService(tx UnitOfWork, store AuditStore, revoker InvitationRevoker, reads db.QuerierSource, clk clock.Clock) *Service {
	return &Service{tx: tx, store: store, revoker: revoker, reads: reads, clock: clk}
}

// Mutation is the work an admin action performs.
//
// IT RETURNS THE COUNT IT CHANGED rather than just an error, and the reason is
// that the count is a fact about the database that only the mutation knows: the
// audit row records what actually changed, not what was asked for. A request
// naming six invitations where two were already revoked must record six, because
// six is the truth.
type Mutation func(ctx context.Context, q db.Querier) (int, error)

// Audited runs a mutation and records it, in ONE transaction.
//
// This is the whole of the atomicity property and it is deliberately the only
// way an operation on this Service touches the database. The order inside the
// transaction is mutation-then-record, and it is that order for the count: the
// record needs the number the mutation reports.
//
// The failure direction is the one that matters and it falls out of the
// transaction rather than being checked:
//
//   - the record fails  → the transaction rolls back → the mutation did not happen
//   - the mutation fails → the transaction rolls back → no record claims it did
//
// Neither needs a compensating action, which is the property a same-transaction
// guarantee is for: there is no interleaving in which one of the two is visible
// without the other.
func (s *Service) Audited(ctx context.Context, e Entry, mutate Mutation) (int, error) {
	if err := e.validate(); err != nil {
		return 0, err
	}
	if mutate == nil {
		return 0, db.ErrNilTxFunc
	}

	var affected int
	err := s.tx.Do(ctx, func(ctx context.Context, q db.Querier) error {
		count, err := mutate(ctx, q)
		if err != nil {
			return fmt.Errorf("performing the admin action: %w", err)
		}
		affected = count

		e.Affected = count
		e.OccurredAt = s.clock.Now()
		rec, err := s.store.Append(ctx, q, e)
		if err != nil {
			return fmt.Errorf("appending the audit record: %w", err)
		}
		if rec.ID.IsZero() {
			return errors.New("appending the audit record reported success and returned no id")
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return affected, nil
}

// RevokeInvitationInput is one invitation and the admin removing it.
type RevokeInvitationInput struct {
	AccountID    id.UUID
	InvitationID id.UUID
	Actor        Actor
}

// RevokeInvitation revokes one pending invitation.
//
// ErrInvitationNotRevocable and nothing else: the store cannot tell the caller
// which of the four reasons applied, and a caller that could is a caller probing
// which invitation ids exist.
//
// It reports how many rows changed, which is 0 for an invitation that was already
// revoked and 1 otherwise. A repeated call is not an error — revoking twice is
// idempotent, and a client retrying after a timeout must not get a 404 for a
// revocation that did happen.
func (s *Service) RevokeInvitation(ctx context.Context, in RevokeInvitationInput) (int, error) {
	if in.InvitationID.IsZero() {
		return 0, ErrInvitationNotRevocable
	}

	entry := Entry{
		AccountID: in.AccountID,
		Action:    ActionInvitationRevoked,
		Actor:     in.Actor,
		Target:    in.InvitationID.String(),
	}
	return s.Audited(ctx, entry, func(ctx context.Context, q db.Querier) (int, error) {
		return s.revoker.RevokePendingInvitation(ctx, q, in.AccountID, in.InvitationID)
	})
}

// RevokeInvitationsInput is many invitations and the admin revoking them.
type RevokeInvitationsInput struct {
	AccountID id.UUID
	InvitationIDs []id.UUID
	Actor         Actor
}

// RevokeInvitations revokes many pending invitations in one transaction and
// writes ONE audit row for the lot.
//
// The bounds are refused rather than clamped, and this is the packet's third
// property stated as code: a bulk operation is the one where an off-by-one is an
// outage, so it does not get the same shape as a single operation and it does
// not get a silent answer.
//
// A duplicate id inside the array is not an error and not double-counted: the
// store's count is the number of rows that changed, so naming the same
// invitation twice records one revocation, which is the truth.
func (s *Service) RevokeInvitations(ctx context.Context, in RevokeInvitationsInput) (int, error) {
	ids, err := validateBulkIDs(in.InvitationIDs)
	if err != nil {
		return 0, err
	}

	entry := Entry{
		AccountID: in.AccountID,
		Action:    ActionInvitationsRevoked,
		Actor:     in.Actor,
		Target: "invitation-revocations",
	}
	return s.Audited(ctx, entry, func(ctx context.Context, q db.Querier) (int, error) {
		return s.revoker.RevokePendingInvitations(ctx, q, in.AccountID, ids)
	})
}

func validateBulkIDs(ids []id.UUID) ([]id.UUID, error) {
	if len(ids) == 0 {
		return nil, ErrNoInvitations
	}
	if len(ids) > MaxBulkInvitationIDs {
		return nil, fmt.Errorf("%w: %d is over the %d accepted", ErrTooManyInvitations, len(ids), MaxBulkInvitationIDs)
	}

	seen := make(map[id.UUID]bool, len(ids))
	out := make([]id.UUID, 0, len(ids))
	for _, one := range ids {
		if one.IsZero() || seen[one] {
			continue
		}
		seen[one] = true
		out = append(out, one)
	}
	if len(out) == 0 {
		return nil, ErrNoInvitations
	}
	return out, nil
}

// List returns one bounded page of an account's audit trail, newest first.
//
// It is the only read on this surface, and it is bounded twice over: the page
// size is checked here rather than trusted, and the cursor is a keyset rather
// than an offset so a concurrent append cannot make the operator skip or repeat
// a row.
//
// The returned records carry the cursor for the NEXT page in Record.Next, already
// encoded. A handler that forgot to thread it back would return a first page and
// an operator would have no way to ask for the second — so the cursor is a field
// on the row rather than something the caller assembles.
func (s *Service) List(ctx context.Context, accountID id.UUID, page Page) ([]Record, error) {
	if accountID.IsZero() {
		return nil, ErrInvitationNotRevocable
	}
	limit, err := page.Normalised()
	if err != nil {
		return nil, err
	}
	_, _, err = page.Cursor()
	if err != nil {
		return nil, err
	}
	return s.store.List(ctx, s.reads.Queryer(), accountID, Page{Limit: limit, Before: page.Before})
}
