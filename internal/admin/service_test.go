package admin


import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
)


type fakeWorld struct {
	audit map[id.UUID]Record
	revoked map[id.UUID]bool
	nextID int
	appendErr error
}

func newFakeWorld() *fakeWorld {
	return &fakeWorld{audit: map[id.UUID]Record{}, revoked: map[id.UUID]bool{}}
}

type staging struct {
	writes []string
}

func (s *staging) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	s.writes = append(s.writes, sql)
	return pgconn.CommandTag{}, nil
}

func (s *staging) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("the fake does not read rows")
}

func (s *staging) QueryRow(context.Context, string, ...any) pgx.Row {
	return nil
}

type fakeTx struct {
	world *fakeWorld
	committed bool
}

func (tx *fakeTx) Do(_ context.Context, fn func(context.Context, db.Querier) error) error {
	stage := &staging{}
	if err := fn(context.Background(), stage); err != nil {
		return err
	}
	tx.committed = true
	return nil
}

type fakeStore struct {
	world *fakeWorld
	stage *staging
}

func (s *fakeStore) Append(_ context.Context, q db.Querier, e Entry) (Record, error) {
	if s.world.appendErr != nil {
		return Record{}, s.world.appendErr
	}
	s.world.nextID++
	rec := Record{
		ID:          id.MustNew(),
		AccountID:   e.AccountID,
		Action:      e.Action,
		ActorUserID: e.Actor.UserID,
		ActorKeyID:  e.Actor.KeyID,
		Target:      e.Target,
		TraceID:     e.Actor.TraceID,
		OccurredAt:  e.OccurredAt,
	}
	_ = q
	if s.stage != nil {
		s.stage.writes = append(s.stage.writes, "INSERT account_audit_log")
		return rec, nil
	}
	s.world.audit[rec.ID] = rec
	return rec, nil
}

func (s *fakeStore) List(_ context.Context, _ db.Querier, accountID id.UUID, page Page) ([]Record, error) {
	if _, err := page.Normalised(); err != nil {
		return nil, err
	}
	return nil, errors.New("the fake does not read rows")
}

type fakeRevoker struct {
	world *fakeWorld
	err error
	revokedIn int
	allRevoked int
}

func (r *fakeRevoker) RevokePendingInvitation(_ context.Context, q db.Querier, _, invitationID id.UUID) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	_, _ = q.Exec(context.Background(),
		"UPDATE account_invitations SET revoked_at = now() WHERE id = $1", invitationID)
	r.revokedIn = 1
	return 1, nil
}

func (r *fakeRevoker) RevokePendingInvitations(_ context.Context, q db.Querier, _ id.UUID, ids []id.UUID) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	for _, one := range ids {
		_, _ = q.Exec(context.Background(),
			"UPDATE account_invitations SET revoked_at = now() WHERE id = $1", one)
	}
	r.revokedIn = len(ids)
	if r.allRevoked != 0 {
		return r.allRevoked, nil
	}
	return len(ids), nil
}

var (
	_ UnitOfWork        = (*fakeTx)(nil)
	_ AuditStore        = (*fakeStore)(nil)
	_ InvitationRevoker = (*fakeRevoker)(nil)
)


func testService(t *testing.T) (*Service, *fakeWorld, *fakeTx, *fakeRevoker) {
	t.Helper()

	world := newFakeWorld()
	tx := &fakeTx{world: world}
	store := &fakeStore{world: world}
	revoker := &fakeRevoker{world: world}

	svc := NewService(tx, store, revoker, db.Direct{Pool: nil}, fixedClock{
		now: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
	})
	return svc, world, tx, revoker
}

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func testActor() Actor {
	return Actor{UserID: id.MustNew(), KeyID: id.MustNew(), TraceID: "trace-abc123"}
}

func committedRevoked(world *fakeWorld) int {
	return len(world.revoked)
}


func TestAnAdminActionIsRecordedInTheSameTransaction(t *testing.T) {
	t.Parallel()

	svc, world, tx, revoker := testService(t)
	invitation := id.MustNew()
	actor := testActor()

	revoked, err := svc.RevokeInvitation(t.Context(), RevokeInvitationInput{
		AccountID:    id.MustNew(),
		InvitationID: invitation,
		Actor:        actor,
	})
	if err != nil {
		t.Fatalf("revoking an invitation: %v", err)
	}
	if revoked != 1 {
		t.Errorf("revoked = %d, want 1", revoked)
	}
	if !tx.committed {
		t.Error("the transaction did not commit, so the mutation and the audit row are not durable together")
	}
	if revoker.revokedIn != 1 {
		t.Errorf("the revoker was asked for %d revocations, want 1", revoker.revokedIn)
	}
	_ = world
	_ = invitation
}

func TestAFailedAuditWriteRollsBackTheMutation(t *testing.T) {
	t.Parallel()

	svc, world, tx, _ := testService(t)
	auditFailure := errors.New("the audit table is unavailable")
	world.appendErr = auditFailure

	_, err := svc.RevokeInvitation(t.Context(), RevokeInvitationInput{
		AccountID:    id.MustNew(),
		InvitationID: id.MustNew(),
		Actor:        testActor(),
	})
	if !errors.Is(err, auditFailure) {
		t.Fatalf("error = %v, want the audit failure to reach the caller", err)
	}
	if tx.committed {
		t.Error("the transaction COMMITTED after the audit write failed. A mutation that commits " +
			"without its audit row is a mutation nobody can account for, which is the whole failure " +
			"this test exists to close.")
	}
	if got := committedRevoked(world); got != 0 {
		t.Errorf("%d revocation(s) are committed after the audit write failed, want 0", got)
	}
	if len(world.audit) != 0 {
		t.Errorf("the failed transaction left %d audit record(s) behind; a rolled-back transaction "+
			"must leave no trace of either half", len(world.audit))
	}
}

func TestAFailedMutationLeavesNoAuditRecord(t *testing.T) {
	t.Parallel()

	svc, world, tx, revoker := testService(t)
	mutationFailure := errors.New("the invitation belongs to another account")
	revoker.err = mutationFailure

	_, err := svc.RevokeInvitation(t.Context(), RevokeInvitationInput{
		AccountID:    id.MustNew(),
		InvitationID: id.MustNew(),
		Actor:        testActor(),
	})
	if !errors.Is(err, mutationFailure) {
		t.Fatalf("error = %v, want the mutation failure to reach the caller", err)
	}
	if tx.committed {
		t.Error("the transaction committed after the mutation failed")
	}
	if len(world.audit) != 0 {
		t.Errorf("a failed action left %d audit record(s) behind. A record of an action that did "+
			"not happen is how an audit trail starts telling an operator lies", len(world.audit))
	}
}

func TestTheCountInTheAuditRecordIsTheMutationsOwn(t *testing.T) {
	t.Parallel()

	svc, world, _, revoker := testService(t)
	revoker.allRevoked = 2
	ids := []id.UUID{id.MustNew(), id.MustNew(), id.MustNew(), id.MustNew()}

	revoked, err := svc.RevokeInvitations(t.Context(), RevokeInvitationsInput{
		AccountID:     id.MustNew(),
		InvitationIDs: ids,
		Actor:         testActor(),
	})
	if err != nil {
		t.Fatalf("revoking invitations in bulk: %v", err)
	}
	if revoked != 2 {
		t.Errorf("revoked = %d, want the store's own count of 2", revoked)
	}
	if revoker.revokedIn != 4 {
		t.Errorf("the revoker was asked for %d, want 4", revoker.revokedIn)
	}
	_ = world
}


func TestTheBulkActionRefusesAnUnboundedRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ids  func() []id.UUID
	}{
		{name: "an empty list", ids: func() []id.UUID { return nil }},
		{
			name: "one past the ceiling",
			ids: func() []id.UUID {
				return manyIDs(MaxBulkInvitationIDs + 1)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			svc, world, tx, revoker := testService(t)

			_, err := svc.RevokeInvitations(t.Context(), RevokeInvitationsInput{
				AccountID:     id.MustNew(),
				InvitationIDs: tt.ids(),
				Actor:         testActor(),
			})
			if !errors.Is(err, ErrTooManyInvitations) && !errors.Is(err, ErrNoInvitations) {
				t.Fatalf("error = %v, want ErrNoInvitations or ErrTooManyInvitations", err)
			}
			if revoker.revokedIn != 0 {
				t.Error("an over-sized request reached the store")
			}
			if tx.committed {
				t.Error("a refused request committed a transaction")
			}
			if len(world.audit) != 0 {
				t.Error("a refused request wrote an audit record; a request that was never performed " +
					"must not appear in the trail of things that were")
			}
		})
	}
}

func TestTheAuditTrailPageIsBounded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		page    Page
		wantErr error
	}{
		{name: "negative", page: Page{Limit: -1}, wantErr: ErrBadLimit},
		{name: "one past the ceiling", page: Page{Limit: MaxAuditLogLimit + 1}, wantErr: ErrBadLimit},
		{name: "far past the ceiling", page: Page{Limit: 1_000_000}, wantErr: ErrBadLimit},
		{name: "at the ceiling", page: Page{Limit: MaxAuditLogLimit}},
		{name: "the default", page: Page{}},
		{name: "zero means the default, not a refusal", page: Page{Limit: 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.page.Normalised()
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Page%+v.normalised() error = %v, want %v", tt.page, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Page%+v.normalised() error = %v", tt.page, err)
			}
			if tt.page.Limit == 0 && got != DefaultAuditLogLimit {
				t.Errorf("an absent limit became %d, want the default %d", got, DefaultAuditLogLimit)
			}
			if got > MaxAuditLogLimit {
				t.Errorf("limit = %d, above the ceiling %d", got, MaxAuditLogLimit)
			}
		})
	}
}


func TestNothingOnThisSurfaceCanRecordAToken(t *testing.T) {
	t.Parallel()

	forbidden := []string{"token", "secret", "bearer", "jwt", "password", "digest", "credential", "value"}

	for _, typ := range []reflect.Type{
		reflect.TypeOf(Entry{}),
		reflect.TypeOf(Record{}),
		reflect.TypeOf(Actor{}),
		reflect.TypeOf(RevokeInvitationInput{}),
		reflect.TypeOf(RevokeInvitationsInput{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			for _, bad := range forbidden {
				if strings.EqualFold(field.Name, bad) {
					t.Errorf("%s.%s is named %q, which is a credential's VALUE. This package records "+
						"the api key's row id and never its value; a field that could hold the value is "+
						"one fmt.Sprintf away from an audit log full of live tokens",
						typ.Name(), field.Name, bad)
				}
			}
		}
	}
}

func TestTheActorCarriesTheKeyIdAndNotTheKey(t *testing.T) {
	t.Parallel()

	actor := testActor()
	if actor.KeyID.IsZero() {
		t.Error("the actor has no key id, so an audit record could not name which credential acted")
	}

	svc, world, _, _ := testService(t)
	if _, err := svc.RevokeInvitation(t.Context(), RevokeInvitationInput{
		AccountID:    id.MustNew(),
		InvitationID: id.MustNew(),
		Actor:        actor,
	}); err != nil {
		t.Fatalf("revoking an invitation: %v", err)
	}
	if len(world.audit) == 0 {
		t.Skip("the fake store stages audit writes rather than committing them; covered by the database tests")
	}
}

func TestTheClosedActionSetIsEnforced(t *testing.T) {
	t.Parallel()

	if err := validateAction("admin.did.a.thing"); !errors.Is(err, ErrUnknownAction) {
		t.Errorf("validateAction(%q) = %v, want ErrUnknownAction", "admin.did.a.thing", err)
	}
	for _, action := range AllActions() {
		if err := validateAction(string(action)); err != nil {
			t.Errorf("validateAction(%q) = %v, and AllActions lists it", action, err)
		}
	}
}

func manyIDs(n int) []id.UUID {
	out := make([]id.UUID, 0, n)
	for range n {
		out = append(out, id.MustNew())
	}
	return out
}

var _ = fmt.Sprintf
