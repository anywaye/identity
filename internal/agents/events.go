package agents

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
)


const eventColumns = `id, agent_id, action, actor_user_id, actor_token_id, trace_id, occurred_at`

// Action is one of the things that can be done to an agent.
//
// IT IS A CLOSED SET IN GO AND NOT A CHECK IN THE SCHEMA, for the reason
// useraudit gives: a closed vocabulary is a code fact, and putting it in the
// schema would make adding an action a migration. A row holding an action this
// build does not know about is refused at the point of use, which is the
// fail-closed direction.
type Action string

const (
	ActionRegistered Action = "agent.registered"

	ActionClaimed Action = "agent.claimed"

	ActionLinkRefreshed Action = "agent.link_refreshed"

	ActionEnabled Action = "agent.enabled"

	ActionDisabled Action = "agent.disabled"

	ActionTokenMinted Action = "agent.token_minted"

	ActionTokenRevoked Action = "agent.token_revoked"
)

// AllActions is the vocabulary, in a fixed order, for the reason
// useraudit.AllActions is: the order reaches a response, and a map's iteration
// order would make two identical requests answer differently.
func AllActions() []Action {
	return []Action{
		ActionRegistered,
		ActionClaimed,
		ActionLinkRefreshed,
		ActionEnabled,
		ActionDisabled,
		ActionTokenMinted,
		ActionTokenRevoked,
	}
}

// ErrUnknownAction is a row or a request naming an action this build does not
// implement.
var ErrUnknownAction = errors.New("not an action this package records")

// IsKnownAction reports whether this build implements the action. Exact match,
// never a prefix: `claim` is not `agent.claimed`.
func IsKnownAction(action string) bool {
	for _, known := range AllActions() {
		if string(known) == action {
			return true
		}
	}
	return false
}

const maxTraceIDLength = 64

// Event is a request to record one thing that happened.
//
// TWO ACTOR FIELDS AND THEY ARE A PAIR, which is the table's
// agent_events_actor_is_whole CHECK: a registration has neither, a claim has a
// human, a rotation has a credential, and a row carrying one without the other is
// a half-written record of who did something.
//
// NEITHER IS A TOKEN VALUE. UserID is a row in `users` and TokenID is a row in
// `agent_tokens` — apikeys.Key has a TokenDigest field a handler holds, and an
// audit path is exactly where a careless `%+v` of it lands.
type Event struct {
	AgentID    id.UUID
	Action     Action
	UserID     id.UUID
	TokenID    id.UUID
	TraceID    string
	OccurredAt time.Time
}

// EventRecord is one row of agent_events.
type EventRecord struct {
	ID         id.UUID
	AgentID    id.UUID
	Action     Action
	UserID     id.UUID
	TokenID    id.UUID
	TraceID    string
	OccurredAt time.Time
}

func (e Event) validate() error {
	if e.AgentID.IsZero() {
		return errors.New("an agent event must name the agent it happened to")
	}
	if !IsKnownAction(string(e.Action)) {
		return fmt.Errorf("%w: %q", ErrUnknownAction, e.Action)
	}
	hasUser, hasToken := !e.UserID.IsZero(), !e.TokenID.IsZero()
	if hasUser && hasToken {
		return errors.New("an agent event names one actor, not two")
	}
	if e.TraceID == "" {
		return errors.New("an agent event must carry the request's trace id")
	}
	if len(e.TraceID) > maxTraceIDLength {
		return fmt.Errorf("an agent event's trace id is %d characters, over the %d accepted", len(e.TraceID), maxTraceIDLength)
	}
	if e.OccurredAt.IsZero() {
		return errors.New("an agent event must carry the instant it happened")
	}
	return nil
}

// Append writes one event row.
//
// q is a db.Querier rather than the pool because this is called from INSIDE the
// transaction the mutation ran in — the same-transaction guarantee, stated the
// way useraudit.Store.Append states it. A store that reached for its own pool
// here would be writing the audit row in a SECOND transaction, which is the bug
// the requirement exists to prevent, and invisible because both writes would
// succeed.
func (s *Store) AppendEvent(ctx context.Context, q db.Querier, e Event) (EventRecord, error) {
	if err := e.validate(); err != nil {
		return EventRecord{}, err
	}
	if q == nil {
		return EventRecord{}, errors.New("appending an agent event: no querier was supplied")
	}

	const query = `
		INSERT INTO agent_events
			(agent_id, action, actor_user_id, actor_token_id, trace_id, occurred_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING ` + eventColumns

	rec, err := scanEvent(q.QueryRow(ctx, query,
		e.AgentID, string(e.Action), nullable(e.UserID), nullable(e.TokenID),
		e.TraceID, e.OccurredAt))
	if err != nil {
		return EventRecord{}, fmt.Errorf("inserting an agent event: %w", err)
	}
	return rec, nil
}

// ListEvents returns what has happened to an agent, newest first.
//
// It is the only read, and it is a read because an operator asking "who claimed
// this and when" is a real question with no other answer.
func (s *Store) ListEvents(ctx context.Context, q db.Querier, agentID id.UUID) ([]EventRecord, error) {
	out := make([]EventRecord, 0, 2)
	if agentID.IsZero() {
		return out, nil
	}

	const query = `
		SELECT ` + eventColumns + `
		FROM agent_events
		WHERE agent_id = $1
		ORDER BY occurred_at DESC, id DESC`

	rows, err := q.Query(ctx, query, agentID)
	if err != nil {
		return nil, fmt.Errorf("agents: listing an agent's events: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("agents: reading an agent's events: %w", err)
		}
		out = append(out, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("agents: reading an agent's events: %w", err)
	}
	return out, nil
}

func scanEvent(row interface{ Scan(...any) error }) (EventRecord, error) {
	var (
		e     EventRecord
		user  *id.UUID
		token *id.UUID
	)
	err := row.Scan(&e.ID, &e.AgentID, &e.Action, &user, &token, &e.TraceID, &e.OccurredAt)
	if err != nil {
		if errors.Is(err, errNoRows) {
			return EventRecord{}, errNoRows
		}
		return EventRecord{}, fmt.Errorf("agents: scanning an agent event: %w", err)
	}
	if user != nil {
		e.UserID = *user
	}
	if token != nil {
		e.TokenID = *token
	}
	return e, nil
}

func nullable(rowID id.UUID) any {
	if rowID.IsZero() {
		return nil
	}
	return rowID
}
