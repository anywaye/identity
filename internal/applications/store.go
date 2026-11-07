package applications

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/anywaye/identity/internal/platform/db"

	"github.com/jackc/pgx/v5"
)

// Store is the applications table.
type Store struct {
	pool db.Pool
}

// NewStore returns a Store backed by pool.
func NewStore(pool db.Pool) *Store { return &Store{pool: pool} }

const applicationColumns = "id, key, name, kind, domain, created_at"

// ByKey looks an application up by its key. Returns ErrNotFound when absent.
func (s *Store) ByKey(ctx context.Context, q db.Querier, key string) (Application, error) {
	query := "SELECT " + applicationColumns + " FROM applications WHERE key = $1"

	var a Application
	var createdAt time.Time
	err := q.QueryRow(ctx, query, key).Scan(
		&a.ID, &a.Key, &a.Name, &a.Kind, &a.Domain, &createdAt,
	)
	if err != nil {
		if isNotFound(err) {
			return Application{}, ErrNotFound
		}
		return Application{}, fmt.Errorf("looking up application %q: %w", key, err)
	}
	a.CreatedAt = createdAt.UTC().Format(time.RFC3339)
	return a, nil
}

// ListKeys returns all registered application keys.
func (s *Store) ListKeys(ctx context.Context, q db.Querier) ([]string, error) {
	query := "SELECT key FROM applications ORDER BY key"
	rows, err := q.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("listing application keys: %w", err)
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, fmt.Errorf("scanning application key: %w", err)
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating application keys: %w", err)
	}
	return keys, nil
}

func isNotFound(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}
