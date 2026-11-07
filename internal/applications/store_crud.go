package applications

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/anywaye/identity/internal/platform/db"
)

// Create inserts a new application.
func (s *Store) Create(ctx context.Context, q db.Querier, a Application) (Application, error) {
	const query = `INSERT INTO applications (key, name, kind, domain) VALUES ($1, $2, $3, $4) RETURNING ` + applicationColumns
	var out Application
	var createdAt time.Time
	err := q.QueryRow(ctx, query, a.Key, a.Name, a.Kind, a.Domain).Scan(
		&out.ID, &out.Key, &out.Name, &out.Kind, &out.Domain, &createdAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return Application{}, ErrKeyTaken
		}
		return Application{}, fmt.Errorf("creating application: %w", err)
	}
	out.CreatedAt = createdAt.UTC().Format(time.RFC3339)
	return out, nil
}

// Update modifies name, kind, and domain for the application with the given key.
func (s *Store) Update(ctx context.Context, q db.Querier, key string, a Application) (Application, error) {
	const query = `UPDATE applications SET name = $2, kind = $3, domain = $4 WHERE key = $1 RETURNING ` + applicationColumns
	var out Application
	var createdAt time.Time
	err := q.QueryRow(ctx, query, key, a.Name, a.Kind, a.Domain).Scan(
		&out.ID, &out.Key, &out.Name, &out.Kind, &out.Domain, &createdAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Application{}, ErrNotFound
		}
		return Application{}, fmt.Errorf("updating application %q: %w", key, err)
	}
	out.CreatedAt = createdAt.UTC().Format(time.RFC3339)
	return out, nil
}

// Delete removes the application with the given key.
func (s *Store) Delete(ctx context.Context, q db.Querier, key string) error {
	const query = `DELETE FROM applications WHERE key = $1`
	ct, err := q.Exec(ctx, query, key)
	if err != nil {
		return fmt.Errorf("deleting application %q: %w", key, err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
