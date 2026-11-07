package applications

import (
	"context"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
)

// Service is the application registry use case.
type Service struct {
	pool db.Pool
	read db.QuerierSource
	store *Store
}

// NewService wires the registry.
func NewService(pool db.Pool) *Service {
	if pool == nil {
		return &Service{}
	}
	return &Service{
		pool:  pool,
		read:  db.Direct{Pool: pool},
		store: NewStore(pool),
	}
}

// Resolve maps an application key to its id.
func (s *Service) Resolve(ctx context.Context, q db.Querier, key string) (id.UUID, error) {
	if s == nil || s.store == nil {
		return id.UUID{}, ErrNotFound
	}
	if key == "" {
		return id.UUID{}, nil
	}
	app, err := s.store.ByKey(ctx, q, key)
	if err != nil {
		return id.UUID{}, err
	}
	return app.ID, nil
}

// List returns all applications.
func (s *Service) List(ctx context.Context) ([]Application, error) {
	if s == nil || s.store == nil || s.read == nil {
		return nil, ErrNotFound
	}
	return s.store.List(ctx, s.read.Queryer())
}

// Get returns one application by key.
func (s *Service) Get(ctx context.Context, key string) (Application, error) {
	if s == nil || s.store == nil || s.read == nil {
		return Application{}, ErrNotFound
	}
	return s.store.ByKey(ctx, s.read.Queryer(), key)
}

// ListKeys returns all registered application keys.
func (s *Service) ListKeys(ctx context.Context, q db.Querier) ([]string, error) {
	if s == nil || s.store == nil {
		return nil, ErrNotFound
	}
	return s.store.ListKeys(ctx, q)
}
