package applications

import (
	"context"

)

// Create validates and inserts a new application.
func (s *Service) Create(ctx context.Context, key, name, kind, domain string) (Application, error) {
	if err := ValidateKey(key); err != nil {
		return Application{}, err
	}
	if name == "" {
		return Application{}, fieldErr("name", "required")
	}
	if kind == "" {
		kind = "web"
	}
	if domain == "" {
		return Application{}, fieldErr("domain", "required")
	}
	if s == nil || s.store == nil || s.read == nil {
		return Application{}, ErrNotFound
	}
	app := Application{Key: key, Name: name, Kind: kind, Domain: domain}
	return s.store.Create(ctx, s.read.Queryer(), app)
}

// Update modifies an existing application.
func (s *Service) Update(ctx context.Context, key, name, kind, domain string) (Application, error) {
	if name == "" {
		return Application{}, fieldErr("name", "required")
	}
	if kind == "" {
		kind = "web"
	}
	if domain == "" {
		return Application{}, fieldErr("domain", "required")
	}
	if s == nil || s.store == nil || s.read == nil {
		return Application{}, ErrNotFound
	}
	app := Application{Key: key, Name: name, Kind: kind, Domain: domain}
	return s.store.Update(ctx, s.read.Queryer(), key, app)
}

// Delete removes an application by key.
func (s *Service) Delete(ctx context.Context, key string) error {
	if s == nil || s.store == nil || s.read == nil {
		return ErrNotFound
	}
	return s.store.Delete(ctx, s.read.Queryer(), key)
}
