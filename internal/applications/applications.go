package applications

import (
	"errors"
	"fmt"
	"strings"

	"github.com/anywaye/identity/internal/platform/id"
)

var (
	ErrNotFound = errors.New("application not found")

	ErrKeyTaken = errors.New("application key already in use")
)

// Application is a platform-owned application that consumes identity.
type Application struct {
	ID        id.UUID
	Key       string
	Name      string
	Kind      string
	Domain    string
	CreatedAt string
}

// FieldError is a per-field validation failure.
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

// ValidateKey checks the shape of an application key.
func ValidateKey(key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fieldErr("key", "required")
	}
	if len(key) > 63 {
		return fieldErr("key", "too_long")
	}
	if !validKeyShape(key) {
		return fieldErr("key", "invalid_format")
	}
	return nil
}

func validKeyShape(key string) bool {
	if len(key) == 0 || len(key) > 63 {
		return false
	}
	for i, r := range key {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
		if r == '-' && (i == 0 || i == len(key)-1) {
			return false
		}
	}
	return true
}
