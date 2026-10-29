package client


import (
	"context"
	"errors"
	"time"

	uuidlib "github.com/google/uuid"

	openapiTypes "github.com/oapi-codegen/runtime/types"
)

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func errorsAs(err error, target any) bool { return errors.As(err, target) }

func uuidOf(s string) openapiTypes.UUID {
	parsed, err := uuidlib.Parse(s)
	if err != nil {
		panic("fixture uuid " + s + ": " + err.Error())
	}
	return parsed
}

func ptr[T any](value T) *T { return &value }
