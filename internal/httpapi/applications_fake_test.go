package httpapi

import (
	"context"

	"github.com/anywaye/identity/internal/applications"
	"github.com/anywaye/identity/internal/platform/id"
)

type fakeApplications struct {
	listErr error
	getErr  error
	apps    []applications.Application
}

func newFakeApplications() *fakeApplications {
	return &fakeApplications{
		apps: []applications.Application{
			{ID: id.MustNew(), Key: "anywaye", Name: "Anywaye", Kind: "web", Domain: "anywaye.com"},
		},
	}
}

func (f *fakeApplications) List(_ context.Context) ([]applications.Application, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.apps, nil
}

func (f *fakeApplications) Get(_ context.Context, key string) (applications.Application, error) {
	if f.getErr != nil {
		return applications.Application{}, f.getErr
	}
	for _, a := range f.apps {
		if a.Key == key {
			return a, nil
		}
	}
	return applications.Application{}, applications.ErrNotFound
}
