package httpapi

import (
	"context"

	"github.com/anywaye/identity/internal/applications"
	"github.com/anywaye/identity/internal/platform/id"
)

type fakeApplications struct {
	listErr    error
	getErr     error
	createErr  error
	updateErr  error
	deleteErr  error
	apps       []applications.Application
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

func (f *fakeApplications) Create(_ context.Context, key, name, kind, domain string) (applications.Application, error) {
	if f.createErr != nil {
		return applications.Application{}, f.createErr
	}
	a := applications.Application{ID: id.MustNew(), Key: key, Name: name, Kind: kind, Domain: domain}
	f.apps = append(f.apps, a)
	return a, nil
}

func (f *fakeApplications) Update(_ context.Context, key, name, kind, domain string) (applications.Application, error) {
	if f.updateErr != nil {
		return applications.Application{}, f.updateErr
	}
	for i, a := range f.apps {
		if a.Key == key {
			f.apps[i].Name = name
			f.apps[i].Kind = kind
			f.apps[i].Domain = domain
			return f.apps[i], nil
		}
	}
	return applications.Application{}, applications.ErrNotFound
}

func (f *fakeApplications) Delete(_ context.Context, key string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	for i, a := range f.apps {
		if a.Key == key {
			f.apps = append(f.apps[:i], f.apps[i+1:]...)
			return nil
		}
	}
	return applications.ErrNotFound
}
