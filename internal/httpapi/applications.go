package httpapi


import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/anywaye/identity/internal/applications"
)

// Applications is the registry use case the v1 routes need.
type Applications interface {
	List(ctx context.Context) ([]applications.Application, error)
	Get(ctx context.Context, key string) (applications.Application, error)
}

// WithApplications mounts the application registry surface.
func WithApplications(a Applications) Option {
	return func(o *options) {
		if a != nil {
			o.applications = a
		}
	}
}

type applicationResponse struct {
	ID     string `json:"id"`
	Key    string `json:"key"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Domain string `json:"domain"`
}

func applicationToResponse(a applications.Application) applicationResponse {
	return applicationResponse{
		ID:     a.ID.String(),
		Key:    a.Key,
		Name:   a.Name,
		Kind:   a.Kind,
		Domain: a.Domain,
	}
}

func (o options) registerApplicationRoutes(r chiRouter) {
	if o.applications == nil {
		return
	}
	r.Get("/v1/applications", o.handleListApplications)
	r.Get("/v1/applications/{key}", o.handleGetApplication)
}

func (o options) handleListApplications(w http.ResponseWriter, r *http.Request) {
	list, err := o.applications.List(r.Context())
	if err != nil {
		problemFor(w, r, http.StatusInternalServerError, "internal_error", "could not list applications")
		return
	}
	out := make([]applicationResponse, 0, len(list))
	for _, a := range list {
		out = append(out, applicationToResponse(a))
	}
	writeJSON(w, http.StatusOK, out)
}

func (o options) handleGetApplication(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	app, err := o.applications.Get(r.Context(), key)
	if err != nil {
		if err == applications.ErrNotFound {
			problemFor(w, r, http.StatusNotFound, "not_found", "application not found")
			return
		}
		problemFor(w, r, http.StatusInternalServerError, "internal_error", "could not get application")
		return
	}
	writeJSON(w, http.StatusOK, applicationToResponse(app))
}
