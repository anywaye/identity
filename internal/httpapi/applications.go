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
	Create(ctx context.Context, key, name, kind, domain string) (applications.Application, error)
	Update(ctx context.Context, key, name, kind, domain string) (applications.Application, error)
	Delete(ctx context.Context, key string) error
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

type createApplicationRequest struct {
	Key    string `json:"key"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Domain string `json:"domain"`
}

type updateApplicationRequest struct {
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
	r.Post("/v1/applications", o.requireStaffSession(o.handleCreateApplication))
	r.Patch("/v1/applications/{key}", o.requireStaffSession(o.handleUpdateApplication))
	r.Delete("/v1/applications/{key}", o.requireStaffSession(o.handleDeleteApplication))
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

func (o options) handleCreateApplication(w http.ResponseWriter, r *http.Request) {
	var body *createApplicationRequest
	if !decodeBody(w, r, &body) {
		return
	}
	if body == nil {
		problemFor(w, r, http.StatusUnprocessableEntity, "validation_failed", "invalid body")
		return
	}
	app, err := o.applications.Create(r.Context(), body.Key, body.Name, body.Kind, body.Domain)
	if err != nil {
		if err == applications.ErrKeyTaken {
			problemFor(w, r, http.StatusConflict, "conflict", "application key already in use")
			return
		}
		if fe, ok := err.(*applications.FieldError); ok {
			problemFor(w, r, http.StatusUnprocessableEntity, "validation_failed", fe.Error())
			return
		}
		problemFor(w, r, http.StatusInternalServerError, "internal_error", "could not create application")
		return
	}
	writeJSON(w, http.StatusCreated, applicationToResponse(app))
}

func (o options) handleUpdateApplication(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	var body *updateApplicationRequest
	if !decodeBody(w, r, &body) {
		return
	}
	if body == nil {
		problemFor(w, r, http.StatusUnprocessableEntity, "validation_failed", "invalid body")
		return
	}
	app, err := o.applications.Update(r.Context(), key, body.Name, body.Kind, body.Domain)
	if err != nil {
		if err == applications.ErrNotFound {
			problemFor(w, r, http.StatusNotFound, "not_found", "application not found")
			return
		}
		if fe, ok := err.(*applications.FieldError); ok {
			problemFor(w, r, http.StatusUnprocessableEntity, "validation_failed", fe.Error())
			return
		}
		problemFor(w, r, http.StatusInternalServerError, "internal_error", "could not update application")
		return
	}
	writeJSON(w, http.StatusOK, applicationToResponse(app))
}

func (o options) handleDeleteApplication(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	if err := o.applications.Delete(r.Context(), key); err != nil {
		if err == applications.ErrNotFound {
			problemFor(w, r, http.StatusNotFound, "not_found", "application not found")
			return
		}
		problemFor(w, r, http.StatusInternalServerError, "internal_error", "could not delete application")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
