package httpapi


import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/admin"
	"github.com/anywaye/identity/internal/apikeys"
	"github.com/anywaye/identity/internal/platform/id"
)

func chiURLParam(r *http.Request, name string) string {
	return chi.URLParam(r, name)
}

const adminPrefix = "admin"

// Admin is the slice of the admin use cases these handlers need.
type Admin interface {
	RevokeInvitation(ctx context.Context, in admin.RevokeInvitationInput) (int, error)
	RevokeInvitations(ctx context.Context, in admin.RevokeInvitationsInput) (int, error)
	List(ctx context.Context, accountID id.UUID, page admin.Page) ([]admin.Record, error)
}

// WithAdmin mounts the admin surface.
//
// Like every other optional surface here it is ABSENT rather than present-and-500:
// a deployment with no admin wiring gets a 404 on these three routes, which is
// the same answer it gets for a route that does not exist, and an operator who
// meant to enable them finds a 404 rather than a stack trace in their log.
func WithAdmin(a Admin) Option {
	return func(o *options) {
		if a != nil {
			o.admin = a
		}
	}
}

func (o options) registerAdminRoutes(r chiRouter) {
	if o.admin == nil {
		return
	}

	r.Get("/v1/accounts/{accountID}/"+adminPrefix+"/audit-log",
		o.requireAdminToken(o.requireAccountRole(accounts.RoleAdmin, o.handleListAuditLog)))

	r.Delete("/v1/accounts/{accountID}/"+adminPrefix+"/invitations/{invitationID}",
		o.requireAdminToken(o.requireAccountRole(accounts.RoleAdmin, o.handleRevokeInvitation)))

	r.Post("/v1/accounts/{accountID}/"+adminPrefix+"/invitation-revocations",
		o.requireAdminToken(o.requireAccountRole(accounts.RoleOwner, o.handleRevokeInvitations)))
}

func (o options) requireAdminToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !o.isAPIKeyRequest(r) {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"the admin surface is reachable by a scoped api key only; a browser session may not use it. "+
					"An admin action is taken by a machine credential that can be named in an audit record, "+
					"and a session cookie is neither")
			return
		}
		next(w, r)
	}
}


type bulkRevokeRequest struct {
	InvitationIDs []string `json:"invitation_ids"`
	Confirm       bool     `json:"confirm"`
}

type auditLogResponse struct {
	Entries []auditLogEntry `json:"entries"`
	Next string `json:"next,omitempty"`
}

type auditLogEntry struct {
	ID string `json:"id"`
	Action string `json:"action"`
	ActorUserID string `json:"actor_user_id"`
	ActorKeyID  string `json:"actor_key_id"`
	Target      string `json:"target"`
	Affected    int    `json:"affected"`
	TraceID     string `json:"trace_id"`
	OccurredAt  string `json:"occurred_at"`
}

func entryResponse(rec admin.Record) auditLogEntry {
	return auditLogEntry{
		ID:          rec.ID.String(),
		Action:      string(rec.Action),
		ActorUserID: rec.ActorUserID.String(),
		ActorKeyID:  rec.ActorKeyID.String(),
		Target:      rec.Target,
		Affected:    rec.Affected,
		TraceID:     rec.TraceID,
		OccurredAt:  rec.OccurredAt.UTC().Format(time.RFC3339),
	}
}

type bulkRevokeResponse struct {
	Requested int `json:"requested"`
	Revoked   int `json:"revoked"`
}


func (o options) handleListAuditLog(w http.ResponseWriter, r *http.Request) {
	account, ok := accountFrom(r.Context())
	if !ok {
		notFound(w, r)
		return
	}

	page, queryErr := auditLogPage(r)
	if queryErr != nil {
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the audit log query is not one this endpoint accepts").
			withFieldErrors(queryErr.fieldErrors()))
		return
	}

	records, err := o.admin.List(r.Context(), account.ID, page)
	if err != nil {
		o.writeAdminError(w, r, err)
		return
	}

	entries := make([]auditLogEntry, 0, len(records))
	for _, rec := range records {
		entries = append(entries, entryResponse(rec))
	}

	out := auditLogResponse{Entries: entries}
	if len(records) > 0 {
		out.Next = records[len(records)-1].Next
	}
	writeJSON(w, http.StatusOK, out)
}

func (o options) handleRevokeInvitation(w http.ResponseWriter, r *http.Request) {
	account, ok := accountFrom(r.Context())
	if !ok {
		notFound(w, r)
		return
	}

	invitationID, ok := invitationIDFrom(r)
	if !ok {
		notFound(w, r)
		return
	}

	actor, ok := adminActorFrom(r.Context())
	if !ok {
		unexpected(w, r, o.logger, errNoAdminActor)
		return
	}

	if _, err := o.admin.RevokeInvitation(r.Context(), admin.RevokeInvitationInput{
		AccountID:    account.ID,
		InvitationID: invitationID,
		Actor:        actor,
	}); err != nil {
		o.writeAdminError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (o options) handleRevokeInvitations(w http.ResponseWriter, r *http.Request) {
	account, ok := accountFrom(r.Context())
	if !ok {
		notFound(w, r)
		return
	}

	var body *bulkRevokeRequest
	if !decodeBody(w, r, &body) {
		return
	}
	if fieldErrs := validateBulkRevoke(body); len(fieldErrs) > 0 {
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("a bulk revocation must name the invitations and confirm the action").
			withFieldErrors(fieldErrs))
		return
	}

	actor, ok := adminActorFrom(r.Context())
	if !ok {
		unexpected(w, r, o.logger, errNoAdminActor)
		return
	}

	ids := make([]id.UUID, 0, len(body.InvitationIDs))
	for _, raw := range body.InvitationIDs {
		parsed, err := id.Parse(raw)
		if err != nil || parsed.IsZero() {
			writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
				withDetail("every invitation id must be a uuid this service issued").
				withFieldErrors([]FieldError{{Field: "invitation_ids", Code: "invalid_format"}}))
			return
		}
		ids = append(ids, parsed)
	}

	revoked, err := o.admin.RevokeInvitations(r.Context(), admin.RevokeInvitationsInput{
		AccountID:     account.ID,
		InvitationIDs: ids,
		Actor:         actor,
	})
	if err != nil {
		o.writeAdminError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, bulkRevokeResponse{Requested: len(ids), Revoked: revoked})
}

var errNoAdminActor = errors.New("an admin route reached its handler with no api key in context")

func adminActorFrom(ctx context.Context) (admin.Actor, bool) {
	scope, ok := ctx.Value(accountContextKey{}).(accountScope)
	if !ok {
		return admin.Actor{}, false
	}
	if scope.KeyID.IsZero() {
		return admin.Actor{}, false
	}
	return admin.Actor{
		UserID:  scope.User.ID,
		KeyID:   scope.KeyID,
		TraceID: traceIDFrom(ctx),
	}, true
}

func validateBulkRevoke(body *bulkRevokeRequest) []FieldError {
	var errs []FieldError

	if !body.Confirm {
		errs = append(errs, FieldError{Field: "confirm", Code: apikeys.CodeRequired})
	}

	switch {
	case len(body.InvitationIDs) == 0:
		errs = append(errs, FieldError{Field: "invitation_ids", Code: apikeys.CodeRequired})
	case len(body.InvitationIDs) > admin.MaxBulkInvitationIDs:
		errs = append(errs, FieldError{Field: "invitation_ids", Code: "too_many"})
	}
	return errs
}

type auditLogQueryError struct {
	detail string
	fields []FieldError
}

func (e auditLogQueryError) Error() string { return e.detail }

func (e auditLogQueryError) fieldErrors() []FieldError { return e.fields }

func auditLogPage(r *http.Request) (admin.Page, *auditLogQueryError) {
	query := r.URL.Query()
	page := admin.Page{Before: query.Get("before")}

	if raw := query.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return admin.Page{}, &auditLogQueryError{
				detail: "the page size must be a whole number",
				fields: []FieldError{{Field: "limit", Code: apikeys.CodeInvalidFormat}},
			}
		}
		page.Limit = limit
	}

	if _, err := page.Normalised(); err != nil {
		return admin.Page{}, &auditLogQueryError{
			detail: fmt.Sprintf("the page size must be between 1 and %d", admin.MaxAuditLogLimit),
			fields: []FieldError{{Field: "limit", Code: apikeys.CodeOutOfRange}},
		}
	}

	if _, _, err := page.Cursor(); err != nil {
		return admin.Page{}, &auditLogQueryError{
			detail: "the page cursor is not one this service issued",
			fields: []FieldError{{Field: "before", Code: apikeys.CodeInvalidFormat}},
		}
	}
	return page, nil
}

func invitationIDFrom(r *http.Request) (id.UUID, bool) {
	parsed, err := id.Parse(chiURLParam(r, "invitationID"))
	if err != nil || parsed.IsZero() {
		return id.UUID{}, false
	}
	return parsed, true
}

func (o options) writeAdminError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, admin.ErrInvitationNotRevocable),
		errors.Is(err, accounts.ErrInvitationNotFound):
		problemFor(w, r, http.StatusNotFound, CodeNotFound,
			"no revocable invitation with that id is visible to you")

	case errors.Is(err, accounts.ErrInvitationUsed),
		errors.Is(err, accounts.ErrInvitationRevoked):
		detail := "that invitation has already been accepted and cannot be revoked"
		if errors.Is(err, accounts.ErrInvitationRevoked) {
			detail = "that invitation has already been revoked"
		}
		problemFor(w, r, http.StatusConflict, CodeConflict, detail)

	case errors.Is(err, admin.ErrNoInvitations):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("a bulk revocation must name at least one invitation").
			withFieldErrors([]FieldError{{Field: "invitation_ids", Code: apikeys.CodeRequired}}))

	case errors.Is(err, admin.ErrTooManyInvitations):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail(fmt.Sprintf("a bulk revocation may name at most %d invitations", admin.MaxBulkInvitationIDs)).
			withFieldErrors([]FieldError{{Field: "invitation_ids", Code: "too_many"}}))

	case errors.Is(err, admin.ErrBadLimit):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail(fmt.Sprintf("the page size must be between 1 and %d", admin.MaxAuditLogLimit)).
			withFieldErrors([]FieldError{{Field: "limit", Code: apikeys.CodeOutOfRange}}))

	case errors.Is(err, admin.ErrBadCursor):
		problemFor(w, r, http.StatusBadRequest, CodeInvalidRequest,
			"the page cursor is not one this service issued")

	default:
		unexpected(w, r, o.logger, err)
	}
}
