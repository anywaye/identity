package httpapi


import (
	"context"
	"errors"
	"net/http"

	"github.com/anywaye/identity/internal/apikeys"
	"github.com/anywaye/identity/internal/auth"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/useraudit"
	"github.com/anywaye/identity/internal/users"
)

func (o options) registerOperatorRoutes(r chiRouter) {
	r.Post("/v1/users/{userID}/disable", o.requireOperatorToken(o.handleDisableUser))
	r.Post("/v1/users/{userID}/enable", o.requireOperatorToken(o.handleEnableUser))
}

func (o options) requireOperatorToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !o.isAPIKeyRequest(r) {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"this route turns a person's account off, which is a deployment decision and not "+
					"something an account does to itself. It is reachable by a scoped api key holding "+
					"the "+apikeys.ScopeUsersDisable+" scope; a browser session may not use it, and "+
					"neither may an account-scoped credential")
			return
		}

		if o.apiKeyCaller == nil {
			unauthorized(w, r)
			return
		}

		caller, err := o.apiKeyCaller.Authenticate(r.Context(), o.presentedAPIKey(r), o.clk.Now())
		if err != nil || caller.Key.ID.IsZero() {
			unauthorized(w, r)
			return
		}

		if required := scopeRequiredBy(r); !caller.Key.Allows(required) {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"this api key does not carry the "+required+" scope")
			return
		}

		next(w, r.WithContext(withOperatorCaller(r.Context(), operatorCaller{
			UserID: caller.User.ID,
			KeyID:  caller.Key.ID,
		})))
	}
}

type operatorCallerKey struct{}

type operatorCaller struct {
	UserID id.UUID
	KeyID  id.UUID
}

func withOperatorCaller(ctx context.Context, c operatorCaller) context.Context {
	return context.WithValue(ctx, operatorCallerKey{}, c)
}

func operatorActorFrom(ctx context.Context) (useraudit.Actor, bool) {
	c, ok := ctx.Value(operatorCallerKey{}).(operatorCaller)
	if !ok || c.KeyID.IsZero() {
		return useraudit.Actor{}, false
	}
	return useraudit.Actor{UserID: c.UserID, KeyID: c.KeyID, TraceID: traceIDFrom(ctx)}, true
}

var errNoOperatorActor = errors.New("an operator route reached its handler with no api key in context")


func (o options) handleDisableUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := operatorSubject(r)
	if !ok {
		notFound(w, r)
		return
	}
	actor, ok := operatorActorFrom(r.Context())
	if !ok {
		unexpected(w, r, o.logger, errNoOperatorActor)
		return
	}

	if err := o.auth.Disable(r.Context(), auth.DisableInput{
		UserID:      userID,
		ActorUserID: actor.UserID,
		ActorKeyID:  actor.KeyID,
		TraceID:     actor.TraceID,
		At:          o.clk.Now(),
	}); err != nil {
		o.writeOperatorError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (o options) handleEnableUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := operatorSubject(r)
	if !ok {
		notFound(w, r)
		return
	}
	actor, ok := operatorActorFrom(r.Context())
	if !ok {
		unexpected(w, r, o.logger, errNoOperatorActor)
		return
	}

	if err := o.auth.Enable(r.Context(), auth.EnableInput{
		UserID:      userID,
		ActorUserID: actor.UserID,
		ActorKeyID:  actor.KeyID,
		TraceID:     actor.TraceID,
		At:          o.clk.Now(),
	}); err != nil {
		o.writeOperatorError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func operatorSubject(r *http.Request) (id.UUID, bool) {
	return userIDFrom(r)
}

func (o options) writeOperatorError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, users.ErrNotFound):
		problemFor(w, r, http.StatusNotFound, CodeNotFound,
			"no user with that id exists on this deployment")

	default:
		unexpected(w, r, o.logger, err)
	}
}
