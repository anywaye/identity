package httpapi

import (
	"context"
	"net/http"

	"github.com/anywaye/identity/internal/platform/id"
)

// TraceHeader is the request and response header carrying the trace id. core:
// "trace_id is always present and always matches the X-Trace-Id response header."
const TraceHeader = "X-Trace-Id"

const maxInboundTraceID = 200

type traceIDKey struct{}

func withTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, traceIDKey{}, traceID)
}

func traceIDFrom(ctx context.Context) string {
	if id, ok := ctx.Value(traceIDKey{}).(string); ok {
		return id
	}
	return ""
}

func traceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceID := inboundTraceID(r)
		if traceID == "" {
			generated, err := id.New()
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			traceID = generated.String()
		}

		w.Header().Set(TraceHeader, traceID)
		next.ServeHTTP(w, r.WithContext(withTraceID(r.Context(), traceID)))
	})
}

func inboundTraceID(r *http.Request) string {
	traceID := r.Header.Get(TraceHeader)
	if traceID == "" || len(traceID) > maxInboundTraceID {
		return ""
	}
	for _, r := range traceID {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == ':':
		default:
			return ""
		}
	}
	return traceID
}
