package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
)

func recoverPanics(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracked := &trackedWriter{ResponseWriter: w}

		defer func() {
			recovered := recover()
			if recovered == nil {
				return
			}
			if rerr, ok := recovered.(error); ok && errors.Is(rerr, http.ErrAbortHandler) {
				panic(recovered)
			}

			logPanic(logger, r, tracked, recovered)
			CaptureError(panicError{recovered}, r)

			if tracked.wroteHeader {
				return
			}
			unexpected(tracked, r, logger, panicError{recovered})
		}()

		next.ServeHTTP(tracked, r)
	})
}

type trackedWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (w *trackedWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *trackedWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.wroteHeader = true
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer, so anything
// that needs Flush or Hijack still works through the wrapper.
func (w *trackedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type panicError struct{ value any }

func (e panicError) Error() string {
	if err, ok := e.value.(error); ok {
		return "panic: " + err.Error()
	}
	return "panic"
}

func logPanic(logger *slog.Logger, r *http.Request, w *trackedWriter, recovered any) {
	if logger == nil {
		return
	}
	logger.Error("panic in a handler",
		"error", panicError{recovered},
		"method", r.Method,
		"path", r.URL.Path,
		"trace_id", traceIDFrom(r.Context()),
		"response_committed", w.wroteHeader,
	)
}
