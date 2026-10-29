package httpapi

import (
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
)

// initErrorReporting configures the Sentry SDK from the environment. An empty
// DSN leaves it disabled, which is the honest "off" state: nothing is captured
// and nothing leaves the process.
func InitErrorReporting() {
	dsn := strings.TrimSpace(os.Getenv("IDENTITY_ERROR_REPORTING_DSN"))
	if dsn == "" {
		return
	}
	release := strings.TrimSpace(os.Getenv("IDENTITY_RELEASE"))
	if release == "" {
		release = strings.TrimSpace(os.Getenv("COURIER_RELEASE"))
	}
	if release == "" {
		release = "unknown"
	}
	environment := strings.TrimSpace(os.Getenv("DEPLOYMENT_ENVIRONMENT"))
	if environment == "" {
		environment = "production"
	}
	err := sentry.Init(sentry.ClientOptions{
		Dsn:              dsn,
		Release:          release,
		Environment:      environment,
		AttachStacktrace: true,
		Debug:            true,
		BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
			if event.Request != nil {
				if u := event.Request.URL; u != "" {
					if i := strings.IndexByte(u, '?'); i >= 0 {
						event.Request.URL = u[:i]
					}
				}
				event.Request.QueryString = ""
			}
			for i := range event.Exception {
				if st := event.Exception[i].Stacktrace; st != nil {
					for j := range st.Frames {
						if strings.Contains(st.Frames[j].Module, "anywaye") ||
							strings.Contains(st.Frames[j].Filename, "anywaye") {
							st.Frames[j].InApp = true
						}
					}
				}
			}
			return event
		},
	})
	if err != nil {
		slog.Error("error reporting init failed", "error", err)
	}
}

// ErrorReportingEnabled reports whether a reporting DSN is configured, so a test can
// assert the off state without touching the Sentry SDK.
func ErrorReportingEnabled() bool {
	return strings.TrimSpace(os.Getenv("IDENTITY_ERROR_REPORTING_DSN")) != ""
}

// captureError reports an unhandled error to the configured store, if any. It
// never raises and never blocks the request path.
func CaptureError(err error, r *http.Request) {
	if err == nil {
		return
	}
	hub := sentry.CurrentHub().Clone()
	if r != nil {
		hub.ConfigureScope(func(scope *sentry.Scope) {
			scope.SetRequest(r)
			if tid := traceIDFrom(r.Context()); tid != "" {
				scope.SetTag("trace_id", tid)
			}
		})
	}
	hub.CaptureException(err)
	if !sentry.Flush(2 * time.Second) {
		slog.Warn("error reporting flush timed out")
	}
}
