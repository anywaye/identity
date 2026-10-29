package courier

import (
	"net/http"
	"time"
)

type testingT interface {
	Helper()
	Fatalf(format string, args ...any)
}

func newTestHTTP() *http.Client {
	return &http.Client{Timeout: 2 * time.Second}
}
