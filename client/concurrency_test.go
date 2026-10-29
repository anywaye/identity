package client


import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestTheClientIsSafeForConcurrentUse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"ab000000-0000-0000-0000-000000000000",` +
			`"email":"someone@example.com"}`))
	}))
	defer server.Close()

	client, err := New(Options{BaseURL: server.URL, Token: apiCredential})
	if err != nil {
		t.Fatalf("building a client: %v", err)
	}

	const goroutines = 32
	const iterations = 8

	var wg sync.WaitGroup
	wg.Add(goroutines)

	failures := make(chan string, goroutines*iterations)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()

			for i := 0; i < iterations; i++ {
				user, err := client.GetCurrentUser(t.Context())
				switch {
				case err != nil:
					failures <- "GetCurrentUser: " + err.Error()
					return
				case user.Email != "someone@example.com":
					failures <- "GetCurrentUser returned " + string(user.Email)
					return
				}

				_ = client.String()
				_ = client.SafeToLog(user)
				_ = client.BaseURL()
				_ = client.HasCredential()
			}
		}()
	}

	wg.Wait()
	close(failures)

	var reported []string
	for failure := range failures {
		reported = append(reported, failure)
	}

	if len(reported) > 0 {
		sortStrings(reported)
		if len(reported) > 4 {
			reported = reported[:4]
		}
		t.Fatalf("%d goroutine(s) failed; the first few:\n  %s\n\n"+
			"Concurrent use of one Client is documented as supported, so a failure here "+
			"is a defect in the client rather than a misuse. If this is a data race "+
			"rather than a wrong value, the usual cause is state added to Redactor or to "+
			"Client without a lock — both were deliberately immutable for this reason.",
			len(reported), joinLines(reported))
	}
}

func joinLines(values []string) string {
	out := ""
	for i, value := range values {
		if i > 0 {
			out += "\n  "
		}
		out += value
	}
	return out
}
