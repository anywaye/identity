package oauthtest_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/oauth"
	"github.com/anywaye/identity/internal/platform/oauthtest"
)


func fetchUserInfo(t *testing.T, uid string) map[string]json.RawMessage {
	t.Helper()

	server := oauthtest.NewServer(t).Person(uid, "someone@example.test", "Someone")
	provider := server.Provider(t, oauth.GitHub())

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, provider.UserInfoURL, nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+server.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", provider.UserInfoURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d, want 200", provider.UserInfoURL, resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the userinfo body: %v", err)
	}

	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("the fake served %q, which is not a JSON object: %v", raw, err)
	}
	return body
}

func TestSubIsAStringAndSurvivesExactly(t *testing.T) {
	t.Parallel()

	const uid = "107346492749283471920"

	body := fetchUserInfo(t, uid)

	raw, ok := body["sub"]
	if !ok {
		t.Fatalf("the fake served no `sub`, so a decoder has nothing to read the uid from: %v", body)
	}
	if !strings.HasPrefix(string(raw), `"`) {
		t.Errorf("sub is %s, which is a JSON %s. It must be a string: a number here is "+
			"a float64 by the time it is re-serialized, and 107346492749283471920 comes "+
			"back as ...3475456 inside a correctly-signed assertion (MD21).",
			raw, strings.Trim(string(raw), `"`))
	}
	var got string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("sub is %s, which is not a decodable string: %v", raw, err)
	}
	if got != uid {
		t.Errorf("sub decoded to %q, want %q. A uid that does not survive its own wire "+
			"format is a fixture that has told us the format is unpinned.", got, uid)
	}
}

func TestAUidTooLargeForInt64IsServedAsSubAlone(t *testing.T) {
	t.Parallel()

	body := fetchUserInfo(t, "107346492749283471920")

	raw, ok := body["id"]
	if ok {
		t.Errorf("the fake served `id` = %s for a uid that does not fit an int64. It must "+
			"be omitted: the only two ways to write this number are exactly (as `sub`) or "+
			"approximately (as `id`), and an approximate provider id keys a publisher on "+
			"the wrong account. The guard is `err == nil` at oauthtest.go:367 — inverted "+
			"to `err != nil` this assertion fires.", raw)
	}
}

func TestAUidThatFitsInt64IsServedUnderBothSpellings(t *testing.T) {
	t.Parallel()

	const uid = "4417"

	body := fetchUserInfo(t, uid)

	sub, ok := body["sub"]
	if !ok {
		t.Fatalf("no `sub` for a uid that fits an int64: %v", body)
	}
	if string(sub) != `"`+uid+`"` {
		t.Errorf("sub = %s, want %q as a JSON string", sub, uid)
	}

	id, ok := body["id"]
	if !ok {
		t.Fatalf("no `id` for a uid that fits an int64. A fake that never serves `id` "+
			"would make a decoder reading `id` fail here and one reading only `sub` pass, "+
			"which is the opposite of what a fake is for. Body: %v", body)
	}
	if string(id) != uid {
		t.Errorf("id = %s, want the bare number %s", id, uid)
	}
}

func TestTheDefaultUIDIsTheOneThatExceedsInt64(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t)
	body := fetchUserInfo(t, server.ProviderUID)

	if _, ok := body["id"]; ok {
		t.Errorf("the default ProviderUID %q produced an `id`, so the default is no longer "+
			"the oversized one and MD21's measurement is no longer being exercised by "+
			"default. If that is deliberate, this test is what should change with it.",
			server.ProviderUID)
	}
	if got := string(body["sub"]); got != `"`+server.ProviderUID+`"` {
		t.Errorf("sub = %s, want %q", got, server.ProviderUID)
	}
}
