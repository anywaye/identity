package oauthtest_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/oauth"
	"github.com/cafaye/identity/internal/platform/oauthtest"
)

// A FAKE IS A CLAIM ABOUT A PROVIDER, and this file pins the one claim here
// that a reader cannot check by looking.
//
// The default `ProviderUID` is `107346492749283471920`: nineteen digits, above
// `int64`'s ceiling of 9223372036854775807, and far above `2^53`. That number
// is deliberate — it is the value that made MD21 visible — and `serveUserInfo`
// has to cope with it:
//
//	if _, err := strconv.ParseInt(s.ProviderUID, 10, 64); err == nil {
//		body["id"] = json.Number(s.ProviderUID)
//	}
//
// So the fake emits `sub` ALWAYS and `id` only when the uid fits an int64.
// Both spellings are served because the decoder picks the one its provider
// uses. The consequence is that a 19-digit uid produces a body carrying
// `sub` and NO `id`, and that is the branch every GitHub test in this
// repository runs through without anyone reading the guard.
//
// WHY IT NEEDS A TEST, which is the part worth stating: `id` is emitted as a
// raw `json.Number` and is never unmarshalled back through an int64 anywhere in
// the OAuth client, so the guard's removal is INVISIBLE TO THE EXISTING
// SUITE — nothing in this repository decodes that field, so every OAuth test
// keeps passing either way. The regression it would allow is silent: a decoder
// that preferred `id` would start reading a float64 that has lost its last
// digits, which is exactly the failure MD21 rules out, and it would do so in a
// fixture whose whole purpose is to make that failure visible.

// fetchUserInfo drives the fake the way a provider is actually driven: over
// HTTP, against the URL the client was configured with, so the assertions below
// are about bytes on the wire rather than about a Go map.
func fetchUserInfo(t *testing.T, uid string) map[string]json.RawMessage {
	t.Helper()

	server := oauthtest.NewServer(t).Person(uid, "someone@example.test", "Someone")
	provider := server.Provider(t, oauth.GitHub())

	// The bearer is not optional: `authorizes` compares it against the fake's own
	// access token, and a 401 here would be the fake refusing rather than a fact
	// about the uid.
	req, err := http.NewRequest(http.MethodGet, provider.UserInfoURL, nil)
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

// The uid crosses as a JSON STRING under `sub`, always, whatever it is. This is
// MD21's ruling as a property of the fixture: a JSON number here is already a
// float64 by the time anything downstream re-serializes it.
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

// A uid that does NOT fit an int64 gets no `id` at all. Not a zero, not a
// truncated value, not the same digits as a float64 — absent.
//
// The reason it has to be absent rather than approximate is the one MD21 names:
// an `id` of 107346492749283480000 is not this user's id. Serving it would let
// a decoder prefer `id` over `sub` and silently key a publisher on a number
// that belongs to nobody.
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

// The other half, and the reason the guard is a guard rather than a deletion:
// a uid that DOES fit gets both spellings, so a decoder that reads either one
// is exercised. Without this the test above would pass against a fake that
// simply never served `id`.
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

// The fixture's own default is the 19-digit one. This is asserted because every
// other test in this repository inherits it silently: change the default and a
// hundred tests change shape without any of them failing to explain why.
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
