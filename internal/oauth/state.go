package oauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

// StateSeparator joins the provider name to the random token inside a state.
//
// It is a character that cannot appear in either part: a provider name is a bare
// lowercase word from the registry, and the token is base64url.
const StateSeparator = "."

const stateBytes = 32

// NewState returns a CSRF state value bound to provider.
//
// It takes no clock and no store, deliberately: the expiry is the cookie's
// Max-Age, which the handler sets from StateTTL, and the value itself has to be
// reproducible nowhere else. A state that could be recomputed from a timestamp
// would be forgeable by anyone who guessed the timestamp.
func NewState(provider string) (string, error) {
	if provider == "" {
		return "", fmt.Errorf("oauth state needs a provider, got %q", provider)
	}

	raw := make([]byte, stateBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("reading random bytes for an oauth state: %w", err)
	}

	return provider + StateSeparator + base64.RawURLEncoding.EncodeToString(raw), nil
}

// VerifyState reports whether presented is the state this service put in the
// cookie for provider.
//
// All three arguments are attacker-influenced: provider comes from the URL, and
// the cookie and the query parameter are both under the browser's control in a
// cross-site request. So every rejection is a plain `false` and there is no branch
// that reveals which part failed.
func VerifyState(provider, sealed, presented string) bool {
	sealedProvider, sealedToken, ok := splitState(sealed)
	if !ok {
		return false
	}
	presentedProvider, presentedToken, ok := splitState(presented)
	if !ok {
		return false
	}

	if subtle.ConstantTimeCompare([]byte(sealedProvider), []byte(provider)) != 1 {
		return false
	}
	if sealedProvider != presentedProvider {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(sealedToken), []byte(presentedToken)) == 1
}

func splitState(value string) (provider, token string, ok bool) {
	provider, token, found := strings.Cut(value, StateSeparator)
	if !found || provider == "" || token == "" {
		return "", "", false
	}
	if strings.Contains(token, StateSeparator) {
		return "", "", false
	}
	return provider, token, true
}
