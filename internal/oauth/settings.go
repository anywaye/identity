package oauth

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// ErrIncompleteSettings means at least one provider is configured but the
// settings every provider shares — the public base URL and the encryption key —
// are not.
//
// It is deliberately distinct from ErrIncompleteProvider: that one says "you gave
// me half of this provider's credentials", this one says "this provider needs two
// things you did not set". An operator reading the first will go looking for a
// secret variable; an operator reading the second will go looking for a base URL,
// and sending them to the same message sends them to the wrong place.
var ErrIncompleteSettings = errors.New("oauth settings are incomplete")

// ProviderSettings is one provider's configuration from the environment: the
// credentials it authenticates with, and the endpoints it is reached at.
//
// THE ENDPOINTS ARE HERE AND NOT ON Settings because they are per provider, exactly
// as the credentials are. An `Settings.Endpoints` map keyed by provider name would
// be the same information with a second thing to forget a provider from.
type ProviderSettings struct {
	ClientID     string
	ClientSecret string
	// Endpoints are this provider's endpoint overrides. Empty fields keep the
	// defaults in endpoints.go, which is what an untouched deployment gets.
	Endpoints ProviderEndpoints
}

// namedProvider is one provider's settings paired with the name they belong to,
// which is what lets Validate and Providers both walk every provider knowing which
// one they are on.
type namedProvider struct {
	name     string
	settings ProviderSettings
}

// providers is the per-provider table: every provider this service knows, in the
// order they are logged.
//
// IT IS THE COMPLETE SET, and `TestEveryProviderThisServiceOffersIsInTheTable` holds
// `knownProviders` against it in both directions. Nothing about a struct literal
// that configures a check looks like a completeness obligation, which is why this
// one is walked rather than trusted.
func (s Settings) providers() []namedProvider {
	return []namedProvider{
		{name: ProviderGoogle, settings: s.Google},
		{name: ProviderGitHub, settings: s.GitHub},
		{name: ProviderMicrosoft, settings: s.Microsoft},
	}
}

// configured reports whether both halves are present. A caller must have run
// Validate before trusting a false here to mean "leave it out".
func (p ProviderSettings) configured() bool {
	return p.ClientID != "" && p.ClientSecret != ""
}

// halfConfigured reports whether exactly one half is present, which is always a
// mistake and never an intention.
func (p ProviderSettings) halfConfigured() bool {
	return (p.ClientID == "") != (p.ClientSecret == "")
}

// Settings is the OAuth configuration as the environment states it, before
// anything has been built from it.
//
// It lives in this package rather than in internal/config so that the rules about
// which combinations of these values make sense stay with the code that consumes
// them. internal/config reads the environment into one of these and calls Validate;
// it does not know what a client secret is.
//
// IT USED TO SAY THAT NOTHING CONSTRUCTED A SETTINGS, and that was false by the
// time it was written: `internal/config`'s `loadOAuth` builds one out of the
// `OAUTH_*` variables on every `Load`, and `cmd/identity` mounts the social routes
// from it. A reader checking would have found the `OAUTH_` strings in that package
// — which is the same class of defect as a README describing an endpoint that
// answers 404, and the record of it belongs here rather than in the history.
type Settings struct {
	// RedirectBaseURL is this service's public base URL. Callback URLs are built
	// from it and from nothing else — never from a Host header.
	RedirectBaseURL string
	// EncryptionKey is standard base64 of 32 bytes, which is what
	// `head -c 32 /dev/urandom | base64` prints.
	EncryptionKey string
	// Google, GitHub and Microsoft are per provider: credentials and endpoint
	// overrides.
	Google    ProviderSettings
	GitHub    ProviderSettings
	Microsoft ProviderSettings
}

// Validate reports whether these settings can be used to serve sign-in.
//
// The rule throughout is AGENTS.md's: a variable that is absent is a supported
// state, and a variable that is present but wrong is an error. So an empty
// Settings is fine, and so is a set base URL with no providers; a key that does
// not decode is never fine.
func (s Settings) Validate() error {
	for _, np := range s.providers() {
		if np.settings.halfConfigured() {
			return fmt.Errorf("%w: set both the client id and the client secret, or neither", ErrIncompleteProvider)
		}

		// Whether or not this provider has credentials: an endpoint that is set to
		// something undialable is a deployment that should find out now, and the
		// deployer is the only person who can fix it.
		if err := np.settings.Endpoints.validate(np.name); err != nil {
			return err
		}
	}

	// Checked whenever present, independently of whether anything reads it: a key
	// that is wrong today is wrong the day a provider is added, and the deployer
	// is the only person who can fix it.
	if _, err := s.Key(); err != nil {
		return err
	}

	if s.RedirectBaseURL != "" {
		if err := validateRedirectBase(s.RedirectBaseURL); err != nil {
			return err
		}
	}

	if s.Enabled() && s.RedirectBaseURL == "" {
		return fmt.Errorf("%w: a provider is configured, so the redirect base url must be set too", ErrIncompleteSettings)
	}
	if s.Enabled() && s.EncryptionKey == "" {
		return fmt.Errorf("%w: a provider is configured, so the token encryption key must be set too", ErrIncompleteSettings)
	}

	return nil
}

// Key decodes the configured encryption key.
//
// The length is checked here rather than being handed to NewCipher so that the
// operator gets an error naming the environment variable, not an error from deep
// inside AES.
func (s Settings) Key() ([]byte, error) {
	if s.EncryptionKey == "" {
		return nil, nil
	}

	raw, err := base64.StdEncoding.DecodeString(s.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("%w: it is not standard base64: %v", ErrInvalidEncKey, err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("%w: it decodes to %d bytes, want 32", ErrInvalidEncKey, len(raw))
	}
	return raw, nil
}

// Enabled reports whether at least one provider is fully configured. The process
// mounts the OAuth routes only when this is true.
//
// IT DOES NOT LOOK AT THE ENDPOINT OVERRIDES, and that is deliberate: an override
// is not credentials. A deployment that pointed Google's token URL at its own IdP
// and has no Google client id has no Google sign-in to offer, and mounting the
// routes because it configured an endpoint would advertise a provider it cannot
// authenticate with.
func (s Settings) Enabled() bool {
	for _, np := range s.providers() {
		if np.settings.configured() {
			return true
		}
	}
	return false
}

// Providers returns the fully-configured providers, each carrying this service's
// endpoints, this deployment's overrides and the operator's credentials.
//
// The order is fixed — google, github, then microsoft — so a startup log line
// naming them is stable between restarts of the same configuration.
func (s Settings) Providers() []Provider {
	out := make([]Provider, 0, len(s.providers()))
	for _, np := range s.providers() {
		if !np.settings.configured() {
			continue
		}
		definition, known := providerByName(np.name)
		if !known {
			// Unreachable through providers(), which holds only known names, and
			// Validate refuses one that is not. Skipped rather than appended as a
			// zero Provider, because a provider with no endpoints is a provider
			// whose sign-in redirects to "".
			continue
		}
		np.settings.Endpoints.applyTo(&definition)
		definition.ClientID = np.settings.ClientID
		definition.ClientSecret = np.settings.ClientSecret
		out = append(out, definition)
	}
	return out
}
