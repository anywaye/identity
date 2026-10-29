package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/anywaye/identity/internal/users"
)

// DefaultProviderTimeout bounds every call this service makes to a provider.
//
// It is a property of the client rather than of the request, because the caller's
// deadline is the browser's: a user who has walked away is still holding a
// connection, and an unbounded call to a third party is how one slow provider
// turns into a saturated identity service.
const DefaultProviderTimeout = 10 * time.Second

const maxIdentityBytes = 256 << 10

var (
	ErrCodeRefused = errors.New("the oauth provider refused the authorization code")

	ErrProviderUnavailable = errors.New("the oauth provider is unavailable")

	ErrNoEmail = errors.New("the oauth provider returned no usable email address")
)

// Tokens is what a provider issued for one authorization code.
type Tokens struct {
	AccessToken string
	RefreshToken string
	ExpiresAt *time.Time
	IDToken string
}

// Identity is what a provider says about the person behind a token.
type Identity struct {
	ProviderUID string
	Email       string
	Name        string
}

// Client performs the two calls this service makes to a provider.
//
// It holds no state between calls and caches nothing, so a test drives it with an
// httptest server and production drives it with the provider's real endpoints.
type Client struct {
	http *http.Client
	redirectBase string
}

// ClientOptions configures a Client.
type ClientOptions struct {
	HTTPClient *http.Client
	RedirectBaseURL string
}

// NewClient returns a Client for the given options.
func NewClient(opts ClientOptions) *Client {
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultProviderTimeout}
	}
	return &Client{http: httpClient, redirectBase: opts.RedirectBaseURL}
}

// Exchange trades an authorization code for a token.
//
// The redirect URI is the same one the authorize step offered, and it has to be:
// both providers compare it against the registered value and refuse a mismatch
// without saying which of the two URLs was wrong.
func (c *Client) Exchange(ctx context.Context, p Provider, code string) (Tokens, error) {
	if strings.TrimSpace(code) == "" {
		return Tokens{}, fmt.Errorf("%w: no code was presented", ErrCodeRefused)
	}

	conf := p.oauth2Config()
	conf.RedirectURL = p.RedirectURI(c.redirectBase)

	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.http)

	token, err := conf.Exchange(ctx, code)
	if err != nil {
		return Tokens{}, providerError("exchanging the authorization code", err)
	}
	if token.AccessToken == "" {
		return Tokens{}, fmt.Errorf("%w: the exchange succeeded with no access token", ErrProviderUnavailable)
	}

	out := Tokens{AccessToken: token.AccessToken, RefreshToken: token.RefreshToken}
	if !token.Expiry.IsZero() {
		expiry := token.Expiry.UTC()
		out.ExpiresAt = &expiry
	}
	if idToken, ok := token.Extra("id_token").(string); ok {
		out.IDToken = idToken
	}
	return out, nil
}

// Identity asks the provider who the token belongs to.
//
// The address is validated against the same rules a registration is held to, and a
// provider that returns something unusable is refused rather than repaired. The
// alternative — accepting whatever came back and letting `users.email`'s CHECK
// reject it later — moves the failure to a place with no provider context.
func (c *Client) Identity(ctx context.Context, p Provider, tokens Tokens) (Identity, error) {
	if tokens.AccessToken == "" {
		return Identity{}, fmt.Errorf("%w: there is no access token to present", ErrProviderUnavailable)
	}

	switch p.Name {
	case ProviderGoogle:
		return c.googleIdentity(ctx, p, tokens)
	case ProviderGitHub:
		return c.githubIdentity(ctx, p, tokens)
	case ProviderMicrosoft:
		return c.microsoftIdentity(ctx, p, tokens)
	case ProviderApple:
		return c.appleIdentity(ctx, p, tokens)
	default:
		return Identity{}, fmt.Errorf("%w: %q has no identity endpoint", ErrUnknownProvider, p.Name)
	}
}

type googleResponse struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	EmailVerified bool   `json:"email_verified"`
}

func (c *Client) googleIdentity(ctx context.Context, p Provider, tokens Tokens) (Identity, error) {
	var body googleResponse
	if err := c.getJSON(ctx, p.UserInfoURL, tokens.AccessToken, &body); err != nil {
		return Identity{}, err
	}

	if !body.EmailVerified {
		return Identity{}, fmt.Errorf("%w: google reports this address as unverified", ErrNoEmail)
	}

	return identity(body.Subject, body.Email, body.Name)
}

type microsoftResponse struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
}

func (c *Client) microsoftIdentity(ctx context.Context, p Provider, tokens Tokens) (Identity, error) {
	var body microsoftResponse
	if err := c.getJSON(ctx, p.UserInfoURL, tokens.AccessToken, &body); err != nil {
		return Identity{}, err
	}

	return identity(body.Subject, body.Email, body.Name)
}

type githubResponse struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
	Login string `json:"login"`
	Name  string `json:"name"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (c *Client) githubIdentity(ctx context.Context, p Provider, tokens Tokens) (Identity, error) {
	var body githubResponse
	if err := c.getJSON(ctx, p.UserInfoURL, tokens.AccessToken, &body); err != nil {
		return Identity{}, err
	}

	name := body.Name
	if name == "" {
		name = body.Login
	}

	uid := ""
	if body.ID > 0 {
		uid = strconv.FormatInt(body.ID, 10)
	}

	email := body.Email
	if email == "" && p.EmailsURL != "" {
		resolved, err := c.githubEmail(ctx, p, tokens)
		if err != nil {
			return Identity{}, err
		}
		email = resolved
	}

	return identity(uid, email, name)
}

func (c *Client) githubEmail(ctx context.Context, p Provider, tokens Tokens) (string, error) {
	var emails []githubEmail
	if err := c.getJSON(ctx, p.EmailsURL, tokens.AccessToken, &emails); err != nil {
		return "", err
	}

	fallback := ""
	for _, e := range emails {
		if !e.Verified {
			continue
		}
		if e.Primary {
			return e.Email, nil
		}
		if fallback == "" {
			fallback = e.Email
		}
	}
	if fallback != "" {
		return fallback, nil
	}

	return "", fmt.Errorf("%w: github has no verified address for this account", ErrNoEmail)
}

func identity(uid, email, name string) (Identity, error) {
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return Identity{}, fmt.Errorf("%w: the provider returned no account identifier", ErrNoEmail)
	}

	normalized := users.NormalizeEmail(email)
	if err := users.ValidateEmail(normalized); err != nil {
		return Identity{}, fmt.Errorf("%w: the provider returned an address this service will not store", ErrNoEmail)
	}

	return Identity{ProviderUID: uid, Email: normalized, Name: strings.TrimSpace(name)}, nil
}

func (c *Client) getJSON(ctx context.Context, endpoint, accessToken string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("%w: building the request: %w", ErrProviderUnavailable, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProviderUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: the provider answered %d", ErrProviderUnavailable, resp.StatusCode)
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, maxIdentityBytes)).Decode(dst); err != nil {
		return fmt.Errorf("%w: reading the identity response: %w", ErrProviderUnavailable, err)
	}
	return nil
}

func providerError(what string, err error) error {
	var retrieve *oauth2.RetrieveError
	if errors.As(err, &retrieve) && retrieve.Response != nil {
		status := retrieve.Response.StatusCode
		if status >= 400 && status < 500 {
			return fmt.Errorf("%w: %s was rejected with %d (%s)", ErrCodeRefused, what, status, retrieve.ErrorCode)
		}
		return fmt.Errorf("%w: %s failed with %d", ErrProviderUnavailable, what, status)
	}
	return fmt.Errorf("%w: %s: %w", ErrProviderUnavailable, what, err)
}
