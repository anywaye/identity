package auth


import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/anywaye/identity/internal/oauth"
	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/users"
)

var (
	ErrSocialEmailInUse = errors.New("that provider account's address already belongs to another account")

	ErrSocialNoProviders = errors.New("social login is not configured")
)

// SocialRegistry is the part of oauth.Registry this use case needs: the provider
// named in the URL, and the configured base URL the callback is checked against.
//
// It is an interface declared here, at the consumer, for the reason UserStore and
// SessionStore are: the use case is testable without a registry and without a
// network, and oauth is not this package's dependency on the way it is not the
// handlers' either.
type SocialRegistry interface {
	Lookup(name string) (oauth.Provider, error)
	RedirectBase() string
}

// SocialExchanger is the part of oauth.Client: the code-for-token exchange and the
// "who is this" call. Both are on one interface because a flow that can do one and
// not the other is a flow that either mints a session for nobody or never learns
// who it is minting one for.
type SocialExchanger interface {
	Exchange(ctx context.Context, p oauth.Provider, code string) (oauth.Tokens, error)
	Identity(ctx context.Context, p oauth.Provider, tokens oauth.Tokens) (oauth.Identity, error)
}

// SocialAccounts is the connected_accounts table, and it is keyed on (provider,
// provider_uid) and never on an address. See internal/oauth.Store for why, and
// oauth.ErrAlreadyLinked for the refusal a unique-index violation becomes.
type SocialAccounts interface {
	ByProviderUID(ctx context.Context, q db.Querier, provider, providerUID string) (oauth.Account, error)
	Create(ctx context.Context, q db.Querier, n oauth.NewAccount) (oauth.Account, error)
	RefreshTokens(ctx context.Context, q db.Querier, accountID id.UUID, t oauth.StoredTokens) error
}

// SocialSealer seals a provider token for storage. The cipher is an interface here
// for one reason beyond testability: this package must never hold the key, and an
// interface it can only Seal through is a promise that it does not.
type SocialSealer interface {
	Seal(plaintext string) (string, error)
}

// SocialService is the use case behind the two social-login routes.
//
// It borrows Service rather than duplicating it: the session minting, the
// second-factor decision and the personal-account provisioning are all questions
// about a LOCAL account, and they are the same questions Register and Login ask. A
// second implementation of "mint a session and clear the failure run in one
// transaction" is a second thing to get right.
type SocialService struct {
	auth     *Service
	registry SocialRegistry
	client   SocialExchanger
	store    SocialAccounts
	sealer   SocialSealer
}

// NewSocialService wires the social-login use case.
//
// auth is the ordinary auth service, not a copy of it: every write below goes
// through its transaction runner, its session store and its tenancy provisioner, so
// a user minted here is a user the rest of the service cannot tell apart from one
// registered with a password.
func NewSocialService(
	a *Service,
	registry SocialRegistry,
	client SocialExchanger,
	store SocialAccounts,
	sealer SocialSealer,
) *SocialService {
	return &SocialService{auth: a, registry: registry, client: client, store: store, sealer: sealer}
}

// SocialCallbackInput is one completed provider round trip.
type SocialCallbackInput struct {
	Provider string
	Code string

	LinkTo users.User

	UserAgent string
	IP        *netip.Addr
}

// Callback finishes a provider round trip and answers with whatever the caller
// needs next.
//
// IT RETURNS A LoginResult, not a social type of its own, and that is the second
// factor. The shape a caller gets here is decided by LoginResult.MFARequired and by
// nothing else, exactly as for a password login, which means an account with a
// confirmed second factor gets a CHALLENGE from a social callback and not a
// session. A social sign-in that minted a session for a two-factor account would be
// the single largest hole this file could have, and reusing the type is what makes
// it a hole somebody cannot add by accident: there is no field of this result from
// which a session can be had without the second factor having been presented.
func (s *SocialService) Callback(ctx context.Context, in SocialCallbackInput) (LoginResult, error) {
	if s.registry == nil {
		return LoginResult{}, ErrSocialNoProviders
	}

	provider, err := s.registry.Lookup(in.Provider)
	if err != nil {
		return LoginResult{}, err
	}

	tokens, err := s.client.Exchange(ctx, provider, in.Code)
	if err != nil {
		return LoginResult{}, err
	}
	identity, err := s.client.Identity(ctx, provider, tokens)
	if err != nil {
		return LoginResult{}, err
	}

	sealed, err := s.seal(tokens)
	if err != nil {
		return LoginResult{}, err
	}

	if !in.LinkTo.ID.IsZero() {
		return s.link(ctx, provider, identity, sealed, in)
	}
	return s.signIn(ctx, provider, identity, sealed, in)
}

func (s *SocialService) seal(tokens oauth.Tokens) (oauth.StoredTokens, error) {
	access, err := s.sealer.Seal(tokens.AccessToken)
	if err != nil {
		return oauth.StoredTokens{}, fmt.Errorf("sealing a provider access token: %w", err)
	}

	out := oauth.StoredTokens{AccessTokenCiphertext: access, ExpiresAt: tokens.ExpiresAt}
	if tokens.RefreshToken == "" {
		return out, nil
	}
	refresh, err := s.sealer.Seal(tokens.RefreshToken)
	if err != nil {
		return oauth.StoredTokens{}, fmt.Errorf("sealing a provider refresh token: %w", err)
	}
	out.RefreshTokenCiphertext = refresh
	return out, nil
}

func (s *SocialService) signIn(
	ctx context.Context,
	provider oauth.Provider,
	identity oauth.Identity,
	sealed oauth.StoredTokens,
	in SocialCallbackInput,
) (LoginResult, error) {
	now := s.auth.clock.Now()

	account, err := s.store.ByProviderUID(ctx, s.auth.read.Queryer(), provider.Name, identity.ProviderUID)
	switch {
	case err == nil:
		return s.signInAs(ctx, account, sealed, in, now)

	case errors.Is(err, oauth.ErrNotFound):
		existing, err := s.auth.users.ByEmail(ctx, s.auth.read.Queryer(), identity.Email)
		switch {
		case err == nil:
			_ = existing
			return LoginResult{}, ErrSocialEmailInUse
		case errors.Is(err, users.ErrNotFound):
			return s.createAndSignIn(ctx, provider, identity, sealed, in, now)
		default:
			return LoginResult{}, fmt.Errorf("looking up a user by a provider's address: %w", err)
		}

	default:
		return LoginResult{}, fmt.Errorf("looking up a connected account: %w", err)
	}
}

func (s *SocialService) signInAs(
	ctx context.Context,
	account oauth.Account,
	sealed oauth.StoredTokens,
	in SocialCallbackInput,
	now time.Time,
) (LoginResult, error) {
	user, err := s.auth.users.ByID(ctx, s.auth.read.Queryer(), account.UserID)
	if err != nil {
		return LoginResult{}, fmt.Errorf("connected account %s names a user that does not exist: %w",
			account.ID, err)
	}

	if err := s.store.RefreshTokens(ctx, s.auth.read.Queryer(), account.ID, sealed); err != nil {
		return LoginResult{}, fmt.Errorf("writing a refreshed provider credential: %w", err)
	}

	return s.auth.startLogin(ctx, user, LoginInput{UserAgent: in.UserAgent, IP: in.IP}, now)
}

func (s *SocialService) createAndSignIn(
	ctx context.Context,
	provider oauth.Provider,
	identity oauth.Identity,
	sealed oauth.StoredTokens,
	in SocialCallbackInput,
	now time.Time,
) (LoginResult, error) {
	digest, err := s.unusablePassword()
	if err != nil {
		return LoginResult{}, err
	}

	var created users.User
	err = s.auth.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		u, err := s.auth.users.Create(ctx, q, users.CreateParams{Email: identity.Email, PasswordDigest: digest})
		if err != nil {
			return err
		}
		if err := s.auth.provisionTenancy(ctx, q, u); err != nil {
			return err
		}
		event, err := outbox.NewUserCreated(now, u.ID, u.Email)
		if err != nil {
			return err
		}
		if err := s.auth.events.Append(ctx, q, event); err != nil {
			return err
		}
		if _, err := s.store.Create(ctx, q, oauth.NewAccount{
			UserID:                 u.ID,
			Provider:               provider.Name,
			ProviderUID:            identity.ProviderUID,
			AccessTokenCiphertext:  sealed.AccessTokenCiphertext,
			RefreshTokenCiphertext: sealed.RefreshTokenCiphertext,
			ExpiresAt:              sealed.ExpiresAt,
		}); err != nil {
			return err
		}
		created = u
		return nil
	})
	if err != nil {
		return LoginResult{}, err
	}

	return s.auth.startLogin(ctx, created, LoginInput{UserAgent: in.UserAgent, IP: in.IP}, now)
}

func (s *SocialService) link(
	ctx context.Context,
	provider oauth.Provider,
	identity oauth.Identity,
	sealed oauth.StoredTokens,
	in SocialCallbackInput,
) (LoginResult, error) {
	owner := in.LinkTo

	existing, err := s.store.ByProviderUID(ctx, s.auth.read.Queryer(), provider.Name, identity.ProviderUID)
	switch {
	case err == nil:
		if existing.UserID != owner.ID {
			return LoginResult{}, oauth.ErrAlreadyLinked
		}
		if err := s.store.RefreshTokens(ctx, s.auth.read.Queryer(), existing.ID, sealed); err != nil {
			return LoginResult{}, fmt.Errorf("writing a re-consented provider credential: %w", err)
		}
		return LoginResult{User: RegisteredUser{ID: owner.ID, Email: owner.Email}}, nil

	case errors.Is(err, oauth.ErrNotFound):
		_, err := s.store.Create(ctx, s.auth.read.Queryer(), oauth.NewAccount{
			UserID:                 owner.ID,
			Provider:               provider.Name,
			ProviderUID:            identity.ProviderUID,
			AccessTokenCiphertext:  sealed.AccessTokenCiphertext,
			RefreshTokenCiphertext: sealed.RefreshTokenCiphertext,
			ExpiresAt:              sealed.ExpiresAt,
		})
		if err != nil {
			return LoginResult{}, err
		}
		return LoginResult{User: RegisteredUser{ID: owner.ID, Email: owner.Email}}, nil

	default:
		return LoginResult{}, fmt.Errorf("looking up a connected account: %w", err)
	}
}

func (s *SocialService) unusablePassword() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("reading random bytes for a social account's password: %w", err)
	}
	digest, err := s.auth.hasher.Hash(base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		return "", fmt.Errorf("hashing a social account's placeholder password: %w", err)
	}
	return digest, nil
}

