package auth


import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"

	"github.com/anywaye/identity/internal/oauth"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/users"
)


type fakeSocialRegistry struct {
	providers map[string]oauth.Provider
	base      string

	lookupErr error
}

func newFakeSocialRegistry(names ...string) *fakeSocialRegistry {
	r := &fakeSocialRegistry{providers: map[string]oauth.Provider{}, base: "https://identity.test"}
	definitions := map[string]oauth.Provider{
		oauth.ProviderGoogle:    oauth.Google(),
		oauth.ProviderGitHub:    oauth.GitHub(),
		oauth.ProviderMicrosoft: oauth.Microsoft(),
		oauth.ProviderApple:     oauth.Apple(),
	}
	for _, name := range names {
		p := definitions[name]
		p.ClientID = "id-" + name
		p.ClientSecret = "secret-" + name
		r.providers[name] = p
	}
	return r
}

func (r *fakeSocialRegistry) Lookup(name string) (oauth.Provider, error) {
	if r.lookupErr != nil {
		return oauth.Provider{}, r.lookupErr
	}
	p, ok := r.providers[name]
	if !ok {
		return oauth.Provider{}, oauth.ErrUnknownProvider
	}
	return p, nil
}

func (r *fakeSocialRegistry) RedirectBase() string { return r.base }

type fakeExchanger struct {
	calls []string

	exchangeErr error
	identityErr error

	tokens   oauth.Tokens
	identity oauth.Identity
}

func (c *fakeExchanger) Exchange(_ context.Context, _ oauth.Provider, _ string) (oauth.Tokens, error) {
	c.calls = append(c.calls, "exchange")
	if c.exchangeErr != nil {
		return oauth.Tokens{}, c.exchangeErr
	}
	return c.tokens, nil
}

func (c *fakeExchanger) Identity(_ context.Context, _ oauth.Provider, _ oauth.Tokens) (oauth.Identity, error) {
	c.calls = append(c.calls, "identity")
	if c.identityErr != nil {
		return oauth.Identity{}, c.identityErr
	}
	return c.identity, nil
}

type fakeAccounts struct {
	rows    map[string]oauth.Account
	creates []oauth.NewAccount
	nextID  int

	createQueriers []db.Querier
	readQueriers []db.Querier

	lookupErr error
	createErr error

	refreshed []refreshCall
	refreshQueriers []db.Querier
}

type refreshCall struct {
	accountID id.UUID
	tokens    oauth.StoredTokens
}

func newFakeAccounts() *fakeAccounts {
	return &fakeAccounts{rows: map[string]oauth.Account{}}
}

func accountKey(provider, providerUID string) string { return provider + "\x00" + providerUID }

func (a *fakeAccounts) ByProviderUID(_ context.Context, q db.Querier, provider, providerUID string) (oauth.Account, error) {
	a.readQueriers = append(a.readQueriers, q)
	if a.lookupErr != nil {
		return oauth.Account{}, a.lookupErr
	}
	row, ok := a.rows[accountKey(provider, providerUID)]
	if !ok {
		return oauth.Account{}, oauth.ErrNotFound
	}
	return row, nil
}

func (a *fakeAccounts) Create(_ context.Context, q db.Querier, n oauth.NewAccount) (oauth.Account, error) {
	a.createQueriers = append(a.createQueriers, q)
	a.creates = append(a.creates, n)

	key := accountKey(n.Provider, n.ProviderUID)
	if _, taken := a.rows[key]; taken {
		return oauth.Account{}, oauth.ErrAlreadyLinked
	}
	if a.createErr != nil {
		return oauth.Account{}, a.createErr
	}

	a.nextID++
	var accountID id.UUID
	accountID[13] = byte(a.nextID)
	row := oauth.Account{
		ID:                     accountID,
		UserID:                 n.UserID,
		Provider:               n.Provider,
		ProviderUID:            n.ProviderUID,
		AccessTokenCiphertext:  n.AccessTokenCiphertext,
		RefreshTokenCiphertext: n.RefreshTokenCiphertext,
		ExpiresAt:              n.ExpiresAt,
		CreatedAt:              start,
		UpdatedAt:              start,
	}
	a.rows[key] = row
	return row, nil
}

func (a *fakeAccounts) RefreshTokens(_ context.Context, q db.Querier, accountID id.UUID, t oauth.StoredTokens) error {
	a.refreshQueriers = append(a.refreshQueriers, q)
	a.refreshed = append(a.refreshed, refreshCall{accountID: accountID, tokens: t})

	for key, row := range a.rows {
		if row.ID == accountID {
			row.AccessTokenCiphertext = t.AccessTokenCiphertext
			if t.RefreshTokenCiphertext != "" {
				row.RefreshTokenCiphertext = t.RefreshTokenCiphertext
			}
			row.ExpiresAt = t.ExpiresAt
			a.rows[key] = row
		}
	}
	return nil
}

type fakeSealer struct {
	sealed []string
	err    error
}

func (s *fakeSealer) Seal(plaintext string) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	s.sealed = append(s.sealed, plaintext)
	return "sealed:" + plaintext, nil
}

type socialFixture struct {
	t        *testing.T
	auth     *fixture
	registry *fakeSocialRegistry
	client   *fakeExchanger
	store    *fakeAccounts
	sealer   *fakeSealer
	svc      *SocialService
}

func newSocialFixtureWithBothProviders(t *testing.T) *socialFixture {
	t.Helper()
	return newSocialFixture(t, oauth.ProviderGoogle, oauth.ProviderGitHub)
}

func newSocialFixture(t *testing.T, names ...string) *socialFixture {
	t.Helper()

	f := &socialFixture{
		t:        t,
		auth:     newFixture(),
		registry: newFakeSocialRegistry(names...),
		client:   &fakeExchanger{},
		store:    newFakeAccounts(),
		sealer:   &fakeSealer{},
	}
	f.svc = NewSocialService(f.auth.svc, f.registry, f.client, f.store, f.sealer)
	return f
}

func socialIP() *netip.Addr {
	addr := netip.MustParseAddr("203.0.113.7")
	return &addr
}

func (f *socialFixture) callback(provider, code, uid, email string) (LoginResult, error) {
	f.client.tokens = oauth.Tokens{AccessToken: "access-" + code, RefreshToken: "refresh-" + code}
	f.client.identity = oauth.Identity{ProviderUID: uid, Email: email, Name: "Test Person"}
	return f.svc.Callback(context.Background(), SocialCallbackInput{
		Provider:  provider,
		Code:      code,
		UserAgent: "test-agent",
		IP:        socialIP(),
	})
}

func (f *socialFixture) signInWith(provider, code string, tokens oauth.Tokens, identity oauth.Identity) (LoginResult, error) {
	f.client.tokens = tokens
	f.client.identity = identity
	return f.svc.Callback(context.Background(), SocialCallbackInput{
		Provider:  provider,
		Code:      code,
		UserAgent: "test-agent",
		IP:        socialIP(),
	})
}

func (f *socialFixture) link(provider, code, uid, email string, owner users.User) (LoginResult, error) {
	f.client.tokens = oauth.Tokens{AccessToken: "access-" + code}
	f.client.identity = oauth.Identity{ProviderUID: uid, Email: email, Name: "Test Person"}
	return f.svc.Callback(context.Background(), SocialCallbackInput{
		Provider:  provider,
		Code:      code,
		LinkTo:    owner,
		UserAgent: "test-agent",
		IP:        socialIP(),
	})
}

func (f *socialFixture) linkOwner(email string) users.User {
	f.t.Helper()
	return f.auth.register(f.t, email, "correct horse battery staple")
}

func (f *socialFixture) sessionsMinted() int { return len(f.auth.sessions.minted) }


func TestASeenProviderIdentitySignsInAsItsOwner(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGoogle)

	owner := f.linkOwner("owner@example.com")

	f.store.rows[accountKey(oauth.ProviderGoogle, "google-uid-1")] = oauth.Account{
		ID:          mustUUID(1),
		UserID:      owner.ID,
		Provider:    oauth.ProviderGoogle,
		ProviderUID: "google-uid-1",
	}

	got, err := f.callback(oauth.ProviderGoogle, "code-1", "google-uid-1", "someone-else@example.com")
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}

	if got.User.ID != owner.ID {
		t.Errorf("signed in as %s, want the connected account's owner %s. A provider identity that "+
			"has been seen must resolve to the user it was linked to, not to whoever holds its "+
			"address today.", got.User.ID, owner.ID)
	}
	if got.User.Email != "owner@example.com" {
		t.Errorf("LoginResult carries the address %q, want the stored user's %q. The result must "+
			"describe the LOCAL account; the provider's address is not this service's to hand out "+
			"as the signed-in identity.", got.User.Email, "owner@example.com")
	}
	if got.Token == "" {
		t.Error("no session token was minted. A provider identity that has been seen signs the " +
			"owner in.")
	}
	if got.MFARequired {
		t.Error("MFARequired is true for an account the double reports as having no second factor.")
	}
	if got.Challenge != nil {
		t.Error("a challenge was returned alongside a session, which is a shape LoginResult does " +
			"not describe.")
	}

	if len(f.auth.sessions.minted) != 1 {
		t.Errorf("%d sessions minted, want 1", len(f.auth.sessions.minted))
	}
	if len(f.auth.users.byEmail) != 1 {
		t.Errorf("the user table holds %d rows, want 1. A returning provider identity must not "+
			"create an account, and creating one would be an orphan nobody can sign in to.",
			len(f.auth.users.byEmail))
	}
	if n := len(f.store.refreshed); n != 1 {
		t.Errorf("%d RefreshTokens calls, want 1. A re-consent writes the freshly issued "+
			"credential so the stored copy does not age into something unusable, and it writes it "+
			"on the way IN rather than on a later provider call.", n)
	}
}

func TestAFreshProviderIdentityCreatesTheAccount(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGitHub)

	got, err := f.callback(oauth.ProviderGitHub, "code-2", "github-uid-2", "new@example.com")
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}

	if got.User.Email != "new@example.com" {
		t.Errorf("signed in as %q, want the address the provider reported", got.User.Email)
	}
	if got.Token == "" {
		t.Error("no session token was minted for a newly created account")
	}
	if len(f.auth.sessions.minted) != 1 {
		t.Errorf("%d sessions minted, want 1", len(f.auth.sessions.minted))
	}

	if len(f.auth.users.byEmail) != 1 {
		t.Errorf("%d users created, want 1", len(f.auth.users.byEmail))
	}
	if len(f.auth.tenancy.provisioned) != 1 {
		t.Fatalf("%d personal accounts provisioned, want 1. A user with no account is a state "+
			"nothing downstream can repair.", len(f.auth.tenancy.provisioned))
	}
	if len(f.auth.events.appended) != 1 {
		t.Errorf("%d outbox events appended, want 1 (user.created)", len(f.auth.events.appended))
	}
	if len(f.store.creates) != 1 {
		t.Fatalf("%d connected accounts created, want 1", len(f.store.creates))
	}

	created := f.store.creates[0]
	if created.ProviderUID != "github-uid-2" || created.Provider != oauth.ProviderGitHub {
		t.Errorf("the connected account is keyed on (%q, %q), want (%q, %q). The key is the "+
			"provider's OWN identifier — an address can be changed at the provider and is not "+
			"unique across accounts there.",
			created.Provider, created.ProviderUID, oauth.ProviderGitHub, "github-uid-2")
	}
	if created.UserID != got.User.ID {
		t.Errorf("the connected account names user %s but the session was minted for %s",
			created.UserID, got.User.ID)
	}

	for _, q := range f.auth.tenancy.queriersUsed {
		if marker, ok := q.(markerQuerier); !ok || marker.name != "transaction" {
			t.Errorf("provisioning was handed the %v querier, want the transaction's. The account "+
				"and the user are one transaction or neither exists.", q)
		}
	}
	for _, q := range f.auth.events.queriersUsed {
		if marker, ok := q.(markerQuerier); !ok || marker.name != "transaction" {
			t.Errorf("the outbox append was handed the %v querier, want the transaction's", q)
		}
	}
	for _, q := range f.store.createQueriers {
		if marker, ok := q.(markerQuerier); !ok || marker.name != "transaction" {
			t.Errorf("the connected-account insert was handed the %v querier, want the "+
				"transaction's. A connected account with no user is the other half of the same "+
				"unrepairable state", q)
		}
	}
}

func TestAFreshMicrosoftIdentityCreatesTheAccount(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderMicrosoft)

	got, err := f.callback(oauth.ProviderMicrosoft, "code-ms", "ms-uid-1", "kaka@example.com")
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}

	if got.User.Email != "kaka@example.com" {
		t.Errorf("signed in as %q, want the address the provider reported", got.User.Email)
	}
	if got.Token == "" {
		t.Error("no session token was minted for a newly created account")
	}
	if len(f.store.creates) != 1 {
		t.Fatalf("%d connected accounts created, want 1", len(f.store.creates))
	}

	created := f.store.creates[0]
	if created.Provider != oauth.ProviderMicrosoft || created.ProviderUID != "ms-uid-1" {
		t.Errorf("the connected account is keyed on (%q, %q), want (%q, %q)",
			created.Provider, created.ProviderUID, oauth.ProviderMicrosoft, "ms-uid-1")
	}
	if created.UserID != got.User.ID {
		t.Errorf("the connected account names user %s but the session was minted for %s",
			created.UserID, got.User.ID)
	}
}

func TestAFreshAppleIdentityCreatesTheAccount(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderApple)

	got, err := f.callback(oauth.ProviderApple, "code-apple", "apple-uid-1", "kaka@example.com")
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}

	if got.User.Email != "kaka@example.com" {
		t.Errorf("signed in as %q, want the address the provider reported", got.User.Email)
	}
	if got.Token == "" {
		t.Error("no session token was minted for a newly created account")
	}
	if len(f.store.creates) != 1 {
		t.Fatalf("%d connected accounts created, want 1", len(f.store.creates))
	}

	created := f.store.creates[0]
	if created.Provider != oauth.ProviderApple || created.ProviderUID != "apple-uid-1" {
		t.Errorf("the connected account is keyed on (%q, %q), want (%q, %q)",
			created.Provider, created.ProviderUID, oauth.ProviderApple, "apple-uid-1")
	}
	if created.UserID != got.User.ID {
		t.Errorf("the connected account names user %s but the session was minted for %s",
			created.UserID, got.User.ID)
	}
}

func TestTheFourOutcomesAreReachableAndAreTheOnesTheCodeNames(t *testing.T) {
	t.Parallel()

	type shape struct {
		wantErr     error
		wantSession bool
		wantUser    string
		describe    string
	}

	for _, tc := range []struct {
		name   string
		setup  func(*socialFixture) users.User
		linkTo bool
		invoke func(*socialFixture, users.User) (LoginResult, error)
		want   shape
	}{
		{
			name: "signIn, provider identity seen",
			setup: func(f *socialFixture) users.User {
				owner := f.linkOwner("owner@example.com")
				f.store.rows[accountKey(oauth.ProviderGoogle, "uid-seen")] = oauth.Account{
					ID: mustUUID(1), UserID: owner.ID,
					Provider: oauth.ProviderGoogle, ProviderUID: "uid-seen",
				}
				return owner
			},
			invoke: func(f *socialFixture, _ users.User) (LoginResult, error) {
				return f.callback(oauth.ProviderGoogle, "c", "uid-seen", "owner@example.com")
			},
			want: shape{wantSession: true, wantUser: "owner@example.com", describe: "signInAs"},
		},
		{
			name: "signIn, address already belongs to an account",
			setup: func(f *socialFixture) users.User {
				f.linkOwner("victim@example.com")
				return users.User{}
			},
			invoke: func(f *socialFixture, _ users.User) (LoginResult, error) {
				return f.callback(oauth.ProviderGoogle, "c", "uid-new", "victim@example.com")
			},
			want: shape{
				wantErr:  ErrSocialEmailInUse,
				describe: "question 4's refusal",
			},
		},
		{
			name:  "signIn, address free",
			setup: func(*socialFixture) users.User { return users.User{} },
			invoke: func(f *socialFixture, _ users.User) (LoginResult, error) {
				return f.callback(oauth.ProviderGoogle, "c", "uid-fresh", "fresh@example.com")
			},
			want: shape{wantSession: true, wantUser: "fresh@example.com", describe: "createAndSignIn"},
		},
		{
			name: "link, provider identity belongs to somebody else",
			setup: func(f *socialFixture) users.User {
				victim := f.linkOwner("victim@example.com")
				attacker := f.linkOwner("attacker@example.com")
				f.store.rows[accountKey(oauth.ProviderGitHub, "uid-theirs")] = oauth.Account{
					ID: mustUUID(1), UserID: victim.ID,
					Provider: oauth.ProviderGitHub, ProviderUID: "uid-theirs",
				}
				return attacker
			},
			linkTo: true,
			invoke: func(f *socialFixture, owner users.User) (LoginResult, error) {
				return f.link(oauth.ProviderGitHub, "c", "uid-theirs", "attacker@example.com", owner)
			},
			want: shape{
				wantErr:  oauth.ErrAlreadyLinked,
				describe: "question 2's refusal",
			},
		},
		{
			name:   "link, provider identity is the caller's own",
			setup:  func(f *socialFixture) users.User { return f.linkOwner("me@example.com") },
			linkTo: true,
			invoke: func(f *socialFixture, owner users.User) (LoginResult, error) {
				return f.link(oauth.ProviderGitHub, "c", "uid-mine", "me@example.com", owner)
			},
			want: shape{wantUser: "me@example.com", describe: "link, and NO session"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newSocialFixture(t, oauth.ProviderGoogle, oauth.ProviderGitHub)
			owner := tc.setup(f)

			got, err := tc.invoke(f, owner)
			if tc.want.wantErr != nil {
				if !errors.Is(err, tc.want.wantErr) {
					t.Fatalf("Callback error = %v, want %v. The handler maps this value to a "+
						"status code, so the VALUE is what makes the mapping reachable.", err, tc.want.wantErr)
				}
				if got.Token != "" {
					t.Errorf("a refused callback returned a session token %q. A refusal that mints a "+
						"credential has already lost: everything after it is a detail.", got.Token)
				}
				if n := f.sessionsMinted(); n != 0 {
					t.Errorf("%d sessions minted on a refusal", n)
				}
				return
			}

			if err != nil {
				t.Fatalf("Callback: %v", err)
			}
			if got.User.Email != tc.want.wantUser {
				t.Errorf("signed in as %q, want %q", got.User.Email, tc.want.wantUser)
			}
			if tc.want.wantSession && got.Token == "" {
				t.Errorf("no session token: this outcome (%s) signs the caller in", tc.want.describe)
			}
			if !tc.want.wantSession && got.Token != "" {
				t.Errorf("a session token was minted for %s: %q. That outcome must mint nothing.",
					tc.want.describe, got.Token)
			}
		})
	}
}


func TestTheAddressCollisionRefusesRatherThanLinks(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGoogle)

	victim := f.linkOwner("victim@example.com")

	got, err := f.callback(oauth.ProviderGoogle, "attacker-code", "attacker-uid", "victim@example.com")
	if !errors.Is(err, ErrSocialEmailInUse) {
		t.Fatalf("Callback error = %v, want ErrSocialEmailInUse. The provider has verified an "+
			"address that already belongs to an account here, and linking it would sign the "+
			"attacker in as the victim. Refusing is a support call; auto-linking is an incident.",
			err)
	}

	if got.Token != "" {
		t.Errorf("the refusal returned a session token %q", got.Token)
	}
	if n := f.sessionsMinted(); n != 0 {
		t.Errorf("%d sessions minted on a refusal", n)
	}
	if n := len(f.store.creates); n != 0 {
		t.Errorf("%d connected accounts created on a refusal. Creating the row IS the takeover — "+
			"the next callback for this provider identity signs the attacker in as the victim. "+
			"Refusing and then linking anyway is the failure this test exists to catch.", n)
	}
	if n := len(f.auth.users.byEmail); n != 1 {
		t.Errorf("%d users exist, want 1 (the victim's). The refusal must not create anything.", n)
	}
	if _, taken := f.auth.users.byEmail["victim@example.com"]; !taken {
		t.Error("the victim's account is gone, which no branch of this file does")
	}
	if got.User.ID.IsZero() == false || got.User.ID == victim.ID {
		t.Errorf("the refusal carries a user (%s); it must carry none", got.User.ID)
	}
}

func TestTheAddressCollisionRefusalIsOnlyOnTheSignInPath(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGitHub)

	f.linkOwner("other@example.com")

	caller := f.linkOwner("caller@example.com")

	got, err := f.link(oauth.ProviderGitHub, "c", "caller-uid", "other@example.com", caller)
	if err != nil {
		t.Fatalf("Callback: %v. A signed-in person linking a provider account whose address "+
			"belongs to another account here is a legitimate operation, and refusing it would "+
			"block a real user for a reason that does not apply to the link path.", err)
	}

	if got.User.ID != caller.ID {
		t.Errorf("the link reported user %s, want the caller %s. The link attaches the provider "+
			"identity to the CALLER, whoever the address belongs to.", got.User.ID, caller.ID)
	}
	if got.Token != "" {
		t.Errorf("the link minted a session token %q. Linking is not signing in.", got.Token)
	}
	if n := len(f.store.creates); n != 1 {
		t.Fatalf("%d connected accounts created, want 1", n)
	}
	if f.store.creates[0].UserID != caller.ID {
		t.Errorf("the connected account names %s, want the caller %s",
			f.store.creates[0].UserID, caller.ID)
	}
}


func TestLinkingReturnsNoSessionAndNoChallenge(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGoogle)

	caller := f.linkOwner("caller@example.com")

	got, err := f.link(oauth.ProviderGoogle, "c", "caller-uid", "caller@example.com", caller)
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}

	if got.Token != "" {
		t.Errorf("Token = %q, want empty. The caller already holds a session; minting a second one "+
			"because a third-party round trip completed is a credential whose lifetime this service "+
			"chose for reasons the caller did not ask for.", got.Token)
	}
	if !got.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt = %v, want the zero time. It is the epoch, and a client that renders "+
			"`expires_at` shows a date in 1970.", got.ExpiresAt)
	}
	if got.Challenge != nil {
		t.Errorf("Challenge = %+v, want nil. The link path never asked about a second factor.", got.Challenge)
	}
	if got.MFARequired {
		t.Error("MFARequired is true on the link path. Nothing asked about a second factor, and " +
			"this flag is what makes internal/httpapi take its challenge branch.")
	}

	if n := f.sessionsMinted(); n != 0 {
		t.Errorf("%d sessions minted by a link", n)
	}
	if got.User.ID != caller.ID || got.User.Email != "caller@example.com" {
		t.Errorf("the link result describes %+v, want the caller it was linked for", got.User)
	}
}

func TestLinkingARefusedIdentityWritesNothing(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGitHub)

	victim := f.linkOwner("victim@example.com")
	attacker := f.linkOwner("attacker@example.com")

	victimRow := oauth.Account{
		ID: mustUUID(1), UserID: victim.ID,
		Provider: oauth.ProviderGitHub, ProviderUID: "victim-uid",
	}
	f.store.rows[accountKey(oauth.ProviderGitHub, "victim-uid")] = victimRow

	got, err := f.link(oauth.ProviderGitHub, "c", "victim-uid", "attacker@example.com", attacker)
	if !errors.Is(err, oauth.ErrAlreadyLinked) {
		t.Fatalf("Callback error = %v, want oauth.ErrAlreadyLinked. Somebody else owns this "+
			"provider identity and the caller is signed in as somebody who does not; a redirect or "+
			"a silent success would tell the caller their account is linked to theirs when it is "+
			"attached to another person's — the exact state an attacker is trying to create.", err)
	}

	if got.Token != "" {
		t.Errorf("a refused link returned a session token %q", got.Token)
	}
	if n := len(f.store.creates); n != 0 {
		t.Errorf("%d connected accounts created on a refused link", n)
	}
	if n := len(f.store.refreshed); n != 0 {
		t.Errorf("%d credential rewrites on a refused link. Rewriting the victim's stored token is "+
			"the other half of the takeover: the attacker's callback would leave the attacker "+
			"holding a usable provider credential on the victim's row.", n)
	}

	stored, lookupErr := f.store.ByProviderUID(context.Background(), markerQuerier{}, oauth.ProviderGitHub, "victim-uid")
	if lookupErr != nil {
		t.Fatalf("reading the victim's row back: %v", lookupErr)
	}
	if stored.UserID != victim.ID {
		t.Errorf("the row now names %s, want the original owner %s", stored.UserID, victim.ID)
	}
}

func TestRelinkingYourOwnIdentityRewritesTheCredentialAndMintsNothing(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGoogle)

	caller := f.linkOwner("caller@example.com")

	f.store.rows[accountKey(oauth.ProviderGoogle, "caller-uid")] = oauth.Account{
		ID: mustUUID(1), UserID: caller.ID,
		Provider:               oauth.ProviderGoogle,
		ProviderUID:            "caller-uid",
		AccessTokenCiphertext:  "sealed:access-old",
		RefreshTokenCiphertext: "sealed:refresh-old",
	}

	f.client.tokens = oauth.Tokens{AccessToken: "access-new"}
	f.client.identity = oauth.Identity{ProviderUID: "caller-uid", Email: "caller@example.com"}

	got, err := f.svc.Callback(context.Background(), SocialCallbackInput{
		Provider: oauth.ProviderGoogle,
		Code:     "reconsent",
		LinkTo:   caller,
	})
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}

	if got.Token != "" {
		t.Errorf("a re-consent minted a session token %q. Linking mints nothing, however it was "+
			"reached.", got.Token)
	}
	if len(f.store.creates) != 0 {
		t.Errorf("%d connected accounts created on a re-consent. The row already exists; a second "+
			"one would be refused by the unique index at best.", len(f.store.creates))
	}
	if len(f.store.refreshed) != 1 {
		t.Fatalf("%d RefreshTokens calls, want 1. A re-consent issues a new provider token and the "+
			"stored copy has to be replaced or it ages into something unusable.", len(f.store.refreshed))
	}
	if got := f.store.refreshed[0].tokens.AccessTokenCiphertext; got != "sealed:access-new" {
		t.Errorf("the stored access token is %q, want the freshly sealed one", got)
	}
	if got := f.store.refreshed[0].tokens.RefreshTokenCiphertext; got != "" {
		t.Errorf("RefreshTokenCiphertext = %q, want empty. This provider issued no refresh token, "+
			"and oauth.Store.RefreshTokens reads empty as KEEP WHAT IS STORED — passing anything "+
			"else here would blank a column that holds a working credential.", got)
	}

	stored, err := f.store.ByProviderUID(context.Background(), markerQuerier{}, oauth.ProviderGoogle, "caller-uid")
	if err != nil {
		t.Fatalf("reading the row back: %v", err)
	}
	if stored.AccessTokenCiphertext != "sealed:access-new" {
		t.Errorf("the stored access token is %q, want the new one", stored.AccessTokenCiphertext)
	}
	if stored.RefreshTokenCiphertext != "sealed:refresh-old" {
		t.Errorf("the stored refresh token is %q, want the previous one to have survived", stored.RefreshTokenCiphertext)
	}
}


func TestAnUnconfiguredProviderIsRefusedBeforeAnyProviderCall(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGoogle)

	if _, err := f.callback(oauth.ProviderGoogle, "real-code", "uid", "person@example.com"); err != nil {
		t.Fatalf("Callback: %v", err)
	}
	spent := len(f.client.calls)
	if spent == 0 {
		t.Fatal("the exchanger was never called even for a CONFIGURED provider, so the assertion " +
			"below would pass for the wrong reason.")
	}

	got, err := f.callback("apple", "real-code", "uid", "person@example.com")
	if !errors.Is(err, oauth.ErrUnknownProvider) {
		t.Fatalf("Callback for an unconfigured provider = %v, want oauth.ErrUnknownProvider. The "+
			"handler renders that as 404, the same answer as a route that does not exist, and "+
			"neither says which providers this deployment configured.", err)
	}
	if got.Token != "" {
		t.Errorf("a refusal returned a session token %q", got.Token)
	}
	if n := len(f.client.calls); n != spent {
		t.Errorf("the unconfigured callback spent %d further provider call(s) (%v). A code is "+
			"single-use at the provider: spending it on a request whose provider does not exist "+
			"burns a real user's sign-in and teaches an attacker that the check is advisory.",
			n-spent, f.client.calls[spent:])
	}
	if len(f.store.creates) != 1 {
		t.Errorf("%d connected accounts exist, want 1 — only the configured callback's. A refusal "+
			"that created an account would be signing somebody in rather than refusing them.", len(f.store.creates))
	}
}

func TestTheExchangePrecedesTheIdentityCall(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGoogle)

	if _, err := f.callback(oauth.ProviderGoogle, "c", "uid", "person@example.com"); err != nil {
		t.Fatalf("Callback: %v", err)
	}

	want := []string{"exchange", "identity"}
	if len(f.client.calls) != len(want) {
		t.Fatalf("provider calls = %v, want %v", f.client.calls, want)
	}
	for i := range want {
		if f.client.calls[i] != want[i] {
			t.Fatalf("provider calls = %v, want %v. The exchange has to come first: Identity "+
				"turns a token into a person, and a token that turns out to be worthless should not "+
				"have been spent asking.", f.client.calls, want)
		}
	}
}

func TestAFailedExchangeStopsBeforeTheIdentityCall(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGoogle)
	f.client.exchangeErr = errors.New("provider refused the code")

	_, err := f.callback(oauth.ProviderGoogle, "bad-code", "uid", "person@example.com")
	if err == nil {
		t.Fatal("Callback succeeded with a refused code")
	}

	if len(f.client.calls) != 1 || f.client.calls[0] != "exchange" {
		t.Errorf("provider calls = %v, want [exchange]. A refused code must cost one call: asking "+
			"the identity endpoint with a token that was never issued spends a round trip to learn "+
			"something already known.", f.client.calls)
	}
	if len(f.store.creates) != 0 {
		t.Errorf("%d connected accounts created after a refused exchange", len(f.store.creates))
	}
	if n := f.sessionsMinted(); n != 0 {
		t.Errorf("%d sessions minted after a refused exchange", n)
	}
}

func TestANilRegistryIsARefusalRatherThanADereference(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t)
	svc := NewSocialService(f.auth.svc, nil, f.client, f.store, f.sealer)

	got, err := svc.Callback(context.Background(), SocialCallbackInput{
		Provider: oauth.ProviderGoogle,
		Code:     "c",
	})
	if !errors.Is(err, ErrSocialNoProviders) {
		t.Fatalf("Callback with no registry = %v, want ErrSocialNoProviders", err)
	}
	if got.Token != "" {
		t.Errorf("returned a session token %q", got.Token)
	}
	if len(f.client.calls) != 0 {
		t.Errorf("provider calls = %v, want none. A deployment with no registry cannot have "+
			"resolved the provider, so nothing may be spent.", f.client.calls)
	}
}


func TestSealedTokensAreStoredAndThePlaintextIsNot(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGoogle)

	expiry := start.Add(time.Hour)

	_, err := f.signInWith(oauth.ProviderGoogle, "c",
		oauth.Tokens{
			AccessToken:  "plain-access-token",
			RefreshToken: "plain-refresh-token",
			ExpiresAt:    &expiry,
		},
		oauth.Identity{ProviderUID: "uid", Email: "person@example.com", Name: "Test Person"},
	)
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}

	if len(f.sealer.sealed) != 2 {
		t.Fatalf("the sealer was called %d times (%v), want 2 — both tokens are sealed before any "+
			"branch runs, so the plaintext exists for the length of one function and goes nowhere "+
			"else", len(f.sealer.sealed), f.sealer.sealed)
	}

	for _, plaintext := range []string{"plain-access-token", "plain-refresh-token"} {
		found := false
		for _, handed := range f.sealer.sealed {
			if handed == plaintext {
				found = true
			}
		}
		if !found {
			t.Errorf("Seal was never handed %q, so it was not sealed before storage", plaintext)
		}
	}

	if len(f.store.creates) != 1 {
		t.Fatalf("%d connected accounts created, want 1", len(f.store.creates))
	}
	created := f.store.creates[0]

	if created.AccessTokenCiphertext != "sealed:plain-access-token" {
		t.Errorf("AccessTokenCiphertext = %q, want the sealed value", created.AccessTokenCiphertext)
	}
	if created.RefreshTokenCiphertext != "sealed:plain-refresh-token" {
		t.Errorf("RefreshTokenCiphertext = %q, want the sealed value", created.RefreshTokenCiphertext)
	}
	if created.ExpiresAt == nil || !created.ExpiresAt.Equal(expiry) {
		t.Errorf("ExpiresAt = %v, want the provider token's expiry %v. It is the PROVIDER token's "+
			"expiry and not a session's", created.ExpiresAt, expiry)
	}

	for field, value := range map[string]string{
		"AccessTokenCiphertext":  created.AccessTokenCiphertext,
		"RefreshTokenCiphertext": created.RefreshTokenCiphertext,
	} {
		for _, plaintext := range []string{"plain-access-token", "plain-refresh-token"} {
			if value == plaintext {
				t.Errorf("%s holds the plaintext provider token", field)
			}
		}
	}
}

func TestAMissingRefreshTokenIsNotAnError(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGitHub)

	_, err := f.signInWith(oauth.ProviderGitHub, "c",
		oauth.Tokens{AccessToken: "access-only"},
		oauth.Identity{ProviderUID: "uid", Email: "person@example.com", Name: "Test Person"},
	)
	if err != nil {
		t.Fatalf("Callback: %v. GitHub issues no refresh token in its normal case, so an empty "+
			"one is not an error", err)
	}

	if len(f.sealer.sealed) != 1 {
		t.Errorf("the sealer was called %d times, want 1. Sealing an empty string would store a "+
			"sealed empty rather than NULL, which is a different fact about the provider.", len(f.sealer.sealed))
	}
	if len(f.store.creates) != 1 {
		t.Fatalf("%d connected accounts created, want 1", len(f.store.creates))
	}
	if got := f.store.creates[0].RefreshTokenCiphertext; got != "" {
		t.Errorf("RefreshTokenCiphertext = %q, want empty so oauth.Store writes NULL", got)
	}
}

func TestAFailingSealerRefusesBeforeAnyWrite(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGoogle)
	f.sealer.err = errors.New("the cipher is not configured")

	_, err := f.callback(oauth.ProviderGoogle, "c", "uid", "person@example.com")
	if err == nil {
		t.Fatal("Callback succeeded with a failing sealer")
	}

	if len(f.store.creates) != 0 {
		t.Errorf("%d connected accounts created despite the seal failing", len(f.store.creates))
	}
	if len(f.auth.users.byEmail) != 0 {
		t.Errorf("%d users created despite the seal failing. A user whose only credential could not "+
			"be stored is an account nobody can ever sign in to again.", len(f.auth.users.byEmail))
	}
	if n := f.sessionsMinted(); n != 0 {
		t.Errorf("%d sessions minted despite the seal failing", n)
	}
}


func TestANewSocialAccountHasAPasswordNobodyCanLogInWith(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGoogle)

	if _, err := f.callback(oauth.ProviderGoogle, "c", "uid", "person@example.com"); err != nil {
		t.Fatalf("Callback: %v", err)
	}

	created, ok := f.auth.users.byEmail["person@example.com"]
	if !ok {
		t.Fatal("no user was created")
	}
	if created.PasswordDigest == "" {
		t.Fatal("the created user has no password digest, and the column is NOT NULL")
	}

	if !users.IsArgon2idDigest(created.PasswordDigest) {
		t.Errorf("PasswordDigest = %q, want an argon2id digest. Inventing a guessable placeholder "+
			"like %q would put a login on the internet; a digest of another shape would be "+
			"distinguishable from every other account's by inspection.", created.PasswordDigest, "password")
	}

	hasher := users.NewHasherWithParams(&argon2id.Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})
	for _, guess := range []string{
		"", "password", "person@example.com", "social", "github", "google", "null", "changeme",
		strings.Repeat("a", 24), strings.Repeat("a", 43), "correct horse battery staple",
	} {
		if hasher.Verify(created.PasswordDigest, guess) {
			t.Errorf("a new social account's password digest verifies against %q. The plaintext has "+
				"to be 24 bytes of crypto/rand that nobody holds, so that password login is "+
				"IMPOSSIBLE rather than merely unlikely.", guess)
		}
	}
}


func TestAFailedCreateLeavesNoConnectedAccount(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGoogle)
	f.store.createErr = oauth.ErrAlreadyLinked

	got, err := f.callback(oauth.ProviderGoogle, "c", "uid", "person@example.com")
	if !errors.Is(err, oauth.ErrAlreadyLinked) {
		t.Fatalf("Callback error = %v, want oauth.ErrAlreadyLinked. A concurrent callback for the "+
			"same provider identity won the race, and the handler has to answer 409 rather than "+
			"500.", err)
	}
	if got.Token != "" {
		t.Errorf("a failed create returned a session token %q", got.Token)
	}
}

func TestAConnectedAccountNamingAMissingUserIsReported(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGoogle)

	orphan := mustUUID(9)
	f.store.rows[accountKey(oauth.ProviderGoogle, "orphan-uid")] = oauth.Account{
		ID: mustUUID(1), UserID: orphan,
		Provider: oauth.ProviderGoogle, ProviderUID: "orphan-uid",
	}

	got, err := f.callback(oauth.ProviderGoogle, "c", "orphan-uid", "person@example.com")
	if err == nil {
		t.Fatal("Callback succeeded against a connected account whose user does not exist")
	}
	if !errors.Is(err, users.ErrNotFound) {
		t.Errorf("error = %v, want it to wrap users.ErrNotFound. The honest answer for a row that "+
			"contradicts its own foreign key is that somebody wrote to the database behind this "+
			"service's back, and the error has to say so rather than present as a login problem.", err)
	}
	if got.Token != "" {
		t.Errorf("returned a session token %q for an orphaned connected account", got.Token)
	}
	if n := len(f.auth.users.byEmail); n != 0 {
		t.Errorf("%d users created to recover from an orphaned row. Rebuilding an identity needs "+
			"the provider's UID and NOT an address — connected_accounts deliberately does not "+
			"store the address — so any such user would be invented.", n)
	}
}

func TestALookupFailureIsNotMistakenForANewIdentity(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGoogle)
	f.store.lookupErr = errors.New("the connection pool is exhausted")

	got, err := f.callback(oauth.ProviderGoogle, "c", "uid", "person@example.com")
	if err == nil {
		t.Fatal("Callback succeeded with a failing connected-account lookup")
	}
	if !strings.Contains(err.Error(), "looking up a connected account") {
		t.Errorf("error = %q, want it to say which lookup failed. An infrastructure error "+
			"presented as an account problem sends an operator to the wrong table.", err.Error())
	}
	if got.Token != "" {
		t.Errorf("returned a session token %q", got.Token)
	}
	if len(f.auth.users.byEmail) != 0 {
		t.Errorf("%d users created after a lookup failure. A store that fails for any reason other "+
			"than ErrNotFound must NOT be read as \"never seen before\" — that is how one provider "+
			"identity becomes two accounts.", len(f.auth.users.byEmail))
	}
	if len(f.store.creates) != 0 {
		t.Errorf("%d connected accounts created after a lookup failure", len(f.store.creates))
	}
}


func TestASocialSignInStillGetsAChallengeForATwoFactorAccount(t *testing.T) {
	t.Parallel()

	t.Run("a returning user", func(t *testing.T) {
		t.Parallel()

		f := newSocialFixture(t, oauth.ProviderGoogle)

		owner := f.linkOwner("owner@example.com")
		f.store.rows[accountKey(oauth.ProviderGoogle, "uid")] = oauth.Account{
			ID: mustUUID(1), UserID: owner.ID,
			Provider: oauth.ProviderGoogle, ProviderUID: "uid",
		}
		f.auth.mfa.enabled[owner.ID] = true

		got, err := f.callback(oauth.ProviderGoogle, "c", "uid", "owner@example.com")
		if err != nil {
			t.Fatalf("Callback: %v", err)
		}

		if !got.MFARequired {
			t.Error("MFARequired is false for an account with a second factor. The social callback " +
				"bypassed the challenge a password login would have produced.")
		}
		if got.Token != "" {
			t.Errorf("Token = %q with a second factor required. This is the hole: a session minted "+
				"for an account that has not presented its factor.", got.Token)
		}
		if got.Challenge == nil {
			t.Error("no challenge was returned, so the caller has no way to finish the login")
		}
		if n := f.sessionsMinted(); n != 0 {
			t.Errorf("%d sessions minted for a two-factor account", n)
		}
	})

	t.Run("a newly created account", func(t *testing.T) {
		t.Parallel()

		f := newSocialFixture(t, oauth.ProviderGoogle)

		got, err := f.callback(oauth.ProviderGoogle, "c", "uid", "fresh@example.com")
		if err != nil {
			t.Fatalf("Callback: %v", err)
		}
		if got.MFARequired {
			t.Error("a brand-new account with no second factor was given a challenge, so the " +
				"challenge in the case above proves nothing")
		}
		if got.Token == "" {
			t.Error("a single-factor social sign-in minted no session")
		}
	})
}


func mustUUID(last byte) id.UUID {
	var out id.UUID
	out[15] = last
	return out
}

var (
	_ SocialRegistry  = (*fakeSocialRegistry)(nil)
	_ SocialExchanger = (*fakeExchanger)(nil)
	_ SocialAccounts  = (*fakeAccounts)(nil)
	_ SocialSealer    = (*fakeSealer)(nil)
)
