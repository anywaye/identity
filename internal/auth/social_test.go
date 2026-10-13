package auth

// TESTS FOR THE SOCIAL-LOGIN USE CASE: WHICH USER A PROVIDER IDENTITY RESOLVES
// TO.
//
// 514 lines of social.go with no test, carrying the one decision in this service
// that can hand an attacker somebody else's account. Everything hard about
// social sign-in — the providers, the CSRF state, the code-for-token exchange,
// the cipher, the table — was written and tested in internal/oauth. What that
// package deliberately does not contain is the decision about WHO a provider
// identity belongs to, and this file is about that and nothing else.
//
// # THE FOUR OUTCOMES, AND WHICH INPUT PRODUCES WHICH
//
// `Callback` dispatches on exactly two facts: whether `LinkTo` is set, and whether
// a connected account already holds this (provider, provider_uid). That yields
// five reachable shapes across the two branches, and every one of them is
// asserted below:
//
//	signIn, provider identity seen  -> signInAs     -> a session, credentials rewritten
//	signIn, address already taken  -> REFUSAL      -> ErrSocialEmailInUse
//	signIn, address free           -> createAndSignIn -> a new user, a session
//	link,   identity is somebody else's -> REFUSAL  -> oauth.ErrAlreadyLinked
//	link,   identity is theirs or free -> link       -> NO session, NO token
//
// # WHY THE REFUSALS ARE THE INTERESTING HALF
//
// A test that only checked the happy paths would pass against an implementation
// that linked on collision. So the two refusals are asserted on three things
// each: the error is the right VALUE (so the handler's mapping is reachable), no
// session was minted, and no row was written. The third is the one that matters —
// an implementation that returned ErrSocialEmailInUse *after* writing the link
// would pass an error-only assertion and still have performed the takeover it
// claims to refuse.
//
// # WHY THE LINK PATH'S MISSING TOKEN IS A SEPARATE ASSERTION
//
// `link` returns a LoginResult, and LoginResult HAS a Token field. Linking
// therefore mints nothing while occupying the type that describes a minted
// session — so "the token is empty" is a fact about a value, not about a
// distinct type, and it can be broken by any edit that starts populating it.
// It is asserted directly, on the returned value, rather than inferred from the
// error being nil.
//
// # WHAT IS NOT HERE, AND WHY
//
// There is no httptest provider server and no assertion on a redirect URL.
// internal/oauth/client_test.go holds the exchange and the identity parsing, and
// the file comment on social.go says the two are that package's decision. What
// this file needs from a provider is a fact — a name, a UID, an address — and a
// double returning one is a smaller and more honest instrument than a server
// standing in for one.
//
// There is also no transaction-rollback assertion. `fakeUnitOfWork` cannot roll
// back, by its own comment, and the tests that need real rollback live in the
// integration suite against a real database. What is asserted instead is that the
// writes SHARE a transaction, by comparing the querier each was handed — the same
// technique service_test.go uses.

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"

	"github.com/cafaye/identity/internal/oauth"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

// ---------------------------------------------------------------------------
// doubles
// ---------------------------------------------------------------------------

// fakeSocialRegistry is the part of oauth.Registry the use case reads.
type fakeSocialRegistry struct {
	providers map[string]oauth.Provider
	base      string

	// lookupErr, when set, is returned instead of resolving. It is how the
	// "an unconfigured provider is a refusal before anything is spent" case is
	// exercised, and the real oauth.ErrUnknownProvider is what production would
	// return.
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

// fakeExchanger is oauth.Client: the code-for-token exchange and the "who is
// this" call.
//
// # THE ORDER IS RECORDED, AND THAT IS THE POINT
//
// `calls` is a slice rather than a pair of counters because the ORDER is a
// documented property of Callback: "the address is only trusted once BOTH
// provider calls have succeeded… Asking first would spend a provider call on a
// code that turns out to be worthless." An implementation that swapped them
// would satisfy any test that only counted them, so `TestTheExchangePrecedesTheIdentityCall`
// reads the slice.
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

// fakeAccounts is the connected_accounts table, keyed on (provider, provider_uid)
// and never on an address — the property the file comment says the whole schema
// turns on, so the double is keyed the same way.
//
// The `queries` field records the querier each call was handed, which is how a
// test tells a read through the pool from a write inside the transaction without
// inspecting SQL.
type fakeAccounts struct {
	rows    map[string]oauth.Account
	creates []oauth.NewAccount
	nextID  int

	// createQueriers records the querier each Create was handed, SEPARATELY from
	// the queriers reads were handed through.
	//
	// It is a second slice rather than a filter on `queriersUsed` because the
	// assertion this exists for is "the INSERT went through the transaction", and
	// filtering a shared list by position requires knowing the call order to be
	// right. A test that picked the wrong element would then assert on a read
	// querier and pass for the wrong reason — which is the same failure mode as a
	// check that silently stopped matching.
	createQueriers []db.Querier
	// readQueriers records what the two lookups were handed, so a test can tell a
	// read from the pool from a read inside a transaction.
	readQueriers []db.Querier

	// lookupErr and createErr simulate infrastructure failures and the unique-index
	// violation oauth.Store turns into ErrAlreadyLinked.
	lookupErr error
	createErr error

	// refreshed records the (account id, tokens) of every RefreshTokens call, which
	// is how the re-consent write is asserted.
	refreshed []refreshCall
	// refreshQueriers records what querier each RefreshTokens was handed.
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

	// The unique index on (provider, provider_uid), enforced by the double rather
	// than asserted about: a `Create` that did not check would let a test pass that
	// believed the index was protecting it.
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

	// The row is updated rather than merely recorded, so a test that reads it back
	// sees the fresh credential — which is the property signInAs claims about
	// keeping the stored copy from aging.
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

// fakeSealer is oauth.Cipher's Seal.
//
// # IT RECORDS, AND THAT IS WHY THE TESTS CAN CLAIM ANYTHING ABOUT CIPHERTEXT
//
// The sealer's output is a marker rather than a real AEAD, so a test can tell
// which token went into which column and prove that the PLAINTEXT is nowhere.
// A real cipher would produce ciphertext that proves nothing about what was fed
// to it — every value is plausible, so "the plaintext was not stored" becomes
// unassertable. `TestSealedTokensAreStoredAndThePlaintextIsNot` depends on this.
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

// socialFixture wires a SocialService over the doubles, reusing the fixture the
// password-path tests already use so both halves of this service are exercised
// through the same auth.Service construction.
type socialFixture struct {
	// t is the running test, because `fixture.register` takes one and this file's
	// helpers need to seed users. It is carried rather than passed to every helper
	// so the call sites below read as the scenario they describe.
	t        *testing.T
	auth     *fixture
	registry *fakeSocialRegistry
	client   *fakeExchanger
	store    *fakeAccounts
	sealer   *fakeSealer
	svc      *SocialService
}

// newSocialFixture takes the test so the helpers below can seed users through
// `fixture.register`, which calls t.Fatalf on a duplicate address. Every test in
// this file passes its own *testing.T, which is what keeps the file safe under
// t.Parallel — a package-level testing.T would be a race.
// newSocialFixture is the fixture with both providers configured, which is what
// every test in disabled_test.go wants: it names one provider and does not care
// about the other.
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

// socialIP is the client address every callback in this file presents. It is a
// pointer because `SocialCallbackInput.IP` is one — the field distinguishes "no
// address" from "the zero address", and a helper returning a value would quietly
// lose that distinction.
func socialIP() *netip.Addr {
	addr := netip.MustParseAddr("203.0.113.7")
	return &addr
}

// callback runs a sign-in callback — the LinkTo-empty case — with the given
// provider, code, UID and address.
//
// It sets both provider answers, so a test that needs different tokens calls
// `f.svc.Callback` directly rather than through this helper. That is a real
// constraint and worth stating: the helper overwrites `f.client.tokens` and
// `f.client.identity` on every call, which is what makes it safe to use for the
// many tests that do not care about the token's contents.
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

// signInWith runs a sign-in callback with tokens and an identity the caller chose,
// for the tests that are ABOUT the token's contents.
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

// link runs a LINK callback — the LinkTo-set case — with the given owner.
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

// linkOwner returns a caller to link to, seeded through the users double.
//
// The password is a fixture constant rather than a parameter because no test in
// this file logs in with a password — the social path never verifies one — and a
// parameter every call site passed the same value for would be noise.
func (f *socialFixture) linkOwner(email string) users.User {
	f.t.Helper()
	return f.auth.register(f.t, email, "correct horse battery staple")
}

// sessionsMinted is how many sessions the fixture's double recorded.
func (f *socialFixture) sessionsMinted() int { return len(f.auth.sessions.minted) }

// ---------------------------------------------------------------------------
// The four outcomes
// ---------------------------------------------------------------------------

// TestASeenProviderIdentitySignsInAsItsOwner is signInAs: outcome one.
//
// The provider identity has been seen, so the callback signs in as the account the
// connected row names — and it does NOT create a second user, does NOT consult
// the address, and does NOT ask question 4 even if the address has since been
// changed at the provider.
//
// That last one is the property worth a test. The address is re-read from the
// provider on every callback, so a person who changes their provider address to
// one this service already holds still signs in as themselves: questions 1 to 3
// are decided by the provider's OWN IDENTIFIER, which is a fact about the
// provider's account and not about a mailbox. An implementation that asked
// question 4 on this path would refuse a legitimate returning user.
func TestASeenProviderIdentitySignsInAsItsOwner(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGoogle)

	owner := f.linkOwner("owner@example.com")

	// The connected row points at `owner`, and the provider now reports an address
	// that belongs to somebody else entirely. Both facts are deliberate.
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

// TestAFreshProviderIdentityCreatesTheAccount is createAndSignIn: outcome three.
//
// The whole of question 5, and the part with the most moving pieces. The user,
// their personal account, the ownership, the outbox event and the connected account
// are ONE transaction, and the session follows. What the test asserts is that all
// five writes happened AND that they shared a transaction — a `createAndSignIn` that
// provisioned the account outside the transaction would pass a count-based
// assertion and leave a user with no account, which is a state nothing downstream
// can repair.
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

	// THE TRANSACTION. Every write inside `createAndSignIn` must have been handed the
	// TRANSACTION's querier, never the pool's reader. Compared by identity against
	// markerQuerier, which is why those markers exist.
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

// TestAFreshMicrosoftIdentityCreatesTheAccount is the same happy path as the
// github one above, run through the third provider.
//
// # WHY THE SECOND COPY OF THE SAME SHAPE
//
// The four outcomes are provider-agnostic in the code: Callback dispatches on
// the registry lookup and the store key, neither of which branches on which
// provider this is. So a second copy cannot find a bug in the dispatch — the
// github tests own that. What it can find is the one thing that is NOT
// provider-agnostic: the provider NAME that reaches the store. A provider
// added to the registry and the settings table and the enum but not to the
// use case's idea of the world would sign a person in and write a connected
// account keyed on a name nothing else agrees on, and the github tests would
// never notice because they never ask microsoft to do anything.
//
// The assertion that matters is therefore the key: (microsoft, uid). The rest
// — a session, a user, a personal account, an event — is the same shape the
// github test asserts, repeated here so the microsoft path is evidenced
// end to end rather than by a key alone.
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

// TestAFreshAppleIdentityCreatesTheAccount is the same happy path as the
// github and microsoft ones, run through the fourth provider.
//
// The same reasoning as the microsoft test, and for apple it is the more
// important half: apple's identity comes from a verified id_token rather than
// a userinfo call, so the name that reaches the store is the one fact that
// ties the account to the provider whose key signed the token. A provider
// added to the registry, the settings table and the enum but not to the use
// case's idea of the world would write a connected account keyed on a name
// nothing else agrees on, and no other test would notice because they never
// ask apple to do anything.
//
// The id_token verification itself is evidenced in
// internal/oauth/client_test.go against the fake JWKS; this test is the use
// case's evidence that the apple name reaches the store.
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

// TestTheFourOutcomesAreReachableAndAreTheOnesTheCodeNames is the table.
//
// Each case is a separate fixture, because the four outcomes differ in what the
// stores hold BEFORE the callback and a shared fixture would let one case's setup
// satisfy another's assertion. The table is here so the four outcomes can be read
// as four outcomes rather than as four tests that might be covering the same one.
//
// The third column is the EXPECTED SHAPE, spelled as a predicate over the result
// rather than as a status code: the point of the table is which input produces
// which outcome, and a status code would not say whether a session was minted.
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

// ---------------------------------------------------------------------------
// The takeover refusal
// ---------------------------------------------------------------------------

// TestTheAddressCollisionRefusesRatherThanLinks is the account-takeover decision,
// and the central test in this file.
//
// The attack it describes: an attacker sets the address of a provider account they
// control to a victim's address on this service. They then arrive at the callback
// with an authorization code that a provider issued for THAT address — and the
// provider considers it verified, because the attacker controls the mailbox, or
// because the provider's own verification is a checkbox. The provider identity has
// never been seen here, so question 1 does not fire. Question 3 does not fire
// either: the attacker is not signed in.
//
// The remaining move is question 4. If this service linked on collision, the
// attacker's provider identity would be attached to the victim's account, and the
// next callback signs them in as the victim. Full account takeover, from an
// address, with no credential.
//
// So the refusal is the whole of the defense, and it is asserted on three things:
// the error is ErrSocialEmailInUse (which internal/httpapi maps to 409), NO
// connected account was written, and NO user was created. The last two are the
// ones that matter — an implementation that detected the collision, created
// nothing, and STILL called `store.Create` would satisfy an error-only assertion
// and have performed the link it claims to refuse.
func TestTheAddressCollisionRefusesRatherThanLinks(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGoogle)

	// The victim's account, holding the address the attacker's provider account now
	// reports.
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

// TestTheAddressCollisionRefusalIsOnlyOnTheSignInPath is the other half of the
// same decision, and the half a reader is most likely to get wrong.
//
// The file comment says questions 1 to 3 are decided by the PROVIDER'S OWN
// IDENTIFIER and that adding question 4 to the link path "would refuse a
// legitimate operation for a reason that does not apply to it". Jumpstart Pro's
// `attach_account` does not ask it either.
//
// So: a signed-in person whose provider account reports an address that belongs to
// a DIFFERENT account here is NOT refused. They are signed in as themselves —
// which is correct, because they already proved who they are with a credential,
// and the address is a fact about the provider's account rather than about them.
//
// The test is the mirror of the one above with the same address and a different
// input, and it is here because an implementation that hoisted the email check
// above the `if !in.LinkTo.ID.IsZero()` branch would pass both refusal tests and
// break this one.
func TestTheAddressCollisionRefusalIsOnlyOnTheSignInPath(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGitHub)

	// Somebody else's account holds this address.
	f.linkOwner("other@example.com")

	// The caller, signed in, links a provider account that reports it.
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

// ---------------------------------------------------------------------------
// The link path mints nothing
// ---------------------------------------------------------------------------

// TestLinkingReturnsNoSessionAndNoChallenge is the assertion the packet names, and
// it is four separate requirements on one value.
//
// `link` returns a `LoginResult`, which HAS a Token field, an ExpiresAt field and
// a Challenge field. So "linking mints nothing" is a statement about a value being
// left zero, not about a distinct type — and any edit that starts populating it
// produces a working, compiling, plausible implementation of a security hole. Each
// field is asserted because each is a separate way that hole could appear:
//
//   - Token: a session credential this service minted because somebody completed a
//     third-party round trip.
//   - ExpiresAt: the epoch, which a client rendering `expires_at` would show as a
//     date in 1970.
//   - Challenge: an MFA challenge on a path that never asked about a second factor.
//   - MFARequired: the flag that would make internal/httpapi take the CHALLENGE
//     branch instead of the link branch.
//
// That last one is the subtle one. internal/httpapi decides which of three
// responses to write by reading `!owner.ID.IsZero()` FIRST and `result.MFARequired`
// second — so a spurious true would not change the response today. It would change
// it the moment somebody reorders those two branches, and it is one boolean.
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

// TestLinkingARefusedIdentityWritesNothing is question 2's refusal, and it is
// distinct from question 4's.
//
// Question 2 fires when the provider identity is ALREADY LINKED to a different
// user. The refusal is oauth.ErrAlreadyLinked rather than ErrSocialEmailInUse
// because the two say different things to the person at the browser: "that oauth
// account is already linked to a different user" versus "an account already exists
// for this address". Collapsing them would leave a client rendering the wrong
// sentence.
//
// The asserted property is that nothing was written and no session was minted. An
// implementation that re-pointed the existing row at the caller would be the
// takeover in its purest form: the victim loses the account and the attacker has
// it, with no error at all.
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

	// And the row is untouched — not merely uncounted.
	stored, lookupErr := f.store.ByProviderUID(context.Background(), markerQuerier{}, oauth.ProviderGitHub, "victim-uid")
	if lookupErr != nil {
		t.Fatalf("reading the victim's row back: %v", lookupErr)
	}
	if stored.UserID != victim.ID {
		t.Errorf("the row now names %s, want the original owner %s", stored.UserID, victim.ID)
	}
}

// TestRelinkingYourOwnIdentityRewritesTheCredentialAndMintsNothing is the
// re-consent path.
//
// Somebody already linked this provider identity to themselves and is asking
// again. The answer is 200 with no session, and the freshly issued credential IS
// written — a person who re-consented has a new token and the stored copy is
// stale, so not writing it would leave the platform unable to make provider calls
// on their behalf until the next sign-in.
//
// The empty RefreshTokenCiphertext case is asserted too: GitHub issues no refresh
// token, and `oauth.Store.RefreshTokens` documents empty as "keep what is stored"
// rather than "store NULL". Passing an empty value must not blank the column.
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

	// GitHub-shaped: no refresh token on this callback.
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

	// And the stored copy really kept the refresh token, read back rather than
	// inferred from the argument.
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

// ---------------------------------------------------------------------------
// The refusals before anything is spent
// ---------------------------------------------------------------------------

// TestAnUnconfiguredProviderIsRefusedBeforeAnyProviderCall is the ordering
// property on the front of `Callback`.
//
// An unconfigured provider must be answered before the code is spent. It is not
// only cheaper: a code is SINGLE-USE at the provider, so spending it on a request
// whose provider does not exist burns a real user's sign-in and teaches an
// attacker that the check is advisory. The test asserts the exchanger was never
// called, which is the only way to see it — the error alone would also come from a
// provider that refused the code.
func TestAnUnconfiguredProviderIsRefusedBeforeAnyProviderCall(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGoogle)

	// The control: a CONFIGURED provider spends the code.
	if _, err := f.callback(oauth.ProviderGoogle, "real-code", "uid", "person@example.com"); err != nil {
		t.Fatalf("Callback: %v", err)
	}
	spent := len(f.client.calls)
	if spent == 0 {
		t.Fatal("the exchanger was never called even for a CONFIGURED provider, so the assertion " +
			"below would pass for the wrong reason.")
	}

	// The case under test: the SAME code, offered for a provider this deployment has
	// no credentials for. The count is compared against the baseline rather than
	// against a literal, so the test reads as "nothing further was spent" — which is
	// the property — rather than as a number that happens to be right today.
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

// TestTheExchangePrecedesTheIdentityCall reads the order off the recorded calls.
//
// social.go says the order "is not interchangeable: Exchange is what makes the token
// real, and Identity is what turns it into a person. Asking first would spend a
// provider call on a code that turns out to be worthless." A counter-based test
// would pass against a swapped implementation; the recorded slice cannot.
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

// TestAFailedExchangeStopsBeforeTheIdentityCall is the same property under
// failure, and it is the case where the ordering earns its keep: a provider that
// refuses the code should cost ONE provider call, not two.
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

// TestANilRegistryIsARefusalRatherThanADereference covers the first line of
// `Callback`.
//
// ErrSocialNoProviders exists for the case where a caller reaches this type with no
// registry at all — "the shape of the mistake rather than a crash". A deployment
// cannot produce it (NewSocial refuses to build the wiring without a registry),
// which is exactly why it needs a test: it is unreachable from production and so
// nothing else would ever execute that branch.
func TestANilRegistryIsARefusalRatherThanADereference(t *testing.T) {
	t.Parallel()

	// No providers configured — which also means no registry lookup can succeed, so
	// the nil below is not the only thing standing between this test and a
	// successful callback.
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

// ---------------------------------------------------------------------------
// Token handling
// ---------------------------------------------------------------------------

// TestSealedTokensAreStoredAndThePlaintextIsNot is the token-handling property:
// the only place a provider token is ever written is the two ciphertext columns.
//
// `fakeSealer` returns a marker derived from its input precisely so this is
// assertable. A real AEAD would make every stored value plausible, and "the
// plaintext was not stored" would become unassertable — which is why the double
// records rather than encrypts.
//
// Three requirements: the access token was sealed before storage, the refresh token
// was sealed too when there was one, and NEITHER plaintext appears in any value
// written to the store.
func TestSealedTokensAreStoredAndThePlaintextIsNot(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGoogle)

	expiry := start.Add(time.Hour)

	// Through `signInWith`, not `callback`: the helper sets its own tokens on every
	// call and would overwrite the plaintexts this test is about. That mistake was
	// made and caught while writing this file — the first version called `callback`
	// and then asserted on "plain-access-token", which had never been sent.
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

	// `sealed` records what was HANDED to the cipher, and the values below record what
	// came BACK. Comparing the two lists is what proves the round trip happened: a
	// Seal that returned its input would leave them identical, and a use case that
	// stored `f.sealer.sealed` by mistake would be caught by the column assertions
	// that follow rather than by this one.
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

	// The negative assertion, stated over every string the store was handed.
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

// TestAMissingRefreshTokenIsNotAnError covers GitHub, which issues none.
//
// An empty refresh token is SQL NULL rather than an empty string — see
// oauth.Store.Create — and asserting "not an error" is not enough, because the
// interesting failure is a service that writes "" and thereby asserts that "the
// provider issued no refresh token" and "we never learned one" are the same fact.
// The stored value has to be empty so the store can decide.
func TestAMissingRefreshTokenIsNotAnError(t *testing.T) {
	t.Parallel()

	f := newSocialFixture(t, oauth.ProviderGitHub)

	// Through `signInWith`, for the reason the seal test above says.
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

// TestAFailingSealerRefusesBeforeAnyWrite covers the seal's position.
//
// Both tokens are sealed BEFORE any branch runs, so a cipher failure stops a
// callback that would otherwise have created a user and written a connected account
// — and there would be no way to repair that state, because the account's only
// credential is the sealed token.
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

// ---------------------------------------------------------------------------
// The unusable password
// ---------------------------------------------------------------------------

// TestANewSocialAccountHasAPasswordNobodyCanLogInWith is the property behind
// `users.password_digest NOT NULL`.
//
// `unusablePassword` hashes 24 bytes of crypto/rand and throws the plaintext away,
// so password login for a social account is IMPOSSIBLE rather than merely
// unlikely. What is asserted is that the stored digest does not verify against any
// known string — the hasher is the real one, so `Verify` is the real check — and
// that it is a real argon2id digest of the expected shape rather than a placeholder
// anybody could recognize.
//
// The shape assertion matters because the alternative implementation named in the
// comment ("password") would satisfy a "cannot log in" test by accident only if it
// were also something the tests did not try; asserting the digest's form makes the
// placeholder visible.
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

	// A real argon2id digest, so nothing in this service can tell a social account
	// apart by the shape of its hash. `users.IsArgon2idDigest` is the production
	// predicate for exactly this, so using it means the test cannot pass against a
	// digest production would reject — and a digest production rejects is an account
	// whose owner can never log in again.
	if !users.IsArgon2idDigest(created.PasswordDigest) {
		t.Errorf("PasswordDigest = %q, want an argon2id digest. Inventing a guessable placeholder "+
			"like %q would put a login on the internet; a digest of another shape would be "+
			"distinguishable from every other account's by inspection.", created.PasswordDigest, "password")
	}

	// Verified against the CHEAP hasher parameters, which are the ones the digest was
	// HASHED with — argon2id encodes its own parameters in the digest, so the
	// production hasher would also work, at a hundred times the cost for no extra
	// coverage. This is the same construction newFixture uses.
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

// ---------------------------------------------------------------------------
// Infrastructure failures inside the write transaction
// ---------------------------------------------------------------------------

// TestAFailedCreateLeavesNoConnectedAccount covers the unique-index race.
//
// Between the address lookup and the insert, somebody else registered that address
// or linked that provider identity. `oauth.Store` turns the violation into
// ErrAlreadyLinked so the handler answers 409 rather than 500, and the user is NOT
// created — the transaction rolled back.
//
// The double cannot roll back, so what is asserted is the ERROR: that a create
// failure propagates rather than being swallowed into a success. A
// `createAndSignIn` that ignored the store's error would return a session for a
// user with no connected account, which is an account that can never sign in again
// — and the caller would be told it worked.
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

// TestAConnectedAccountNamingAMissingUserIsReported is the dead-user branch, and
// it is asserted as a REPORT rather than a recovery.
//
// `connected_accounts.user_id` is a foreign key with ON DELETE CASCADE, so this
// state is unreachable through the service. The code reports it rather than
// handling it, and the reasoning is in the comment: fabricating an identity to
// "recover" from it would need an address the row does not have, because
// `connected_accounts` stores the provider's identifier and NOT the address.
//
// The assertion is that the error NAMES the account row and does not return a
// session. A recovery — minting a session for whoever the row points at, or
// creating a replacement user — would be the dangerous answer, and a test that
// accepted either would be blessing it.
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

// TestALookupFailureIsNotMistakenForANewIdentity closes the error-handling shape.
//
// `signIn` switches on `errors.Is(err, oauth.ErrNotFound)`, so a store that fails
// for any OTHER reason must not fall through to `createAndSignIn`. It does not,
// because the switch has a `default` — and that default is what this test holds.
//
// The failure it prevents is an infrastructure error becoming a duplicate account:
// a transient database failure in the connected-account lookup reads as "not seen
// before" to anything that checks only for ErrNotFound, and the result is two rows
// for one provider identity where the schema permits exactly one.
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

// ---------------------------------------------------------------------------
// The second factor
// ---------------------------------------------------------------------------

// TestASocialSignInStillGetsAChallengeForATwoFactorAccount is why `Callback`
// returns a `LoginResult` rather than a type of its own.
//
// A social sign-in that minted a session for an account with a confirmed second
// factor would be the single largest hole this file could have. The defense is
// structural — `startLogin` is the same function a password login goes through, so
// there is no field of this result from which a session can be had without the
// second factor having been presented.
//
// The test asserts the observable shape on BOTH paths that mint: a returning user
// whose account has a second factor, and a brand-new account. The second is worth
// having separately because `createAndSignIn` builds a LoginResult through a
// different call site than `signInAs`, and a challenge check on one of them says
// nothing about the other.
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
		// The account has a confirmed second factor.
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

		// The fresh account has no second factor, so this is the CONTROL for the case
		// above rather than a duplicate of it: it proves the challenge on the returning
		// path came from the account's factor and not from the social callback refusing
		// to mint sessions at all.
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

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// mustUUID builds a deterministic id.UUID from its last byte, so an account row
// in a test reads as `mustUUID(1)` rather than as sixteen hex digits.
func mustUUID(last byte) id.UUID {
	var out id.UUID
	out[15] = last
	return out
}

// compile-time assurance that the doubles still satisfy the four interfaces the
// use case declares at its consumer.
//
// It is the same obligation social.go carries itself, and it is worth the two lines
// because the failure it catches is invisible otherwise: a seam that widened would
// leave these doubles compiling and failing at runtime inside the use case, one
// missing call at a time, rather than failing a build with a list of what no longer
// compiles.
var (
	_ SocialRegistry  = (*fakeSocialRegistry)(nil)
	_ SocialExchanger = (*fakeExchanger)(nil)
	_ SocialAccounts  = (*fakeAccounts)(nil)
	_ SocialSealer    = (*fakeSealer)(nil)
)
