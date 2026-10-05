package apikeys

// THE MINT'S ACCOUNT BOUNDARY, and the one refusal that keeps the operator surface
// a boundary rather than a route.
//
// Everything else in this package's authority model is about what a token may DO with
// the account it was minted for. `users:disable` is the one scope that names no
// account, so a credential carrying it is a deployment-wide credential — and the mint
// in this package hands out credentials FOR AN ACCOUNT to that account's owner. If
// the mint would grant it, then every account owner in the deployment could mint
// their way to disabling any user on it, through a settings page, by a role check
// that has nothing to do with the capability being granted.
//
// So the refusal lives in `Service.Mint` rather than in the handler that calls it, and
// the tests below are against the real use case over a real database rather than
// against the HTTP layer — a handler-only check would pass every test in
// `internal/httpapi` and leave `Mint` open to the next caller.

import (
	"errors"
	"testing"
)

// TestTheMintRefusesToGrantTheOperatorScope is the refusal itself, walked over the
// shapes a request can arrive in.
//
// EVERY ROW BUT THE LAST IS A REFUSAL, including the one holding nothing but the
// operator scope: "grant me only that" is the shape an attacker or a careless script
// would use, and a check that only fired on a mixed list would miss it.
func TestTheMintRefusesToGrantTheOperatorScope(t *testing.T) {
	f := newServiceFixture(t)

	cases := []struct {
		name   string
		scopes []string
	}{
		{"the operator scope alone", []string{ScopeUsersDisable}},
		{"the operator scope beside an account scope", []string{ScopeAccountsRead, ScopeUsersDisable}},
		{"the operator scope beside every account scope", everyAccountScopePlusOperator()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name := f.label("Operator")
			_, err := f.svc.Mint(t.Context(), MintInput{
				AccountID: f.account,
				Name:      name,
				Scopes:    tc.scopes,
				MintedBy:  f.owner,
			})
			if !errors.Is(err, ErrScopeNotMintableHere) {
				t.Fatalf("minting %v = %v, want ErrScopeNotMintableHere. An account owner who "+
					"can mint this holds a credential that turns off any user on the deployment, "+
					"which is the reach the account boundary exists to prevent", tc.scopes, err)
			}
			if rows := f.apiKeyRows(t); rows != 0 {
				t.Errorf("the refused mint wrote %d key(s) anyway; the check runs before the "+
					"transaction and before the entropy is spent, so a refusal costs no rows", rows)
			}
		})
	}
}

// TestAnAccountOwnerMayStillMintEveryOtherScope is the negative control, and it is
// here because a refusal that fires on everything is a route nobody can use and a
// green suite.
//
// The grant is the whole vocabulary MINUS the operator scope, in one request, and it
// must succeed — which is also the check that the refusal above is keyed on the one
// name rather than on the length of the list.
func TestAnAccountOwnerMayStillMintEveryOtherScope(t *testing.T) {
	f := newServiceFixture(t)

	issued, err := f.svc.Mint(t.Context(), MintInput{
		AccountID: f.account,
		Name:      f.label("Everything else"),
		Scopes:    everyAccountScope(),
		MintedBy:  f.owner,
	})
	if err != nil {
		t.Fatalf("minting every account scope: %v", err)
	}
	if issued.Token == "" {
		t.Fatal("the 201 carried no token, so this is not a usable credential")
	}

	for _, scope := range issued.Key.Scopes {
		if scope == ScopeUsersDisable {
			t.Errorf("a granted key carries %s", scope)
		}
	}
	if len(issued.Key.Scopes) != len(AllScopes())-1 {
		t.Errorf("the key carries %d scopes, want the %d that are not the operator's: %v",
			len(issued.Key.Scopes), len(AllScopes())-1, issued.Key.Scopes)
	}
}

// TestTheRefusalIsNotAValidationFailure is the shape of the answer, and it is the
// part a client switches on.
//
// A 422 naming `scopes` as invalid would send a developer to the vocabulary table to
// look for a typo that is not there: the request is well-formed and every name in it
// is one this build implements. What is wrong is the SURFACE. `ErrNotAuthorized` is
// the neighbouring sentinel and it is deliberately not reused — a caller that
// distinguishes "you are not an owner" from "this page cannot hand that out" gets two
// different actions, and conflating them would report an authorization problem where
// the request was authorized and the grant was not.
func TestTheRefusalIsNotAValidationFailure(t *testing.T) {
	f := newServiceFixture(t)

	_, err := f.svc.Mint(t.Context(), MintInput{
		AccountID: f.account,
		Name:      f.label("NotAuthorized"),
		Scopes:    []string{ScopeUsersDisable},
		MintedBy:  f.owner,
	})

	if errors.Is(err, ErrNotAuthorized) {
		t.Error("the refusal is ErrNotAuthorized, so a caller cannot tell \"you are not the owner\" " +
			"from \"this surface cannot grant that scope\" — and the first is a false statement here, " +
			"because the owner IS the owner")
	}
	var fieldErr *FieldError
	if errors.As(err, &fieldErr) {
		t.Errorf("the refusal is a FieldError on %q, so the HTTP layer would answer 422 and send a "+
			"developer to the vocabulary table hunting a typo that is not there", fieldErr.Field)
	}
	if !errors.Is(err, ErrScopeNotMintableHere) {
		t.Errorf("err = %v, want ErrScopeNotMintableHere", err)
	}
}

// TestAMemberCannotMintTheOperatorScopeEither is the role axis, and it is a separate
// test because the owner case says nothing about it.
//
// **WHICH REFUSAL A MEMBER GETS IS ASSERTED RATHER THAN ASSUMED, and it is not the
// one this file's other tests might suggest.** Scope validation runs BEFORE the
// transaction, and `requireOwner` runs inside it — so a member asking for
// `users:disable` is refused with `ErrScopeNotMintableHere`, not with
// `ErrNotAuthorized`.
//
// That ordering is the house shape rather than an oversight: `Mint` validates name,
// scopes and expiry before it spends entropy or opens a transaction, so a rejected
// request costs neither. The cost is that a member's sentence is about the scope
// rather than their role. **It discloses nothing**, because the vocabulary is
// published in `openapi/v1.yaml` and in the README's scope table — telling somebody
// what a scope is called is not a secret, and a member learns they cannot mint it
// either way. It is asserted here because the alternative — a test that expects
// `ErrNotAuthorized` — would be a false claim about this use case's order, and the
// failure would read as a regression in the role check.
func TestAMemberCannotMintTheOperatorScopeEither(t *testing.T) {
	f := newServiceFixture(t)

	_, err := f.svc.Mint(t.Context(), MintInput{
		AccountID: f.account,
		Name:      f.label("Member"),
		Scopes:    []string{ScopeUsersDisable},
		MintedBy:  f.member,
	})
	if !errors.Is(err, ErrScopeNotMintableHere) {
		t.Fatalf("a member minting the operator scope = %v, want a refusal. The scope check runs "+
			"before the transaction and `requireOwner` inside it, so this is the scope refusal — "+
			"which is safe to name because the vocabulary is published", err)
	}
	if rows := f.apiKeyRows(t); rows != 0 {
		t.Errorf("the refused mint wrote %d key(s)", rows)
	}

	// AND THE ROLE CHECK IS STILL THE ANSWER FOR A MEMBER ASKING FOR ANYTHING ELSE,
	// so the assertion above is about the ordering rather than about the role check
	// having gone missing.
	_, err = f.svc.Mint(t.Context(), MintInput{
		AccountID: f.account,
		Name:      f.label("Member ordinary"),
		Scopes:    []string{ScopeAccountsRead},
		MintedBy:  f.member,
	})
	if !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("a member minting an ordinary scope = %v, want ErrNotAuthorized. That is the "+
			"refusal about their role, and it is the one they would get for every other request", err)
	}
}

// TestAnInventedScopeIsStillAValidationFailure is the last of the three refusals, so
// that the new one has not displaced either old one.
//
// `ValidateScopes` REFUSES rather than curates — a request for `accounts:admin` is a
// 422 naming the field, because a CI job that asked for a scope that does not exist
// and silently received a narrower one is a script that runs for a week and fails on
// the write it was written to do. `users:disable` is a scope that DOES exist, so it is
// not that case, and this is what keeps the two apart.
func TestAnInventedScopeIsStillAValidationFailure(t *testing.T) {
	f := newServiceFixture(t)

	_, err := f.svc.Mint(t.Context(), MintInput{
		AccountID: f.account,
		Name:      f.label("Invented"),
		Scopes:    []string{"accounts:admin"},
		MintedBy:  f.owner,
	})
	if errors.Is(err, ErrScopeNotMintableHere) {
		t.Errorf("an invented scope = %v. That refusal means \"this page cannot grant that scope\", "+
			"which is a different statement from \"that scope does not exist\" — and conflating them "+
			"sends a developer looking for a vocabulary entry that is there", err)
	}
	var fieldErr *FieldError
	if !errors.As(err, &fieldErr) {
		t.Fatalf("an invented scope = %v, want a *FieldError. `ValidateScopes` refuses rather than "+
			"curates, and the new refusal must not have swallowed that one", err)
	}
	if fieldErr.Field != "scopes" || fieldErr.Code != CodeUnsupported {
		t.Errorf("field error = %+v, want scopes/%s", fieldErr, CodeUnsupported)
	}
}

// apiKeyRows counts the fixture's api_keys, over the private schema.
//
// It reads the TABLE rather than a store method because "the refusal wrote nothing"
// is a claim about rows and the store's own list would be a route through code the
// refusal is supposed to have stopped — if `ListForAccount` were also broken, the
// count would be wrong in the direction that makes the test pass.
func (f *serviceFixture) apiKeyRows(t *testing.T) int {
	t.Helper()

	var count int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM api_keys`).Scan(&count); err != nil {
		t.Fatalf("counting api_keys: %v", err)
	}
	return count
}

// everyAccountScope is the vocabulary minus the operator scope.
func everyAccountScope() []string {
	var out []string
	for _, scope := range AllScopes() {
		if scope != ScopeUsersDisable {
			out = append(out, scope)
		}
	}
	return out
}

// everyAccountScopePlusOperator is the whole vocabulary, for the mint that must be
// refused on the strength of one name among them.
func everyAccountScopePlusOperator() []string {
	return append(everyAccountScope(), ScopeUsersDisable)
}
