package apikeys


import (
	"errors"
	"slices"
	"testing"
)

func TestTheMintRefusesToGrantTheOperatorScope(t *testing.T) {
	f := newServiceFixture(t)

	cases := []struct {
		name   string
		scopes []string
	}{
		{"the operator scope alone", []string{ScopeUsersDisable}},
		{"the operator scope beside an account scope", []string{ScopeAccountsRead, ScopeUsersDisable}},
		{"the operator scope beside every account scope", everyAccountScopePlusOperator()},
		{"the introspect scope alone", []string{ScopeTokensIntrospect}},
		{"the introspect scope beside an account scope", []string{ScopeAccountsRead, ScopeTokensIntrospect}},
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
		if scope == ScopeUsersDisable || scope == ScopeTokensIntrospect {
			t.Errorf("a granted key carries %s", scope)
		}
	}
	if len(issued.Key.Scopes) != len(AllScopes())-len(operatorScopes()) {
		t.Errorf("the key carries %d scopes, want the %d that are not the operator's: %v",
			len(issued.Key.Scopes), len(AllScopes())-len(operatorScopes()), issued.Key.Scopes)
	}
}

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

func (f *serviceFixture) apiKeyRows(t *testing.T) int {
	t.Helper()

	var count int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM api_keys`).Scan(&count); err != nil {
		t.Fatalf("counting api_keys: %v", err)
	}
	return count
}

func operatorScopes() []string {
	return []string{ScopeUsersDisable, ScopeTokensIntrospect}
}

func everyAccountScope() []string {
	var out []string
	for _, scope := range AllScopes() {
		if !slices.Contains(operatorScopes(), scope) {
			out = append(out, scope)
		}
	}
	return out
}

func everyAccountScopePlusOperator() []string {
	out := append([]string{}, everyAccountScope()...)
	out = append(out, operatorScopes()...)
	return out
}
