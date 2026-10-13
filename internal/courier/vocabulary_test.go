package courier

import (
	"testing"
)

// courierRequired is `Courier.Mailers.required/1`: what each type must carry.
//
// The `welcome` row is present because identity sends an address confirmation as
// it — courier's own `welcome` template IS a registration's address confirmation,
// and it renders `url`. The mapping is `verify_email` → `welcome`, and the
// argument for it is in `RecoveryMailer`'s section on the mapping.
//
// The required-field lists are READ FROM COURIER'S DOCUMENT rather than guessed:
// `SendMessageRequest` requires `user_id` and `to` of every type, and its field
// descriptions name `url` as required by `password_reset`, `team_invitation` and
// `email_change_current`, `reason` by `account_security`, and `previous_email` by
// `email_change_new` — the same lists `Courier.Mailers.required/1` returns.
var courierRequired = map[string][]string{
	TypeWelcome:            {"user_id", "to"},
	TypePasswordReset:      {"user_id", "to", "url"},
	TypeTeamInvitation:     {"user_id", "to", "url", "account_name", "invited_by"},
	TypeAccountSecurity:    {"user_id", "to", "reason"},
	TypeEmailChangeCurrent: {"user_id", "to", "url"},
	TypeEmailChangeNew:     {"user_id", "to", "previous_email"},
}

// TestTheRequiredFieldMapIsThePackagesVocabulary holds `courierRequired`'s keys to this
// package's Type* constants.
//
// `courierRequired`'s keys are the vocabulary the stubs below accept, which is
// courier's whole catalog, which is this package's constants, which is the enum
// in courier's document. Three lists that must agree with nothing in the type
// system joining them: the drift check holds the constants against courier's
// document, and this holds the required-field map against the constants. A row
// for a type nothing declares is a vocabulary this package claims and does not
// have, and a declared type with no row is one no stub will accept. Either
// direction is the failure this packet exists to fix.
func TestTheRequiredFieldMapIsThePackagesVocabulary(t *testing.T) {
	for typ := range courierRequired {
		if !IsType(typ) {
			t.Errorf("the required-field map accepts %q, which is not one of this package's "+
				"Type* constants; courier's send path and this package's vocabulary "+
				"have drifted apart", typ)
		}
	}
	for _, typ := range identityTypes {
		if _, ok := courierRequired[typ]; !ok {
			t.Errorf("this package declares %q and the required-field map has no row for it, so "+
				"a test exercising courier's own validation of that type would get "+
				"a 422 unknown_notification_type", typ)
		}
	}
}

// stringOf reads a decoded JSON value as a string.
//
// It is a function because the stubs decode into `map[string]any`, where every
// value is an `any`, and the alternative at each of a dozen call sites is a
// type assertion that panics on a field the request did not carry — which is
// exactly the field a test is asking about.
func stringOf(value any) string {
	text, _ := value.(string)
	return text
}
