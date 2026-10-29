package courier

import (
	"testing"
)

var courierRequired = map[string][]string{
	TypeWelcome:            {"user_id", "to"},
	TypePasswordReset:      {"user_id", "to", "url"},
	TypeTeamInvitation:     {"user_id", "to", "url", "account_name", "invited_by"},
	TypeAccountSecurity:    {"user_id", "to", "reason"},
	TypeEmailChangeCurrent: {"user_id", "to", "url"},
	TypeEmailChangeNew:     {"user_id", "to", "previous_email"},
}

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

func stringOf(value any) string {
	text, _ := value.(string)
	return text
}
