package courier

import (
	"errors"

	"github.com/anywaye/identity/internal/recovery"
)

const (
	resetLinkTemplate  = "https://app.example.com/reset?token=" + TokenPlaceholder
	verifyLinkTemplate = "https://app.example.com/verify-email?token=" + TokenPlaceholder

	invitationLinkTemplate = "https://app.example.com/invitations/accept?token=" + TokenPlaceholder
	changeLinkTemplate     = "https://app.example.com/confirm-change?token=" + TokenPlaceholder
)

func testLinkTemplates() map[recovery.Purpose]string {
	return map[recovery.Purpose]string{
		recovery.PurposePasswordReset: resetLinkTemplate,
		recovery.PurposeVerifyEmail:   verifyLinkTemplate,
		recovery.PurposeEmailChange:   changeLinkTemplate,
	}
}

func isError(got, want error) bool { return errors.Is(got, want) }

func errorsAs(err error, target **Error) bool { return errors.As(err, target) }

func newTestClient(t testingT, baseURL, token string) *Client {
	t.Helper()
	client, err := New(Config{BaseURL: baseURL, Token: token, HTTPClient: newTestHTTP()})
	if err != nil {
		t.Fatalf("building a client for %s: %v", baseURL, err)
	}
	return client
}
