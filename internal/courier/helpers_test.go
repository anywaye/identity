package courier

import (
	"errors"

	"github.com/anywaye/identity/internal/recovery"
)

// resetLinkTemplate, verifyLinkTemplate and changeLinkTemplate are the three
// things a deployment says when it has said where each kind of link goes.
//
// THEY ARE CONSTANTS RATHER THAN INLINE STRINGS in every fixture, because the
// relationship between them is what this package's per-purpose work is about:
// three purposes, three screens, one credential shape. A fixture that spelled one
// out inline would let a test assert "the links differ" against strings that
// happen to differ here, which is the tautology the negative control in
// `link_purpose_test.go` exists to rule out.
const (
	resetLinkTemplate  = "https://app.example.com/reset?token=" + TokenPlaceholder
	verifyLinkTemplate = "https://app.example.com/verify-email?token=" + TokenPlaceholder

	// invitationLinkTemplate is the accept-screen link, and it is a constant for
	// the reason the two above are: the live tier renders the link the way the
	// adapter does, and a fixture that spelled it inline would let a test assert
	// against a URL the production path would not produce.
	invitationLinkTemplate = "https://app.example.com/invitations/accept?token=" + TokenPlaceholder
	changeLinkTemplate     = "https://app.example.com/confirm-change?token=" + TokenPlaceholder
)

// testLinkTemplates is a complete, valid per-purpose set, for the fixtures that
// are about something else.
//
// IT IS COMPLETE RATHER THAN PARTIAL because `NewRecoveryMailer` refuses a purpose
// with no template — deliberately, and for the reason the field's comment gives. A
// partial fixture would make every test that is not about link purposes fail for a
// reason that has nothing to do with what it is checking.
//
// IT CARRIES THE `email_change` TEMPLATE because the current-address half of an
// email change is delivered with its confirmation link, and the new-address half
// is the one message of the four that carries no link — so the set is complete at
// three purposes for four messages, and the asymmetry is courier's contract
// rather than an omission.
func testLinkTemplates() map[recovery.Purpose]string {
	return map[recovery.Purpose]string{
		recovery.PurposePasswordReset: resetLinkTemplate,
		recovery.PurposeVerifyEmail:   verifyLinkTemplate,
		recovery.PurposeEmailChange:   changeLinkTemplate,
	}
}

// isError is `errors.Is` with the error written first.
//
// It exists so a table row reads `if !isError(err, tc.wantErrIs)` rather than
// `if !errors.Is(tc.wantErrIs, err)`, and the reversal is deliberate. `errors.Is`
// reads as "is target an error" in prose, which is the wrong way round for the
// question every row of a table is asking: the answer to "what did we get" and the
// answer to "what did we want" are different questions, and a helper that makes the
// subject the first argument makes it obvious which one is which.
func isError(got, want error) bool { return errors.Is(got, want) }

// errorsAs is the one place this package's tests reach for a typed error, so the
// `errors.As` call is greppable rather than scattered across the suite.
func errorsAs(err error, target **Error) bool { return errors.As(err, target) }

// newTestClient builds a Client pointed at a test server with a known credential.
//
// IT IS NOT A PRODUCTION SHORTCUT: it goes through `New` and therefore through the
// same base-URL validation, the same refusal of an empty credential and the same
// closure construction, so a test using it is testing the real constructor. The
// only thing it supplies is the transport.
func newTestClient(t testingT, baseURL, token string) *Client {
	t.Helper()
	client, err := New(Config{BaseURL: baseURL, Token: token, HTTPClient: newTestHTTP()})
	if err != nil {
		t.Fatalf("building a client for %s: %v", baseURL, err)
	}
	return client
}
