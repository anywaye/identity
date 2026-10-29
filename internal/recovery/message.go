package recovery

import (
	"fmt"
	"strings"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)


type messageKind string

const (
	messageReset       messageKind = "password_reset"
	messageVerify      messageKind = "verify_email"
	messageChangeFirst messageKind = "email_change_current"
	messageChangeNew   messageKind = "email_change_new"
)

const (
	passwordResetBody = `Somebody asked to reset the password for the account registered to ` +
		`{{email}}.

Your reset code is:

    {{token}}

Enter it where you sign in to choose a new password. It works once, and only
until {{expiry}}.

If this was not you, nothing has changed. Nobody can sign in with this code
without it, and it stops working as soon as it is used or when it expires.
`

	verifyEmailBody = `Confirm the address {{email}} for your anywaye account.

Your confirmation code is:

    {{token}}

Enter it where you sign in. It works once, and only until {{expiry}}.

This service does not call an address verified until somebody proves they can
read mail sent to it, which is what this code is for.
`

	emailChangeCurrentBody = `Somebody signed in to the anywaye account on {{email}} and asked to
change the address it uses.

If that was you, confirm it with this code:

    {{token}}

If it was not you, do nothing. The request cannot go any further without this
code, and nothing about the account has changed yet.

It works once, and only until {{expiry}}. Confirming it sends one more message,
to the NEW address — the change only completes when that one is confirmed too.
`

	emailChangeNewBody = `Somebody asked to move the anywaye account on {{email}} to this address.

Confirm it with this code:

    {{token}}

If you were expecting this, enter the code and the account's address becomes
{{target}}. If you were not expecting it, do nothing: a change needs this address
and the old one both confirmed, and the old one has already been.

It works once, and only until {{expiry}}.
`
)

var messageBodies = map[messageKind]struct {
	Subject string
	Body    string
}{
	messageReset:       {Subject: "Reset your anywaye password", Body: passwordResetBody},
	messageVerify:      {Subject: "Confirm your anywaye email address", Body: verifyEmailBody},
	messageChangeFirst: {Subject: "Confirm an email address change", Body: emailChangeCurrentBody},
	messageChangeNew:   {Subject: "Confirm your new anywaye email address", Body: emailChangeNewBody},
}

type messageData struct {
	To     string
	Email  string
	Target string
	Token  string
	Expiry time.Time
	UserID id.UUID
}

func messageFor(kind messageKind, data messageData) (Message, error) {
	parts, ok := messageBodies[kind]
	if !ok {
		return Message{}, fmt.Errorf("recovery: %q is not a message this build can render", kind)
	}
	if data.Token == "" {
		return Message{}, fmt.Errorf("recovery: refusing to render the %s message with no token", kind)
	}

	body := strings.NewReplacer(
		"{{email}}", data.Email,
		"{{target}}", data.Target,
		"{{token}}", data.Token,
		"{{expiry}}", data.Expiry.UTC().Format(time.RFC1123),
	).Replace(parts.Body)

	return Message{Subject: parts.Subject, Body: body, UserID: data.UserID}, nil
}
