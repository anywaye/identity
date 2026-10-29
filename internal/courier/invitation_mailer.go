package courier


import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/anywaye/identity/internal/accounts"
)

// InvitationMailer sends one team_invitation through the client.
//
// IT HAS NO CREDENTIAL FIELD, for the reason RecoveryMailer and Client have
// none: the credential is a closure inside the Client, and this struct holds
// the client rather than the token.
type InvitationMailer struct {
	client *Client

	link LinkTemplate

	logger *slog.Logger

	now func() time.Time
}

// InvitationMailerConfig is what NewInvitationMailer needs.
type InvitationMailerConfig struct {
	Client *Client

	LinkTemplate string

	Logger *slog.Logger
}

// NewInvitationMailer builds the invitation mailer.
//
// IT VALIDATES THE LINK TEMPLATE HERE, at construction, for the reason
// `NewRecoveryMailer` does: a deployment with a template courier would reject
// is broken at boot rather than at a user's first invitation.
func NewInvitationMailer(cfg InvitationMailerConfig) (*InvitationMailer, error) {
	if cfg.Client == nil {
		return nil, errors.New("courier: no client to send with")
	}
	link, err := ValidateLinkTemplate(cfg.LinkTemplate)
	if err != nil {
		return nil, err
	}
	return &InvitationMailer{
		client: cfg.Client,
		link:   link,
		logger: cfg.Logger,
		now:    time.Now,
	}, nil
}

// SendInvitation delivers one invitation email, and reports what courier said.
//
// # THE REQUEST
//
// courier's `team_invitation` requires `email`, `url`, `account_name` and
// `invited_by`, and each is filled from the invitation: the invitee's address,
// the accept link, the account's name and who sent it. The invitation's id is
// the request's `user_id` — courier requires one and an invitee has no user,
// because the invitation exists precisely because they have not signed up.
// courier's own consumer makes the same compromise for the same reason.
//
// # THE IDEMPOTENCY KEY
//
// Derived from the invitation and its token, so a retry of one send is one
// send — the same property RecoveryMailer's key has, and for the same reason:
// a random key per attempt would make the header decorative. The token is
// hashed, never used as the key itself: an `Idempotency-Key` is a header
// courier writes to its own logs and its own unique index, and a live
// credential in somebody else's store is a credential the next reader can
// redeem.
func (m *InvitationMailer) SendInvitation(ctx context.Context, invitation accounts.OutgoingInvitation) error {
	if invitation.Token == "" {
		return fmt.Errorf("%w: the invitation has no token to put in the link", ErrInvalidRequest)
	}

	link, err := m.link.render(invitation.Token)
	if err != nil {
		return fmt.Errorf("%w: the invitation link: %w", ErrInvalidRequest, err)
	}

	key, err := invitationIdempotencyKeyFor(invitation.ID.String(), invitation.Token)
	if err != nil {
		return err
	}

	started := m.now()
	result, err := m.client.SendMessage(ctx, MessageRequest{
		Type:           TypeTeamInvitation,
		UserID:         invitation.ID.String(),
		To:             invitation.Email,
		URL:            link,
		AccountName:    invitation.AccountName,
		InvitedBy:      invitation.InvitedBy,
		Role:           invitation.Role,
		IdempotencyKey: key,
	})
	if err != nil {
		m.logSendFailure(invitation, started, err)
		return err
	}

	m.log("courier accepted an invitation for delivery",
		"message_id", result.MessageID,
		"event_id", result.EventID,
		"status", result.Status,
		"duration", m.now().Sub(started),
	)
	return nil
}

func (m *InvitationMailer) logSendFailure(invitation accounts.OutgoingInvitation, started time.Time, err error) {
	attrs := []any{
		"invitation_id", invitation.ID,
		"duration", m.now().Sub(started),
		"retryable", Retryable(err),
	}
	var refused *Error
	if errors.As(err, &refused) {
		attrs = append(attrs,
			"status", refused.Status,
			"code", refused.Code,
			"trace_id", refused.TraceID,
		)
		if len(refused.Fields) > 0 {
			attrs = append(attrs, "fields", fieldsString(refused.Fields))
		}
	}
	attrs = append(attrs, "error", err)
	m.log("courier did not accept an invitation", attrs...)
}

func (m *InvitationMailer) log(msg string, attrs ...any) {
	if m.logger == nil {
		return
	}
	m.logger.Info(msg, attrs...)
}

// String makes this mailer safe to print, on the same terms as the others.
func (m *InvitationMailer) String() string {
	return "courier.InvitationMailer{" + m.client.String() + "}"
}
