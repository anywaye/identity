package courier

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/anywaye/identity/internal/recovery"
)


// ErrUnsupportedMessage means identity rendered a message courier has no type for.
//
// IT IS ITS OWN SENTINEL RATHER THAN A 422 COURIER ANSWERED, because the client
// refuses to send rather than to send and be told. The table below is now EMPTY —
// courier has carried both email-change types since `20373bf` and this adapter
// maps all four of `recovery`'s messages onto them — but the sentinel is not
// deleted, because the refusal is the failure direction the whole design leans
// towards: a message kind that is not in `courierTypeFor` is REFUSED, and a fifth
// message added to `internal/recovery` cannot be delivered by accident through a
// fallback that guessed.
//
// The refusal was the decision this packet was most careful about, and the
// reasoning belongs on the mapping below rather than here. What belongs HERE is
// the property that makes it safe: the failure happens before the wire, so no
// token is in a body courier will render, and the caller is told a deployment is
// missing a capability rather than that a mailbox refused.
//
// The alternative was weighing rather than skipping, and the weighing is why the
// vocabulary exists. Mapping `email_change_current` onto courier's `password_reset`
// would be one line and would put "Somebody asked to reset the password on your
// account" into the only message a hijacked session cannot get past — a message
// whose entire value is that it warns an account owner that somebody is moving
// their address. A wrong-but-delivered security notice is worse than a loud
// failure. courier's m70 built the two types instead of letting that happen, and
// this adapter now uses them.
var ErrUnsupportedMessage = errors.New("courier: courier cannot send this message")

const (
	kindPasswordReset = "Reset your anywaye password"
	kindVerifyEmail   = "Confirm your anywaye email address"
	kindChangeCurrent = "Confirm an email address change"
	kindChangeNew     = "Confirm your new anywaye email address"
)

var knownSubjects = map[string]struct{}{
	kindPasswordReset: {},
	kindVerifyEmail:   {},
	kindChangeCurrent: {},
	kindChangeNew:     {},
}

var courierTypeFor = map[string]string{
	kindPasswordReset: TypePasswordReset,
	kindVerifyEmail:   TypeWelcome,
	kindChangeCurrent: TypeEmailChangeCurrent,
	kindChangeNew:     TypeEmailChangeNew,
}

var linkPurposeFor = map[string]recovery.Purpose{
	kindPasswordReset: recovery.PurposePasswordReset,
	kindVerifyEmail:   recovery.PurposeVerifyEmail,
	kindChangeCurrent: recovery.PurposeEmailChange,
}

// RecoveryMailer is courier's implementation of `recovery.Mailer`.
//
// IT HAS NO CREDENTIAL FIELD, for the same reason `Client` has none: the
// credential is a closure inside the `Client`, and this struct holds the client
// rather than the token.
type RecoveryMailer struct {
	client *Client

	linkTemplates LinkTemplates

	logger *slog.Logger

	now func() time.Time
}

// LinkTemplate is how a deployment says what a link looks like.
//
// IT IS A TEMPLATE WITH ONE PLACEHOLDER RATHER THAN A BASE URL, because a base URL
// is only half the answer: a product might want `…/reset?token=…`, a path segment,
// or a URL with the token somewhere else entirely, and a base-URL-plus-convention
// implementation picks a convention on the platform's behalf.
//
// The placeholder is `{token}` and it is REQUIRED, and "required" is checked at
// construction: a template with no placeholder produces a link that reaches a
// screen with no token on it, which is a mail a user can follow and cannot use.
// Failing at construction means the deployment is broken at boot rather than at a
// user's first password reset.
//
// IT SAYS WHAT A LINK LOOKS LIKE AND NOT WHAT A RECOVERY LINK LOOKS LIKE, because the
// second is narrower than the type is: a verification link is not a recovery link.
// The wording was one of the things that let a single template pass for a decision.
type LinkTemplate string

// LinkTemplates is a deployment's per-purpose link templates.
//
// THE KEY IS `recovery.Purpose` RATHER THAN courier's `NotificationType`, and rather
// than a subject, for one reason: it is the vocabulary that says what redeeming the
// token DOES, which is the thing that decides which screen the link belongs on.
// Keying it by a courier type would have made this package depend on the narrower of
// the two mappings above — the one where an address confirmation is a registration —
// and would have made the purpose a derived fact of a delivery decision.
type LinkTemplates map[recovery.Purpose]LinkTemplate

// TokenPlaceholder is what a link template must contain.
const TokenPlaceholder = "{token}"

// ValidateLinkTemplate refuses a template this package cannot render a working
// link from.
//
// THREE REFUSALS, and each is a link that does not work rather than a style
// opinion: a template with no `{token}` (a link with no credential on it), one
// that is not an absolute URL (courier's schema says `format: uri`, and a
// relative one cannot be rendered in a mail), and one with a query or a fragment
// in the template itself rather than in the substitution (the token would land
// somewhere the deployment did not intend).
//
// IT IS CALLED ONCE PER PURPOSE RATHER THAN ONCE PER MAILER, and `resolveLinkTemplates`
// is the only caller. The rule is a property of a template, so every template gets
// it — one template validated once used to mean four messages covered by accident
// of there being one of it, and a rule applied to one purpose and not the next is
// the same class of defect as the one this package exists to have fixed.
func ValidateLinkTemplate(raw string) (LinkTemplate, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("courier: the link template is empty")
	}
	if !strings.Contains(trimmed, TokenPlaceholder) {
		return "", fmt.Errorf("courier: the link template has no %s in it, "+
			"so the link a user follows would carry no token", TokenPlaceholder)
	}
	probe := strings.ReplaceAll(trimmed, TokenPlaceholder,
		"6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061")
	if err := checkAbsoluteHTTPURL(probe); err != nil {
		return "", fmt.Errorf("courier: the link template: %w", err)
	}
	return LinkTemplate(trimmed), nil
}

var errNoToken = errors.New("courier: refusing to render a link with no token")

func (l LinkTemplate) render(token string) (string, error) {
	if token == "" {
		return "", errNoToken
	}
	if !strings.Contains(string(l), TokenPlaceholder) {
		return "", errors.New("courier: the link template has no placeholder in it")
	}
	return strings.ReplaceAll(string(l), TokenPlaceholder, token), nil
}

// RecoveryMailerConfig is what NewRecoveryMailer needs.
type RecoveryMailerConfig struct {
	Client *Client

	LinkTemplates map[recovery.Purpose]string

	Logger *slog.Logger
}

// NewRecoveryMailer builds courier's `recovery.Mailer`.
//
// IT VALIDATES EVERY LINK TEMPLATE HERE, at construction, for the reason
// `ValidateLinkTemplate` gives: a deployment with a template courier would reject
// is broken at boot rather than at a user's first password reset. That is the same
// rule `OIDC_SIGNING_KEY` follows, and the same rule the house rule "present but
// unparseable is a startup failure" exists to enforce.
//
// IT ALSO REFUSES A PURPOSE WITH NO TEMPLATE, and that is the rule this packet
// added. Every other validation here is about a link that is malformed; this one is
// about a link that is ABSENT, which is the state identity-24 found a verification
// mail reaching a user's screen in the wrong shape of answer.
func NewRecoveryMailer(cfg RecoveryMailerConfig) (*RecoveryMailer, error) {
	if cfg.Client == nil {
		return nil, errors.New("courier: no client to send with")
	}
	templates, err := resolveLinkTemplates(cfg.LinkTemplates)
	if err != nil {
		return nil, err
	}
	return &RecoveryMailer{
		client:        cfg.Client,
		linkTemplates: templates,
		logger:        cfg.Logger,
		now:           time.Now,
	}, nil
}

func resolveLinkTemplates(raw map[recovery.Purpose]string) (LinkTemplates, error) {
	out := make(LinkTemplates, len(linkPurposeFor))
	for _, deliverable := range linkPurposesInOrder() {
		value, present := raw[deliverable.purpose]
		if !present {
			return nil, fmt.Errorf("courier: no link template for the %q message, so a %s "+
				"link has nowhere to point and the mail would carry a button that goes "+
				"nowhere. Set the %s variable to the screen that redeems one",
				deliverable.subject, deliverable.purpose, deliverable.purpose)
		}
		template, err := ValidateLinkTemplate(value)
		if err != nil {
			return nil, fmt.Errorf("courier: the %s link template: %w", deliverable.purpose, err)
		}
		out[deliverable.purpose] = template
	}
	for _, purpose := range purposesInOrder(raw) {
		if _, deliverable := out[purpose]; deliverable {
			continue
		}
		return nil, fmt.Errorf("courier: a link template was configured for the %q purpose, "+
			"which no message this adapter can deliver carries: courier has no template "+
			"for it, so the setting would be honored nowhere", purpose)
	}
	return out, nil
}

type deliverableLink struct {
	subject string
	purpose recovery.Purpose
}

func linkPurposesInOrder() []deliverableLink {
	out := make([]deliverableLink, 0, len(linkPurposeFor))
	for subject, purpose := range linkPurposeFor {
		out = append(out, deliverableLink{subject: subject, purpose: purpose})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].purpose < out[j].purpose })
	return out
}

func purposesInOrder(set map[recovery.Purpose]string) []recovery.Purpose {
	purposes := make([]recovery.Purpose, 0, len(set))
	for purpose := range set {
		purposes = append(purposes, purpose)
	}
	sort.Slice(purposes, func(i, j int) bool { return purposes[i] < purposes[j] })
	return purposes
}

// Send delivers one rendered message, and reports what courier said.
//
// IT IS THE WHOLE ADAPTER, and there are three things in it.
//
// # 1. THE KIND, FROM THE SUBJECT
//
// `courierTypeFor` above says why the subject is the key. What happens on a miss is
// the part that matters: `ErrUnsupportedMessage`, before the wire, so no token
// reaches courier for a message courier cannot render.
//
// # 2. THE LINK, AND WHICH TEMPLATE GETS IT
//
// courier's `password_reset` REQUIRES `url` and answers 422 without one — a
// recorded 422, in `recorded_test.go`. The token goes into the template configured
// for this message's PURPOSE and the result is what courier's own template renders.
//
// `linkPurposeFor` is the table that decides which template, and consulting it is
// the whole of what changed when a deployment could say where each kind of link goes.
// The lookup is OPTIONAL rather than a refusal, and the option is the point:
// `email_change_new` is courier's one message with no link, so a message with no
// entry there is delivered without a url rather than refused. Rendering another
// purpose's link — or an empty one — would produce a mail that renders perfectly
// and sends the reader to a screen that cannot redeem what it is carrying, which is
// the defect the per-purpose table exists to prevent.
//
// The token is in a URL rather than in prose, which is a real change from
// `recovery`'s own bodies ("Your reset code is: …") and it is courier's decision
// rather than this service's: courier's document has no field for a bare code. It
// also means the credential now lives in a URL, which is a wider blast radius than
// a body — referrers, proxies, browser history. That is a genuine cost and it is
// WHY the link is a configured template rather than something this package builds:
// the deployment that owns the screen owns where the credential travels.
//
// # 3. THE ERROR, AND WHICH ONES ARE ABOUT THE CALLER
//
// courier's 409 and its declined-preference 422 are facts about a RECIPIENT. They
// are returned as this package's sentinels and `recovery` decides what to tell the
// caller, because that decision is `recovery`'s: it knows whether the request was
// anonymous, and an anonymous caller must not learn that an address is
// undeliverable.
func (m *RecoveryMailer) Send(ctx context.Context, message recovery.Message) error {
	courierType, ok := courierTypeFor[message.Subject]
	if !ok {
		m.log("refusing a message courier has no type for",
			"subject", message.Subject,
			"reason", "courier's NotificationType is [welcome, password_reset, team_invitation, account_security, email_change_current, email_change_new] and this service's courierTypeFor has no entry for it — a message kind that is not in the table is refused rather than delivered by a fallback that guessed",
		)
		return fmt.Errorf("%w: %q", ErrUnsupportedMessage, message.Subject)
	}

	purpose, hasPurpose := linkPurposeFor[message.Subject]

	if message.To == "" {
		return errors.New("courier: refusing to send a message with no recipient")
	}

	token := tokenFromBody(message.Body)
	if token == "" {
		return fmt.Errorf("%w: %s has no token in it", ErrInvalidRequest, message.Subject)
	}

	userID, err := userIDFrom(message)
	if err != nil {
		m.log("refusing a message identity cannot address",
			"subject", message.Subject,
			"reason", "the message named no account, and courier's request requires one",
		)
		return fmt.Errorf("%w: %s: %w", ErrUnsupportedMessage, message.Subject, err)
	}

	var link string
	if hasPurpose {
		link, err = m.linkTemplates[purpose].render(token)
		if err != nil {
			return fmt.Errorf("%w: the %s link: %w", ErrInvalidRequest, purpose, err)
		}
	}

	var previousEmail string
	if courierType == TypeEmailChangeNew {
		previousEmail = previousEmailFromBody(message.Body)
		if previousEmail == "" {
			m.log("refusing an email change that names no previous address",
				"subject", message.Subject,
				"reason", "courier's email_change_new requires previous_email, and the "+
					"rendered body does not name the address the account is moving from",
			)
			return fmt.Errorf("%w: %s names no address to move from", ErrInvalidRequest, message.Subject)
		}
	}

	key, err := idempotencyKeyFor(courierType, userID, token)
	if err != nil {
		return err
	}

	started := m.now()
	result, err := m.client.SendMessage(ctx, MessageRequest{
		Type:           courierType,
		UserID:         userID,
		To:             message.To,
		URL:            link,
		PreviousEmail:  previousEmail,
		IdempotencyKey: key,
	})
	if err != nil {
		m.logSendFailure(message, courierType, started, err)
		return err
	}

	m.log("courier accepted a message for delivery",
		"type", courierType,
		"message_id", result.MessageID,
		"event_id", result.EventID,
		"status", result.Status,
		"duration", m.now().Sub(started),
	)
	return nil
}

// Ready reports whether courier is up, and is `recovery.Mailer.Ready`.
//
// The `ErrNoMailer` wrap is the whole of the translation: `recovery` answers its
// anonymous request paths with 503 when the seam cannot deliver, and its own
// `ErrNoMailer` is the sentinel the HTTP layer maps to that. A courier that is
// down and a deployment with no mailer are the same answer to a user, and they are
// the same answer to an operator at the level of a status line; the distinction
// that matters — a token was never minted — holds for both.
func (m *RecoveryMailer) Ready(ctx context.Context) error {
	if err := m.client.Ready(ctx); err != nil {
		return fmt.Errorf("%w: %w", recovery.ErrNoMailer, err)
	}
	return nil
}

// String makes this mailer safe to print, on the same terms as `Client`.
func (m *RecoveryMailer) String() string {
	return "courier.RecoveryMailer{" + m.client.String() + "}"
}

func (m *RecoveryMailer) logSendFailure(message recovery.Message, courierType string, started time.Time, err error) {
	attrs := []any{
		"type", courierType,
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
	attrs = append(attrs, "subject", message.Subject, "error", err)
	m.log("courier did not accept a message", attrs...)
}

func (m *RecoveryMailer) log(msg string, attrs ...any) {
	if m.logger == nil {
		return
	}
	m.logger.Warn(msg, attrs...)
}


const bodyMarker = "\n\n    "

func tokenFromBody(body string) string {
	_, after, found := strings.Cut(body, bodyMarker)
	if !found {
		return ""
	}
	token, _, _ := strings.Cut(after, "\n")
	return strings.TrimSpace(token)
}

const (
	previousEmailPrefix = "account on "
	previousEmailSuffix = " to this address."
)

func previousEmailFromBody(body string) string {
	firstLine, _, _ := strings.Cut(body, "\n")
	_, after, found := strings.Cut(firstLine, previousEmailPrefix)
	if !found {
		return ""
	}
	email, _, _ := strings.Cut(after, previousEmailSuffix)
	return strings.TrimSpace(email)
}

func userIDFrom(message recovery.Message) (string, error) {
	if message.UserID.IsZero() {
		return "", errors.New("recovery.Message carried no user id")
	}
	return message.UserID.String(), nil
}

func checkAbsoluteHTTPURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %q is not a URL", ErrNoBaseURL, raw)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%w: %q is not an http or https URL", ErrNoBaseURL, raw)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: %q has no host", ErrNoBaseURL, raw)
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("%w: %q has a fragment; a mail client does not send one to a server",
			ErrNoBaseURL, raw)
	}
	if parsed.User != nil {
		return fmt.Errorf("%w: %q has a userinfo section", ErrNoBaseURL, raw)
	}
	return nil
}

var _ recovery.Mailer = (*RecoveryMailer)(nil)
