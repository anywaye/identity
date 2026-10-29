package courier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	messagesPath = "/v1/messages"

	readyzPath = "/readyz"
)

const (
	DefaultTimeout      = 5 * time.Second
	DefaultProbeTimeout = 2 * time.Second
)

const maxResponseBytes = 64 << 10

const (
	TypeWelcome = "welcome"

	TypePasswordReset = "password_reset"

	TypeTeamInvitation = "team_invitation"

	TypeAccountSecurity = "account_security"

	TypeEmailChangeCurrent = "email_change_current"

	TypeEmailChangeNew = "email_change_new"
)

// StatusAccepted is the only `data.status` courier will ever send.
//
// It is named here rather than read as a free string because courier's document is
// emphatic that a 200 means the provider ACCEPTED the message and nothing more:
// there is no delivery receipt, and a client that recorded `delivered` would be
// asserting a fact about somebody else's inbox that courier cannot know. A second
// value appearing here would mean courier started claiming delivery, and it should
// be a test failure rather than a quiet success.
const StatusAccepted = "accepted"

// FieldPreferencesDisabled is the `errors[].code` courier answers when the
// recipient has turned this notification type off.
//
// IT IS NAMED AND NOT PARSED LOOSE, because this is the one refusal on courier's
// send path that is a fact about a RECIPIENT rather than about the deployment, and
// the whole of the concealment decision in `recovery` rests on telling the two
// apart. Anything else with a 422 is this client's own request being wrong, which
// is a different failure with a different answer.
const FieldPreferencesDisabled = "notification_preferences_disabled"

// FieldError is one entry of courier's `errors[]`, which its conventions reserve
// for a 422 and nothing else.
type FieldError struct {
	Field string `json:"field"`
	Code  string `json:"code"`
}

// MessageRequest is one `POST /v1/messages` body.
//
// IT IS STRUCTURALLY A SUBSET OF courier's vocabulary, and that is the point
// rather than an omission: `account_name`, `invited_by` and `role` exist for
// `team_invitation` alone, and a field this client cannot populate is a field
// whose value could only ever be empty. Sending `omitempty` placeholders for them
// would be a request courier has to be told to ignore, and the vocabulary is
// closed precisely so that nothing has to be ignored.
//
// THE THREE `team_invitation` FIELDS ARE THE EXCEPTION THAT PROVES THE RULE, and
// they are in it rather than omitted because identity now sends that message:
// an invitation's accept link is built from a token only this process holds, so
// the mail cannot wait for a consumer that can never render it. They are
// `omitempty` because they are meaningless for every other type — a `welcome`
// with an `account_name` is a field courier's schema does not use — and
// `validate` refuses a `team_invitation` missing any of the four, so the
// vocabulary stays closed in both directions.
type MessageRequest struct {
	Type string `json:"type"`

	UserID string `json:"user_id"`

	To string `json:"to"`

	Name string `json:"name,omitempty"`

	URL string `json:"url,omitempty"`

	AccountName string `json:"account_name,omitempty"`

	InvitedBy string `json:"invited_by,omitempty"`

	Role string `json:"role,omitempty"`

	PreviousEmail string `json:"previous_email,omitempty"`

	IdempotencyKey string `json:"-"`
}

// MessageResult is the `data` object of a 200.
//
// Every field is required by courier's schema and every one is checked on the way
// in: a 200 whose body is missing `message_id` is not an accepted send, it is a
// response this client does not understand, and the two must not collapse into one.
// `TestSendMessageReadsCouriersContract` has a row for each.
type MessageResult struct {
	MessageID string `json:"message_id"`

	EventID string `json:"event_id"`

	Type string `json:"notification_type"`

	UserID string `json:"user_id"`

	Status string `json:"status"`
}

type sentResponse struct {
	Data MessageResult `json:"data"`
}

// Client is a courier client.
//
// IT HAS NO CREDENTIAL FIELD, and that is the whole of the credential design: Go
// prints an exported struct field by value under `%#v` and does NOT consult
// `String()`, so a `token string` on this struct is a leak that no method on this
// package can intercept. The credential lives inside `authorize`'s closure and
// inside `scrub`'s closure, and there is no formatting verb in Go that prints a
// closure's environment.
type Client struct {
	baseURL string

	http *http.Client

	timeout      time.Duration
	probeTimeout time.Duration

	authorize func(*http.Request) error

	scrub func(string) bool

	newKey func() (string, error)
}

// Config is what New needs.
//
// Token is a construction-time value and is not retained: `New` moves it into
// closures and the `Config` may be garbage collected immediately. That is the
// difference between a credential held for a process's life and one held for a
// constructor call, and it is the reason `Config` is not `Client`.
type Config struct {
	BaseURL string

	Token string

	Timeout time.Duration

	ProbeTimeout time.Duration

	HTTPClient *http.Client
}

var (
	ErrNoBaseURL = errors.New("courier: no usable base URL")

	ErrNoToken = errors.New("courier: no service credential")

	ErrInvalidRequest = errors.New("courier: the request is not one courier can accept")

	ErrSuppressed = errors.New("courier: the recipient's mailbox cannot receive mail")

	ErrDeclined = errors.New("courier: the recipient has declined this notification")

	ErrRefused = errors.New("courier: the request was refused")

	ErrUnauthenticated = errors.New("courier: the service credential was not accepted")

	ErrUnavailable = errors.New("courier: cannot deliver right now")

	ErrMalformedResponse = errors.New("courier: the response was not one this client can read")

	ErrTimeout = errors.New("courier: the request outran its bound")
)

// New builds a Client.
//
// The two refusals are the two an anonymous client would otherwise be, and both
// are refusals because each has a plausible-looking wrong answer: no base URL
// would send somewhere arbitrary, and no credential would send as nobody.
func New(cfg Config) (*Client, error) {
	base, err := normaliseBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if cfg.Token == "" {
		return nil, ErrNoToken
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	probe := cfg.ProbeTimeout
	if probe <= 0 {
		probe = DefaultProbeTimeout
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	token := cfg.Token
	credential := "Bearer " + token

	return &Client{
		baseURL:      base,
		http:         httpClient,
		timeout:      timeout,
		probeTimeout: probe,
		authorize: func(r *http.Request) error {
			r.Header.Set("Authorization", credential)
			return nil
		},
		scrub:  func(s string) bool { return strings.Contains(s, token) },
		newKey: newUUIDv4,
	}, nil
}

// String makes this client safe to print.
//
// `fmt` calls this for `%v`, `%+v`, `%s` and `%q`, which between them are
// effectively every way a value reaches a log line. It reports the two things a
// reader of a log needs — where requests go, and that this client holds a
// credential — and nothing else. `%#v` bypasses this method by design in Go; the
// closures above are what make that safe, and the two are load-bearing together
// rather than one being a convenience.
func (c *Client) String() string {
	return "courier.Client{base_url: " + c.baseURL + ", authenticated: " +
		strconv.FormatBool(c.HasCredential()) + "}"
}

// HasCredential reports whether this client can authenticate.
//
// It exists so `String` can say `authenticated: true` without consulting a field,
// and so a test can assert the client is not anonymous without reading its guts.
func (c *Client) HasCredential() bool { return c.authorize != nil }

// SendMessage asks courier to send one message, and reports what courier said.
//
// IT IS SYNCHRONOUS, and the decision is recorded rather than assumed. courier's
// own document gives the argument against a queue: a 202 "would answer before the
// suppression check ran, and a refusal that arrives after the response is a
// refusal the caller cannot act on". identity cannot tell a user their password
// reset is on its way and then find out an hour later that the mailbox was
// suppressed — and the alternative is not a wiring change here, because the outbox
// publisher is deliberately not started in this repository, so an asynchronous
// send would be a new subsystem rather than a decision about this one.
//
// THE COST IS LATENCY ON ONE REQUEST PATH, and it is named rather than absorbed:
// `POST /v1/password-resets` and `POST /v1/email-changes/current-address` now
// block on courier blocking on SMTP, bounded by `Config.Timeout`. Nothing else
// about those routes changes, and `Ready` — which runs on the same path — has its
// own, smaller bound.
func (c *Client) SendMessage(ctx context.Context, req MessageRequest) (MessageResult, error) {
	if err := validate(req); err != nil {
		return MessageResult{}, err
	}

	key := req.IdempotencyKey
	if key == "" {
		generated, err := c.newKey()
		if err != nil {
			return MessageResult{}, fmt.Errorf("courier: minting an idempotency key: %w", err)
		}
		key = generated
	}

	body, err := json.Marshal(req)
	if err != nil {
		return MessageResult{}, fmt.Errorf("courier: encoding the request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	_, status, raw, err := c.do(ctx, http.MethodPost, messagesPath, "send", key, body)
	if err != nil {
		return MessageResult{}, err
	}

	var sent sentResponse
	if err := json.Unmarshal(raw, &sent); err != nil {
		return MessageResult{}, fmt.Errorf("%w: courier answered %d with a body that is not a send result",
			ErrMalformedResponse, status)
	}
	if err := validateResult(sent.Data); err != nil {
		return MessageResult{}, err
	}
	return sent.Data, nil
}

// Ready reports whether courier is up. It is the implementation behind
// `recovery.Mailer.Ready`.
//
// IT PROBES `/readyz` AND NOTHING ELSE, for the reason the constant says: that
// route runs before auth, before routing and before the rest of the platform
// exists, it sends nothing, and it is the one courier operation whose cost does
// not grow with the platform's state.
//
// WHAT IT DOES NOT ESTABLISH is worth being exact about, because a probe that
// over-promises is worse than none. courier's `/readyz` says courier's database
// answers; it does NOT say courier can deliver, because courier's adapter check is
// scoped to production and a courier in any other environment answers ready with
// a silent adapter. A nil return means "courier is reachable and its database
// answers" and nothing more, and the send is where a misconfigured adapter is
// discovered. `RecoveryMailer` says so in the line it writes at boot, because an
// operator who reads "courier is ready" as "mail will be sent" has been told
// something this method cannot support.
func (c *Client) Ready(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.probeTimeout)
	defer cancel()

	_, status, _, err := c.do(ctx, http.MethodGet, readyzPath, "probe", "", nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return &Error{
			Op:       "probe",
			Status:   status,
			Code:     codeUnreadable,
			sentinel: ErrUnavailable,
			retry:    true,
			cause:    errNotOK,
		}
	}
	return nil
}

func (c *Client) do(
	ctx context.Context, method, path, op, idempotencyKey string, body []byte,
) (MessageResult, int, []byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return MessageResult{}, 0, nil, fmt.Errorf("courier: building the request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if err := c.authorize(req); err != nil {
		return MessageResult{}, 0, nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return MessageResult{}, 0, nil, c.transportError(ctx, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if readErr != nil && len(raw) == 0 {
			raw = nil
		}
		return MessageResult{}, resp.StatusCode, raw, classify(op, resp.StatusCode, resp.Header, raw)
	}

	if readErr != nil {
		return MessageResult{}, resp.StatusCode, nil, c.transportError(ctx, readErr)
	}
	return MessageResult{}, resp.StatusCode, raw, nil
}

func (c *Client) transportError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
		return fmt.Errorf("%w: %w", ErrTimeout, context.DeadlineExceeded)
	case errors.Is(err, context.Canceled), errors.Is(ctx.Err(), context.Canceled):
		return fmt.Errorf("courier: the caller gave up: %w", context.Canceled)
	default:
		return c.scrubbed(fmt.Errorf("courier: the request did not complete: %w", err))
	}
}

func (c *Client) scrubbed(err error) error {
	if err == nil || !c.scrub(err.Error()) {
		return err
	}
	return errors.New("courier: [redacted: the string contained this client's credential]")
}

func validate(req MessageRequest) error {
	if !IsType(req.Type) {
		return fmt.Errorf("%w: %q is not a type courier sends", ErrInvalidRequest, req.Type)
	}
	if req.To == "" {
		return fmt.Errorf("%w: no recipient", ErrInvalidRequest)
	}
	if !isUUID(req.UserID) {
		return fmt.Errorf("%w: %q is not a user id courier can key a preference by",
			ErrInvalidRequest, req.UserID)
	}
	switch req.Type {
	case TypePasswordReset, TypeEmailChangeCurrent:
		if req.URL == "" {
			return fmt.Errorf("%w: a %s needs the link it carries", ErrInvalidRequest, req.Type)
		}
	case TypeEmailChangeNew:
		if req.PreviousEmail == "" {
			return fmt.Errorf("%w: a %s needs the address the account is moving from",
				ErrInvalidRequest, req.Type)
		}
	}
	if req.Type == TypeTeamInvitation {
		if req.URL == "" {
			return fmt.Errorf("%w: a %s needs the link it carries", ErrInvalidRequest, req.Type)
		}
		if req.AccountName == "" {
			return fmt.Errorf("%w: a %s needs the account it invites to", ErrInvalidRequest, req.Type)
		}
		if req.InvitedBy == "" {
			return fmt.Errorf("%w: a %s needs the name of the person who sent it",
				ErrInvalidRequest, req.Type)
		}
	}
	return nil
}

// IsType reports whether a type is one courier's document declares.
//
// Exported because `RecoveryMailer`'s mapping and its refusals both have to know
// the vocabulary, and because a second place in this package deciding it would be
// a second list. It is a SWITCH AND NOT A MAP for the reason `courierTypeFor` is
// a map and not a switch: the dangerous direction is the silent one. A type that
// is not a case here is refused by `validate` as "not a type courier sends", so
// a constant added to the block above and forgotten here is a LIE in the package's
// own vocabulary — a caller legitimately sending `email_change_current` would be
// refused locally as invalid. The drift check is what holds this list to
// courier's document; the constants block is what holds the values.
func IsType(t string) bool {
	switch t {
	case TypeWelcome, TypePasswordReset, TypeTeamInvitation,
		TypeAccountSecurity, TypeEmailChangeCurrent, TypeEmailChangeNew:
		return true
	default:
		return false
	}
}

func validateResult(got MessageResult) error {
	switch {
	case got.MessageID == "":
		return fmt.Errorf("%w: courier answered a send with no message id", ErrMalformedResponse)
	case got.EventID == "":
		return fmt.Errorf("%w: courier answered a send with no event id", ErrMalformedResponse)
	case got.Status == "":
		return fmt.Errorf("%w: courier answered a send with no status", ErrMalformedResponse)
	}
	return nil
}

// Error is courier's refusal, made printable without leaking anything courier said
// verbatim.
//
// courier's `detail` is prose written for whoever reads the response, and one of
// its refusals is a sentence explaining that somebody's mailbox hard-bounced. This
// package is a platform mail path whose errors end up in a log aggregator, so
// `detail` is not carried here at all: the trace id is, and that is precisely the
// handle courier's own document offers for finding the cause in its logs.
//
// It is ONE type with an unexported sentinel rather than a type per case, for the
// reason the sentinels above give: the caller branches, and `errors.Is` is the
// branch.
type Error struct {
	Op string

	Status int

	Code string

	TraceID string

	Fields []FieldError

	retry bool

	sentinel error
	cause    error
}

// Error is the message a human reads, and it is assembled from a fixed vocabulary
// rather than from anything courier sent.
//
// The reason is the one `client/redact.go` gives and the one `transportError`
// applies: an `Error()` string is the single most likely thing in a process to end
// up in a log aggregator, and this service's mail path holds live reset tokens.
// `Code`, `TraceID` and the field names are courier's bounded enums.
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("courier: ")
	b.WriteString(e.Op)
	if e.Status != 0 {
		b.WriteString(" refused with ")
		b.WriteString(statusText(e.Status))
	}
	if e.Code != "" {
		b.WriteString(", code ")
		b.WriteString(e.Code)
	}
	if len(e.Fields) > 0 {
		b.WriteString(", fields ")
		b.WriteString(fieldsString(e.Fields))
	}
	if e.TraceID != "" {
		b.WriteString(", courier trace ")
		b.WriteString(e.TraceID)
	}
	if e.cause != nil {
		b.WriteString(": ")
		b.WriteString(e.cause.Error())
	}
	return b.String()
}

// Unwrap makes `errors.Is` work against the sentinel and the cause.
func (e *Error) Unwrap() error {
	if e.cause != nil {
		return e.cause
	}
	return e.sentinel
}

// Is reports whether this error matches one of this package's sentinels, so
// `errors.Is` reads the same against a courier error and against a bare one.
func (e *Error) Is(target error) bool { return target == e.sentinel }

// Retryable reports whether trying again can help.
//
// It is a function over the error and not a field a caller reads, so that the
// question has exactly one answer: courier's own promise that a 503 released its
// `Idempotency-Key` and wrote no row, that a 409 does not, and that a credential
// courier will not take will not be taken on a second attempt.
func Retryable(err error) bool {
	var refused *Error
	if errors.As(err, &refused) {
		return refused.retry
	}
	return errors.Is(err, ErrTimeout)
}

func normaliseBaseURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", ErrNoBaseURL
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w: %q is not a URL", ErrNoBaseURL, trimmed)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("%w: %q is not an http or https URL", ErrNoBaseURL, trimmed)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("%w: %q has no host", ErrNoBaseURL, trimmed)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: %q has a query or a fragment", ErrNoBaseURL, trimmed)
	}
	return strings.TrimRight(trimmed, "/"), nil
}
