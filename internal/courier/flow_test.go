package courier

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/recovery"
	"github.com/anywaye/identity/internal/sessions"
	"github.com/anywaye/identity/internal/users"
)


type noOpAccessRevoker struct{}

func (noOpAccessRevoker) RevokeAccessTokensForUser(context.Context, db.Querier, id.UUID, time.Time) error {
	return nil
}

type recoveryFlow struct {
	svc *recovery.Service
	who registeredAccount
}

type registeredAccount struct {
	id    id.UUID
	email string
}

func newRecoveryFlow(t *testing.T, mailer recovery.Mailer) *recoveryFlow {
	t.Helper()

	pool := dbtest.Pool(t)
	store := users.NewStore(pool)

	sum := sha256.Sum256([]byte(t.Name()))
	var noise [4]byte
	if _, err := rand.Read(noise[:]); err != nil {
		t.Fatalf("generating an address suffix: %v", err)
	}
	email := "flow-" + hex.EncodeToString(sum[:6]) + "-" + hex.EncodeToString(noise[:]) +
		"@example.com"

	user, err := store.Create(context.Background(), pool, users.CreateParams{
		Email:          email,
		PasswordDigest: testPasswordDigest(t),
	})
	if err != nil {
		t.Fatalf("registering %s: %v", email, err)
	}

	return &recoveryFlow{
		who: registeredAccount{id: user.ID, email: user.Email},
		svc: recovery.NewService(
			db.TxRunner{Pool: pool},
			db.Direct{Pool: pool},
			recovery.NewStore(pool),
			store,
			sessions.NewStore(pool),
			noOpAccessRevoker{},
			outbox.NewStore(pool),
			mailer,
			testHasher(t),
			clock.System{},
			noSecondFactor{},
		),
	}
}

type noSecondFactor struct{}

func (noSecondFactor) Enabled(context.Context, db.Querier, id.UUID) (bool, error) {
	return false, nil
}

func testPasswordDigest(t *testing.T) string {
	t.Helper()
	digest, err := testHasher(t).Hash("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}
	return digest
}

func testHasher(t *testing.T) *users.Hasher {
	t.Helper()
	params := users.DefaultParams()
	params.Memory = 8 * 1024
	params.Iterations = 1
	params.Parallelism = 1
	return users.NewHasherWithParams(params)
}

func TestTheWholePasswordResetPathReachesCouriersDoor(t *testing.T) {
	stub := newCourierStub(t)
	flow := newRecoveryFlow(t, stub.mailer(t))

	if err := flow.svc.RequestPasswordReset(context.Background(), flow.who.email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}

	if len(stub.sent) != 1 {
		t.Fatalf("courier saw %d requests, want 1", len(stub.sent))
	}
	sent := stub.sent[0]

	if sent.Method != http.MethodPost || sent.Path != messagesPath {
		t.Errorf("courier saw %s %s, want POST %s", sent.Method, sent.Path, messagesPath)
	}
	if !strings.HasPrefix(sent.Authorization, "Bearer ") {
		t.Errorf("Authorization = %q, want a bearer credential; courier's /v1 is behind "+
			":authenticated and an anonymous send is an open relay", sent.Authorization)
	}
	if !isUUID(sent.IdempotencyKey) {
		t.Errorf("Idempotency-Key = %q; courier answers 422 for anything that is not a uuid",
			sent.IdempotencyKey)
	}
	if sent.Accept != "application/json" {
		t.Errorf("Accept = %q; courier's :accepts plug answers 406 without it", sent.Accept)
	}

	if sent.Body["type"] != TypePasswordReset {
		t.Errorf("type = %v, want %q", sent.Body["type"], TypePasswordReset)
	}
	if sent.Body["to"] != flow.who.email {
		t.Errorf("to = %v, want the account's own address %q", sent.Body["to"], flow.who.email)
	}
	if sent.Body["user_id"] != flow.who.id.String() {
		t.Errorf("user_id = %v, want the account the flow looked up (%s)",
			sent.Body["user_id"], flow.who.id)
	}

	link := stringOf(sent.Body["url"])
	if !strings.HasPrefix(link, testLinkPrefix) {
		t.Errorf("url = %q, want the configured template's shape; the adapter must not "+
			"invent a product's path", link)
	}
	token := stub.tokenFromLastRequest(t)
	if token == "" {
		t.Fatal("no token reached courier's request; a reset link with nothing in it is a " +
			"mail a user can follow and cannot use")
	}
	if !strings.Contains(link, token) {
		t.Errorf("url = %q, want the token in it", link)
	}
	for field, value := range sent.Body {
		if field == "url" {
			continue
		}
		if strings.Contains(stringOf(value), token) {
			t.Errorf("the token also appears in %q", field)
		}
	}
	for _, forbidden := range []string{"from", "subject", "text", "html", "body", "account_id"} {
		if _, present := sent.Body[forbidden]; present {
			t.Errorf("the request carried %q, which courier's closed vocabulary does not have",
				forbidden)
		}
	}
}

func TestAnUnregisteredAddressNeverReachesCourier(t *testing.T) {
	stub := newCourierStub(t)
	flow := newRecoveryFlow(t, stub.mailer(t))

	const nobody = "nobody-registered-this-address@example.com"
	if err := flow.svc.RequestPasswordReset(context.Background(), nobody); err != nil {
		t.Fatalf("RequestPasswordReset for an unregistered address returned %v; it must "+
			"return nil so the two cases are indistinguishable", err)
	}
	if len(stub.sent) != 0 {
		t.Errorf("courier saw %d requests for an unregistered address, want 0", len(stub.sent))
	}

	if err := flow.svc.RequestPasswordReset(context.Background(), flow.who.email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if len(stub.sent) != 1 {
		t.Errorf("courier saw %d requests for a registered address, want 1", len(stub.sent))
	}
}

func TestTheTwoOutcomesAgreeOnEverythingACallerCanSee(t *testing.T) {
	stub := newCourierStub(t)
	flow := newRecoveryFlow(t, stub.mailer(t))

	registered := flow.requestReset(t, flow.who.email)
	unregistered := flow.requestReset(t, "still-nobody@example.com")

	if !errors.Is(registered, unregistered) {
		t.Errorf("a registered address produced %v and an unregistered one %v; that "+
			"difference is the oracle", registered, unregistered)
	}
}

func TestACourierThatIsDownRefusesBeforeAnythingIsMinted(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == readyzPath {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		t.Errorf("a request reached courier's send path while courier was down: %s", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(acceptedBody))
	}))
	defer down.Close()

	flow := newRecoveryFlow(t, testMailer(t, down.URL, nil))

	err := flow.svc.RequestPasswordReset(context.Background(), flow.who.email)
	if !isError(err, recovery.ErrNoMailer) {
		t.Fatalf("RequestPasswordReset = %v, want recovery.ErrNoMailer, which the HTTP "+
			"layer answers 503 so a product knows not to render \"check your inbox\"", err)
	}
	if got := flow.liveTokens(t); got != 0 {
		t.Errorf("%d recovery tokens exist after a refused request; the check is supposed "+
			"to happen before a credential is minted", got)
	}
}

func TestASuppressedMailboxIsRefusedRatherThanReportedAsSent(t *testing.T) {
	suppressed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == readyzPath {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"code":"conflict","detail":"That mailbox does not ` +
			`exist: it hard-bounced a previous message.","instance":"/v1/messages",` +
			`"status":409,"title":"Conflict","trace_id":"sup-1",` +
			`"type":"https://docs.anywaye.com/errors/conflict"}`))
	}))
	defer suppressed.Close()

	flow := newRecoveryFlow(t, testMailer(t, suppressed.URL, nil))

	err := flow.svc.RequestPasswordReset(context.Background(), flow.who.email)
	if err == nil {
		t.Fatal("RequestPasswordReset reported success for a suppressed mailbox; the user " +
			"would wait for a message courier will never send")
	}
	if !isError(err, ErrSuppressed) {
		t.Errorf("error = %v, want one matching ErrSuppressed", err)
	}
	if Retryable(err) {
		t.Error("a suppression was reported as retryable; waiting does not unsuppress a mailbox")
	}
	if got := flow.liveTokens(t); got != 1 {
		t.Errorf("%d recovery tokens exist, want 1: the digest is written before the send "+
			"and the row expires harmlessly", got)
	}
}

func TestTheSuppressionNeverReachesTheAddress(t *testing.T) {
	suppressed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == readyzPath {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"code":"conflict","detail":"That mailbox does not ` +
			`exist.","status":409,"trace_id":"sup-2",` +
			`"type":"https://docs.anywaye.com/errors/conflict"}`))
	}))
	defer suppressed.Close()

	var log strings.Builder
	flow := newRecoveryFlow(t, testMailer(t, suppressed.URL, slog.New(slog.NewTextHandler(&log, nil))))

	address := flow.who.email

	err := flow.svc.RequestPasswordReset(context.Background(), address)
	if err == nil {
		t.Fatal("the send succeeded against a courier that refused it")
	}

	if strings.Contains(err.Error(), "does not exist") {
		t.Errorf("the error carries courier's prose: %v", err)
	}
	if strings.Contains(log.String(), address) {
		t.Errorf("the log carries the recipient:\n%s", log.String())
	}
	if !strings.Contains(log.String(), "sup-2") {
		t.Errorf("the log has no handle on courier's logs:\n%s", log.String())
	}
}


func (f *recoveryFlow) requestReset(t *testing.T, email string) error {
	t.Helper()
	return f.svc.RequestPasswordReset(context.Background(), email)
}

func (f *recoveryFlow) liveTokens(t *testing.T) int {
	t.Helper()
	pool := dbtest.Pool(t)
	var count int
	err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM recovery_tokens WHERE user_id = $1 AND expires_at > now()`,
		f.who.id).Scan(&count)
	if err != nil {
		t.Fatalf("counting recovery tokens: %v", err)
	}
	return count
}


const testLinkPrefix = "https://app.example.com/reset"

const acceptedBody = `{"data":{"status":"accepted",` +
	`"user_id":"6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",` +
	`"message_id":"courier-16c22f7a-deda-443c-bdac-d7dcf2405b70",` +
	`"event_id":"0f1d27fc-47ed-4547-aba6-3e98aeaaa198",` +
	`"notification_type":"password_reset"}}`

type stubbedRequest struct {
	Method         string
	Path           string
	Authorization  string
	IdempotencyKey string
	Accept         string
	ContentType    string
	Body           map[string]any
}

type courierStub struct {
	server *httptest.Server
	sent   []stubbedRequest
}

func newCourierStub(t *testing.T) *courierStub {
	t.Helper()
	stub := &courierStub{}

	stub.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == readyzPath {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}

		body := map[string]any{}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		stub.sent = append(stub.sent, stubbedRequest{
			Method:         r.Method,
			Path:           r.URL.Path,
			Authorization:  r.Header.Get("Authorization"),
			IdempotencyKey: r.Header.Get("Idempotency-Key"),
			Accept:         r.Header.Get("Accept"),
			ContentType:    r.Header.Get("Content-Type"),
			Body:           body,
		})

		if field := courierRefusal(body); field != "" {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"code":"validation_failed","detail":"` + field +
				`","errors":[{"code":"invalid_format","field":"` + field + `"}],` +
				`"status":422,"trace_id":"stub-1",` +
				`"type":"https://docs.anywaye.com/errors/validation_failed"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(acceptedBody))
	}))
	t.Cleanup(stub.server.Close)
	return stub
}

func (s *courierStub) mailer(t *testing.T) recovery.Mailer {
	t.Helper()
	return testMailer(t, s.server.URL, nil)
}

func (s *courierStub) tokenFromLastRequest(t *testing.T) string {
	t.Helper()
	if len(s.sent) == 0 {
		t.Fatal("no request reached courier")
	}
	link := stringOf(s.sent[len(s.sent)-1].Body["url"])
	_, after, found := strings.Cut(link, "token=")
	if !found {
		return ""
	}
	token, _, _ := strings.Cut(after, "&")
	return token
}

func courierRefusal(body map[string]any) string {
	for field := range body {
		switch field {
		case "type", "user_id", "to", "name", "url", "account_name", "invited_by", "role":
		default:
			return field
		}
	}
	if !IsType(stringOf(body["type"])) {
		return "type"
	}
	if !isUUID(stringOf(body["user_id"])) {
		return "user_id"
	}
	if stringOf(body["to"]) == "" {
		return "to"
	}
	if stringOf(body["type"]) == TypePasswordReset && stringOf(body["url"]) == "" {
		return "url"
	}
	return ""
}
