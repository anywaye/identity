package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/mfa"
	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
)


var testMFAKey = testKey32("identity-httpapi-mfa-key-32-byte")

const testMFAIssuer = "anywaye identity"

func testMFAService(pool *pgxpool.Pool, clk clock.Clock) *mfa.Service {
	vault, err := mfa.NewAESCipher(testMFAKey)
	if err != nil {
		panic("httpapi: the MFA test key is not 32 bytes: " + err.Error())
	}
	return mfa.NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		mfa.NewStore(pool),
		outbox.NewStore(pool),
		sessions.NewStore(pool),
		vault,
		clk,
		testMFAIssuer,
	)
}

type enrolledUser struct {
	User         id.UUID
	Secret       string
	RecoveryCode string
}

func (e enrolledUser) code(t *testing.T, at time.Time) string {
	t.Helper()
	code, err := mfa.Code(e.Secret, at)
	if err != nil {
		t.Fatalf("mfa.Code: %v", err)
	}
	return code
}

func enrollMFA(t *testing.T, svc *mfa.Service, userID id.UUID, now time.Time) enrolledUser {
	t.Helper()
	ctx := context.Background()

	started, err := svc.StartEnrollment(ctx, mfa.StartEnrollmentInput{UserID: userID})
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	code, err := mfa.Code(started.Secret, now)
	if err != nil {
		t.Fatalf("mfa.Code: %v", err)
	}
	confirmed, err := svc.Confirm(ctx, mfa.ConfirmInput{
		UserID:       userID,
		EnrollmentID: started.Credential.ID,
		Factor:       code,
	})
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if len(confirmed.RecoveryCodes) == 0 {
		t.Fatal("the confirmation issued no recovery codes")
	}

	return enrolledUser{User: userID, Secret: started.Secret, RecoveryCode: confirmed.RecoveryCodes[0]}
}

func sendWith(t *testing.T, h http.Handler, method, path, token, challenge, body string) *httptest.ResponseRecorder {
	t.Helper()

	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequestWithContext(context.Background(), method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if challenge != "" {
		req.AddCookie(&http.Cookie{Name: MFAChallengeCookieName, Value: challenge})
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func testKey32(literal string) []byte {
	var key [32]byte
	copy(key[:], literal)
	return key[:]
}
