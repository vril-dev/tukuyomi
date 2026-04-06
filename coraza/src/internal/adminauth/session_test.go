package adminauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIssueAndValidate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()

	token, csrf, expiresAt, err := Issue("session-secret-123456", 2*time.Hour, now)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if token == "" || csrf == "" {
		t.Fatal("Issue() should return token and csrf")
	}

	session, err := Validate("session-secret-123456", token, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !session.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("expires_at = %s want %s", session.ExpiresAt, expiresAt)
	}
	if session.CSRFToken != csrf {
		t.Fatalf("csrf = %q want %q", session.CSRFToken, csrf)
	}
}

func TestValidateRejectsExpiredSession(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	token, _, _, err := Issue("session-secret-123456", time.Minute, now)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if _, err := Validate("session-secret-123456", token, now.Add(2*time.Minute)); err != ErrExpiredSession {
		t.Fatalf("Validate() error = %v want %v", err, ErrExpiredSession)
	}
}

func TestValidateCSRF(t *testing.T) {
	session := Session{
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		CSRFToken: "csrf-token-123",
	}

	req := httptest.NewRequest(http.MethodPost, "/tukuyomi-api/rules", nil)
	req.Header.Set(CSRFHeaderName, "csrf-token-123")
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "csrf-token-123"})

	if err := ValidateCSRF(req, session); err != nil {
		t.Fatalf("ValidateCSRF() error = %v", err)
	}
}

func TestValidateCSRFRejectsMismatch(t *testing.T) {
	session := Session{
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		CSRFToken: "csrf-token-123",
	}

	req := httptest.NewRequest(http.MethodPost, "/tukuyomi-api/rules", nil)
	req.Header.Set(CSRFHeaderName, "csrf-token-123")
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "other-token"})

	if err := ValidateCSRF(req, session); err != ErrCSRFMismatch {
		t.Fatalf("ValidateCSRF() error = %v want %v", err, ErrCSRFMismatch)
	}
}
