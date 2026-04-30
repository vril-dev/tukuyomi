package adminauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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

func TestValidateCSRFWithCookieNames(t *testing.T) {
	session := Session{
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		CSRFToken: "center-csrf-token",
	}
	names := CenterCookieNames()

	req := httptest.NewRequest(http.MethodPut, "/center-api/auth/account", nil)
	req.Header.Set(CSRFHeaderName, session.CSRFToken)
	req.AddCookie(&http.Cookie{Name: names.CSRF, Value: session.CSRFToken})

	if err := ValidateCSRFWithCookieNames(req, session, names); err != nil {
		t.Fatalf("ValidateCSRFWithCookieNames() error = %v", err)
	}
}
