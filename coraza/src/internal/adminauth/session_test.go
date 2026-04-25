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
