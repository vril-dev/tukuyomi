package adminauth

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	SessionCookieName = "tukuyomi_admin_session"
	CSRFCookieName    = "tukuyomi_admin_csrf"
	CSRFHeaderName    = "X-CSRF-Token"
	cookiePath        = "/"
)

var (
	ErrCSRFRequired = errors.New("csrf token required")
	ErrCSRFMismatch = errors.New("csrf token mismatch")
)

type Session struct {
	ExpiresAt time.Time
	CSRFToken string
}

func ValidateCSRF(r *http.Request, session Session) error {
	if r == nil || isSafeMethod(r.Method) {
		return nil
	}

	headerToken := strings.TrimSpace(r.Header.Get(CSRFHeaderName))
	if headerToken == "" {
		return ErrCSRFRequired
	}

	cookie, err := r.Cookie(CSRFCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return ErrCSRFRequired
	}

	cookieToken := strings.TrimSpace(cookie.Value)
	if !secureEqual(headerToken, cookieToken) || !secureEqual(headerToken, session.CSRFToken) {
		return ErrCSRFMismatch
	}

	return nil
}

func SetCookies(w http.ResponseWriter, sessionToken, csrfToken string, expiresAt time.Time, secure bool) {
	if w == nil {
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionToken,
		Path:     cookiePath,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt.UTC(),
		MaxAge:   int(time.Until(expiresAt.UTC()).Seconds()),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    csrfToken,
		Path:     cookiePath,
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt.UTC(),
		MaxAge:   int(time.Until(expiresAt.UTC()).Seconds()),
	})
}

func ClearCookies(w http.ResponseWriter, secure bool) {
	if w == nil {
		return
	}

	for _, name := range []string{SessionCookieName, CSRFCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     cookiePath,
			HttpOnly: name == SessionCookieName,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
			Expires:  time.Unix(0, 0).UTC(),
		})
	}
}

func secureEqual(a, b string) bool {
	if a == "" || b == "" || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func isSafeMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}
