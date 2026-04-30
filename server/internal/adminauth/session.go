package adminauth

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	SessionCookieName       = "tukuyomi_admin_session"
	CSRFCookieName          = "tukuyomi_admin_csrf"
	CenterSessionCookieName = "tukuyomi_center_session"
	CenterCSRFCookieName    = "tukuyomi_center_csrf"
	CSRFHeaderName          = "X-CSRF-Token"
	cookiePath              = "/"
)

var (
	ErrCSRFRequired = errors.New("csrf token required")
	ErrCSRFMismatch = errors.New("csrf token mismatch")
)

type Session struct {
	ExpiresAt time.Time
	CSRFToken string
}

type CookieNames struct {
	Session string
	CSRF    string
}

func DefaultCookieNames() CookieNames {
	return CookieNames{
		Session: SessionCookieName,
		CSRF:    CSRFCookieName,
	}
}

func CenterCookieNames() CookieNames {
	return CookieNames{
		Session: CenterSessionCookieName,
		CSRF:    CenterCSRFCookieName,
	}
}

func (names CookieNames) Normalized() CookieNames {
	names.Session = strings.TrimSpace(names.Session)
	names.CSRF = strings.TrimSpace(names.CSRF)
	if names.Session == "" {
		names.Session = SessionCookieName
	}
	if names.CSRF == "" {
		names.CSRF = CSRFCookieName
	}
	return names
}

func ValidateCSRF(r *http.Request, session Session) error {
	return ValidateCSRFWithCookieNames(r, session, DefaultCookieNames())
}

func ValidateCSRFWithCookieNames(r *http.Request, session Session, names CookieNames) error {
	if r == nil || isSafeMethod(r.Method) {
		return nil
	}
	names = names.Normalized()

	headerToken := strings.TrimSpace(r.Header.Get(CSRFHeaderName))
	if headerToken == "" {
		return ErrCSRFRequired
	}

	cookie, err := r.Cookie(names.CSRF)
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
	SetCookiesWithNames(w, DefaultCookieNames(), sessionToken, csrfToken, expiresAt, secure)
}

func SetCookiesWithNames(w http.ResponseWriter, names CookieNames, sessionToken, csrfToken string, expiresAt time.Time, secure bool) {
	if w == nil {
		return
	}
	names = names.Normalized()

	http.SetCookie(w, &http.Cookie{
		Name:     names.Session,
		Value:    sessionToken,
		Path:     cookiePath,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt.UTC(),
		MaxAge:   int(time.Until(expiresAt.UTC()).Seconds()),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     names.CSRF,
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
	ClearCookiesWithNames(w, DefaultCookieNames(), secure)
}

func ClearCookiesWithNames(w http.ResponseWriter, names CookieNames, secure bool) {
	if w == nil {
		return
	}
	names = names.Normalized()

	for _, name := range []string{names.Session, names.CSRF} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     cookiePath,
			HttpOnly: name == names.Session,
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
