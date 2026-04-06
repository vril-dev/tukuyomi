package adminauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
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
	ErrInvalidSession = errors.New("invalid admin session")
	ErrExpiredSession = errors.New("expired admin session")
	ErrCSRFRequired   = errors.New("csrf token required")
	ErrCSRFMismatch   = errors.New("csrf token mismatch")
)

type Session struct {
	ExpiresAt time.Time
	CSRFToken string
}

type sessionPayload struct {
	Version int    `json:"v"`
	Expiry  int64  `json:"exp"`
	ID      string `json:"sid"`
	CSRF    string `json:"csrf"`
}

func Issue(secret string, ttl time.Duration, now time.Time) (token string, csrf string, expiresAt time.Time, err error) {
	if strings.TrimSpace(secret) == "" {
		return "", "", time.Time{}, ErrInvalidSession
	}
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}

	sessionID, err := randomToken(18)
	if err != nil {
		return "", "", time.Time{}, err
	}
	csrf, err = randomToken(24)
	if err != nil {
		return "", "", time.Time{}, err
	}
	expiresAt = now.UTC().Add(ttl)

	payload := sessionPayload{
		Version: 1,
		Expiry:  expiresAt.Unix(),
		ID:      sessionID,
		CSRF:    csrf,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", "", time.Time{}, err
	}

	sig := sign(secret, raw)
	token = base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(sig)
	return token, csrf, expiresAt, nil
}

func Validate(secret, token string, now time.Time) (Session, error) {
	if strings.TrimSpace(secret) == "" || strings.TrimSpace(token) == "" {
		return Session{}, ErrInvalidSession
	}

	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return Session{}, ErrInvalidSession
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Session{}, ErrInvalidSession
	}
	gotSig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Session{}, ErrInvalidSession
	}

	wantSig := sign(secret, raw)
	if subtle.ConstantTimeCompare(gotSig, wantSig) != 1 {
		return Session{}, ErrInvalidSession
	}

	var payload sessionPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return Session{}, ErrInvalidSession
	}
	if payload.Version != 1 || payload.Expiry <= 0 || payload.ID == "" || payload.CSRF == "" {
		return Session{}, ErrInvalidSession
	}

	expiresAt := time.Unix(payload.Expiry, 0).UTC()
	if !now.UTC().Before(expiresAt) {
		return Session{}, ErrExpiredSession
	}

	return Session{
		ExpiresAt: expiresAt,
		CSRFToken: payload.CSRF,
	}, nil
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

func sign(secret string, payload []byte) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
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
