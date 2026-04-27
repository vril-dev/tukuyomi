package botchallenge

import (
	"fmt"
	"net/http"

	"tukuyomi/internal/botdefensesignals"
	"tukuyomi/internal/bottelemetry"
)

type Decision struct {
	Status            int
	CookieName        string
	BrowserCookieName string
	Token             string
	TTLSeconds        int
}

func Write(w http.ResponseWriter, r *http.Request, d Decision) {
	status := d.Status
	if status == 0 {
		status = http.StatusTooManyRequests
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Tukuyomi-Bot-Challenge", "required")

	if r == nil || !botdefensesignals.AcceptsHTML(r.Header.Get("Accept")) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":"bot challenge required"}`))
		return
	}

	maxAge := d.TTLSeconds
	if maxAge < 1 {
		maxAge = 1
	}
	html := fmt.Sprintf(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Challenge Required</title></head>
<body>
<p>Verifying browser...</p>
<script>
(() => {
  const token = %q;
  const cookieName = %q;
  const browserCookieName = %q;
  document.cookie = cookieName + "=" + token + "; Path=/; Max-Age=%d; SameSite=Lax";
  if (browserCookieName) {
    try {
      %s
    } catch (_) {}
  }
  window.location.replace(window.location.href);
})();
</script>
<noscript>JavaScript is required to continue.</noscript>
</body></html>`, d.Token, d.CookieName, d.BrowserCookieName, maxAge, bottelemetry.CookieWriteScript("browserCookieName", maxAge))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(html))
}
