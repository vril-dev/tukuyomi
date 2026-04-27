package proxyerror

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type Config struct {
	HTMLFile    string
	RedirectURL string
}

type Response struct {
	htmlFile    string
	htmlBody    []byte
	htmlEnabled bool
	redirectURL string
}

func New(cfg Config) (Response, error) {
	resp := Response{
		htmlFile:    strings.TrimSpace(cfg.HTMLFile),
		redirectURL: strings.TrimSpace(cfg.RedirectURL),
	}
	if resp.htmlFile != "" && resp.redirectURL != "" {
		return Response{}, fmt.Errorf("error_html_file and error_redirect_url are mutually exclusive")
	}
	if resp.htmlFile != "" {
		body, err := os.ReadFile(resp.htmlFile)
		if err != nil {
			return Response{}, fmt.Errorf("error_html_file read error: %w", err)
		}
		resp.htmlBody = body
		resp.htmlEnabled = true
	}
	if resp.redirectURL != "" {
		if err := validateRedirectURL(resp.redirectURL); err != nil {
			return Response{}, fmt.Errorf("error_redirect_url %w", err)
		}
	}
	return resp, nil
}

func (r Response) Write(w http.ResponseWriter, req *http.Request) {
	if r.redirectURL != "" && canRedirect(req) {
		http.Redirect(w, req, r.redirectURL, http.StatusFound)
		return
	}
	if r.htmlEnabled && prefersHTML(req) {
		writeCustomHTML(w, http.StatusServiceUnavailable, r.htmlBody)
		return
	}
	if r.redirectURL != "" || r.htmlEnabled {
		writeDefault(w, req, http.StatusServiceUnavailable)
		return
	}
	writeDefault(w, req, http.StatusBadGateway)
}

func canRedirect(req *http.Request) bool {
	if req == nil {
		return false
	}
	switch req.Method {
	case http.MethodGet, http.MethodHead:
		return true
	default:
		return false
	}
}

func prefersHTML(req *http.Request) bool {
	if req == nil {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(req.Header.Get("Accept")))
	if v == "" {
		return false
	}
	return strings.Contains(v, "text/html") || strings.Contains(v, "application/xhtml+xml")
}

func writeDefault(w http.ResponseWriter, req *http.Request, status int) {
	if prefersHTML(req) {
		writeBuiltInHTML(w, status)
		return
	}
	message := http.StatusText(status)
	if message == "" {
		message = "Service Unavailable"
	}
	http.Error(w, message, status)
}

func writeCustomHTML(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeBuiltInHTML(w http.ResponseWriter, status int) {
	writeCustomHTML(w, status, []byte(defaultHTML(status)))
}

func defaultHTML(status int) string {
	title := http.StatusText(status)
	if title == "" {
		title = "Service Unavailable"
	}
	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>%d %s</title>
</head>
<body>
  <main>
    <h1>%s</h1>
    <p>The protected application is temporarily unavailable. Please try again later.</p>
  </main>
</body>
</html>`, status, title, title)
}

func validateRedirectURL(raw string) error {
	v := strings.TrimSpace(raw)
	if v == "" || strings.HasPrefix(v, "/") {
		return nil
	}
	u, err := url.Parse(v)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("must be an absolute URL or start with '/'")
	}
	switch strings.ToLower(strings.TrimSpace(u.Scheme)) {
	case "http", "https":
		return nil
	default:
		return fmt.Errorf("scheme must be http or https")
	}
}
