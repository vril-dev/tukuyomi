package handler

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type proxyErrorResponse struct {
	htmlFile    string
	htmlBody    []byte
	htmlEnabled bool
	redirectURL string
}

func newProxyErrorResponse(htmlFile string, redirectURL string) (proxyErrorResponse, error) {
	resp := proxyErrorResponse{
		htmlFile:    strings.TrimSpace(htmlFile),
		redirectURL: strings.TrimSpace(redirectURL),
	}
	if resp.htmlFile != "" && resp.redirectURL != "" {
		return proxyErrorResponse{}, fmt.Errorf("proxy error html file and redirect URL are mutually exclusive")
	}
	if resp.htmlFile != "" {
		body, err := os.ReadFile(resp.htmlFile)
		if err != nil {
			return proxyErrorResponse{}, fmt.Errorf("proxy error html file read error: %w", err)
		}
		resp.htmlBody = body
		resp.htmlEnabled = true
	}
	if resp.redirectURL != "" {
		if err := validateProxyErrorRedirectURL(resp.redirectURL); err != nil {
			return proxyErrorResponse{}, fmt.Errorf("proxy error redirect URL %w", err)
		}
	}
	return resp, nil
}

func (r proxyErrorResponse) Write(w http.ResponseWriter, req *http.Request) {
	if r.redirectURL != "" && canRedirectProxyError(req) {
		http.Redirect(w, req, r.redirectURL, http.StatusFound)
		return
	}
	if r.htmlEnabled && prefersHTMLProxyError(req) {
		writeCustomProxyErrorHTML(w, http.StatusServiceUnavailable, r.htmlBody)
		return
	}
	if r.redirectURL != "" || r.htmlEnabled {
		writeDefaultProxyError(w, req, http.StatusServiceUnavailable)
		return
	}
	writeDefaultProxyError(w, req, http.StatusBadGateway)
}

func canRedirectProxyError(req *http.Request) bool {
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

func prefersHTMLProxyError(req *http.Request) bool {
	if req == nil {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(req.Header.Get("Accept")))
	if v == "" {
		return false
	}
	return strings.Contains(v, "text/html") || strings.Contains(v, "application/xhtml+xml")
}

func writeDefaultProxyError(w http.ResponseWriter, req *http.Request, status int) {
	if prefersHTMLProxyError(req) {
		writeBuiltInProxyErrorHTML(w, status)
		return
	}
	message := http.StatusText(status)
	if message == "" {
		message = "Service Unavailable"
	}
	http.Error(w, message, status)
}

func writeCustomProxyErrorHTML(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeBuiltInProxyErrorHTML(w http.ResponseWriter, status int) {
	writeCustomProxyErrorHTML(w, status, []byte(defaultProxyErrorHTML(status)))
}

func defaultProxyErrorHTML(status int) string {
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

func validateProxyErrorRedirectURL(raw string) error {
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
