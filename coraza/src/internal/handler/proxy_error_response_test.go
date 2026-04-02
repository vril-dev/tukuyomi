package handler

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

func TestProxyHandlerSupportsCustomErrorHTML(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	htmlPath := filepath.Join(t.TempDir(), "proxy-error.html")
	htmlBody := "<html><body><h1>backend unavailable</h1></body></html>"
	if err := os.WriteFile(htmlPath, []byte(htmlBody), 0o644); err != nil {
		t.Fatalf("write html file: %v", err)
	}

	oldAppURL := config.AppURL
	oldHTMLFile := config.ProxyErrorHTMLFile
	oldRedirectURL := config.ProxyErrorRedirectURL
	oldProxy := proxy
	oldOnce := proxyInitOnce
	config.AppURL = "http://" + addr
	config.ProxyErrorHTMLFile = htmlPath
	config.ProxyErrorRedirectURL = ""
	proxy = nil
	proxyInitOnce = sync.Once{}
	t.Cleanup(func() {
		config.AppURL = oldAppURL
		config.ProxyErrorHTMLFile = oldHTMLFile
		config.ProxyErrorRedirectURL = oldRedirectURL
		proxy = oldProxy
		proxyInitOnce = oldOnce
	})

	router := gin.New()
	router.Any("/*path", ProxyHandler)
	srv := httptest.NewServer(router)
	defer srv.Close()

	reqHTML, _ := http.NewRequest(http.MethodGet, srv.URL+"/app", nil)
	reqHTML.Header.Set("Accept", "text/html")
	resHTML, err := http.DefaultClient.Do(reqHTML)
	if err != nil {
		t.Fatalf("html request failed: %v", err)
	}
	bodyHTML, _ := io.ReadAll(resHTML.Body)
	resHTML.Body.Close()
	if resHTML.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unexpected html status: %d", resHTML.StatusCode)
	}
	if ct := resHTML.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("unexpected html content-type: %q", ct)
	}
	if string(bodyHTML) != htmlBody {
		t.Fatalf("unexpected html body: %q", string(bodyHTML))
	}

	reqText, _ := http.NewRequest(http.MethodGet, srv.URL+"/app", nil)
	reqText.Header.Set("Accept", "application/json")
	resText, err := http.DefaultClient.Do(reqText)
	if err != nil {
		t.Fatalf("plain-text request failed: %v", err)
	}
	bodyText, _ := io.ReadAll(resText.Body)
	resText.Body.Close()
	if resText.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unexpected plain-text status: %d", resText.StatusCode)
	}
	if ct := resText.Header.Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("unexpected plain-text content-type: %q", ct)
	}
	if !strings.Contains(string(bodyText), "Service Unavailable") {
		t.Fatalf("unexpected plain-text body: %q", string(bodyText))
	}
}

func TestProxyHandlerRedirectsGETRequestsToMaintenanceURL(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	oldAppURL := config.AppURL
	oldHTMLFile := config.ProxyErrorHTMLFile
	oldRedirectURL := config.ProxyErrorRedirectURL
	oldProxy := proxy
	oldOnce := proxyInitOnce
	config.AppURL = "http://" + addr
	config.ProxyErrorHTMLFile = ""
	config.ProxyErrorRedirectURL = "/maintenance"
	proxy = nil
	proxyInitOnce = sync.Once{}
	t.Cleanup(func() {
		config.AppURL = oldAppURL
		config.ProxyErrorHTMLFile = oldHTMLFile
		config.ProxyErrorRedirectURL = oldRedirectURL
		proxy = oldProxy
		proxyInitOnce = oldOnce
	})

	router := gin.New()
	router.Any("/*path", ProxyHandler)
	srv := httptest.NewServer(router)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/app", nil)
	req.Header.Set("Accept", "text/html")
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("redirect request failed: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("unexpected redirect status: %d", res.StatusCode)
	}
	if got := res.Header.Get("Location"); got != "/maintenance" {
		t.Fatalf("unexpected redirect location: %q", got)
	}
}
