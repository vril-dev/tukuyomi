package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
	"tukuyomi/internal/serverruntime"
	"tukuyomi/internal/waf"
)

func TestServerHTTP3AltSvcHeader(t *testing.T) {
	t.Parallel()

	got, err := serverHTTP3AltSvcHeader(":9443", 86400)
	if err != nil {
		t.Fatalf("serverHTTP3AltSvcHeader: %v", err)
	}
	if got != `h3=":9443"; ma=86400` {
		t.Fatalf("unexpected alt-svc header: %q", got)
	}
}

func TestWrapHTTP3AltSvcHandlerAddsHeader(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest(http.MethodGet, "https://proxy.example.test/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	rec := httptest.NewRecorder()
	wrapHTTP3AltSvcHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), `h3=":443"; ma=86400`).ServeHTTP(rec, req)
	if got := rec.Header().Get("Alt-Svc"); got != `h3=":443"; ma=86400` {
		t.Fatalf("unexpected Alt-Svc header: %q", got)
	}
}

func TestHTTP3ServerStartsAndAdvertisesAltSvc(t *testing.T) {
	restore := setServerTLSGlobalsForTest(t)
	defer restore()
	serverruntime.ResetHTTP3Status()

	certFile, keyFile := writeServerTLSFiles(t, []string{"127.0.0.1", "localhost"})
	tlsConfig, err := config.BuildServerTLSConfig(certFile, keyFile, "tls1.2")
	if err != nil {
		t.Fatalf("BuildServerTLSConfig: %v", err)
	}

	port := reserveLocalPort(t)
	addr := net.JoinHostPort("127.0.0.1", port)
	config.ListenAddr = addr
	config.ServerTLSEnabled = true
	config.ServerHTTP3Enabled = true
	config.ServerHTTP3AltSvcMaxAgeSec = 86400
	config.ServerMaxHeaderBytes = 1 << 20
	config.ServerIdleTimeout = 30 * time.Second

	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	http3Srv, altSvc, err := buildManagedServerHTTP3Server(tlsConfig, baseHandler)
	if err != nil {
		t.Fatalf("buildManagedServerHTTP3Server: %v", err)
	}
	if altSvc == "" {
		t.Fatal("expected Alt-Svc header value")
	}
	http3Lifecycle := newManagedServerLifecycle(2 * time.Second)
	if err := runHTTP3Server(http3Lifecycle, nil, http3Srv); err != nil {
		t.Fatalf("runHTTP3Server: %v", err)
	}
	defer func() {
		if err := http3Lifecycle.shutdown(); err != nil {
			t.Fatalf("http3 shutdown: %v", err)
		}
	}()

	httpsSrv := &http.Server{
		Addr:      addr,
		Handler:   wrapHTTP3AltSvcHandler(baseHandler, altSvc),
		TLSConfig: tlsConfig,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- httpsSrv.ListenAndServeTLS("", "")
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpsSrv.Shutdown(ctx)
		select {
		case err := <-errCh:
			if err != nil && err != http.ErrServerClosed {
				t.Fatalf("https server exit: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for https server shutdown")
		}
	}()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	var resp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err = client.Get("https://" + addr + "/")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("https request failed: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", resp.StatusCode, string(body))
	}
	if got := resp.Header.Get("Alt-Svc"); !strings.Contains(got, `h3=":`) || !strings.Contains(got, `ma=86400`) {
		t.Fatalf("unexpected Alt-Svc header: %q", got)
	}
	if !serverruntime.HTTP3StatusSnapshot().Advertised {
		t.Fatal("expected advertised http3 runtime status")
	}

	http3Transport := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	defer http3Transport.Close()
	http3Client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: http3Transport,
	}
	http3Resp, err := http3Client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("http3 request failed: %v", err)
	}
	defer http3Resp.Body.Close()
	http3Body, err := io.ReadAll(http3Resp.Body)
	if err != nil {
		t.Fatalf("ReadAll(http3): %v", err)
	}
	if http3Resp.StatusCode != http.StatusOK || string(http3Body) != "ok" {
		t.Fatalf("unexpected http3 response: status=%d body=%q", http3Resp.StatusCode, string(http3Body))
	}
}

func TestHTTP3RequestBodyIsInspectedAndForwardedWhole(t *testing.T) {
	restore := setServerTLSGlobalsForTest(t)
	defer restore()
	serverruntime.ResetHTTP3Status()

	prevRulesFile, prevCRSEnable := config.RulesFile, config.CRSEnable
	prevMode, prevLimit, prevOversize := config.WAFRequestBodyMode, config.WAFRequestBodyInspectLimitBytes, config.WAFRequestBodyOversizeAction
	defer func() {
		config.RulesFile, config.CRSEnable = prevRulesFile, prevCRSEnable
		config.WAFRequestBodyMode, config.WAFRequestBodyInspectLimitBytes, config.WAFRequestBodyOversizeAction = prevMode, prevLimit, prevOversize
	}()
	config.RulesFile = config.DefaultBaseRuleAssetPath
	config.CRSEnable = false
	config.WAFRequestBodyMode = config.WAFRequestBodyModeEnforce
	config.WAFRequestBodyInspectLimitBytes = 1024
	config.WAFRequestBodyOversizeAction = config.WAFRequestBodyOversizeInspectPrefix

	tmp := t.TempDir()
	stageRoot := filepath.Join(tmp, "stage")
	if err := os.MkdirAll(stageRoot, 0o755); err != nil {
		t.Fatalf("mkdir stage: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stageRoot, config.DefaultBaseRuleAssetPath), []byte("SecRuleEngine On\nSecRule ARGS \"@rx (?i)<script>\" \"id:100001,phase:2,deny,status:403,log\"\nSecRule REQUEST_URI \"@beginsWith /admin\" \"id:100002,phase:1,deny,status:403,log\"\n"), 0o644); err != nil {
		t.Fatalf("write base rule: %v", err)
	}
	t.Setenv("WAF_RULE_ASSET_FS_ROOT", stageRoot)
	if err := handler.InitLogsStatsStoreWithBackend("db", "sqlite", filepath.Join(tmp, "tukuyomi.db"), "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	defer func() { _ = handler.InitLogsStatsStore(false, "", 0) }()
	if err := handler.ImportWAFRuleAssetsStorage(); err != nil {
		t.Fatalf("import waf rule assets: %v", err)
	}
	if err := waf.ReloadBaseWAF(); err != nil {
		t.Fatalf("reload waf: %v", err)
	}
	engine := waf.GetBaseEngine()
	if engine == nil {
		t.Fatal("expected base WAF engine")
	}

	certFile, keyFile := writeServerTLSFiles(t, []string{"127.0.0.1", "localhost"})
	tlsConfig, err := config.BuildServerTLSConfig(certFile, keyFile, "tls1.2")
	if err != nil {
		t.Fatalf("BuildServerTLSConfig: %v", err)
	}
	config.ServerTLSEnabled = true
	config.ServerHTTP3Enabled = true
	config.ServerHTTP3AltSvcMaxAgeSec = 86400
	config.ServerMaxHeaderBytes = 1 << 20
	config.ServerIdleTimeout = 30 * time.Second

	appHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decision, err := engine.InspectRequest(r)
		if err != nil {
			t.Errorf("InspectRequest: %v", err)
		}
		if it := decision.Interruption; it != nil {
			w.WriteHeader(it.Status)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read forwarded body: %v", err)
		}
		w.Header().Set("X-Forwarded-Body-Bytes", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
	})
	// Another test may take the reserved UDP port before the listener binds,
	// so retry with a fresh port on a bind conflict.
	var addr string
	var http3Lifecycle *managedServerLifecycle
	for attempt := 1; ; attempt++ {
		addr = net.JoinHostPort("127.0.0.1", reserveLocalUDPPort(t))
		config.ListenAddr = addr
		http3Srv, _, err := buildManagedServerHTTP3ServerForAddr(addr, tlsConfig, appHandler)
		if err != nil {
			t.Fatalf("buildManagedServerHTTP3ServerForAddr: %v", err)
		}
		http3Lifecycle = newManagedServerLifecycle(2 * time.Second)
		err = runHTTP3Server(http3Lifecycle, nil, http3Srv)
		if err == nil {
			break
		}
		if attempt >= 5 || !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("runHTTP3Server: %v", err)
		}
	}
	defer func() {
		if err := http3Lifecycle.shutdown(); err != nil {
			t.Fatalf("http3 shutdown: %v", err)
		}
	}()

	transport := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer transport.Close()
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	post := func(body string, knownLength bool) *http.Response {
		t.Helper()
		newRequest := func() *http.Request {
			var reader io.Reader = strings.NewReader(body)
			if !knownLength {
				reader = io.MultiReader(strings.NewReader(body))
			}
			req, err := http.NewRequest(http.MethodPost, "https://"+addr+"/form", reader)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			if !knownLength {
				req.ContentLength = -1
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return req
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			resp, err := client.Do(newRequest())
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				return resp
			}
			if time.Now().After(deadline) {
				t.Fatalf("http3 request failed: %v", err)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	if resp := post("q=%3Cscript%3E&pad="+strings.Repeat("a", 4096), true); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("http3 body attack status=%d want=403", resp.StatusCode)
	}
	large := "name=alice&pad=" + strings.Repeat("a", 4096)
	for _, knownLength := range []bool{true, false} {
		resp := post(large, knownLength)
		if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Forwarded-Body-Bytes") != strconv.Itoa(len(large)) {
			t.Fatalf("knownLength=%t status=%d forwarded=%q want %d", knownLength, resp.StatusCode, resp.Header.Get("X-Forwarded-Body-Bytes"), len(large))
		}
	}

	// REQUEST_URI rules anchored at "/" must match over HTTP/3 as well, even
	// when the HTTP/3 server sets the scheme and host on the request URL.
	resp, err := client.Get("https://" + addr + "/admin/users?a=1")
	if err != nil {
		t.Fatalf("http3 GET: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("http3 REQUEST_URI prefix rule status=%d want=403", resp.StatusCode)
	}
}

func reserveLocalUDPPort(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()
	_, port, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	return port
}

func reserveLocalPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	return port
}
