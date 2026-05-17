package handler

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
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

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/proxyaccesslog"

	"golang.org/x/net/http2"
)

func boolValue(v any) bool {
	b, _ := v.(bool)
	return b
}

type testProxyStatusWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (w testProxyStatusWriter) Status() int {
	return w.status
}

func (w testProxyStatusWriter) Size() int {
	return w.size
}

func TestProxyHandlerEmitsAccessLogWithBodyByteCounts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initConfigDBStoreForTest(t)

	var observedUpstreamName string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observedUpstreamName = r.Header.Get(proxyObservabilityUpstreamNameHeader)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream body: %v", err)
		}
		if string(body) != "payload" {
			t.Fatalf("upstream body=%q want=payload", string(body))
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("pong"))
	}))
	defer upstream.Close()

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := `{
  "upstreams": [
    { "name": "primary", "url": ` + strconv.Quote(upstream.URL) + `, "weight": 1, "enabled": true }
  ],
  "default_route": {"name":"fallback","action":{"upstream":"primary"}},
  "emit_upstream_name_request_header": true,
  "buffer_request_body": true
}`
	if err := os.WriteFile(proxyCfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	importProxyRuntimeDBForTest(t, raw)
	if err := InitProxyRuntime(proxyCfgPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	r := gin.New()
	r.NoRoute(ProxyHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/upload?mode=test", strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Country-Code", "jp")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d want=%d", res.StatusCode, http.StatusCreated)
	}
	if observedUpstreamName != "primary" {
		t.Fatalf("%s=%q want=primary", proxyObservabilityUpstreamNameHeader, observedUpstreamName)
	}

	events := readProxyLogEvents(t)
	evt := findLastProxyLogEvent(t, events, "proxy_access")
	if got := intValue(evt["status"]); got != http.StatusCreated {
		t.Fatalf("proxy_access status=%d want=%d", got, http.StatusCreated)
	}
	if got := anyToString(evt["method"]); got != http.MethodPost {
		t.Fatalf("proxy_access method=%q want=%s", got, http.MethodPost)
	}
	if got := anyToString(evt["selected_upstream"]); got != "primary" {
		t.Fatalf("proxy_access selected_upstream=%q want=primary", got)
	}
	if got := anyToString(evt["selected_upstream_url"]); got != upstream.URL {
		t.Fatalf("proxy_access selected_upstream_url=%q want=%q", got, upstream.URL)
	}
	if got := anyToString(evt["selected_upstream_admin_state"]); got != "enabled" {
		t.Fatalf("proxy_access selected_upstream_admin_state=%q want=enabled", got)
	}
	if got := anyToString(evt["selected_upstream_health_state"]); got != "unknown" {
		t.Fatalf("proxy_access selected_upstream_health_state=%q want=unknown", got)
	}
	if got := intValue(evt["selected_upstream_effective_weight"]); got != 1 {
		t.Fatalf("proxy_access selected_upstream_effective_weight=%d want=1", got)
	}
	if got := boolValue(evt["selected_upstream_effective_selectable"]); !got {
		t.Fatalf("proxy_access selected_upstream_effective_selectable=%v want=true", got)
	}
	if got := intValue(evt["selected_upstream_inflight"]); got != 0 {
		t.Fatalf("proxy_access selected_upstream_inflight=%d want=0", got)
	}
	if got := intValue(evt["request_body_bytes"]); got != len("payload") {
		t.Fatalf("proxy_access request_body_bytes=%d want=%d", got, len("payload"))
	}
	if got := intValue(evt["response_body_bytes"]); got != len("pong") {
		t.Fatalf("proxy_access response_body_bytes=%d want=%d", got, len("pong"))
	}
	if got := anyToString(evt["country"]); got != "JP" {
		t.Fatalf("proxy_access country=%q want=JP", got)
	}
	if got := anyToString(evt["country_source"]); got != "header" {
		t.Fatalf("proxy_access country_source=%q want=header", got)
	}
}

func TestProxyHandlerHTTP2AccessLogUsesActualResponseStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initConfigDBStoreForTest(t)

	const responseBody = "missing"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(responseBody))
	}))
	defer upstream.Close()

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := `{
  "upstreams": [
    { "name": "primary", "url": ` + strconv.Quote(upstream.URL) + `, "weight": 1, "enabled": true }
  ],
  "default_route": {"name":"fallback","action":{"upstream":"primary"}}
}`
	if err := os.WriteFile(proxyCfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	importProxyRuntimeDBForTest(t, raw)
	if err := InitProxyRuntime(proxyCfgPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	r := gin.New()
	r.NoRoute(ProxyHandler)
	cert := nativeHTTP1TestCertificate(t)
	srv, addr := nativeHTTP1StartConfiguredTLSHTTP2Server(t, &nativeHTTP1Server{Handler: r}, &tls.Config{Certificates: []tls.Certificate{cert}})
	defer srv.Close()

	tr := &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/robots.txt", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if got := res.StatusCode; got != http.StatusNotFound {
		t.Fatalf("status=%d want=%d body=%q", got, http.StatusNotFound, string(body))
	}

	evt := findLastProxyLogEvent(t, readProxyLogEvents(t), "proxy_access")
	if got := anyToString(evt["path"]); got != "/robots.txt" {
		t.Fatalf("proxy_access path=%q want=/robots.txt", got)
	}
	if got := intValue(evt["status"]); got != http.StatusNotFound {
		t.Fatalf("proxy_access status=%d want=%d", got, http.StatusNotFound)
	}
	if got := intValue(evt["response_body_bytes"]); got != len(responseBody) {
		t.Fatalf("proxy_access response_body_bytes=%d want=%d", got, len(responseBody))
	}
}

func TestEmitProxyAccessLogMinimalSkipsExpandedFields(t *testing.T) {
	initConfigDBStoreForTest(t)

	proxyaccesslog.SetRuntimeMode(proxyaccesslog.ModeMinimal)
	t.Cleanup(func() {
		proxyaccesslog.SetRuntimeMode(proxyaccesslog.ModeFull)
	})

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/demo", nil)
	classification := proxyRouteClassification{
		Source:        proxyRouteResolutionRoute,
		RouteName:     "route-a",
		OriginalHost:  "proxy.local",
		OriginalPath:  "/demo",
		RewrittenPath: "/demo",
	}
	selection := proxyRouteTransportSelection{
		SelectedUpstream:    "primary",
		SelectedUpstreamURL: "http://backend.local",
	}
	ctx := withProxyRouteClassification(req.Context(), classification)
	ctx = withProxyRouteTransportSelection(ctx, selection)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	emitProxyAccessLog(req, testProxyStatusWriter{ResponseWriter: rec, status: http.StatusAccepted}, "req-1", "198.51.100.10", "JP")

	events := readProxyLogEvents(t)
	evt := findLastProxyLogEvent(t, events, "proxy_access")
	if got := intValue(evt["status"]); got != http.StatusAccepted {
		t.Fatalf("proxy_access status=%d want=%d", got, http.StatusAccepted)
	}
	if got := anyToString(evt["selected_upstream"]); got != "" {
		t.Fatalf("minimal selected_upstream=%q want empty", got)
	}
	if got := intValue(evt["request_body_bytes"]); got != 0 {
		t.Fatalf("minimal request_body_bytes=%d want omitted/zero", got)
	}
}

func TestEmitProxyAccessLogOffSkipsAccessEvent(t *testing.T) {
	initConfigDBStoreForTest(t)

	proxyaccesslog.SetRuntimeMode(proxyaccesslog.ModeOff)
	t.Cleanup(func() {
		proxyaccesslog.SetRuntimeMode(proxyaccesslog.ModeFull)
	})

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/demo", nil)
	rec := httptest.NewRecorder()
	emitProxyAccessLog(req, testProxyStatusWriter{ResponseWriter: rec, status: http.StatusOK}, "req-1", "198.51.100.10", "JP")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := FlushProxyAccessLogAsync(ctx); err != nil {
		t.Fatalf("flush proxy access log: %v", err)
	}
	events := readProxyLogEvents(t)
	if got := countProxyLogEvents(events, "proxy_access"); got != 0 {
		t.Fatalf("access_log_mode=off wrote %d proxy_access events: %#v", got, events)
	}
}

func TestProxyHandlerBlocksRouteAccessCIDRMissBeforeUpstream(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initConfigDBStoreForTest(t)

	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := `{
  "upstreams": [
    { "name": "center", "url": ` + strconv.Quote(upstream.URL) + `, "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "name": "center-ui",
      "priority": 10,
      "match": { "path": { "type": "prefix", "value": "/center-ui" } },
      "access": { "allow_cidrs": ["203.0.113.10/32"] },
      "action": { "upstream": "center" }
    }
  ]
}`
	if err := os.WriteFile(proxyCfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	importProxyRuntimeDBForTest(t, raw)
	if err := InitProxyRuntime(proxyCfgPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	r := gin.New()
	r.NoRoute(ProxyHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/center-ui/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d want=%d", res.StatusCode, http.StatusForbidden)
	}
	if contentType := res.Header.Get("Content-Type"); !strings.Contains(contentType, "application/json") {
		t.Fatalf("content-type=%q want application/json", contentType)
	}
	if cacheControl := res.Header.Get("Cache-Control"); cacheControl != "no-store" {
		t.Fatalf("cache-control=%q want no-store", cacheControl)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "route source forbidden") {
		t.Fatalf("body=%q want route source forbidden", string(body))
	}
	if upstreamHit {
		t.Fatal("upstream was called despite route access block")
	}
}

func TestProxyHandlerBypassesEdgeGateForLocalCenterProtectedRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restoreEdgeRuntime := setEdgeRuntimeForTest(true, true)
	defer restoreEdgeRuntime()
	store := initConfigDBStoreForTest(t)

	identity, err := newEdgeDeviceIdentity("gateway-a", "default")
	if err != nil {
		t.Fatalf("newEdgeDeviceIdentity: %v", err)
	}
	identity.EnrollmentStatus = edgeEnrollmentStatusPending
	identity.CenterURL = "http://127.0.0.1:9092"
	if err := upsertEdgeDeviceIdentity(store, identity); err != nil {
		t.Fatalf("upsertEdgeDeviceIdentity: %v", err)
	}
	if gate := currentEdgeProxyGateState(); !gate.Locked {
		t.Fatalf("test requires locked edge gate, got %+v", gate)
	}

	centerHit := false
	center := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		centerHit = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer center.Close()

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := `{
  "upstreams": [
    { "name": "center", "url": ` + strconv.Quote(center.URL) + `, "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "name": "center-ui",
      "priority": 10,
      "match": { "path": { "type": "prefix", "value": "/center-ui" } },
      "action": { "upstream": "center" }
    },
    {
      "name": "app",
      "priority": 20,
      "match": { "path": { "type": "prefix", "value": "/app" } },
      "action": { "upstream": "center" }
    }
  ]
}`
	if err := os.WriteFile(proxyCfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	importProxyRuntimeDBForTest(t, raw)
	if err := InitProxyRuntime(proxyCfgPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	r := gin.New()
	r.NoRoute(ProxyHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	centerRes, err := http.Get(srv.URL + "/center-ui/")
	if err != nil {
		t.Fatalf("center-ui request: %v", err)
	}
	_ = centerRes.Body.Close()
	if centerRes.StatusCode != http.StatusNoContent {
		t.Fatalf("center-ui status=%d want %d", centerRes.StatusCode, http.StatusNoContent)
	}
	if !centerHit {
		t.Fatal("center route did not reach upstream")
	}

	appRes, err := http.Get(srv.URL + "/app/")
	if err != nil {
		t.Fatalf("app request: %v", err)
	}
	defer appRes.Body.Close()
	if appRes.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("app status=%d want %d", appRes.StatusCode, http.StatusServiceUnavailable)
	}
	body, err := io.ReadAll(appRes.Body)
	if err != nil {
		t.Fatalf("read app body: %v", err)
	}
	if !strings.Contains(string(body), "device_not_approved") {
		t.Fatalf("app body=%q want device_not_approved", string(body))
	}
}

func TestProxyHandlerDisabledEmitUpstreamNameHeaderStripsSpoofedHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initConfigDBStoreForTest(t)

	var observedUpstreamName string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observedUpstreamName = r.Header.Get(proxyObservabilityUpstreamNameHeader)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("pong"))
	}))
	defer upstream.Close()

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := `{
  "emit_upstream_name_request_header": false,
  "upstreams": [
    { "name": "primary", "url": ` + strconv.Quote(upstream.URL) + `, "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "name": "primary",
      "priority": 10,
      "action": {
        "upstream": "primary"
      }
    }
  ]
}`
	if err := os.WriteFile(proxyCfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	importProxyRuntimeDBForTest(t, raw)
	if err := InitProxyRuntime(proxyCfgPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	r := gin.New()
	r.NoRoute(ProxyHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set(proxyObservabilityUpstreamNameHeader, "spoofed")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want=%d", res.StatusCode, http.StatusOK)
	}
	if observedUpstreamName != "" {
		t.Fatalf("%s=%q want empty", proxyObservabilityUpstreamNameHeader, observedUpstreamName)
	}
}

func TestProxyHandlerCountryBlockLogOmitsSelectedTargetFields(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initConfigDBStoreForTest(t)

	prevCountry := GetCountryBlockFile()
	t.Cleanup(func() {
		restoreDir := t.TempDir()
		restorePath := filepath.Join(restoreDir, "country-block.json")
		raw, err := json.Marshal(prevCountry)
		if err != nil {
			t.Fatalf("marshal previous country block: %v", err)
		}
		if err := os.WriteFile(restorePath, raw, 0o600); err != nil {
			t.Fatalf("write restored country block: %v", err)
		}
		importCountryBlockDBForTest(t, string(raw))
		if err := InitCountryBlock(restorePath, ""); err != nil {
			t.Fatalf("restore country block: %v", err)
		}
	})

	tmp := t.TempDir()
	countryPath := filepath.Join(tmp, "country-block.json")
	if err := os.WriteFile(countryPath, []byte(`{
  "default": {
    "blocked_countries": ["JP"]
  }
}`), 0o600); err != nil {
		t.Fatalf("write country-block.json: %v", err)
	}
	importCountryBlockDBForTest(t, `{
  "default": {
    "blocked_countries": ["JP"]
  }
}`)
	if err := InitCountryBlock(countryPath, ""); err != nil {
		t.Fatalf("InitCountryBlock: %v", err)
	}

	proxyCfgPath := filepath.Join(tmp, "proxy.json")
	raw := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "name": "service-a",
      "priority": 10,
      "match": {
        "hosts": ["api.example.com"],
        "path": { "type": "prefix", "value": "/servicea/" }
      },
      "action": {
        "upstream": "primary",
        "host_rewrite": "service-a.internal",
        "path_rewrite": { "prefix": "/service-a/" }
      }
    }
  ]
}`
	if err := os.WriteFile(proxyCfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	importProxyRuntimeDBForTest(t, raw)
	if err := InitProxyRuntime(proxyCfgPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	r := gin.New()
	r.NoRoute(ProxyHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/servicea/users?lang=ja", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "api.example.com"
	req.Header.Set("X-Country-Code", "jp")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d want=%d", res.StatusCode, http.StatusForbidden)
	}

	events := readProxyLogEvents(t)
	routeEvt := findLastProxyLogEvent(t, events, "proxy_route")
	if got := anyToString(routeEvt["method"]); got != http.MethodGet {
		t.Fatalf("proxy_route method=%q want=%s", got, http.MethodGet)
	}
	if got := anyToString(routeEvt["selected_route"]); got != "service-a" {
		t.Fatalf("proxy_route selected_route=%q want=service-a", got)
	}
	if got := anyToString(routeEvt["selected_upstream"]); got != "" {
		t.Fatalf("proxy_route selected_upstream=%q want empty", got)
	}
	if got := anyToString(routeEvt["selected_upstream_admin_state"]); got != "" {
		t.Fatalf("proxy_route selected_upstream_admin_state=%q want empty", got)
	}
	if got := anyToString(routeEvt["selected_upstream_health_state"]); got != "" {
		t.Fatalf("proxy_route selected_upstream_health_state=%q want empty", got)
	}

	blockEvt := findLastProxyLogEvent(t, events, "country_block")
	if got := anyToString(blockEvt["selected_route"]); got != "service-a" {
		t.Fatalf("country_block selected_route=%q want=service-a", got)
	}
	if got := anyToString(blockEvt["selected_upstream"]); got != "" {
		t.Fatalf("country_block selected_upstream=%q want empty", got)
	}
	if got := anyToString(blockEvt["selected_upstream_url"]); got != "" {
		t.Fatalf("country_block selected_upstream_url=%q want empty", got)
	}
	if got := anyToString(blockEvt["selected_upstream_admin_state"]); got != "" {
		t.Fatalf("country_block selected_upstream_admin_state=%q want empty", got)
	}
	if got := anyToString(blockEvt["selected_upstream_health_state"]); got != "" {
		t.Fatalf("country_block selected_upstream_health_state=%q want empty", got)
	}
}

func TestProxyHandlerEmitsErrorLogWithBodyByteCounts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initConfigDBStoreForTest(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := `{
  "upstreams": [
    { "name": "primary", "url": "http://` + addr + `", "weight": 1, "enabled": true }
  ],
  "default_route": {"name":"fallback","action":{"upstream":"primary"}},
  "buffer_request_body": true
}`
	if err := os.WriteFile(proxyCfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	importProxyRuntimeDBForTest(t, raw)
	if err := InitProxyRuntime(proxyCfgPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	r := gin.New()
	r.NoRoute(ProxyHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/upload", strings.NewReader("abc"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadGateway {
		t.Fatalf("status=%d want=%d", res.StatusCode, http.StatusBadGateway)
	}

	events := readProxyLogEvents(t)
	errEvt := findLastProxyLogEvent(t, events, "proxy_error")
	if got := intValue(errEvt["request_body_bytes"]); got != len("abc") {
		t.Fatalf("proxy_error request_body_bytes=%d want=%d", got, len("abc"))
	}
	if got := intValue(errEvt["response_body_bytes"]); got <= 0 {
		t.Fatalf("proxy_error response_body_bytes=%d want>0", got)
	}

	accessEvt := findLastProxyLogEvent(t, events, "proxy_access")
	if got := intValue(accessEvt["status"]); got != http.StatusBadGateway {
		t.Fatalf("proxy_access status=%d want=%d", got, http.StatusBadGateway)
	}
}

func TestStatusHandlerIncludesProxyUpstreamKeepAlive(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initConfigDBStoreForTest(t)

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "default_route": {"name":"fallback","action":{"upstream":"primary"}},
  "upstream_keepalive_sec": 45
}`
	if err := os.WriteFile(proxyCfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	importProxyRuntimeDBForTest(t, raw)
	if err := InitProxyRuntime(proxyCfgPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/tukuyomi-api/status", nil)

	StatusHandler(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var payload map[string]any
	if err := json.NewDecoder(bytes.NewReader(rec.Body.Bytes())).Decode(&payload); err != nil {
		t.Fatalf("decode status body: %v", err)
	}
	if got := intValue(payload["proxy_upstream_keepalive_sec"]); got != 45 {
		t.Fatalf("proxy_upstream_keepalive_sec=%d want=45", got)
	}
	if got := anyToString(payload["request_country_effective_mode"]); got != "header" {
		t.Fatalf("request_country_effective_mode=%q want=header", got)
	}
	if got := anyToString(payload["request_country_managed_path"]); got != managedRequestCountryMMDBPath() {
		t.Fatalf("request_country_managed_path=%q want=%q", got, managedRequestCountryMMDBPath())
	}
}

func readProxyLogEvents(t *testing.T) []map[string]any {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := FlushProxyAccessLogAsync(ctx); err != nil {
		t.Fatalf("flush proxy access log: %v", err)
	}

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	lines, _, _, _, err := store.ReadWAFLogs("", 1000, nil, "", "", "", time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("read db logs: %v", err)
	}
	out := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		evt := map[string]any(line)
		out = append(out, evt)
	}
	return out
}

func countProxyLogEvents(events []map[string]any, want string) int {
	count := 0
	for _, evt := range events {
		if anyToString(evt["event"]) == want {
			count++
		}
	}
	return count
}

func findLastProxyLogEvent(t *testing.T, events []map[string]any, want string) map[string]any {
	t.Helper()

	for i := len(events) - 1; i >= 0; i-- {
		if anyToString(events[i]["event"]) == want {
			return events[i]
		}
	}
	t.Fatalf("missing log event %q in %#v", want, events)
	return nil
}
