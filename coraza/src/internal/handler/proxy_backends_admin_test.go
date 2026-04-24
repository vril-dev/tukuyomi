package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

func TestGetProxyBackendsReturnsRuntimeBackendList(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tmp := t.TempDir()
	restore := saveUpstreamRuntimeFilePathForTest(t, filepath.Join(tmp, "conf", "upstream-runtime.json"))
	defer restore()

	proxyPath := filepath.Join(tmp, "proxy.json")
	proxyRaw := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true },
    { "name": "secondary", "url": "http://127.0.0.1:8081", "weight": 2, "enabled": true }
  ]
}`
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o644); err != nil {
		t.Fatalf("write proxy.json: %v", err)
	}
	initConfigDBStoreForTest(t)
	importProxyRuntimeDBForTest(t, proxyRaw)
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/tukuyomi-api/proxy-backends", nil)
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = req

	GetProxyBackends(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out proxyBackendsStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if out.ETag == "" {
		t.Fatal("expected etag")
	}
	if got, want := len(out.Backends), 2; got != want {
		t.Fatalf("len(backends)=%d want=%d", got, want)
	}
	if got, want := out.Path, config.UpstreamRuntimeFile; got != want {
		t.Fatalf("path=%q want=%q", got, want)
	}
}

func TestGetProxyBackendsReportsDBRuntimeStorage(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "store.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	runtimePath := filepath.Join(tmp, "conf", "upstream-runtime.json")
	restore := saveUpstreamRuntimeFilePathForTest(t, runtimePath)
	defer restore()

	proxyPath := filepath.Join(tmp, "proxy.json")
	if err := os.WriteFile(proxyPath, []byte(`{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ]
}`), 0o644); err != nil {
		t.Fatalf("write proxy.json: %v", err)
	}
	importProxyRuntimeDBForTest(t, `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ]
}`)
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/tukuyomi-api/proxy-backends", nil)
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = req

	GetProxyBackends(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out proxyBackendsStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if got, want := out.Storage, "db:upstream_runtime"; got != want {
		t.Fatalf("storage=%q want=%q", got, want)
	}
	if _, err := os.Stat(runtimePath); !os.IsNotExist(err) {
		t.Fatalf("upstream runtime seed file should not be restored, stat err=%v", err)
	}
}

func TestPutAndDeleteProxyBackendRuntimeOverrideRoundTrip(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tmp := t.TempDir()
	restore := saveUpstreamRuntimeFilePathForTest(t, filepath.Join(tmp, "conf", "upstream-runtime.json"))
	defer restore()

	proxyPath := filepath.Join(tmp, "proxy.json")
	proxyRaw := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true },
    { "name": "secondary", "url": "http://127.0.0.1:8081", "weight": 2, "enabled": true }
  ]
}`
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o644); err != nil {
		t.Fatalf("write proxy.json: %v", err)
	}
	initConfigDBStoreForTest(t)
	importProxyRuntimeDBForTest(t, proxyRaw)
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	getRec := httptest.NewRecorder()
	getReq := httptest.NewRequest(http.MethodGet, "/tukuyomi-api/proxy-backends", nil)
	getCtx, _ := gin.CreateTestContext(getRec)
	getCtx.Request = getReq
	GetProxyBackends(getCtx)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", getRec.Code, getRec.Body.String())
	}
	var initial proxyBackendsStatusResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &initial); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	primaryKey := proxyBackendLookupKey("primary", "http://127.0.0.1:8080")

	putBody := []byte(`{"admin_state":"draining","weight_override":5}`)
	putRec := httptest.NewRecorder()
	putReq := httptest.NewRequest(http.MethodPut, "/tukuyomi-api/proxy-backends/"+primaryKey+"/runtime-override", bytes.NewReader(putBody))
	putReq.Header.Set("Content-Type", "application/json")
	putReq.Header.Set("If-Match", initial.ETag)
	putCtx, _ := gin.CreateTestContext(putRec)
	putCtx.Params = gin.Params{{Key: "backend_key", Value: primaryKey}}
	putCtx.Request = putReq

	PutProxyBackendRuntimeOverride(putCtx)

	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", putRec.Code, putRec.Body.String())
	}
	var afterPut proxyBackendsStatusResponse
	if err := json.Unmarshal(putRec.Body.Bytes(), &afterPut); err != nil {
		t.Fatalf("decode PUT response: %v", err)
	}
	primaryAfterPut := findProxyBackendStatus(t, afterPut.Backends, primaryKey)
	if got, want := primaryAfterPut.AdminState, string(upstreamAdminStateDraining); got != want {
		t.Fatalf("admin_state=%q want=%q", got, want)
	}
	if got, want := primaryAfterPut.WeightOverride, 5; got != want {
		t.Fatalf("weight_override=%d want=%d", got, want)
	}
	if primaryAfterPut.EffectiveSelectable {
		t.Fatal("draining backend should not be selectable")
	}
	runtimeFile, _, found, err := getLogsStatsStore().loadActiveUpstreamRuntimeConfig(configuredManagedBackendKeys(currentProxyConfig()))
	if err != nil || !found {
		t.Fatalf("load upstream runtime from db found=%v err=%v", found, err)
	}
	if _, ok := runtimeFile.Backends[primaryKey]; !ok {
		t.Fatalf("runtime DB missing primary key: %#v", runtimeFile.Backends)
	}

	deleteRec := httptest.NewRecorder()
	deleteReq := httptest.NewRequest(http.MethodDelete, "/tukuyomi-api/proxy-backends/"+primaryKey+"/runtime-override", nil)
	deleteReq.Header.Set("If-Match", afterPut.ETag)
	deleteCtx, _ := gin.CreateTestContext(deleteRec)
	deleteCtx.Params = gin.Params{{Key: "backend_key", Value: primaryKey}}
	deleteCtx.Request = deleteReq

	DeleteProxyBackendRuntimeOverride(deleteCtx)

	if deleteRec.Code != http.StatusOK {
		t.Fatalf("DELETE status=%d body=%s", deleteRec.Code, deleteRec.Body.String())
	}
	var afterDelete proxyBackendsStatusResponse
	if err := json.Unmarshal(deleteRec.Body.Bytes(), &afterDelete); err != nil {
		t.Fatalf("decode DELETE response: %v", err)
	}
	primaryAfterDelete := findProxyBackendStatus(t, afterDelete.Backends, primaryKey)
	if got, want := primaryAfterDelete.AdminState, string(upstreamAdminStateEnabled); got != want {
		t.Fatalf("admin_state after delete=%q want=%q", got, want)
	}
	if got := primaryAfterDelete.WeightOverride; got != 0 {
		t.Fatalf("weight_override after delete=%d want=0", got)
	}
	if !primaryAfterDelete.EffectiveSelectable {
		t.Fatal("enabled backend should be selectable after delete")
	}
}

func TestGetProxyBackendsIncludesVhostManagedAliasAsStatusOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	restoreRuntimePath := saveUpstreamRuntimeFilePathForTest(t, filepath.Join(tmp, "conf", "upstream-runtime.json"))
	defer restoreRuntimePath()

	docroot := filepath.Join(tmp, "static")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatalf("MkdirAll(docroot): %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, "index.html"), []byte("ok\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(index): %v", err)
	}

	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := os.WriteFile(vhostPath, []byte(`{
  "vhosts": [
    {
      "name": "docs",
      "mode": "static",
      "hostname": "docs.example.com",
      "listen_port": 9401,
      "document_root": "`+filepath.ToSlash(docroot)+`",
      "generated_target": "docs-static",
      "linked_upstream_name": "docs"
    }
  ]
}`), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	if err := os.WriteFile(proxyPath, []byte(`{
  "upstreams": [
    { "name": "docs", "url": "http://127.0.0.1:8081", "weight": 1, "enabled": true },
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ]
}`), 0o600); err != nil {
		t.Fatalf("write proxy.json: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/tukuyomi-api/proxy-backends", nil)
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = req

	GetProxyBackends(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out proxyBackendsStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if got, want := len(out.Backends), 2; got != want {
		t.Fatalf("len(backends)=%d want=%d", got, want)
	}
	docs := findProxyBackendStatus(t, out.Backends, proxyBackendLookupKey("docs", "static://docs-static"))
	if got, want := docs.ProviderClass, proxyUpstreamProviderClassVhostManaged; got != want {
		t.Fatalf("provider_class=%q want=%q", got, want)
	}
	if got, want := docs.ManagedByVhost, "docs"; got != want {
		t.Fatalf("managed_by_vhost=%q want=%q", got, want)
	}
	if docs.RuntimeOpsSupported {
		t.Fatal("vhost-bound configured upstream should be status-only in this slice")
	}
	if got, want := docs.HealthState, "unknown"; got != want {
		t.Fatalf("health_state=%q want=%q", got, want)
	}
}

func TestPutProxyBackendRuntimeOverrideRejectsVhostManagedAlias(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	restoreRuntimePath := saveUpstreamRuntimeFilePathForTest(t, filepath.Join(tmp, "conf", "upstream-runtime.json"))
	defer restoreRuntimePath()

	docroot := filepath.Join(tmp, "static")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatalf("MkdirAll(docroot): %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, "index.html"), []byte("ok\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(index): %v", err)
	}

	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := os.WriteFile(vhostPath, []byte(`{
  "vhosts": [
    {
      "name": "docs",
      "mode": "static",
      "hostname": "docs.example.com",
      "listen_port": 9401,
      "document_root": "`+filepath.ToSlash(docroot)+`",
      "generated_target": "docs-static",
      "linked_upstream_name": "docs"
    }
  ]
}`), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	if err := os.WriteFile(proxyPath, []byte(`{
  "upstreams": [
    { "name": "docs", "url": "http://127.0.0.1:8081", "weight": 1, "enabled": true },
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ]
}`), 0o600); err != nil {
		t.Fatalf("write proxy.json: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	getRec := httptest.NewRecorder()
	getReq := httptest.NewRequest(http.MethodGet, "/tukuyomi-api/proxy-backends", nil)
	getCtx, _ := gin.CreateTestContext(getRec)
	getCtx.Request = getReq
	GetProxyBackends(getCtx)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", getRec.Code, getRec.Body.String())
	}
	var initial proxyBackendsStatusResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &initial); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}

	linkedKey := proxyBackendLookupKey("docs", "static://docs-static")
	putRec := httptest.NewRecorder()
	putReq := httptest.NewRequest(http.MethodPut, "/tukuyomi-api/proxy-backends/"+linkedKey+"/runtime-override", bytes.NewReader([]byte(`{"admin_state":"disabled"}`)))
	putReq.Header.Set("Content-Type", "application/json")
	putReq.Header.Set("If-Match", initial.ETag)
	putCtx, _ := gin.CreateTestContext(putRec)
	putCtx.Params = gin.Params{{Key: "backend_key", Value: linkedKey}}
	putCtx.Request = putReq

	PutProxyBackendRuntimeOverride(putCtx)

	if putRec.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", putRec.Code, putRec.Body.String())
	}
}

func saveUpstreamRuntimeFilePathForTest(t *testing.T, path string) func() {
	t.Helper()
	prev := config.UpstreamRuntimeFile
	config.UpstreamRuntimeFile = path
	return func() {
		config.UpstreamRuntimeFile = prev
	}
}

func findProxyBackendStatus(t *testing.T, backends []upstreamBackendStatus, key string) upstreamBackendStatus {
	t.Helper()
	for _, backend := range backends {
		if backend.Key == key {
			return backend
		}
	}
	t.Fatalf("backend %q not found in %#v", key, backends)
	return upstreamBackendStatus{}
}
