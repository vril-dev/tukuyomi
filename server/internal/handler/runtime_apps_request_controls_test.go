package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"net/http"
	"net/http/httptest"

	"golang.org/x/crypto/bcrypt"
)

func TestServeProxyAppliesVhostRewriteAccessAndBasicAuth(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	docroot := filepath.Join(tmp, "static")
	if err := os.MkdirAll(filepath.Join(docroot, "public"), 0o755); err != nil {
		t.Fatalf("MkdirAll(public): %v", err)
	}
	if err := os.MkdirAll(filepath.Join(docroot, "admin"), 0o755); err != nil {
		t.Fatalf("MkdirAll(admin): %v", err)
	}
	if err := os.MkdirAll(filepath.Join(docroot, "assets"), 0o755); err != nil {
		t.Fatalf("MkdirAll(assets): %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, "public", "index.html"), []byte("public-index\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(public/index.html): %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, "admin", "index.html"), []byte("admin-index\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(admin/index.html): %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, "assets", "app.js"), []byte("console.log('bundle');\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(assets/app.js): %v", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}

	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	vhosts := `{
  "vhosts": [
    {
      "name": "docs",
      "mode": "static",
      "hostname": "127.0.0.1",
      "listen_port": 9401,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "generated_target": "docs-static",
      "linked_upstream_name": "docs",
      "rewrite_rules": [
        {
          "pattern": "^/docs$",
          "replacement": "/public/",
          "flag": "last"
        },
        {
          "pattern": "^/public/$",
          "replacement": "/public/index.html",
          "flag": "break"
        },
        {
          "pattern": "^/bundle$",
          "replacement": "/assets/app.js",
          "flag": "break"
        },
        {
          "pattern": "^/old$",
          "replacement": "/public/index.html?from=legacy",
          "flag": "permanent",
          "preserve_query": true
        }
      ],
      "access_rules": [
        {
          "path_pattern": "/public",
          "action": "allow"
        },
        {
          "path_pattern": "/admin",
          "action": "allow",
          "cidrs": ["127.0.0.1/32"],
          "basic_auth": {
            "realm": "Ops",
            "users": [
              {
                "username": "alice",
                "password_hash": "` + string(hash) + `"
              }
            ]
          }
        },
        {
          "path_pattern": "/private",
          "action": "deny"
        }
      ],
      "basic_auth": {
        "realm": "Docs",
        "users": [
          {
            "username": "alice",
            "password_hash": "` + string(hash) + `"
          }
        ]
      }
    }
  ]
}`
	if err := os.WriteFile(vhostPath, []byte(vhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	proxyRaw := `{
  "upstreams": [
    { "name": "docs", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "default_route": {
    "action": {
      "upstream": "docs-static"
    }
  }
}`
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
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

	t.Run("public path bypasses vhost auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://docs.example.com/public/index.html", nil)
		req.RemoteAddr = "203.0.113.8:41234"
		rec := serveProxyTestRequest(t, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "public-index") {
			t.Fatalf("unexpected body=%q", rec.Body.String())
		}
	})

	t.Run("ordered rewrite resolves after auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://docs.example.com/docs", nil)
		req.RemoteAddr = "203.0.113.8:41234"
		req.SetBasicAuth("alice", "s3cret")
		rec := serveProxyTestRequest(t, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "public-index") {
			t.Fatalf("unexpected body=%q", rec.Body.String())
		}
	})

	t.Run("rewrite break serves asset", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://docs.example.com/bundle", nil)
		req.RemoteAddr = "203.0.113.8:41234"
		req.SetBasicAuth("alice", "s3cret")
		rec := serveProxyTestRequest(t, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "bundle") {
			t.Fatalf("unexpected body=%q", rec.Body.String())
		}
	})

	t.Run("redirect preserves query", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://docs.example.com/old?keep=1", nil)
		req.RemoteAddr = "203.0.113.8:41234"
		req.SetBasicAuth("alice", "s3cret")
		rec := serveProxyTestRequest(t, req)
		if rec.Code != http.StatusMovedPermanently {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Location"); got != "/public/index.html?from=legacy&keep=1" {
			t.Fatalf("location=%q", got)
		}
	})

	t.Run("deny rule blocks path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://docs.example.com/private", nil)
		req.RemoteAddr = "203.0.113.8:41234"
		rec := serveProxyTestRequest(t, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("vhost auth applies when no path rule matches", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://docs.example.com/", nil)
		req.RemoteAddr = "203.0.113.8:41234"
		rec := serveProxyTestRequest(t, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, `realm="Docs"`) {
			t.Fatalf("WWW-Authenticate=%q", got)
		}
	})

	t.Run("path auth enforces cidr and credentials", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://docs.example.com/admin/", nil)
		req.RemoteAddr = "203.0.113.8:41234"
		rec := serveProxyTestRequest(t, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}

		req = httptest.NewRequest(http.MethodGet, "http://docs.example.com/admin/", nil)
		req.RemoteAddr = "127.0.0.1:41234"
		rec = serveProxyTestRequest(t, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, `realm="Ops"`) {
			t.Fatalf("WWW-Authenticate=%q", got)
		}

		req = httptest.NewRequest(http.MethodGet, "http://docs.example.com/admin/", nil)
		req.RemoteAddr = "127.0.0.1:41234"
		req.SetBasicAuth("alice", "s3cret")
		rec = serveProxyTestRequest(t, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "admin-index") {
			t.Fatalf("unexpected body=%q", rec.Body.String())
		}
	})
}

func TestVhostRemoteAddrAcceptsProxyProtocolRewrittenRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "198.51.100.10:45678"

	addr, ok := vhostRemoteAddr(req)
	if !ok {
		t.Fatal("expected remote addr to parse")
	}
	if got := addr.String(); got != "198.51.100.10" {
		t.Fatalf("vhostRemoteAddr=%q want=198.51.100.10", got)
	}
}

func TestBuildPHPRuntimePoolConfigIncludesINIOverrides(t *testing.T) {
	vhost := VhostConfig{
		Name:         "app",
		Mode:         "php-fpm",
		ListenPort:   9081,
		DocumentRoot: "data/vhosts/samples/php-app/public",
		PHPValues: map[string]string{
			"memory_limit": "512M",
		},
		PHPAdminValues: map[string]string{
			"open_basedir": "/srv/app",
		},
	}
	body := buildPHPRuntimePoolConfig(vhost, "app")
	if !strings.Contains(body, `php_value[memory_limit] = "512M"`) {
		t.Fatalf("pool config missing php_value override: %s", body)
	}
	if !strings.Contains(body, `php_admin_value[open_basedir] = "/srv/app"`) {
		t.Fatalf("pool config missing php_admin_value override: %s", body)
	}
}

func TestValidateVhostConfigRejectsPlaintextBasicAuthHash(t *testing.T) {
	raw := `{
  "vhosts": [
    {
      "name": "docs",
      "mode": "static",
      "hostname": "127.0.0.1",
      "listen_port": 9401,
      "document_root": "data/vhosts/samples/static-site/public",
      "generated_target": "docs-static",
      "linked_upstream_name": "docs",
      "basic_auth": {
        "users": [
          {
            "username": "alice",
            "password_hash": "plaintext"
          }
        ]
      }
    }
  ]
}`
	if _, err := ValidateVhostConfigRawWithInventory(raw, PHPRuntimeInventoryFile{}); err == nil || !strings.Contains(err.Error(), "password_hash must be a valid bcrypt hash") {
		t.Fatalf("ValidateVhostConfigRawWithInventory err=%v", err)
	}
}

func serveProxyTestRequest(t *testing.T, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	decision, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision: %v", err)
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), decision))
	rec := httptest.NewRecorder()
	ServeProxy(rec, req)
	return rec
}
