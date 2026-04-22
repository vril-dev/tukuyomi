package cacheconf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromBytesLegacy(t *testing.T) {
	rs, err := LoadFromBytes([]byte("ALLOW prefix=/assets/ methods=GET,HEAD ttl=600 vary=Accept-Encoding\n"))
	if err != nil {
		t.Fatalf("LoadFromBytes(legacy) error = %v", err)
	}
	if rs == nil || len(rs.Rules) != 1 {
		t.Fatalf("rules=%v", rs)
	}
	if rs.Rules[0].Kind != "ALLOW" || rs.Rules[0].Prefix != "/assets/" {
		t.Fatalf("rule=%+v", rs.Rules[0])
	}
}

func TestLoadFromBytesJSON(t *testing.T) {
	rs, err := LoadFromBytes([]byte(`{
  "rules": [
    {
      "kind": "DENY",
      "match": { "type": "exact", "value": "/tukuyomi-api/" },
      "methods": ["GET", "HEAD"],
      "ttl": 600
    }
  ]
}`))
	if err != nil {
		t.Fatalf("LoadFromBytes(JSON) error = %v", err)
	}
	if rs == nil || len(rs.Rules) != 1 {
		t.Fatalf("rules=%v", rs)
	}
	if rs.Rules[0].Kind != "DENY" || rs.Rules[0].Exact != "/tukuyomi-api/" {
		t.Fatalf("rule=%+v", rs.Rules[0])
	}
}

func TestLoadFromBytesJSONCanonicalHostScopes(t *testing.T) {
	rs, err := LoadFromBytes([]byte(`{
  "default": {
    "rules": [
      {
        "kind": "ALLOW",
        "match": { "type": "prefix", "value": "/assets/" },
        "methods": ["GET", "HEAD"],
        "ttl": 600
      }
    ]
  },
  "hosts": {
    "admin.example.com": {
      "rules": [
        {
          "kind": "DENY",
          "match": { "type": "prefix", "value": "/" },
          "methods": ["GET", "HEAD"],
          "ttl": 60
        }
      ]
    }
  }
}`))
	if err != nil {
		t.Fatalf("LoadFromBytes(canonical) error = %v", err)
	}
	if rs == nil || len(rs.Rules) != 1 {
		t.Fatalf("default rules=%v", rs)
	}
	if len(rs.Hosts) != 1 {
		t.Fatalf("hosts=%v", rs.Hosts)
	}
	if _, ok := rs.Hosts["admin.example.com"]; !ok {
		t.Fatalf("hosts=%v", rs.Hosts)
	}
	if rule, allow := rs.Match("admin.example.com", false, "GET", "/assets/app.js"); allow || rule == nil || rule.Kind != "DENY" {
		t.Fatalf("admin host match = (%+v,%v) want DENY,false", rule, allow)
	}
	if rule, allow := rs.Match("www.example.com", false, "GET", "/assets/app.js"); !allow || rule == nil || rule.Kind != "ALLOW" {
		t.Fatalf("default host match = (%+v,%v) want ALLOW,true", rule, allow)
	}
}

func TestLoadJSONFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	if err := os.WriteFile(path, []byte(`{
  "rules": [
    {
      "kind": "ALLOW",
      "match": { "type": "prefix", "value": "/assets/" },
      "methods": ["GET", "HEAD"],
      "ttl": 900
    }
  ]
}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	rs, err := Load(path)
	if err != nil {
		t.Fatalf("Load(JSON file) error = %v", err)
	}
	if rs == nil || len(rs.Rules) != 1 {
		t.Fatalf("rules=%v", rs)
	}
	if rs.Rules[0].Kind != "ALLOW" || rs.Rules[0].Prefix != "/assets/" || rs.Rules[0].TTL != 900 {
		t.Fatalf("rule=%+v", rs.Rules[0])
	}
}
