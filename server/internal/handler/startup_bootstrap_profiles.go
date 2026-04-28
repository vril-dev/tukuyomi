package handler

import (
	"fmt"
	"os"
	"strings"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/cacheconf"
)

const startupBootstrapProfileEnv = "WAF_DB_IMPORT_PROFILE"

type startupBootstrapProfile string

const (
	startupBootstrapProfileNone          startupBootstrapProfile = ""
	startupBootstrapProfileMinimal       startupBootstrapProfile = "minimal"
	startupBootstrapProfileAPIGateway    startupBootstrapProfile = "api-gateway"
	startupBootstrapProfileNextJS        startupBootstrapProfile = "nextjs"
	startupBootstrapProfileWordPress     startupBootstrapProfile = "wordpress"
	startupBootstrapProfileReleaseBinary startupBootstrapProfile = "release-binary"
)

type startupBootstrapProfileSpec struct {
	ProxyRaw  string
	PolicyRaw map[string]string
}

const minimalPresetProxySeedRaw = "{\n  \"upstreams\": [\n    {\n      \"name\": \"primary\",\n      \"url\": \"http://host.docker.internal:18080\",\n      \"weight\": 1,\n      \"enabled\": true\n    }\n  ],\n  \"load_balancing_strategy\": \"round_robin\",\n  \"routes\": [],\n  \"dial_timeout\": 5,\n  \"response_header_timeout\": 10,\n  \"idle_conn_timeout\": 90,\n  \"upstream_keepalive_sec\": 30,\n  \"max_idle_conns\": 100,\n  \"max_idle_conns_per_host\": 100,\n  \"max_conns_per_host\": 600,\n  \"force_http2\": true,\n  \"disable_compression\": false,\n  \"expose_waf_debug_headers\": false,\n  \"expect_continue_timeout\": 1,\n  \"tls_insecure_skip_verify\": false,\n  \"tls_ca_bundle\": \"\",\n  \"tls_min_version\": \"\",\n  \"tls_max_version\": \"\",\n  \"tls_client_cert\": \"\",\n  \"tls_client_key\": \"\",\n  \"buffer_request_body\": true,\n  \"max_response_buffer_bytes\": 1048576,\n  \"flush_interval_ms\": 25,\n  \"health_check_path\": \"/bench\",\n  \"health_check_headers\": {},\n  \"health_check_expected_body\": \"\",\n  \"health_check_expected_body_regex\": \"\",\n  \"health_check_interval_sec\": 15,\n  \"health_check_timeout_sec\": 2,\n  \"default_route\": null,\n  \"error_html_file\": \"\",\n  \"error_redirect_url\": \"\"\n}\n"

const apiGatewayBootstrapProxyRaw = `{
  "upstreams": [
    {
      "name": "api",
      "url": "http://api:8080",
      "weight": 1,
      "enabled": true
    }
  ],
  "routes": [
    {
      "name": "protected-host",
      "enabled": true,
      "priority": 10,
      "match": {
        "hosts": ["protected.example.test"],
        "path": { "type": "prefix", "value": "/v1/" }
      },
      "action": {
        "upstream": "api",
        "request_headers": {
          "add": { "X-Protected-Host": "matched" }
        }
      }
    }
  ],
  "default_route": {
    "name": "default",
    "enabled": true,
    "action": { "upstream": "api" }
  },
  "dial_timeout": 5,
  "response_header_timeout": 10,
  "idle_conn_timeout": 90,
  "max_idle_conns": 100,
  "max_idle_conns_per_host": 100,
  "max_conns_per_host": 600,
  "force_http2": false,
  "disable_compression": false,
  "response_compression": {
    "enabled": false,
    "algorithms": ["gzip"],
    "min_bytes": 256,
    "mime_types": ["application/json", "text/*"]
  },
  "expect_continue_timeout": 1,
  "tls_insecure_skip_verify": false,
  "tls_client_cert": "",
  "tls_client_key": "",
  "buffer_request_body": false,
  "max_response_buffer_bytes": 0,
  "flush_interval_ms": 0,
  "health_check_path": "/v1/health",
  "health_check_interval_sec": 15,
  "health_check_timeout_sec": 2
}
`

const apiGatewayBootstrapCacheRulesRaw = `{
  "rules": [
    {
      "kind": "DENY",
      "match": {
        "type": "prefix",
        "value": "/v1/"
      },
      "methods": ["GET", "HEAD"],
      "ttl": 60
    },
    {
      "kind": "DENY",
      "match": {
        "type": "prefix",
        "value": "/tukuyomi-api/"
      },
      "methods": ["GET", "HEAD"],
      "ttl": 600
    }
  ]
}
`

const apiGatewayBootstrapRateLimitRaw = `{
  "default": {
    "enabled": true,
    "allowlist_ips": [],
    "allowlist_countries": [],
    "default_policy": {
      "enabled": true,
      "limit": 60,
      "window_seconds": 60,
      "burst": 10,
      "key_by": "ip",
      "action": {
        "status": 429,
        "retry_after_seconds": 60
      }
    },
    "rules": [
      {
        "name": "auth-login",
        "match_type": "exact",
        "match_value": "/v1/auth/login",
        "methods": ["POST"],
        "policy": {
          "enabled": true,
          "limit": 6,
          "window_seconds": 60,
          "burst": 0,
          "key_by": "ip",
          "action": {
            "status": 429,
            "retry_after_seconds": 60
          }
        }
      }
    ]
  },
  "hosts": {}
}
`

const apiGatewayBootstrapBotDefenseRaw = `{
  "default": {
    "enabled": true,
    "dry_run": false,
    "mode": "suspicious",
    "path_prefixes": ["/v1/"],
    "path_policies": [],
    "exempt_cidrs": [
      "127.0.0.1/32",
      "::1/128",
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16",
      "fc00::/7"
    ],
    "suspicious_user_agents": [
      "curl",
      "wget",
      "python-requests",
      "python-urllib",
      "python-httpx",
      "go-http-client",
      "aiohttp",
      "libwww-perl",
      "scrapy",
      "headless",
      "selenium",
      "puppeteer",
      "playwright",
      "sqlmap",
      "nikto",
      "nmap",
      "masscan"
    ],
    "challenge_cookie_name": "__tukuyomi_bot_ok",
    "challenge_secret": "",
    "challenge_ttl_seconds": 21600,
    "challenge_status_code": 429,
    "behavioral_detection": {
      "enabled": false,
      "window_seconds": 60,
      "burst_threshold": 12,
      "path_fanout_threshold": 6,
      "ua_churn_threshold": 4,
      "missing_cookie_threshold": 6,
      "score_threshold": 2,
      "risk_score_per_signal": 2
    },
    "browser_signals": {
      "enabled": false,
      "js_cookie_name": "__tukuyomi_bot_js",
      "score_threshold": 1,
      "risk_score_per_signal": 2
    },
    "device_signals": {
      "enabled": false,
      "require_time_zone": true,
      "require_platform": true,
      "require_hardware_concurrency": true,
      "check_mobile_touch": true,
      "invisible_html_injection": false,
      "invisible_max_body_bytes": 262144,
      "score_threshold": 2,
      "risk_score_per_signal": 2
    },
    "header_signals": {
      "enabled": false,
      "require_accept_language": true,
      "require_fetch_metadata": true,
      "require_client_hints": true,
      "require_upgrade_insecure_requests": true,
      "score_threshold": 2,
      "risk_score_per_signal": 2
    },
    "tls_signals": {
      "enabled": false,
      "require_sni": true,
      "require_alpn": true,
      "require_modern_tls": true,
      "score_threshold": 2,
      "risk_score_per_signal": 2
    },
    "quarantine": {
      "enabled": false,
      "threshold": 8,
      "strikes_required": 2,
      "strike_window_seconds": 300,
      "ttl_seconds": 900,
      "status_code": 403,
      "reputation_feedback_seconds": 0
    }
  },
  "hosts": {}
}
`

const apiGatewayBootstrapSemanticRaw = `{
  "default": {
    "enabled": true,
    "mode": "challenge",
    "exempt_path_prefixes": [
      "/tukuyomi-api",
      "/tukuyomi-ui",
      "/health",
      "/healthz",
      "/favicon.ico"
    ],
    "log_threshold": 6,
    "challenge_threshold": 8,
    "block_threshold": 12,
    "max_inspect_body": 16384
  },
  "hosts": {}
}
`

const nextJSBootstrapProxyRaw = `{
  "upstreams": [
    {
      "name": "nextjs",
      "url": "http://nextjs:3000",
      "weight": 1,
      "enabled": true
    }
  ],
  "dial_timeout": 5,
  "response_header_timeout": 10,
  "idle_conn_timeout": 90,
  "max_idle_conns": 100,
  "max_idle_conns_per_host": 100,
  "max_conns_per_host": 600,
  "force_http2": false,
  "disable_compression": false,
  "response_compression": {
    "enabled": false,
    "algorithms": ["gzip"],
    "min_bytes": 256,
    "mime_types": ["application/json", "text/*", "image/svg+xml"]
  },
  "expect_continue_timeout": 1,
  "tls_insecure_skip_verify": false,
  "tls_client_cert": "",
  "tls_client_key": "",
  "buffer_request_body": false,
  "max_response_buffer_bytes": 0,
  "flush_interval_ms": 0,
  "health_check_path": "/",
  "health_check_interval_sec": 15,
  "health_check_timeout_sec": 2
}
`

const nextJSBootstrapCacheRulesRaw = `{
  "rules": [
    {
      "kind": "ALLOW",
      "match": {
        "type": "prefix",
        "value": "/_next/static/"
      },
      "methods": ["GET", "HEAD"],
      "ttl": 600,
      "vary": ["Accept-Encoding"]
    },
    {
      "kind": "ALLOW",
      "match": {
        "type": "prefix",
        "value": "/"
      },
      "methods": ["GET", "HEAD"],
      "ttl": 60,
      "vary": ["Accept-Encoding"]
    },
    {
      "kind": "DENY",
      "match": {
        "type": "prefix",
        "value": "/tukuyomi-api/"
      },
      "methods": ["GET", "HEAD"],
      "ttl": 600
    }
  ]
}
`

const nextJSBootstrapRateLimitRaw = `{
  "default": {
    "enabled": true,
    "allowlist_ips": [],
    "allowlist_countries": [],
    "default_policy": {
      "enabled": true,
      "limit": 120,
      "window_seconds": 60,
      "burst": 20,
      "key_by": "ip",
      "action": {
        "status": 429,
        "retry_after_seconds": 60
      }
    },
    "rules": [
      {
        "name": "auth-api",
        "match_type": "prefix",
        "match_value": "/api/auth",
        "methods": ["POST"],
        "policy": {
          "enabled": true,
          "limit": 15,
          "window_seconds": 60,
          "burst": 5,
          "key_by": "ip",
          "action": {
            "status": 429,
            "retry_after_seconds": 60
          }
        }
      }
    ]
  },
  "hosts": {}
}
`

const nextJSBootstrapSemanticRaw = `{
  "default": {
    "enabled": true,
    "mode": "log_only",
    "exempt_path_prefixes": [
      "/tukuyomi-api",
      "/tukuyomi-ui",
      "/health",
      "/healthz",
      "/metrics",
      "/favicon.ico",
      "/_next/",
      "/assets/",
      "/static/"
    ],
    "log_threshold": 7,
    "challenge_threshold": 10,
    "block_threshold": 13,
    "max_inspect_body": 8192
  },
  "hosts": {}
}
`

const wordPressBootstrapProxyRaw = `{
  "upstreams": [
    {
      "name": "wordpress",
      "url": "http://wordpress:80",
      "weight": 1,
      "enabled": true
    }
  ],
  "dial_timeout": 5,
  "response_header_timeout": 10,
  "idle_conn_timeout": 90,
  "max_idle_conns": 100,
  "max_idle_conns_per_host": 100,
  "max_conns_per_host": 600,
  "force_http2": false,
  "disable_compression": false,
  "response_compression": {
    "enabled": false,
    "algorithms": ["gzip"],
    "min_bytes": 256,
    "mime_types": ["application/json", "text/*", "application/xml"]
  },
  "expect_continue_timeout": 1,
  "tls_insecure_skip_verify": false,
  "tls_client_cert": "",
  "tls_client_key": "",
  "buffer_request_body": false,
  "max_response_buffer_bytes": 0,
  "flush_interval_ms": 0,
  "health_check_path": "/",
  "health_check_interval_sec": 15,
  "health_check_timeout_sec": 2
}
`

const wordPressBootstrapCacheRulesRaw = `{
  "rules": [
    {
      "kind": "ALLOW",
      "match": {
        "type": "prefix",
        "value": "/wp-content/uploads/"
      },
      "methods": ["GET", "HEAD"],
      "ttl": 300,
      "vary": ["Accept-Encoding"]
    },
    {
      "kind": "DENY",
      "match": {
        "type": "prefix",
        "value": "/wp-admin/"
      },
      "methods": ["GET", "HEAD"],
      "ttl": 60
    },
    {
      "kind": "DENY",
      "match": {
        "type": "exact",
        "value": "/wp-login.php"
      },
      "methods": ["GET", "HEAD"],
      "ttl": 60
    },
    {
      "kind": "DENY",
      "match": {
        "type": "prefix",
        "value": "/tukuyomi-api/"
      },
      "methods": ["GET", "HEAD"],
      "ttl": 600
    }
  ]
}
`

const wordPressBootstrapRateLimitRaw = `{
  "default": {
    "enabled": true,
    "allowlist_ips": [],
    "allowlist_countries": [],
    "default_policy": {
      "enabled": true,
      "limit": 80,
      "window_seconds": 60,
      "burst": 10,
      "key_by": "ip",
      "action": {
        "status": 429,
        "retry_after_seconds": 60
      }
    },
    "rules": [
      {
        "name": "wp-login",
        "match_type": "exact",
        "match_value": "/wp-login.php",
        "methods": ["POST"],
        "policy": {
          "enabled": true,
          "limit": 8,
          "window_seconds": 60,
          "burst": 0,
          "key_by": "ip",
          "action": {
            "status": 429,
            "retry_after_seconds": 60
          }
        }
      }
    ]
  },
  "hosts": {}
}
`

const wordPressBootstrapSemanticRaw = `{
  "default": {
    "enabled": true,
    "mode": "log_only",
    "exempt_path_prefixes": [
      "/tukuyomi-api",
      "/tukuyomi-ui",
      "/health",
      "/healthz",
      "/favicon.ico",
      "/wp-admin/",
      "/wp-content/",
      "/wp-includes/"
    ],
    "log_threshold": 7,
    "challenge_threshold": 10,
    "block_threshold": 13,
    "max_inspect_body": 8192
  },
  "hosts": {}
}
`

const wordPressBootstrapBypassRaw = `{
  "default": {
    "entries": [
      {
        "path": "/wp-admin/admin-ajax.php"
      }
    ]
  }
}
`

const releaseBinaryBootstrapProxyRaw = `{
  "upstreams": [
    {
      "name": "protected-api",
      "url": "http://protected-api:8080",
      "weight": 1,
      "enabled": true
    }
  ],
  "routes": [
    {
      "name": "protected-host",
      "enabled": true,
      "priority": 10,
      "match": {
        "hosts": ["protected.example.test"],
        "path": { "type": "prefix", "value": "/v1/" }
      },
      "action": {
        "upstream": "protected-api",
        "request_headers": {
          "add": { "X-Protected-Host": "matched" }
        }
      }
    }
  ],
  "default_route": {
    "name": "default",
    "enabled": true,
    "action": { "upstream": "protected-api" }
  },
  "dial_timeout": 5,
  "response_header_timeout": 10,
  "idle_conn_timeout": 90,
  "max_idle_conns": 100,
  "max_idle_conns_per_host": 100,
  "max_conns_per_host": 600,
  "force_http2": false,
  "disable_compression": false,
  "response_compression": {
    "enabled": true,
    "algorithms": ["zstd", "br", "gzip"],
    "min_bytes": 1,
    "mime_types": ["application/json", "text/*"]
  },
  "expect_continue_timeout": 1,
  "tls_insecure_skip_verify": false,
  "tls_client_cert": "",
  "tls_client_key": "",
  "buffer_request_body": false,
  "max_response_buffer_bytes": 1048576,
  "flush_interval_ms": 0,
  "health_check_path": "",
  "health_check_interval_sec": 15,
  "health_check_timeout_sec": 2
}
`

func currentStartupBootstrapProfile() startupBootstrapProfile {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(startupBootstrapProfileEnv))) {
	case "":
		return startupBootstrapProfileNone
	case string(startupBootstrapProfileMinimal):
		return startupBootstrapProfileMinimal
	case string(startupBootstrapProfileAPIGateway):
		return startupBootstrapProfileAPIGateway
	case string(startupBootstrapProfileNextJS):
		return startupBootstrapProfileNextJS
	case string(startupBootstrapProfileWordPress):
		return startupBootstrapProfileWordPress
	case string(startupBootstrapProfileReleaseBinary):
		return startupBootstrapProfileReleaseBinary
	default:
		return startupBootstrapProfileNone
	}
}

func startupBootstrapProfileSpecFor(profile startupBootstrapProfile) (startupBootstrapProfileSpec, bool) {
	switch profile {
	case startupBootstrapProfileAPIGateway:
		return startupBootstrapProfileSpec{
			ProxyRaw: apiGatewayBootstrapProxyRaw,
			PolicyRaw: map[string]string{
				cacheConfigBlobKey:      apiGatewayBootstrapCacheRulesRaw,
				rateLimitConfigBlobKey:  apiGatewayBootstrapRateLimitRaw,
				botDefenseConfigBlobKey: apiGatewayBootstrapBotDefenseRaw,
				semanticConfigBlobKey:   apiGatewayBootstrapSemanticRaw,
			},
		}, true
	case startupBootstrapProfileNextJS:
		return startupBootstrapProfileSpec{
			ProxyRaw: nextJSBootstrapProxyRaw,
			PolicyRaw: map[string]string{
				cacheConfigBlobKey:     nextJSBootstrapCacheRulesRaw,
				rateLimitConfigBlobKey: nextJSBootstrapRateLimitRaw,
				semanticConfigBlobKey:  nextJSBootstrapSemanticRaw,
			},
		}, true
	case startupBootstrapProfileWordPress:
		return startupBootstrapProfileSpec{
			ProxyRaw: wordPressBootstrapProxyRaw,
			PolicyRaw: map[string]string{
				cacheConfigBlobKey:     wordPressBootstrapCacheRulesRaw,
				bypassConfigBlobKey:    wordPressBootstrapBypassRaw,
				rateLimitConfigBlobKey: wordPressBootstrapRateLimitRaw,
				semanticConfigBlobKey:  wordPressBootstrapSemanticRaw,
			},
		}, true
	case startupBootstrapProfileReleaseBinary:
		return startupBootstrapProfileSpec{ProxyRaw: releaseBinaryBootstrapProxyRaw}, true
	case startupBootstrapProfileMinimal:
		return startupBootstrapProfileSpec{ProxyRaw: minimalPresetProxySeedRaw}, true
	default:
		return startupBootstrapProfileSpec{}, false
	}
}

func startupProxySeedRaw(path string, raw []byte, hadFile bool) string {
	if hadFile && strings.TrimSpace(string(raw)) != "" {
		return string(raw)
	}
	if spec, ok := startupBootstrapProfileSpecFor(currentStartupBootstrapProfile()); ok && strings.TrimSpace(spec.ProxyRaw) != "" {
		return spec.ProxyRaw
	}
	switch {
	case hasStartupSeedPathSuffix(path, "conf/proxy.json"), hasStartupSeedPathSuffix(path, "seed/proxy.json"):
		return minimalPresetProxySeedRaw
	default:
		return string(raw)
	}
}

func startupPolicySeedRaw(domain string, raw []byte, hadFile bool) (string, error) {
	if hadFile && strings.TrimSpace(string(raw)) != "" {
		return string(raw), nil
	}
	if spec, ok := startupBootstrapProfileSpecFor(currentStartupBootstrapProfile()); ok {
		if override, found := spec.PolicyRaw[domain]; found {
			return override, nil
		}
		return startupDefaultPolicySeedRaw(domain)
	}
	return string(raw), nil
}

func startupDefaultPolicySeedRaw(domain string) (string, error) {
	switch domain {
	case cacheConfigBlobKey:
		return string(mustCacheRulesJSON(&cacheconf.Ruleset{})), nil
	case bypassConfigBlobKey:
		raw, err := bypassconf.MarshalJSON(bypassconf.File{Default: bypassconf.Scope{Entries: []bypassconf.Entry{}}})
		if err != nil {
			return "", err
		}
		return string(raw), nil
	case countryBlockConfigBlobKey:
		raw, err := defaultCountryBlockPolicyRaw()
		if err != nil {
			return "", err
		}
		return string(raw), nil
	case rateLimitConfigBlobKey:
		return defaultRateLimitPolicyRaw(), nil
	case botDefenseConfigBlobKey:
		return defaultBotDefensePolicyRaw(), nil
	case semanticConfigBlobKey:
		return defaultSemanticPolicyRaw(), nil
	case notificationConfigBlobKey:
		return defaultNotificationPolicyRaw(), nil
	case ipReputationConfigBlobKey:
		return defaultIPReputationPolicyRaw(), nil
	default:
		return "", fmt.Errorf("unsupported startup policy domain %q", domain)
	}
}
