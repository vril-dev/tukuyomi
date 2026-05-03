package center

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

var defaultCenterManageAPIAllowCIDRs = []string{
	"127.0.0.0/8",
	"::1/128",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
}

type centerSourceAllowlists struct {
	Client    []netip.Prefix
	ManageAPI []netip.Prefix
	CenterAPI []netip.Prefix
}

func parseCenterSourceCIDREnv(name string, fallback []string) ([]string, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return normalizeCenterSourceCIDRStrings(name, fallback)
	}
	return normalizeCenterSourceCIDRStrings(name, splitCenterSourceCIDRList(raw))
}

func splitCenterSourceCIDRList(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		switch r {
		case ',', '\n', '\r', '\t', ' ':
			return true
		default:
			return false
		}
	})
}

func defaultCenterManageAPIAllowCIDRStrings() []string {
	return append([]string(nil), defaultCenterManageAPIAllowCIDRs...)
}

func normalizeCenterSourceCIDRStrings(field string, in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for i, raw := range in {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		prefix, err := parseCenterSourcePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", field, i, err)
		}
		normalized := prefix.String()
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func parseCenterSourcePrefix(raw string) (netip.Prefix, error) {
	value := strings.TrimSpace(raw)
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", raw)
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP or CIDR %q", raw)
	}
	addr = addr.Unmap()
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(addr, bits), nil
}

func compileCenterSourceAllowlists(cfg RuntimeConfig) (centerSourceAllowlists, error) {
	client, err := compileCenterSourceAllowlist("client_allow_cidrs", cfg.ClientAllowCIDRs, nil)
	if err != nil {
		return centerSourceAllowlists{}, err
	}
	manageAPI, err := compileCenterSourceAllowlist("manage_api_allow_cidrs", cfg.ManageAPIAllowCIDRs, defaultCenterManageAPIAllowCIDRs)
	if err != nil {
		return centerSourceAllowlists{}, err
	}
	centerAPI, err := compileCenterSourceAllowlist("center_api_allow_cidrs", cfg.CenterAPIAllowCIDRs, nil)
	if err != nil {
		return centerSourceAllowlists{}, err
	}
	return centerSourceAllowlists{
		Client:    client,
		ManageAPI: manageAPI,
		CenterAPI: centerAPI,
	}, nil
}

func compileCenterSourceAllowlist(field string, cidrs []string, fallback []string) ([]netip.Prefix, error) {
	normalized, err := normalizeCenterSourceCIDRStrings(field, cidrs)
	if err != nil {
		return nil, err
	}
	if len(normalized) == 0 && len(cidrs) == 0 && len(fallback) > 0 {
		normalized, err = normalizeCenterSourceCIDRStrings(field, fallback)
		if err != nil {
			return nil, err
		}
	}
	out := make([]netip.Prefix, 0, len(normalized))
	for _, raw := range normalized {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid CIDR %q", field, raw)
		}
		out = append(out, prefix.Masked())
	}
	return out, nil
}

func centerSourceAllowlistMiddleware(apiBase, uiBase string, allowlists centerSourceAllowlists) gin.HandlerFunc {
	return func(c *gin.Context) {
		prefixes, scoped := centerSourceAllowlistForPath(c.Request.URL.Path, apiBase, uiBase, allowlists)
		if scoped && !centerSourceAllowed(c.Request, prefixes) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "source ip forbidden"})
			return
		}
		c.Next()
	}
}

func centerSourceAllowlistForPath(requestPath, apiBase, uiBase string, allowlists centerSourceAllowlists) ([]netip.Prefix, bool) {
	switch {
	case centerPathHasPrefix(requestPath, apiBase):
		return allowlists.ManageAPI, true
	case centerPathHasPrefix(requestPath, uiBase):
		return allowlists.Client, true
	case centerPathHasPrefix(requestPath, "/v1"):
		return allowlists.CenterAPI, true
	default:
		return nil, false
	}
}

func centerPathHasPrefix(requestPath, base string) bool {
	requestPath = strings.TrimSpace(requestPath)
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if requestPath == "" || base == "" {
		return false
	}
	return requestPath == base || strings.HasPrefix(requestPath, base+"/")
}

func centerSourceAllowed(r *http.Request, prefixes []netip.Prefix) bool {
	if len(prefixes) == 0 {
		return true
	}
	source, ok := centerRequestSourceIP(r)
	if !ok {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(source) {
			return true
		}
	}
	return false
}

func centerRequestSourceIP(r *http.Request) (netip.Addr, bool) {
	if r == nil {
		return netip.Addr{}, false
	}
	host := strings.TrimSpace(r.RemoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if idx := strings.IndexByte(host, '%'); idx >= 0 {
		host = host[:idx]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}
