package requestmeta

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

const (
	HeaderXForwardedFor = "X-Forwarded-For"
	HeaderXRealIP       = "X-Real-IP"

	// maxForwardedForEntries bounds how many X-Forwarded-For entries are
	// read from the right. A chain longer than this is decided from its
	// rightmost entries.
	maxForwardedForEntries = 32
)

// TrustedProxies names the peers whose forwarded header may name the client
// and the one header they write, in the canonical spelling
// (NormalizeForwardedHeader); an empty Header means X-Forwarded-For. The zero
// value trusts no peer.
type TrustedProxies struct {
	Header   string
	Prefixes []netip.Prefix
}

// Enabled reports whether any peer is trusted.
func (t TrustedProxies) Enabled() bool {
	return len(t.Prefixes) > 0
}

func (t TrustedProxies) trusts(ip netip.Addr) bool {
	for _, prefix := range t.Prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// NormalizeForwardedHeader returns the canonical name of a supported
// forwarded header, X-Forwarded-For for an empty value, or "" for an
// unsupported name.
func NormalizeForwardedHeader(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "x-forwarded-for":
		return HeaderXForwardedFor
	case "x-real-ip":
		return HeaderXRealIP
	default:
		return ""
	}
}

// ClientAddr returns the client address of req. It is the peer address
// (the connection source, or the PROXY protocol source) unless the peer is
// a trusted proxy. For a trusted peer, X-Forwarded-For is read from the
// right: trusted entries are skipped and the first other entry is the
// client; when every entry is trusted, the leftmost one is. A missing header
// or an entry that is not an IP address gives the peer. Only the configured
// header is read, because a proxy that writes one header passes the client's
// copy of the other. ok is false when the peer address cannot be parsed.
func ClientAddr(req *http.Request, trust TrustedProxies) (addr netip.Addr, peerTrusted bool, ok bool) {
	if req == nil {
		return netip.Addr{}, false, false
	}
	peer, ok := PeerAddr(req.RemoteAddr)
	if !ok {
		return netip.Addr{}, false, false
	}
	if !trust.trusts(peer) {
		return peer, false, true
	}
	if trust.Header == HeaderXRealIP {
		values := req.Header.Values(HeaderXRealIP)
		if len(values) != 1 {
			return peer, true, true
		}
		if ip, ok := ParseForwardedAddr(values[0]); ok {
			return ip, true, true
		}
		return peer, true, true
	}
	return clientFromForwardedFor(req.Header.Values(HeaderXForwardedFor), peer, trust), true, true
}

// ClientIPFromRequest returns ClientAddr as a string. When the peer address
// cannot be parsed, it returns the host part of RemoteAddr as it is.
func ClientIPFromRequest(req *http.Request, trust TrustedProxies) (string, bool) {
	if req == nil {
		return "", false
	}
	addr, peerTrusted, ok := ClientAddr(req, trust)
	if !ok {
		host := strings.TrimSpace(req.RemoteAddr)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		return host, false
	}
	return addr.String(), peerTrusted
}

func clientFromForwardedFor(lines []string, peer netip.Addr, trust TrustedProxies) netip.Addr {
	var leftmost netip.Addr
	seen := 0
	for i := len(lines) - 1; i >= 0; i-- {
		rest := lines[i]
		for rest != "" {
			entry := rest
			rest = ""
			if j := strings.LastIndexByte(entry, ','); j >= 0 {
				entry, rest = entry[j+1:], entry[:j]
			}
			ip, ok := ParseForwardedAddr(entry)
			if !ok {
				return peer
			}
			if !trust.trusts(ip) {
				return ip
			}
			leftmost = ip
			seen++
			if seen >= maxForwardedForEntries {
				return leftmost
			}
		}
	}
	if !leftmost.IsValid() {
		return peer
	}
	return leftmost
}

// PeerAddr parses a RemoteAddr value.
func PeerAddr(remoteAddr string) (netip.Addr, bool) {
	host := strings.TrimSpace(remoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return parseIPLiteral(host)
}

// ParseForwardedAddr parses one forwarded entry: an IP address, IP:port,
// [IPv6] or [IPv6]:port. A zone is dropped and an IPv4-mapped IPv6 address
// is returned as IPv4.
func ParseForwardedAddr(raw string) (netip.Addr, bool) {
	value := strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(value, "["):
		if host, _, err := net.SplitHostPort(value); err == nil {
			value = host
		} else if strings.HasSuffix(value, "]") {
			value = value[1 : len(value)-1]
		} else {
			return netip.Addr{}, false
		}
	case strings.Count(value, ":") == 1:
		host, _, err := net.SplitHostPort(value)
		if err != nil {
			return netip.Addr{}, false
		}
		value = host
	}
	return parseIPLiteral(value)
}

func parseIPLiteral(raw string) (netip.Addr, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return netip.Addr{}, false
	}
	if idx := strings.IndexByte(value, '%'); idx >= 0 {
		value = value[:idx]
	}
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}
