package policyhost

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func NormalizePattern(raw string) (string, error) {
	host := strings.TrimSpace(strings.ToLower(raw))
	if host == "" {
		return "", fmt.Errorf("host is required")
	}
	if strings.Contains(host, "/") {
		return "", fmt.Errorf("host must not contain '/'")
	}
	if strings.Contains(host, "*") {
		return "", fmt.Errorf("wildcard host is not supported")
	}
	parsed, err := url.Parse("http://" + host)
	if err != nil || parsed.Hostname() == "" {
		return "", fmt.Errorf("host must be a valid host or host:port")
	}
	normalizedHost := strings.Trim(strings.ToLower(parsed.Hostname()), "[]")
	if normalizedHost == "" {
		return "", fmt.Errorf("host is required")
	}
	port := strings.TrimSpace(parsed.Port())
	if port == "" {
		return normalizedHost, nil
	}
	if _, err := validatePort(port); err != nil {
		return "", err
	}
	return net.JoinHostPort(normalizedHost, port), nil
}

func Candidates(raw string, tls bool) []string {
	normalized, err := NormalizePattern(raw)
	if err != nil || normalized == "" {
		return nil
	}
	host, port, hasPort := splitHostPort(normalized)
	out := make([]string, 0, 2)
	if hasPort {
		out = append(out, net.JoinHostPort(host, port))
	} else {
		if tls {
			out = append(out, net.JoinHostPort(host, "443"))
		} else {
			out = append(out, net.JoinHostPort(host, "80"))
		}
	}
	out = append(out, host)
	return unique(out)
}

func splitHostPort(normalized string) (string, string, bool) {
	if host, port, err := net.SplitHostPort(normalized); err == nil {
		return strings.Trim(strings.ToLower(host), "[]"), port, true
	}
	return strings.Trim(strings.ToLower(normalized), "[]"), "", false
}

func validatePort(raw string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("port must be numeric")
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port must be between 1 and 65535")
	}
	return port, nil
}

func unique(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		next := strings.TrimSpace(raw)
		if next == "" {
			continue
		}
		if _, ok := seen[next]; ok {
			continue
		}
		seen[next] = struct{}{}
		out = append(out, next)
	}
	return out
}
