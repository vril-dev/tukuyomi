package handler

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const maxVhostRewritePasses = 8

type vhostRequestControlResult struct {
	RequestPath string
	Query       string
	Response    *http.Response
}

func applyVhostRequestControls(r *http.Request, vhost VhostConfig, requestPath string, rawQuery string) (vhostRequestControlResult, error) {
	requestPath = normalizeVhostRequestPath(requestPath)
	rawQuery = strings.TrimPrefix(strings.TrimSpace(rawQuery), "?")

	if resp, handled, err := evaluateVhostAccessControl(r, vhost, requestPath); err != nil {
		return vhostRequestControlResult{}, err
	} else if handled {
		if resp != nil {
			return vhostRequestControlResult{Response: resp}, nil
		}
		return vhostRequestControlResult{
			RequestPath: requestPath,
			Query:       rawQuery,
		}, nil
	}

	nextPath, nextQuery, resp, err := applyVhostRewriteRules(requestPath, rawQuery, vhost.RewriteRules)
	if err != nil {
		return vhostRequestControlResult{}, err
	}
	if resp != nil {
		return vhostRequestControlResult{Response: resp}, nil
	}
	return vhostRequestControlResult{
		RequestPath: nextPath,
		Query:       nextQuery,
	}, nil
}

func evaluateVhostAccessControl(r *http.Request, vhost VhostConfig, requestPath string) (*http.Response, bool, error) {
	requestPath = normalizeVhostRequestPath(requestPath)
	clientIP, ok := vhostRemoteAddr(r)
	for _, rule := range vhost.AccessRules {
		if !vhostAccessRuleMatchesPath(rule.PathPattern, requestPath) {
			continue
		}
		if rule.Action == "allow" {
			if len(rule.CIDRs) > 0 && (!ok || !vhostCIDRMatch(rule.CIDRs, clientIP)) {
				return buildDirectStatusResponse(r, http.StatusForbidden), true, nil
			}
			if rule.BasicAuth != nil {
				resp, err := enforceVhostBasicAuth(r, rule.BasicAuth)
				if err != nil {
					return nil, true, err
				}
				if resp != nil {
					return resp, true, nil
				}
			}
			return nil, true, nil
		}
		if rule.Action == "deny" {
			if len(rule.CIDRs) == 0 || (ok && vhostCIDRMatch(rule.CIDRs, clientIP)) {
				return buildDirectStatusResponse(r, http.StatusForbidden), true, nil
			}
		}
	}
	if vhost.BasicAuth != nil {
		resp, err := enforceVhostBasicAuth(r, vhost.BasicAuth)
		if err != nil {
			return nil, true, err
		}
		if resp != nil {
			return resp, true, nil
		}
	}
	return nil, false, nil
}

func applyVhostRewriteRules(requestPath string, rawQuery string, rules []VhostRewriteRule) (string, string, *http.Response, error) {
	requestPath = normalizeVhostRequestPath(requestPath)
	rawQuery = strings.TrimPrefix(strings.TrimSpace(rawQuery), "?")
	if len(rules) == 0 {
		return requestPath, rawQuery, nil, nil
	}
	currentPath := requestPath
	currentQuery := rawQuery
	for pass := 0; pass < maxVhostRewritePasses; pass++ {
		restart := false
		matched := false
		for _, rule := range rules {
			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return "", "", nil, err
			}
			if !re.MatchString(currentPath) {
				continue
			}
			matched = true
			rewritten := re.ReplaceAllString(currentPath, rule.Replacement)
			nextPath, nextQuery := splitVhostRewriteResult(rewritten, currentQuery, rule.PreserveQuery)
			switch rule.Flag {
			case "redirect":
				return "", "", buildVhostRedirectResponse(nextPath, nextQuery, http.StatusFound), nil
			case "permanent":
				return "", "", buildVhostRedirectResponse(nextPath, nextQuery, http.StatusMovedPermanently), nil
			case "last":
				currentPath = nextPath
				currentQuery = nextQuery
				restart = true
			default:
				return nextPath, nextQuery, nil, nil
			}
			break
		}
		if !matched {
			return currentPath, currentQuery, nil, nil
		}
		if !restart {
			return currentPath, currentQuery, nil, nil
		}
	}
	return "", "", nil, fmt.Errorf("rewrite limit exceeded for %q", requestPath)
}

func splitVhostRewriteResult(rewritten string, originalQuery string, preserveQuery bool) (string, string) {
	pathPart := strings.TrimSpace(rewritten)
	replacementQuery := ""
	if idx := strings.Index(pathPart, "?"); idx >= 0 {
		replacementQuery = strings.TrimSpace(pathPart[idx+1:])
		pathPart = pathPart[:idx]
	}
	nextPath := normalizeVhostRequestPath(pathPart)
	switch {
	case replacementQuery != "" && preserveQuery:
		return nextPath, mergeVhostQueryStrings(replacementQuery, originalQuery)
	case replacementQuery != "":
		return nextPath, replacementQuery
	case preserveQuery:
		return nextPath, originalQuery
	default:
		return nextPath, ""
	}
}

func mergeVhostQueryStrings(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		next := strings.TrimPrefix(strings.TrimSpace(part), "?")
		if next == "" {
			continue
		}
		out = append(out, next)
	}
	return strings.Join(out, "&")
}

func vhostAccessRuleMatchesPath(pattern string, requestPath string) bool {
	pattern = normalizeVhostRequestPath(pattern)
	requestPath = normalizeVhostRequestPath(requestPath)
	if pattern == "/" {
		return true
	}
	return requestPath == pattern || strings.HasPrefix(requestPath, pattern+"/")
}

func vhostCIDRMatch(cidrs []string, addr netip.Addr) bool {
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func vhostRemoteAddr(r *http.Request) (netip.Addr, bool) {
	if r == nil {
		return netip.Addr{}, false
	}
	host := strings.TrimSpace(r.RemoteAddr)
	if host == "" {
		return netip.Addr{}, false
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

func enforceVhostBasicAuth(r *http.Request, auth *VhostBasicAuth) (*http.Response, error) {
	if auth == nil {
		return nil, nil
	}
	username, password, ok := r.BasicAuth()
	if !ok {
		return buildVhostUnauthorizedResponse(r, auth.Realm), nil
	}
	for _, user := range auth.Users {
		if user.Username != username {
			continue
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
			return buildVhostUnauthorizedResponse(r, auth.Realm), nil
		}
		return nil, nil
	}
	return buildVhostUnauthorizedResponse(r, auth.Realm), nil
}

func buildVhostUnauthorizedResponse(r *http.Request, realm string) *http.Response {
	escapedRealm := strings.ReplaceAll(strings.TrimSpace(realm), `"`, `\"`)
	if escapedRealm == "" {
		escapedRealm = "Restricted"
	}
	resp := buildDirectStatusResponse(r, http.StatusUnauthorized)
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	resp.Header.Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, escapedRealm))
	body := []byte("Unauthorized\n")
	resp.Body = ioNopCloserBytes(body, r)
	resp.ContentLength = int64(len(body))
	return resp
}

func buildVhostRedirectResponse(path string, rawQuery string, statusCode int) *http.Response {
	body := []byte(http.StatusText(statusCode) + "\n")
	location := requestURI(path, rawQuery)
	return &http.Response{
		StatusCode:    statusCode,
		Status:        fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Location": []string{location}, "Content-Type": []string{"text/plain; charset=utf-8"}},
		Body:          ioNopCloserBytes(body, nil),
		ContentLength: int64(len(body)),
	}
}

func ioNopCloserBytes(body []byte, r *http.Request) io.ReadCloser {
	if r != nil && r.Method == http.MethodHead {
		return io.NopCloser(bytes.NewReader(nil))
	}
	return io.NopCloser(bytes.NewReader(body))
}
