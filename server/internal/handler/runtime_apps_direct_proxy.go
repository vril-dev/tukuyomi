package handler

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type vhostResolvedRequest struct {
	Kind           string
	StatusCode     int
	FilePath       string
	ScriptFilename string
	ScriptName     string
	PathInfo       string
	OriginalPath   string
	RequestPath    string
	Query          string
}

const directStaticResponseMarkerHeader = "X-Tukuyomi-Internal-Direct-Static"

var errVhostPathEscapesDocumentRoot = errors.New("runtime app path escapes document root")
var errVhostHiddenPathBlocked = errors.New("runtime app hidden path blocked")
var psgiDirectTransport = &http.Transport{
	Proxy:                 nil,
	DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	MaxIdleConns:          32,
	MaxIdleConnsPerHost:   8,
	IdleConnTimeout:       90 * time.Second,
	ResponseHeaderTimeout: 60 * time.Second,
}

func shouldServeDirectProxyTarget(target *url.URL) bool {
	if target == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(target.Scheme)) {
	case "fcgi", "psgi", "static":
		return true
	default:
		return false
	}
}

func serveDirectProxyTarget(w http.ResponseWriter, r *http.Request, decision proxyRouteDecision) error {
	defer releaseProxyRouteSelection(decision.TransportSelection)
	vhost, ok := proxyVhostForDecision(decision)
	if !ok {
		return fmt.Errorf("no Runtime App metadata found for selected upstream %q (%s)", decision.SelectedUpstream, decision.SelectedUpstreamURL)
	}
	resp, err := buildDirectVhostResponse(r, decision, vhost)
	if err != nil {
		return err
	}
	return writeDirectProxyResponse(w, r, resp)
}

func proxyVhostForDecision(decision proxyRouteDecision) (VhostConfig, bool) {
	cfg := currentVhostConfig()
	for _, vhost := range cfg.Vhosts {
		if vhost.GeneratedTarget != "" && vhost.GeneratedTarget == decision.SelectedUpstream {
			return vhost, true
		}
	}
	if decision.Target == nil {
		return VhostConfig{}, false
	}
	if shouldServeDirectProxyTarget(decision.Target) {
		for _, vhost := range cfg.Vhosts {
			if vhost.LinkedUpstreamName != "" && vhost.LinkedUpstreamName == decision.SelectedUpstream {
				return vhost, true
			}
		}
	}
	target := decision.Target
	if strings.EqualFold(target.Scheme, "fcgi") {
		host := strings.TrimSpace(target.Hostname())
		port, _ := strconv.Atoi(strings.TrimSpace(target.Port()))
		for _, vhost := range cfg.Vhosts {
			if normalizeVhostMode(vhost.Mode) != "php-fpm" {
				continue
			}
			if port > 0 && vhost.ListenPort == port && proxyTargetHostMatchesRuntime(host, vhost.Hostname) {
				return vhost, true
			}
			if vhost.GeneratedTarget != "" && target.Host == vhost.GeneratedTarget {
				return vhost, true
			}
			if host != "" && host == vhost.GeneratedTarget {
				return vhost, true
			}
		}
	}
	if strings.EqualFold(target.Scheme, "psgi") {
		host := strings.TrimSpace(target.Hostname())
		port, _ := strconv.Atoi(strings.TrimSpace(target.Port()))
		for _, vhost := range cfg.Vhosts {
			if normalizeVhostMode(vhost.Mode) != "psgi" {
				continue
			}
			if port > 0 && vhost.ListenPort == port && proxyTargetHostMatchesRuntime(host, vhost.Hostname) {
				return vhost, true
			}
			if vhost.GeneratedTarget != "" && target.Host == vhost.GeneratedTarget {
				return vhost, true
			}
			if host != "" && host == vhost.GeneratedTarget {
				return vhost, true
			}
		}
	}
	if strings.EqualFold(target.Scheme, "static") {
		for _, vhost := range cfg.Vhosts {
			if normalizeVhostMode(vhost.Mode) != "static" {
				continue
			}
			if target.Host == vhost.GeneratedTarget || decision.SelectedUpstream == vhost.GeneratedTarget {
				return vhost, true
			}
		}
	}
	return VhostConfig{}, false
}

func proxyTargetHostMatchesRuntime(targetHost string, listenHost string) bool {
	return normalizeRuntimeListenHost(targetHost) == normalizeRuntimeListenHost(listenHost)
}

func buildDirectVhostResponse(r *http.Request, decision proxyRouteDecision, vhost VhostConfig) (*http.Response, error) {
	requestPath := decision.RewrittenPath
	if requestPath == "" {
		requestPath = requestPathFromDecision(decision, r)
	}
	query := decision.RewrittenQuery
	if query == "" {
		query = requestQueryFromDecision(decision, r)
	}
	control, err := applyVhostRequestControls(r, vhost, requestPath, query)
	if err != nil {
		return nil, err
	}
	if control.Response != nil {
		return control.Response, nil
	}
	requestPath = control.RequestPath
	query = control.Query
	resolved, err := resolveVhostRequest(vhost, requestPath, query, r.Method)
	if err != nil {
		return nil, err
	}
	if resolved.OriginalPath == "" {
		resolved.OriginalPath = requestPath
	}
	switch resolved.Kind {
	case "static":
		return buildStaticVhostResponse(r, resolved)
	case "php":
		return buildFastCGIVhostResponse(r, decision.Target, vhost, resolved)
	case "psgi":
		return buildPSGIVhostResponse(r, vhost, resolved)
	case "status":
		return buildDirectStatusResponse(r, resolved.StatusCode), nil
	default:
		return nil, fmt.Errorf("unsupported Runtime App resolution kind %q", resolved.Kind)
	}
}

func requestPathFromDecision(decision proxyRouteDecision, r *http.Request) string {
	if strings.TrimSpace(decision.OriginalPath) != "" {
		return decision.OriginalPath
	}
	if r == nil || r.URL == nil {
		return "/"
	}
	return r.URL.Path
}

func requestQueryFromDecision(decision proxyRouteDecision, r *http.Request) string {
	if decision.RewrittenQuery != "" {
		return decision.RewrittenQuery
	}
	if strings.TrimSpace(decision.OriginalQuery) != "" {
		return decision.OriginalQuery
	}
	if r == nil || r.URL == nil {
		return ""
	}
	return r.URL.RawQuery
}

func resolveVhostRequest(vhost VhostConfig, requestPath string, rawQuery string, method string) (vhostResolvedRequest, error) {
	tryFiles := effectiveVhostTryFiles(vhost)
	for _, entry := range tryFiles {
		if strings.TrimSpace(entry) == "@psgi" && normalizeVhostMode(vhost.Mode) == "psgi" {
			return vhostResolvedRequest{
				Kind:         "psgi",
				RequestPath:  normalizeVhostRequestPath(requestPath),
				OriginalPath: requestPath,
				Query:        rawQuery,
			}, nil
		}
		candidatePath, candidateQuery := expandVhostTryFilesEntry(entry, requestPath, rawQuery)
		resolved, ok, err := resolveVhostTryFileCandidate(vhost, candidatePath, candidateQuery, method)
		if err != nil {
			return vhostResolvedRequest{}, err
		}
		if ok {
			return resolved, nil
		}
	}
	return vhostResolvedRequest{Kind: "status", StatusCode: http.StatusNotFound}, nil
}

func effectiveVhostTryFiles(vhost VhostConfig) []string {
	if len(vhost.TryFiles) > 0 {
		return append([]string(nil), vhost.TryFiles...)
	}
	switch normalizeVhostMode(vhost.Mode) {
	case "php-fpm":
		return []string{"$uri", "$uri/", "/index.php?$query_string"}
	case "psgi":
		return []string{"$uri", "$uri/", "@psgi"}
	default:
		return []string{"$uri", "$uri/", "/index.html"}
	}
}

func expandVhostTryFilesEntry(entry string, requestPath string, rawQuery string) (string, string) {
	pathPart := strings.TrimSpace(entry)
	queryPart := rawQuery
	if idx := strings.Index(pathPart, "?"); idx >= 0 {
		queryPart = pathPart[idx+1:]
		pathPart = pathPart[:idx]
	}
	if strings.TrimSpace(pathPart) == "@psgi" {
		queryPart = strings.ReplaceAll(queryPart, "$query_string", rawQuery)
		return "@psgi", strings.TrimPrefix(strings.TrimSpace(queryPart), "?")
	}
	pathPart = strings.ReplaceAll(pathPart, "$uri", normalizeVhostRequestPath(requestPath))
	queryPart = strings.ReplaceAll(queryPart, "$query_string", rawQuery)
	return normalizeVhostRequestPath(pathPart), strings.TrimPrefix(strings.TrimSpace(queryPart), "?")
}

func normalizeVhostRequestPath(in string) string {
	out := strings.TrimSpace(in)
	if out == "" {
		return "/"
	}
	if !strings.HasPrefix(out, "/") {
		out = "/" + out
	}
	return path.Clean(out)
}

func resolveVhostTryFileCandidate(vhost VhostConfig, candidatePath string, candidateQuery string, method string) (vhostResolvedRequest, bool, error) {
	if strings.TrimSpace(candidatePath) == "@psgi" {
		if normalizeVhostMode(vhost.Mode) != "psgi" {
			return vhostResolvedRequest{}, false, nil
		}
		return vhostResolvedRequest{
			Kind:        "psgi",
			RequestPath: "/",
			Query:       candidateQuery,
		}, true, nil
	}
	resolvedPath, info, err := resolveVhostFilesystemPath(vhost.DocumentRoot, candidatePath)
	if err != nil {
		if errors.Is(err, errVhostPathEscapesDocumentRoot) || errors.Is(err, errVhostHiddenPathBlocked) {
			return vhostResolvedRequest{Kind: "status", StatusCode: http.StatusNotFound}, true, nil
		}
		return vhostResolvedRequest{}, false, err
	}
	if info == nil {
		resolved := maybeResolvePathInfoPHP(vhost, candidatePath, candidateQuery)
		return resolved, resolved.Kind != "", nil
	}
	if info.IsDir() {
		indexPath, ok, err := resolveVhostDirectoryIndex(vhost, candidatePath)
		if err != nil {
			return vhostResolvedRequest{}, false, err
		}
		if !ok {
			return vhostResolvedRequest{}, false, nil
		}
		return resolveVhostTryFileCandidate(vhost, indexPath, candidateQuery, method)
	}
	if normalizeVhostMode(vhost.Mode) == "php-fpm" && strings.HasSuffix(strings.ToLower(resolvedPath), ".php") {
		return vhostResolvedRequest{
			Kind:           "php",
			FilePath:       resolvedPath,
			ScriptFilename: resolvedPath,
			ScriptName:     candidatePath,
			RequestPath:    candidatePath,
			Query:          candidateQuery,
		}, true, nil
	}
	if method != http.MethodGet && method != http.MethodHead {
		return vhostResolvedRequest{Kind: "status", StatusCode: http.StatusMethodNotAllowed}, true, nil
	}
	return vhostResolvedRequest{
		Kind:        "static",
		FilePath:    resolvedPath,
		RequestPath: candidatePath,
		Query:       candidateQuery,
	}, true, nil
}

func maybeResolvePathInfoPHP(vhost VhostConfig, candidatePath string, candidateQuery string) vhostResolvedRequest {
	if normalizeVhostMode(vhost.Mode) != "php-fpm" {
		return vhostResolvedRequest{}
	}
	scriptName, scriptFilename, pathInfo, ok := resolveVhostPHPPathInfo(vhost.DocumentRoot, candidatePath)
	if !ok {
		return vhostResolvedRequest{}
	}
	return vhostResolvedRequest{
		Kind:           "php",
		FilePath:       scriptFilename,
		ScriptFilename: scriptFilename,
		ScriptName:     scriptName,
		PathInfo:       pathInfo,
		RequestPath:    candidatePath,
		Query:          candidateQuery,
	}
}

func resolveVhostDirectoryIndex(vhost VhostConfig, candidatePath string) (string, bool, error) {
	indices := []string{"index.html", "index.htm"}
	if normalizeVhostMode(vhost.Mode) == "php-fpm" {
		indices = append(indices, "index.php")
	}
	base := normalizeVhostRequestPath(candidatePath)
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	for _, name := range indices {
		next := path.Join(base, name)
		resolvedPath, info, err := resolveVhostFilesystemPath(vhost.DocumentRoot, next)
		if err != nil {
			if errors.Is(err, errVhostPathEscapesDocumentRoot) || errors.Is(err, errVhostHiddenPathBlocked) {
				continue
			}
			return "", false, err
		}
		if info != nil && !info.IsDir() && resolvedPath != "" {
			return next, true, nil
		}
	}
	return "", false, nil
}

func resolveVhostFilesystemPath(documentRoot string, requestPath string) (string, os.FileInfo, error) {
	documentRootAbs, err := filepath.Abs(strings.TrimSpace(documentRoot))
	if err != nil {
		return "", nil, err
	}
	documentRootReal, err := filepath.EvalSymlinks(documentRootAbs)
	if err != nil {
		return "", nil, err
	}
	cleanPath := normalizeVhostRequestPath(requestPath)
	if err := validateVhostVisiblePath(cleanPath); err != nil {
		return "", nil, err
	}
	joined := filepath.Join(documentRootAbs, filepath.FromSlash(strings.TrimPrefix(cleanPath, "/")))
	rel, err := filepath.Rel(documentRootAbs, joined)
	if err != nil {
		return "", nil, err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", nil, fmt.Errorf("%w for %q", errVhostPathEscapesDocumentRoot, requestPath)
	}
	info, err := os.Lstat(joined)
	if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
		return joined, nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	resolvedPath, err := filepath.EvalSymlinks(joined)
	if err != nil {
		return "", nil, err
	}
	resolvedRel, err := filepath.Rel(documentRootReal, resolvedPath)
	if err != nil {
		return "", nil, err
	}
	if resolvedRel == ".." || strings.HasPrefix(resolvedRel, ".."+string(filepath.Separator)) {
		return "", nil, fmt.Errorf("%w for %q", errVhostPathEscapesDocumentRoot, requestPath)
	}
	info, err = os.Stat(resolvedPath)
	if err != nil {
		return "", nil, err
	}
	return resolvedPath, info, nil
}

func validateVhostVisiblePath(cleanPath string) error {
	for _, segment := range strings.Split(strings.TrimPrefix(cleanPath, "/"), "/") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		if !strings.HasPrefix(segment, ".") {
			continue
		}
		if segment == ".well-known" {
			continue
		}
		return fmt.Errorf("%w for %q", errVhostHiddenPathBlocked, cleanPath)
	}
	return nil
}

func resolveVhostPHPPathInfo(documentRoot string, requestPath string) (string, string, string, bool) {
	clean := normalizeVhostRequestPath(requestPath)
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	for i := len(parts); i > 0; i-- {
		scriptName := "/" + strings.Join(parts[:i], "/")
		if !strings.HasSuffix(strings.ToLower(scriptName), ".php") {
			continue
		}
		resolvedPath, info, err := resolveVhostFilesystemPath(documentRoot, scriptName)
		if err != nil || info == nil || info.IsDir() {
			continue
		}
		pathInfo := ""
		if i < len(parts) {
			pathInfo = "/" + strings.Join(parts[i:], "/")
		}
		return scriptName, resolvedPath, pathInfo, true
	}
	return "", "", "", false
}

func buildPSGIVhostResponse(r *http.Request, vhost VhostConfig, resolved vhostResolvedRequest) (*http.Response, error) {
	if r == nil {
		return nil, fmt.Errorf("request is nil")
	}
	if vhost.ListenPort < 1 || vhost.ListenPort > 65535 {
		return nil, fmt.Errorf("Runtime App %q listen_port is invalid", vhost.Name)
	}
	targetURL := &url.URL{
		Scheme:   "http",
		Host:     runtimeListenEndpoint(vhost.Hostname, vhost.ListenPort),
		Path:     normalizeVhostRequestPath(resolved.RequestPath),
		RawQuery: strings.TrimPrefix(strings.TrimSpace(resolved.Query), "?"),
	}
	outReq := cloneTukuyomiProxyOutboundRequest(r)
	if outReq == nil {
		return nil, fmt.Errorf("request clone failed")
	}
	outReq.URL = targetURL
	outReq.RequestURI = ""
	outReq.Close = false
	if outReq.Body == nil {
		outReq.Body = http.NoBody
	}
	outReq.Host = r.Host
	removeProxyHopByHopHeaders(outReq.Header)
	setTukuyomiProxyXForwarded(outReq.Header, r)
	if _, ok := outReq.Header["User-Agent"]; !ok {
		outReq.Header.Set("User-Agent", "")
	}
	resp, err := psgiDirectTransport.RoundTrip(outReq)
	if err != nil {
		return nil, err
	}
	removeProxyHopByHopHeaders(resp.Header)
	resp.Request = r
	return resp, nil
}

func buildStaticVhostResponse(r *http.Request, resolved vhostResolvedRequest) (*http.Response, error) {
	file, err := os.Open(resolved.FilePath)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if info.IsDir() {
		_ = file.Close()
		return nil, fmt.Errorf("static path %q is a directory", resolved.FilePath)
	}
	contentType, err := detectStaticVhostContentType(file, resolved.FilePath)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	modTime := info.ModTime().UTC().Truncate(time.Second)
	etag := buildStaticVhostETag(info)
	statusCode := http.StatusOK
	body := io.ReadCloser(file)
	contentLength := info.Size()
	header := http.Header{
		"Content-Type":                   []string{contentType},
		"Cache-Control":                  []string{"public, max-age=0, must-revalidate"},
		"X-Content-Type-Options":         []string{"nosniff"},
		directStaticResponseMarkerHeader: []string{"1"},
	}
	header.Set("ETag", etag)
	if !modTime.IsZero() {
		header.Set("Last-Modified", modTime.Format(http.TimeFormat))
	}
	if shouldReturnNotModifiedForStatic(r, etag, modTime) {
		statusCode = http.StatusNotModified
		contentLength = 0
		_ = file.Close()
		body = io.NopCloser(bytes.NewReader(nil))
	} else {
		header.Set("Content-Length", strconv.FormatInt(contentLength, 10))
	}
	return &http.Response{
		StatusCode:    statusCode,
		Status:        fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          body,
		ContentLength: contentLength,
		Request:       r,
	}, nil
}

func detectStaticVhostContentType(file *os.File, filePath string) (string, error) {
	contentType := mime.TypeByExtension(strings.ToLower(filepath.Ext(filePath)))
	if contentType != "" {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return "", err
		}
		return contentType, nil
	}
	var sniff [512]byte
	n, err := file.Read(sniff[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	return http.DetectContentType(sniff[:n]), nil
}

func buildStaticVhostETag(info os.FileInfo) string {
	return fmt.Sprintf(`W/"%x-%x"`, info.Size(), info.ModTime().UTC().UnixNano())
}

func shouldReturnNotModifiedForStatic(r *http.Request, etag string, modTime time.Time) bool {
	if r == nil {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if staticIfNoneMatchMatches(r.Header.Get("If-None-Match"), etag) {
		return true
	}
	if strings.TrimSpace(r.Header.Get("If-None-Match")) != "" {
		return false
	}
	rawIMS := strings.TrimSpace(r.Header.Get("If-Modified-Since"))
	if rawIMS == "" || modTime.IsZero() {
		return false
	}
	ims, err := http.ParseTime(rawIMS)
	if err != nil {
		return false
	}
	return !modTime.After(ims.Add(time.Second))
}

func staticIfNoneMatchMatches(raw string, etag string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	for _, token := range strings.Split(raw, ",") {
		next := textproto.TrimString(token)
		if next == "*" {
			return true
		}
		if weakETagEqual(next, etag) {
			return true
		}
	}
	return false
}

func weakETagEqual(a string, b string) bool {
	return stripWeakETag(a) == stripWeakETag(b)
}

func stripWeakETag(in string) string {
	out := textproto.TrimString(in)
	if strings.HasPrefix(out, "W/") || strings.HasPrefix(out, "w/") {
		out = textproto.TrimString(out[2:])
	}
	return out
}

func isDirectStaticResponse(res *http.Response) bool {
	if res == nil || res.Header == nil {
		return false
	}
	return strings.TrimSpace(res.Header.Get(directStaticResponseMarkerHeader)) == "1"
}

func buildDirectStatusResponse(r *http.Request, statusCode int) *http.Response {
	body := []byte(http.StatusText(statusCode) + "\n")
	respBody := io.NopCloser(bytes.NewReader(body))
	if r != nil && r.Method == http.MethodHead {
		respBody = io.NopCloser(bytes.NewReader(nil))
	}
	header := http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}}
	if statusCode == http.StatusMethodNotAllowed {
		header.Set("Allow", "GET, HEAD")
	}
	return &http.Response{
		StatusCode:    statusCode,
		Status:        fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          respBody,
		ContentLength: int64(len(body)),
		Request:       r,
	}
}

func vhostLogMessage(message string) string {
	message = strings.TrimSpace(message)
	if len(message) <= 2048 {
		return message
	}
	return message[:2048] + "...[truncated]"
}

func buildFastCGIVhostResponse(r *http.Request, target *url.URL, vhost VhostConfig, resolved vhostResolvedRequest) (*http.Response, error) {
	if target == nil {
		return nil, fmt.Errorf("fcgi target is required")
	}
	params, body, err := buildFastCGIRequest(r, vhost, resolved)
	if err != nil {
		return nil, err
	}
	stdout, stderr, err := executeFastCGIRequest(r.Context(), target, params, body)
	if err != nil {
		return nil, fmt.Errorf("fastcgi execute: %w", err)
	}
	if len(stderr) > 0 {
		log.Printf("[RUNTIME_APP][PHP][ERROR] fastcgi stderr app=%q script=%q err=%s", vhost.Name, resolved.ScriptName, vhostLogMessage(string(stderr)))
	}
	if len(stdout) == 0 {
		return buildDirectStatusResponse(r, http.StatusInternalServerError), nil
	}
	resp, err := parseFastCGIHTTPResponse(stdout, r)
	if err != nil {
		log.Printf("[RUNTIME_APP][PHP][ERROR] fastcgi response parse failed app=%q script=%q err=%s", vhost.Name, resolved.ScriptName, vhostLogMessage(err.Error()))
		return buildDirectStatusResponse(r, http.StatusInternalServerError), nil
	}
	return resp, nil
}

func buildFastCGIRequest(r *http.Request, vhost VhostConfig, resolved vhostResolvedRequest) (map[string]string, []byte, error) {
	body := []byte(nil)
	if r != nil && r.Body != nil {
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			return nil, nil, err
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	serverName, serverPort := fastCGIServerIdentity(r, vhost)
	remoteAddr, remotePort := fastCGIRemoteIdentity(r)
	requestPath := resolved.RequestPath
	if strings.TrimSpace(resolved.OriginalPath) != "" {
		requestPath = resolved.OriginalPath
	}
	if requestPath == "" {
		requestPath = "/"
	}
	query := resolved.Query
	params := map[string]string{
		"GATEWAY_INTERFACE": "CGI/1.1",
		"SERVER_SOFTWARE":   "tukuyomi/fastcgi",
		"SERVER_PROTOCOL":   httpProtocolOrDefault(r),
		"REQUEST_METHOD":    requestMethodOrDefault(r),
		"REQUEST_SCHEME":    requestScheme(r),
		"SCRIPT_FILENAME":   resolved.ScriptFilename,
		"SCRIPT_NAME":       resolved.ScriptName,
		"DOCUMENT_ROOT":     strings.TrimSpace(vhost.DocumentRoot),
		"DOCUMENT_URI":      requestPath,
		"REQUEST_URI":       requestURI(requestPath, query),
		"QUERY_STRING":      query,
		"REMOTE_ADDR":       remoteAddr,
		"REMOTE_PORT":       remotePort,
		"SERVER_NAME":       serverName,
		"SERVER_PORT":       serverPort,
	}
	if requestScheme(r) == "https" {
		params["HTTPS"] = "on"
	}
	if resolved.PathInfo != "" {
		params["PATH_INFO"] = resolved.PathInfo
		params["PATH_TRANSLATED"] = filepath.Join(strings.TrimSpace(vhost.DocumentRoot), filepath.FromSlash(strings.TrimPrefix(resolved.PathInfo, "/")))
	}
	if len(body) > 0 {
		params["CONTENT_LENGTH"] = strconv.Itoa(len(body))
	}
	if r != nil {
		if contentType := strings.TrimSpace(r.Header.Get("Content-Type")); contentType != "" {
			params["CONTENT_TYPE"] = contentType
		}
		for name, values := range r.Header {
			key := "HTTP_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
			if key == "HTTP_CONTENT_TYPE" || key == "HTTP_CONTENT_LENGTH" {
				continue
			}
			params[key] = strings.Join(values, ", ")
		}
	}
	return params, body, nil
}

func requestURI(requestPath string, rawQuery string) string {
	if strings.TrimSpace(rawQuery) == "" {
		return requestPath
	}
	return requestPath + "?" + rawQuery
}

func requestMethodOrDefault(r *http.Request) string {
	if r == nil || strings.TrimSpace(r.Method) == "" {
		return http.MethodGet
	}
	return r.Method
}

func httpProtocolOrDefault(r *http.Request) string {
	if r == nil || strings.TrimSpace(r.Proto) == "" {
		return "HTTP/1.1"
	}
	return r.Proto
}

func requestScheme(r *http.Request) string {
	if r != nil && r.TLS != nil {
		return "https"
	}
	return "http"
}

func fastCGIServerIdentity(r *http.Request, vhost VhostConfig) (string, string) {
	host := strings.TrimSpace(vhost.Hostname)
	port := ""
	if r != nil && strings.TrimSpace(r.Host) != "" {
		if parsedHost, parsedPort, err := net.SplitHostPort(r.Host); err == nil {
			host = parsedHost
			port = parsedPort
		} else {
			host = r.Host
		}
	}
	if port == "" {
		if r != nil && r.TLS != nil {
			port = "443"
		} else {
			port = "80"
		}
	}
	return host, port
}

func fastCGIRemoteIdentity(r *http.Request) (string, string) {
	if r == nil {
		return "", ""
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr), ""
	}
	return host, port
}

func writeDirectProxyResponse(w http.ResponseWriter, r *http.Request, resp *http.Response) error {
	if resp == nil {
		return fmt.Errorf("response is required")
	}
	if resp.Request == nil {
		resp.Request = r
	}
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	if err := onProxyResponse(resp); err != nil {
		return err
	}
	reqID := directProxyResponseRequestID(w, r)
	cacheStatus := strings.TrimSpace(w.Header().Get(proxyResponseCacheHeader))
	defer func() {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()
	dst := w.Header()
	for key := range dst {
		delete(dst, key)
	}
	for key, values := range resp.Header {
		if http.CanonicalHeaderKey(key) == http.CanonicalHeaderKey(directStaticResponseMarkerHeader) {
			continue
		}
		dst[key] = append([]string(nil), values...)
	}
	if reqID != "" {
		dst.Set("X-Request-ID", reqID)
	}
	if cacheStatus != "" {
		dst.Set(proxyResponseCacheHeader, cacheStatus)
	}
	w.WriteHeader(resp.StatusCode)
	if r != nil && r.Method == http.MethodHead {
		return nil
	}
	if resp.Body == nil {
		return nil
	}
	_, err := io.Copy(w, resp.Body)
	return err
}

func directProxyResponseRequestID(w http.ResponseWriter, r *http.Request) string {
	if r != nil {
		if reqID := strings.TrimSpace(proxyContextRequestID(r.Context())); reqID != "" {
			return strings.TrimSpace(reqID)
		}
		if reqID := strings.TrimSpace(r.Header.Get("X-Request-ID")); reqID != "" {
			return reqID
		}
	}
	if w != nil {
		return strings.TrimSpace(w.Header().Get("X-Request-ID"))
	}
	return ""
}

const (
	fcgiVersion1     = 1
	fcgiBeginRequest = 1
	fcgiEndRequest   = 3
	fcgiParams       = 4
	fcgiStdin        = 5
	fcgiStdout       = 6
	fcgiStderr       = 7
	fcgiResponder    = 1
	fcgiRequestID    = 1
)

func executeFastCGIRequest(ctx context.Context, target *url.URL, params map[string]string, body []byte) ([]byte, []byte, error) {
	network, address, err := fastCGIEndpoint(target)
	if err != nil {
		return nil, nil, err
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := writeFastCGIRecord(conn, fcgiBeginRequest, fcgiRequestID, []byte{0, fcgiResponder, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, nil, err
	}
	paramPairs := make([]string, 0, len(params))
	for name := range params {
		paramPairs = append(paramPairs, name)
	}
	sort.Strings(paramPairs)
	paramBuf := bytes.NewBuffer(nil)
	for _, name := range paramPairs {
		writeFastCGINameValue(paramBuf, name, params[name])
	}
	if err := writeFastCGIStream(conn, fcgiParams, fcgiRequestID, paramBuf.Bytes()); err != nil {
		return nil, nil, err
	}
	if err := writeFastCGIRecord(conn, fcgiParams, fcgiRequestID, nil); err != nil {
		return nil, nil, err
	}
	if err := writeFastCGIStream(conn, fcgiStdin, fcgiRequestID, body); err != nil {
		return nil, nil, err
	}
	if err := writeFastCGIRecord(conn, fcgiStdin, fcgiRequestID, nil); err != nil {
		return nil, nil, err
	}
	return readFastCGIResponse(conn)
}

func fastCGIEndpoint(target *url.URL) (string, string, error) {
	if target == nil {
		return "", "", fmt.Errorf("fastcgi target is required")
	}
	if !strings.EqualFold(target.Scheme, "fcgi") {
		return "", "", fmt.Errorf("fastcgi target must use fcgi scheme")
	}
	if strings.TrimSpace(target.Host) != "" {
		address, err := proxyDialAddress(target)
		if err != nil {
			return "", "", err
		}
		return "tcp", address, nil
	}
	if strings.TrimSpace(target.Path) == "" {
		return "", "", fmt.Errorf("fastcgi unix socket path is empty")
	}
	return "unix", strings.TrimSpace(target.Path), nil
}

func writeFastCGIStream(w io.Writer, recordType uint8, requestID uint16, payload []byte) error {
	for len(payload) > 0 {
		chunk := payload
		if len(chunk) > 65535 {
			chunk = payload[:65535]
		}
		if err := writeFastCGIRecord(w, recordType, requestID, chunk); err != nil {
			return err
		}
		payload = payload[len(chunk):]
	}
	return nil
}

func writeFastCGIRecord(w io.Writer, recordType uint8, requestID uint16, content []byte) error {
	padding := (8 - (len(content) % 8)) % 8
	header := []byte{
		fcgiVersion1,
		recordType,
		byte(requestID >> 8),
		byte(requestID),
		byte(len(content) >> 8),
		byte(len(content)),
		byte(padding),
		0,
	}
	if err := writeFastCGIFull(w, header); err != nil {
		return err
	}
	if len(content) > 0 {
		if err := writeFastCGIFull(w, content); err != nil {
			return err
		}
	}
	if padding > 0 {
		return writeFastCGIFull(w, make([]byte, padding))
	}
	return nil
}

func writeFastCGIFull(w io.Writer, buf []byte) error {
	for len(buf) > 0 {
		n, err := w.Write(buf)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		buf = buf[n:]
	}
	return nil
}

func writeFastCGINameValue(w io.Writer, name string, value string) {
	writeFastCGILength(w, len(name))
	writeFastCGILength(w, len(value))
	_, _ = io.WriteString(w, name)
	_, _ = io.WriteString(w, value)
}

func writeFastCGILength(w io.Writer, n int) {
	if n < 128 {
		_, _ = w.Write([]byte{byte(n)})
		return
	}
	_, _ = w.Write([]byte{
		byte((n >> 24) | 0x80),
		byte(n >> 16),
		byte(n >> 8),
		byte(n),
	})
}

func readFastCGIResponse(r io.Reader) ([]byte, []byte, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	header := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			if (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) && (stdout.Len() > 0 || stderr.Len() > 0) {
				return stdout.Bytes(), stderr.Bytes(), nil
			}
			return nil, nil, err
		}
		if header[0] != fcgiVersion1 {
			return nil, nil, fmt.Errorf("unsupported fastcgi version %d", header[0])
		}
		recordType := header[1]
		contentLength := int(header[4])<<8 | int(header[5])
		paddingLength := int(header[6])
		content := make([]byte, contentLength)
		if _, err := io.ReadFull(r, content); err != nil {
			return nil, nil, err
		}
		if paddingLength > 0 {
			if _, err := io.CopyN(io.Discard, r, int64(paddingLength)); err != nil {
				return nil, nil, err
			}
		}
		switch recordType {
		case fcgiStdout:
			stdout.Write(content)
		case fcgiStderr:
			stderr.Write(content)
		case fcgiEndRequest:
			return stdout.Bytes(), stderr.Bytes(), nil
		}
	}
}

func parseFastCGIHTTPResponse(stdout []byte, req *http.Request) (*http.Response, error) {
	headerBodySep := []byte("\r\n\r\n")
	idx := bytes.Index(stdout, headerBodySep)
	sepLen := len(headerBodySep)
	if idx < 0 {
		headerBodySep = []byte("\n\n")
		idx = bytes.Index(stdout, headerBodySep)
		sepLen = len(headerBodySep)
	}
	if idx < 0 {
		return nil, fmt.Errorf("fastcgi response did not include headers")
	}
	headerBlock := string(stdout[:idx])
	body := stdout[idx+sepLen:]
	tp := textproto.NewReader(bufio.NewReader(strings.NewReader(headerBlock + "\r\n\r\n")))
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	statusCode := http.StatusOK
	statusText := http.StatusText(statusCode)
	if rawStatus := strings.TrimSpace(mimeHeader.Get("Status")); rawStatus != "" {
		codeText := rawStatus
		if space := strings.IndexByte(rawStatus, ' '); space >= 0 {
			codeText = rawStatus[:space]
			statusText = strings.TrimSpace(rawStatus[space+1:])
		}
		if code, err := strconv.Atoi(codeText); err == nil {
			statusCode = code
			if statusText == "" {
				statusText = http.StatusText(code)
			}
		}
		mimeHeader.Del("Status")
	}
	respBody := io.NopCloser(bytes.NewReader(body))
	contentLength := int64(len(body))
	if req != nil && req.Method == http.MethodHead {
		respBody = io.NopCloser(bytes.NewReader(nil))
	}
	return &http.Response{
		StatusCode:    statusCode,
		Status:        fmt.Sprintf("%d %s", statusCode, strings.TrimSpace(statusText)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header(mimeHeader),
		Body:          respBody,
		ContentLength: contentLength,
		Request:       req,
	}, nil
}
