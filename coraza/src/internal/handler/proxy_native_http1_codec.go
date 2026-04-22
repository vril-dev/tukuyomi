package handler

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
)

const (
	nativeHTTP1MaxRequestHeaderBytes  = 1 << 20
	nativeHTTP1MaxResponseHeaderBytes = 1 << 20
	nativeHTTP1MaxTrailerBytes        = 64 << 10
	nativeHTTP1MaxChunkLineBytes      = 4096
)

func nativeHTTP1ParseRequestLine(line []byte) (method, target, proto []byte, err error) {
	raw := strings.TrimRight(string(line), "\r\n")
	parts := strings.Split(raw, " ")
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf("invalid HTTP/1 request line")
	}
	if !nativeHTTP1SafeToken(parts[0]) {
		return nil, nil, nil, fmt.Errorf("invalid HTTP/1 request method")
	}
	if parts[2] != "HTTP/1.0" && parts[2] != "HTTP/1.1" {
		return nil, nil, nil, fmt.Errorf("unsupported HTTP/1 request version %q", parts[2])
	}
	if err := nativeHTTP1ValidateRequestTarget(parts[1], parts[0]); err != nil {
		return nil, nil, nil, err
	}
	return []byte(parts[0]), []byte(parts[1]), []byte(parts[2]), nil
}

func nativeHTTP1BuildRequest(br *bufio.Reader, maxHeaderBytes int, remoteAddr net.Addr, tlsState *tls.ConnectionState) (*http.Request, error) {
	if maxHeaderBytes <= 0 {
		maxHeaderBytes = nativeHTTP1MaxRequestHeaderBytes
	}
	line, err := nativeHTTP1ReadLineLimited(br, maxHeaderBytes)
	if err != nil {
		return nil, err
	}
	methodRaw, targetRaw, protoRaw, err := nativeHTTP1ParseRequestLine([]byte(line))
	if err != nil {
		return nil, err
	}
	method := string(methodRaw)
	target := string(targetRaw)
	proto := string(protoRaw)
	major, minor := 1, 1
	if proto == "HTTP/1.0" {
		minor = 0
	}
	header, err := nativeHTTP1ReadRequestHeaderBlock(br, maxHeaderBytes-len(line))
	if err != nil {
		return nil, err
	}
	host, err := nativeHTTP1ResolveRequestHost(header, target, method, minor)
	if err != nil {
		return nil, err
	}
	u, err := nativeHTTP1RequestURL(target, method)
	if err != nil {
		return nil, err
	}
	contentLength, hasContentLength, err := nativeHTTP1NormalizeContentLength(header)
	if err != nil {
		return nil, err
	}
	transferEncoding, err := nativeHTTP1NormalizeTransferEncoding(header)
	if err != nil {
		return nil, err
	}
	if len(transferEncoding) > 0 && hasContentLength {
		return nil, fmt.Errorf("HTTP/1 request cannot contain both Transfer-Encoding and Content-Length")
	}
	body := io.NopCloser(bytes.NewReader(nil))
	if len(transferEncoding) > 0 {
		body = io.NopCloser(&nativeHTTP1ChunkedReader{br: br, trailer: make(http.Header)})
		contentLength = -1
	} else if hasContentLength && contentLength > 0 {
		body = io.NopCloser(&io.LimitedReader{R: br, N: contentLength})
	}
	req := &http.Request{
		Method:           method,
		URL:              u,
		Proto:            proto,
		ProtoMajor:       major,
		ProtoMinor:       minor,
		Header:           header,
		Body:             body,
		ContentLength:    contentLength,
		TransferEncoding: transferEncoding,
		Host:             host,
		RequestURI:       target,
		RemoteAddr:       "",
		TLS:              tlsState,
	}
	if remoteAddr != nil {
		req.RemoteAddr = remoteAddr.String()
	}
	req = req.WithContext(context.Background())
	return req, nil
}

func nativeHTTP1ReadHeaderBlock(br *bufio.Reader, maxBytes int) (http.Header, error) {
	return nativeHTTP1ReadHeaderBlockKind(br, maxBytes, "upstream response")
}

func nativeHTTP1ReadRequestHeaderBlock(br *bufio.Reader, maxBytes int) (http.Header, error) {
	return nativeHTTP1ReadHeaderBlockKind(br, maxBytes, "request")
}

func nativeHTTP1ReadHeaderBlockKind(br *bufio.Reader, maxBytes int, kind string) (http.Header, error) {
	header := make(http.Header)
	used := 0
	for {
		line, err := nativeHTTP1ReadLineLimited(br, maxBytes-used)
		if err != nil {
			return nil, err
		}
		used += len(line)
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			return header, nil
		}
		if strings.HasPrefix(trimmed, " ") || strings.HasPrefix(trimmed, "\t") {
			return nil, fmt.Errorf("%s folded headers are not supported", kind)
		}
		idx := strings.IndexByte(trimmed, ':')
		if idx <= 0 {
			return nil, fmt.Errorf("invalid %s header line %q", kind, trimmed)
		}
		name := http.CanonicalHeaderKey(strings.TrimSpace(trimmed[:idx]))
		value := textproto.TrimString(trimmed[idx+1:])
		if !nativeHTTP1SafeHeaderName(name) || !nativeHTTP1SafeHeaderValue(value) {
			return nil, fmt.Errorf("invalid %s header %q", kind, name)
		}
		header.Add(name, value)
	}
}

func nativeHTTP1ReadLineLimited(br *bufio.Reader, limit int) (string, error) {
	if limit <= 0 {
		return "", fmt.Errorf("HTTP/1 headers exceed limit")
	}
	var out bytes.Buffer
	for {
		part, err := br.ReadSlice('\n')
		out.Write(part)
		if out.Len() > limit {
			return "", fmt.Errorf("HTTP/1 headers exceed limit")
		}
		if err == nil {
			line := out.String()
			if !strings.HasSuffix(line, "\r\n") {
				return "", fmt.Errorf("HTTP/1 line missing CRLF terminator")
			}
			return line, nil
		}
		if err != bufio.ErrBufferFull {
			return "", err
		}
	}
}

type nativeHTTP1ChunkedReader struct {
	br             *bufio.Reader
	trailer        http.Header
	chunkRemaining int64
	needCRLF       bool
	done           bool
}

func (r *nativeHTTP1ChunkedReader) Read(p []byte) (int, error) {
	if r == nil || r.br == nil || r.done {
		return 0, io.EOF
	}
	for r.chunkRemaining == 0 {
		if r.needCRLF {
			if err := nativeHTTP1ReadExactCRLF(r.br); err != nil {
				return 0, err
			}
			r.needCRLF = false
		}
		size, err := r.readChunkSize()
		if err != nil {
			return 0, err
		}
		if size == 0 {
			trailer, err := nativeHTTP1ReadHeaderBlock(r.br, nativeHTTP1MaxTrailerBytes)
			if err != nil {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return 0, err
			}
			for name, values := range trailer {
				for _, value := range values {
					r.trailer.Add(name, value)
				}
			}
			r.done = true
			return 0, io.EOF
		}
		r.chunkRemaining = size
	}
	if int64(len(p)) > r.chunkRemaining {
		p = p[:r.chunkRemaining]
	}
	n, err := r.br.Read(p)
	r.chunkRemaining -= int64(n)
	if err == io.EOF && r.chunkRemaining > 0 {
		err = io.ErrUnexpectedEOF
	}
	if r.chunkRemaining == 0 {
		r.needCRLF = true
	}
	return n, err
}

func (r *nativeHTTP1ChunkedReader) readChunkSize() (int64, error) {
	line, err := nativeHTTP1ReadLineLimited(r.br, nativeHTTP1MaxChunkLineBytes)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return 0, err
	}
	line = strings.TrimRight(line, "\r\n")
	if strings.ContainsAny(line, "\r\n\x00") {
		return 0, fmt.Errorf("invalid upstream chunk size line")
	}
	if idx := strings.IndexByte(line, ';'); idx >= 0 {
		line = line[:idx]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return 0, fmt.Errorf("empty upstream chunk size")
	}
	size, err := strconv.ParseInt(line, 16, 64)
	if err != nil || size < 0 {
		return 0, fmt.Errorf("invalid upstream chunk size %q", line)
	}
	return size, nil
}

func nativeHTTP1ReadExactCRLF(r *bufio.Reader) error {
	cr, err := r.ReadByte()
	if err != nil {
		return err
	}
	lf, err := r.ReadByte()
	if err != nil {
		return err
	}
	if cr != '\r' || lf != '\n' {
		return fmt.Errorf("invalid upstream chunk terminator")
	}
	return nil
}

func nativeHTTP1SafeToken(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c <= 0x20 || c >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", rune(c)) {
			return false
		}
	}
	return true
}

func nativeHTTP1SafeHeaderName(name string) bool {
	return proxyRouteHeaderNamePattern.MatchString(name)
}

func nativeHTTP1SafeHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '\t' {
			continue
		}
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

func nativeHTTP1ValidateRequestTarget(target string, method string) error {
	if target == "" {
		return fmt.Errorf("empty HTTP/1 request target")
	}
	for i := 0; i < len(target); i++ {
		c := target[i]
		if c <= 0x20 || c == 0x7f || c >= 0x80 {
			return fmt.Errorf("invalid HTTP/1 request target")
		}
	}
	switch {
	case target == "*":
		return nil
	case strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://"):
		u, err := url.Parse(target)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("invalid HTTP/1 absolute-form target")
		}
		return nil
	case strings.HasPrefix(target, "/"):
		if _, err := url.ParseRequestURI(target); err != nil {
			return fmt.Errorf("invalid HTTP/1 origin-form target")
		}
		return nil
	default:
		if method != http.MethodConnect {
			return fmt.Errorf("HTTP/1 authority-form target is only valid for CONNECT")
		}
		if strings.ContainsAny(target, "/?#") {
			return fmt.Errorf("invalid HTTP/1 authority-form target")
		}
		if _, _, err := net.SplitHostPort(target); err == nil {
			return nil
		}
		if strings.Count(target, ":") > 1 {
			return fmt.Errorf("invalid HTTP/1 authority-form target")
		}
		return nil
	}
}

func nativeHTTP1RequestURL(target string, method string) (*url.URL, error) {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return url.Parse(target)
	}
	if target == "*" {
		return &url.URL{Path: "*"}, nil
	}
	if method == http.MethodConnect && !strings.HasPrefix(target, "/") {
		return &url.URL{Host: target}, nil
	}
	return url.ParseRequestURI(target)
}

func nativeHTTP1ResolveRequestHost(header http.Header, target string, method string, minor int) (string, error) {
	values := header.Values("Host")
	targetHost := ""
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		u, err := url.Parse(target)
		if err != nil {
			return "", err
		}
		targetHost = u.Host
	} else if method == http.MethodConnect && !strings.HasPrefix(target, "/") {
		targetHost = target
	}
	if len(values) == 0 {
		if targetHost != "" {
			return targetHost, nil
		}
		if minor >= 1 {
			return "", fmt.Errorf("HTTP/1.1 request missing Host header")
		}
		return "", nil
	}
	host := strings.TrimSpace(values[0])
	if host == "" || strings.ContainsAny(host, "\r\n\x00") {
		return "", fmt.Errorf("invalid HTTP/1 Host header")
	}
	for _, value := range values[1:] {
		if strings.TrimSpace(value) != host {
			return "", fmt.Errorf("conflicting HTTP/1 Host headers")
		}
	}
	if targetHost != "" && !strings.EqualFold(host, targetHost) {
		return "", fmt.Errorf("HTTP/1 Host header conflicts with request target")
	}
	return host, nil
}

func nativeHTTP1NormalizeContentLength(header http.Header) (int64, bool, error) {
	values := header.Values("Content-Length")
	if len(values) == 0 {
		return -1, false, nil
	}
	var length int64 = -1
	for _, raw := range values {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.ContainsAny(raw, "+-") {
			return 0, true, fmt.Errorf("invalid HTTP/1 Content-Length")
		}
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 0 {
			return 0, true, fmt.Errorf("invalid HTTP/1 Content-Length")
		}
		if length >= 0 && parsed != length {
			return 0, true, fmt.Errorf("conflicting HTTP/1 Content-Length headers")
		}
		length = parsed
	}
	header.Del("Content-Length")
	header.Set("Content-Length", strconv.FormatInt(length, 10))
	return length, true, nil
}

func nativeHTTP1NormalizeTransferEncoding(header http.Header) ([]string, error) {
	values := header.Values("Transfer-Encoding")
	if len(values) == 0 {
		return nil, nil
	}
	var codings []string
	for _, raw := range values {
		for _, part := range strings.Split(raw, ",") {
			coding := strings.ToLower(strings.TrimSpace(part))
			if coding == "" {
				return nil, fmt.Errorf("invalid HTTP/1 Transfer-Encoding")
			}
			codings = append(codings, coding)
		}
	}
	if len(codings) != 1 || codings[0] != "chunked" {
		return nil, fmt.Errorf("unsupported HTTP/1 Transfer-Encoding")
	}
	header.Del("Transfer-Encoding")
	return []string{"chunked"}, nil
}
