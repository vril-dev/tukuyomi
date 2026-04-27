package handler

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

func TestNativeHTTP1ResponseWriterContentLengthFraming(t *testing.T) {
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "2")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	conn, br := nativeHTTP1DialRaw(t, addr)
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	_, header := nativeHTTP1ReadRawResponseHead(t, br)
	if got := header.Get("Content-Length"); got != "2" {
		t.Fatalf("Content-Length=%q want 2", got)
	}
	if got := header.Get("Transfer-Encoding"); got != "" {
		t.Fatalf("Transfer-Encoding=%q want empty", got)
	}
	body := make([]byte, 2)
	if _, err := io.ReadFull(br, body); err != nil {
		t.Fatalf("ReadFull body: %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("body=%q want ok", string(body))
	}
}

func TestNativeHTTP1ResponseWriterChunkedFraming(t *testing.T) {
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	conn, br := nativeHTTP1DialRaw(t, addr)
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	_, header := nativeHTTP1ReadRawResponseHead(t, br)
	if got := header.Get("Transfer-Encoding"); got != "chunked" {
		t.Fatalf("Transfer-Encoding=%q want chunked", got)
	}
	if got := header.Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length=%q want empty", got)
	}
	nativeHTTP1ExpectRawLine(t, br, "5")
	body := make([]byte, 5)
	if _, err := io.ReadFull(br, body); err != nil {
		t.Fatalf("ReadFull chunk body: %v", err)
	}
	if string(body) != "hello" {
		t.Fatalf("chunk body=%q want hello", string(body))
	}
	nativeHTTP1ExpectRawLine(t, br, "")
	nativeHTTP1ExpectRawLine(t, br, "0")
	nativeHTTP1ExpectRawLine(t, br, "")
}

func TestNativeHTTP1ResponseWriterNoBodyFraming(t *testing.T) {
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "99")
		w.Header().Set("Transfer-Encoding", "chunked")
		w.WriteHeader(http.StatusNoContent)
		_, _ = w.Write([]byte("ignored"))
	}))
	defer srv.Close()

	conn, br := nativeHTTP1DialRaw(t, addr)
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	status, header := nativeHTTP1ReadRawResponseHead(t, br)
	if !strings.Contains(status, "204") {
		t.Fatalf("status=%q want 204", status)
	}
	if got := header.Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length=%q want empty", got)
	}
	if got := header.Get("Transfer-Encoding"); got != "" {
		t.Fatalf("Transfer-Encoding=%q want empty", got)
	}
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if b, err := br.Peek(1); err == nil {
		t.Fatalf("unexpected body byte after 204: %q", b)
	}
}

func TestNativeHTTP1ResponseWriterHTTP10CloseDelimited(t *testing.T) {
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("legacy"))
	}))
	defer srv.Close()

	conn, br := nativeHTTP1DialRaw(t, addr)
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.0\r\n\r\n")
	_, header := nativeHTTP1ReadRawResponseHead(t, br)
	if got := header.Get("Transfer-Encoding"); got != "" {
		t.Fatalf("Transfer-Encoding=%q want empty", got)
	}
	if got := header.Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length=%q want empty", got)
	}
	if got := header.Get("Connection"); !strings.EqualFold(got, "close") {
		t.Fatalf("Connection=%q want close", got)
	}
	body, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("ReadAll body: %v", err)
	}
	if string(body) != "legacy" {
		t.Fatalf("body=%q want legacy", string(body))
	}
}

func TestNativeHTTP1ResponseWriterFlushStreamsChunk(t *testing.T) {
	release := make(chan struct{})
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("response writer does not implement http.Flusher")
		}
		_, _ = w.Write([]byte("a"))
		flusher.Flush()
		<-release
		_, _ = w.Write([]byte("b"))
	}))
	defer srv.Close()
	defer close(release)

	conn, br := nativeHTTP1DialRaw(t, addr)
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	_, header := nativeHTTP1ReadRawResponseHead(t, br)
	if got := header.Get("Transfer-Encoding"); got != "chunked" {
		t.Fatalf("Transfer-Encoding=%q want chunked", got)
	}
	nativeHTTP1ExpectRawLine(t, br, "1")
	first := make([]byte, 1)
	if _, err := io.ReadFull(br, first); err != nil {
		t.Fatalf("ReadFull first chunk: %v", err)
	}
	if string(first) != "a" {
		t.Fatalf("first chunk=%q want a", string(first))
	}
}

func TestNativeHTTP1ResponseWriterTrailerPrefix(t *testing.T) {
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(http.TrailerPrefix+"X-End", "done")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	conn, br := nativeHTTP1DialRaw(t, addr)
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	_, header := nativeHTTP1ReadRawResponseHead(t, br)
	if got := header.Get("Trailer"); got != "X-End" {
		t.Fatalf("Trailer=%q want X-End", got)
	}
	nativeHTTP1ExpectRawLine(t, br, "2")
	body := make([]byte, 2)
	if _, err := io.ReadFull(br, body); err != nil {
		t.Fatalf("ReadFull chunk body: %v", err)
	}
	nativeHTTP1ExpectRawLine(t, br, "")
	nativeHTTP1ExpectRawLine(t, br, "0")
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read trailer: %v", err)
	}
	if strings.TrimSpace(line) != "X-End: done" {
		t.Fatalf("trailer line=%q want X-End: done", line)
	}
	nativeHTTP1ExpectRawLine(t, br, "")
}

func TestNativeHTTP1ResponseWriterExplicitTrailerLateValue(t *testing.T) {
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Trailer", "X-Late")
		_, _ = w.Write([]byte("ok"))
		w.Header().Set("X-Late", "done")
	}))
	defer srv.Close()

	conn, br := nativeHTTP1DialRaw(t, addr)
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	_, header := nativeHTTP1ReadRawResponseHead(t, br)
	if got := header.Get("Trailer"); got != "X-Late" {
		t.Fatalf("Trailer=%q want X-Late", got)
	}
	nativeHTTP1ExpectRawLine(t, br, "2")
	body := make([]byte, 2)
	if _, err := io.ReadFull(br, body); err != nil {
		t.Fatalf("ReadFull chunk body: %v", err)
	}
	nativeHTTP1ExpectRawLine(t, br, "")
	nativeHTTP1ExpectRawLine(t, br, "0")
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read trailer: %v", err)
	}
	if strings.TrimSpace(line) != "X-Late: done" {
		t.Fatalf("trailer line=%q want X-Late: done", line)
	}
	nativeHTTP1ExpectRawLine(t, br, "")
}

func TestNativeHTTP1ResponseWriterReaderFrom(t *testing.T) {
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		readerFrom, ok := w.(io.ReaderFrom)
		if !ok {
			t.Fatal("response writer does not implement io.ReaderFrom")
		}
		if _, err := readerFrom.ReadFrom(strings.NewReader("copied")); err != nil {
			t.Fatalf("ReadFrom: %v", err)
		}
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll body: %v", err)
	}
	if string(body) != "copied" {
		t.Fatalf("body=%q want copied", string(body))
	}
}

func TestNativeHTTP1ResponseWriterInformationalThenFinal(t *testing.T) {
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", "</early.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("Link")
		w.Header().Set("X-Final", "ok")
		_, _ = w.Write([]byte("done"))
	}))
	defer srv.Close()

	conn, br := nativeHTTP1DialRaw(t, addr)
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	status, header := nativeHTTP1ReadRawResponseHead(t, br)
	if status != "HTTP/1.1 103 Early Hints" {
		t.Fatalf("informational status=%q want 103", status)
	}
	if got := header.Get("Link"); got != "</early.css>; rel=preload" {
		t.Fatalf("early Link=%q want preload", got)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("ReadResponse final: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll final body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("final status=%d want 200", resp.StatusCode)
	}
	if resp.Header.Get("Link") != "" {
		t.Fatalf("final Link leaked: %q", resp.Header.Get("Link"))
	}
	if resp.Header.Get("X-Final") != "ok" {
		t.Fatalf("X-Final=%q want ok", resp.Header.Get("X-Final"))
	}
	if string(body) != "done" {
		t.Fatalf("body=%q want done", string(body))
	}
}

func TestNativeHTTP1ExpectContinueOnBodyRead(t *testing.T) {
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Pre-Read", "final-only")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll request body: %v", err)
			return
		}
		w.Header().Set("X-Body", string(body))
		_, _ = w.Write([]byte("accepted"))
	}))
	defer srv.Close()

	conn, br := nativeHTTP1DialRaw(t, addr)
	defer conn.Close()
	_, _ = io.WriteString(conn, "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n")
	status, header := nativeHTTP1ReadRawResponseHead(t, br)
	if status != "HTTP/1.1 100 Continue" {
		t.Fatalf("status=%q want 100 Continue", status)
	}
	if got := header.Get("X-Pre-Read"); got != "" {
		t.Fatalf("automatic 100 Continue leaked final header X-Pre-Read=%q", got)
	}
	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatalf("write body: %v", err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("ReadResponse final: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Pre-Read"); got != "final-only" {
		t.Fatalf("X-Pre-Read=%q want final-only", got)
	}
	if got := resp.Header.Get("X-Body"); got != "ping" {
		t.Fatalf("X-Body=%q want ping", got)
	}
}

func TestNativeHTTP1ExpectContinueNotSentWhenBodyUnread(t *testing.T) {
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-No-Body-Read", "true")
		_, _ = w.Write([]byte("rejected"))
	}))
	defer srv.Close()

	conn, br := nativeHTTP1DialRaw(t, addr)
	defer conn.Close()
	_, _ = io.WriteString(conn, "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-No-Body-Read"); got != "true" {
		t.Fatalf("X-No-Body-Read=%q want true", got)
	}
}

func TestNativeHTTP1ResponseWriterScrubsInvalidHeaderAndCounts(t *testing.T) {
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Good", "ok")
		w.Header()["X-Bad"] = []string{"bad\r\nvalue"}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if got := resp.Header.Get("X-Good"); got != "ok" {
		t.Fatalf("X-Good=%q want ok", got)
	}
	if got := resp.Header.Get("X-Bad"); got != "" {
		t.Fatalf("X-Bad leaked: %q", got)
	}
	if got := srv.scrubbedHeaders.Load(); got == 0 {
		t.Fatal("scrubbedHeaders was not incremented")
	}
}

func TestNativeHTTP1ResponseWriterShortContentLengthCloses(t *testing.T) {
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "4")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	conn, br := nativeHTTP1DialRaw(t, addr)
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_, header := nativeHTTP1ReadRawResponseHead(t, br)
	if got := header.Get("Content-Length"); got != "4" {
		t.Fatalf("Content-Length=%q want 4", got)
	}
	buf := make([]byte, 4)
	n, err := io.ReadFull(br, buf)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ReadFull err=%v want unexpected EOF", err)
	}
	if n != 2 || string(buf[:n]) != "ok" {
		t.Fatalf("body n=%d data=%q want 2 ok", n, string(buf[:n]))
	}
	if got := srv.keepAliveReuses.Load(); got != 0 {
		t.Fatalf("keepAliveReuses=%d want 0", got)
	}
}

func nativeHTTP1DialRaw(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	return conn, bufio.NewReader(conn)
}

func nativeHTTP1ReadRawResponseHead(t *testing.T, br *bufio.Reader) (string, textproto.MIMEHeader) {
	t.Helper()
	tr := textproto.NewReader(br)
	status, err := tr.ReadLine()
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	header, err := tr.ReadMIMEHeader()
	if err != nil {
		t.Fatalf("read response headers: %v", err)
	}
	return status, header
}

func nativeHTTP1ExpectRawLine(t *testing.T, br *bufio.Reader, want string) {
	t.Helper()
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read line: %v", err)
	}
	if got := strings.TrimRight(line, "\r\n"); got != want {
		t.Fatalf("line=%q want %q", got, want)
	}
}
