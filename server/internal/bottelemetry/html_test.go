package bottelemetry

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestInjectHTMLInsertsBeforeBodyClose(t *testing.T) {
	body := []byte("<html><body><h1>Hello</h1></body></html>")
	updated, changed := InjectHTML(body, "tky_bot", 60)
	if !changed {
		t.Fatal("expected injection")
	}
	out := string(updated)
	if !strings.Contains(out, ScriptMarker) {
		t.Fatalf("missing marker: %s", out)
	}
	if !strings.Contains(out, "</script></body>") {
		t.Fatalf("script should be inserted before body close: %s", out)
	}
}

func TestInjectHTMLSkipsExistingMarker(t *testing.T) {
	body := []byte(`<html><body><script id="tukuyomi-bot-telemetry"></script></body></html>`)
	updated, changed := InjectHTML(body, "tky_bot", 60)
	if changed {
		t.Fatal("did not expect duplicate injection")
	}
	if string(updated) != string(body) {
		t.Fatal("body changed unexpectedly")
	}
}

func TestBufferResponseBodyWithLimit(t *testing.T) {
	res := &http.Response{
		Header:        http.Header{},
		Body:          io.NopCloser(strings.NewReader("hello")),
		ContentLength: 5,
	}
	if err := BufferResponseBodyWithLimit(res, 10); err != nil {
		t.Fatalf("BufferResponseBodyWithLimit: %v", err)
	}
	if res.ContentLength != 5 || res.Header.Get("Content-Length") != "5" {
		t.Fatalf("unexpected response metadata: length=%d header=%q", res.ContentLength, res.Header.Get("Content-Length"))
	}
	got, _ := io.ReadAll(res.Body)
	if string(got) != "hello" {
		t.Fatalf("body=%q want hello", string(got))
	}

	res = &http.Response{Body: io.NopCloser(strings.NewReader("too long"))}
	if err := BufferResponseBodyWithLimit(res, 3); err != io.ErrShortBuffer {
		t.Fatalf("err=%v want ErrShortBuffer", err)
	}
}
