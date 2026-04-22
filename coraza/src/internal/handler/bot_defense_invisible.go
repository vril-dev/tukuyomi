package handler

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const botDefenseInvisibleScriptMarker = "tukuyomi-bot-telemetry"

func maybeInjectBotDefenseTelemetry(res *http.Response) error {
	rt, _ := selectBotDefenseRuntime(currentBotDefenseRuntime(), res.Request)
	if !canInjectBotDefenseTelemetry(rt, res.Request, res) {
		return nil
	}
	if err := bufferProxyResponseBodyWithLimit(res, rt.DeviceSignals.InvisibleMaxBodyBytes); err != nil {
		return nil
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	_ = res.Body.Close()
	updated, changed := injectBotDefenseTelemetryHTML(body, rt)
	if !changed {
		res.Body = io.NopCloser(bytes.NewReader(body))
		res.ContentLength = int64(len(body))
		return nil
	}
	res.Body = io.NopCloser(bytes.NewReader(updated))
	res.ContentLength = int64(len(updated))
	if res.Header != nil {
		res.Header.Set("Content-Length", strconv.FormatInt(res.ContentLength, 10))
		res.Header.Del("ETag")
		res.Header.Set("X-Tukuyomi-Bot-Telemetry", "injected")
	}
	return nil
}

func injectBotDefenseTelemetryHTML(body []byte, rt *runtimeBotDefenseConfig) ([]byte, bool) {
	if len(body) == 0 || rt == nil {
		return body, false
	}
	lower := bytes.ToLower(body)
	if bytes.Contains(lower, []byte(botDefenseInvisibleScriptMarker)) {
		return body, false
	}
	cookieName := botDefenseTelemetryCookieName(rt)
	if cookieName == "" {
		return body, false
	}
	maxAge := int(rt.ChallengeTTL.Seconds())
	if maxAge < 1 {
		maxAge = 3600
	}
	script := buildBotDefenseInvisibleTelemetryScript(cookieName, maxAge)
	closeIdx := bytes.LastIndex(lower, []byte("</body>"))
	if closeIdx >= 0 {
		out := make([]byte, 0, len(body)+len(script))
		out = append(out, body[:closeIdx]...)
		out = append(out, script...)
		out = append(out, body[closeIdx:]...)
		return out, true
	}
	out := append(append([]byte(nil), body...), script...)
	return out, true
}

func buildBotDefenseInvisibleTelemetryScript(cookieName string, maxAge int) []byte {
	var b strings.Builder
	b.WriteString(`<script id="`)
	b.WriteString(botDefenseInvisibleScriptMarker)
	b.WriteString(`">`)
	b.WriteString(`(()=>{try{`)
	b.WriteString(botDefenseTelemetryCookieWriteScript(strconv.Quote(cookieName), maxAge))
	b.WriteString(`}catch(_){}})();`)
	b.WriteString(`</script>`)
	return []byte(b.String())
}

func bufferProxyResponseBodyWithLimit(res *http.Response, limit int64) error {
	if limit <= 0 || res == nil || res.Body == nil {
		return nil
	}
	if res.ContentLength > limit && res.ContentLength > 0 {
		return io.ErrShortBuffer
	}
	lr := io.LimitReader(res.Body, limit+1)
	body, err := io.ReadAll(lr)
	if err != nil {
		return err
	}
	if int64(len(body)) > limit {
		return io.ErrShortBuffer
	}
	_ = res.Body.Close()
	res.Body = io.NopCloser(bytes.NewReader(body))
	res.ContentLength = int64(len(body))
	if res.Header != nil {
		res.Header.Set("Content-Length", strconv.FormatInt(res.ContentLength, 10))
	}
	return nil
}
