package bottelemetry

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const ScriptMarker = "tukuyomi-bot-telemetry"

func InjectHTML(body []byte, cookieName string, maxAge int) ([]byte, bool) {
	if len(body) == 0 || strings.TrimSpace(cookieName) == "" {
		return body, false
	}
	lower := bytes.ToLower(body)
	if bytes.Contains(lower, []byte(ScriptMarker)) {
		return body, false
	}
	if maxAge < 1 {
		maxAge = 3600
	}
	script := BuildInvisibleScript(cookieName, maxAge)
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

func BuildInvisibleScript(cookieName string, maxAge int) []byte {
	var b strings.Builder
	b.WriteString(`<script id="`)
	b.WriteString(ScriptMarker)
	b.WriteString(`">`)
	b.WriteString(`(()=>{try{`)
	b.WriteString(CookieWriteScript(strconv.Quote(cookieName), maxAge))
	b.WriteString(`}catch(_){}})();`)
	b.WriteString(`</script>`)
	return []byte(b.String())
}

func CookieWriteScript(cookieExpression string, maxAge int) string {
	return fmt.Sprintf(`const telemetry = {
        wd: navigator.webdriver === true,
        lc: Array.isArray(navigator.languages) ? navigator.languages.length : 0,
        sw: typeof screen === "object" && typeof screen.width === "number" ? screen.width : 0,
        sh: typeof screen === "object" && typeof screen.height === "number" ? screen.height : 0,
        tz: typeof Intl === "object" && Intl.DateTimeFormat ? (Intl.DateTimeFormat().resolvedOptions().timeZone || "") : "",
        pf: typeof navigator === "object" && typeof navigator.platform === "string" ? navigator.platform : "",
        hc: typeof navigator === "object" && typeof navigator.hardwareConcurrency === "number" ? navigator.hardwareConcurrency : 0,
        mt: typeof navigator === "object" && typeof navigator.maxTouchPoints === "number" ? navigator.maxTouchPoints : 0
      };
      document.cookie = %s + "=" + encodeURIComponent(JSON.stringify(telemetry)) + "; Path=/; Max-Age=%d; SameSite=Lax";`, cookieExpression, maxAge)
}

func BufferResponseBodyWithLimit(res *http.Response, limit int64) error {
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
