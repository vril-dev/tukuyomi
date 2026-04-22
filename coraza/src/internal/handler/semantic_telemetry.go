package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	semanticPatternUUID          = regexp.MustCompile(`\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	semanticPatternLongHex       = regexp.MustCompile(`\b[0-9a-f]{16,}\b`)
	semanticPatternEmail         = regexp.MustCompile(`\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)
	semanticPatternJWT           = regexp.MustCompile(`\beyj[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+\b`)
	semanticPatternNumber        = regexp.MustCompile(`\b\d+\b`)
	semanticPatternSegmentDigits = regexp.MustCompile(`^\d+$`)
)

var semanticSubjectHeaderCandidates = []string{
	"X-Authenticated-User",
	"X-Authenticated-Email",
	"X-Forwarded-User",
	"X-Remote-User",
	"Remote-User",
	"X-User",
	"X-Email",
}

var semanticSessionHeaderCandidates = []string{
	"X-Session-ID",
	"X-Session",
	"Session-ID",
}

var semanticSessionCookieCandidates = []string{
	"session",
	"sessionid",
	"sid",
	"connect.sid",
	"jsessionid",
	"phpsessid",
	"laravel_session",
	"__session",
	"_session",
}

type semanticCorrelationContext struct {
	ActorKey      string `json:"actor_key,omitempty"`
	ActorBasis    string `json:"actor_basis,omitempty"`
	ClientKey     string `json:"client_key,omitempty"`
	SessionKey    string `json:"session_key,omitempty"`
	SessionSource string `json:"session_source,omitempty"`
	SubjectKey    string `json:"subject_key,omitempty"`
	SubjectSource string `json:"subject_source,omitempty"`
	RequestKey    string `json:"request_key,omitempty"`
	PathClass     string `json:"path_class,omitempty"`
	TargetClass   string `json:"target_class,omitempty"`
	SurfaceClass  string `json:"surface_class,omitempty"`
}

type semanticFingerprintSet struct {
	QueryHash    string `json:"query_hash,omitempty"`
	FormHash     string `json:"form_hash,omitempty"`
	JSONHash     string `json:"json_hash,omitempty"`
	BodyHash     string `json:"body_hash,omitempty"`
	HeaderHash   string `json:"header_hash,omitempty"`
	CombinedHash string `json:"combined_hash,omitempty"`
}

type semanticTelemetry struct {
	Context        semanticCorrelationContext `json:"context"`
	Fingerprints   semanticFingerprintSet     `json:"fingerprints"`
	FeatureBuckets []string                   `json:"feature_buckets,omitempty"`
}

func buildSemanticTelemetry(r *http.Request, clientIP, requestID string, bodyChunk []byte) *semanticTelemetry {
	if r == nil || r.URL == nil {
		return nil
	}

	context := semanticCorrelationContext{
		ClientKey:   semanticHashedKey("client", clientIP),
		RequestKey:  strings.TrimSpace(requestID),
		PathClass:   semanticPathClass(r.URL.Path),
		TargetClass: semanticTargetClass(r),
	}

	subjectRaw, subjectSource := semanticSubjectFromRequest(r)
	if subjectRaw != "" {
		context.SubjectKey = semanticHashedKey("subject", subjectRaw)
		context.SubjectSource = subjectSource
	}

	sessionRaw, sessionSource := semanticSessionFromRequest(r)
	if sessionRaw != "" {
		context.SessionKey = semanticHashedKey("session", sessionRaw)
		context.SessionSource = sessionSource
	}

	switch {
	case context.SubjectKey != "":
		context.ActorKey = context.SubjectKey
		context.ActorBasis = "subject"
	case context.SessionKey != "":
		context.ActorKey = context.SessionKey
		context.ActorBasis = "session"
	case context.ClientKey != "":
		context.ActorKey = context.ClientKey
		context.ActorBasis = "client"
	}

	contentType := semanticNormalizedContentType(r.Header.Get("Content-Type"))
	fingerprints := semanticFingerprintSet{
		QueryHash:  semanticQueryFingerprint(r.URL.RawQuery),
		HeaderHash: semanticHeaderFingerprint(r.Header),
	}
	if formHash := semanticFormFingerprint(bodyChunk, contentType); formHash != "" {
		fingerprints.FormHash = formHash
	}
	if jsonHash := semanticJSONFingerprint(bodyChunk, contentType); jsonHash != "" {
		fingerprints.JSONHash = jsonHash
	}
	if bodyHash := semanticBodyFingerprint(bodyChunk, contentType); bodyHash != "" {
		fingerprints.BodyHash = bodyHash
	}

	buckets := make([]string, 0, 8)
	surfaces := make([]string, 0, 4)
	if context.ActorBasis != "" {
		buckets = append(buckets, "actor:"+context.ActorBasis)
	}
	if fingerprints.QueryHash != "" {
		surfaces = append(surfaces, "query")
	}
	if fingerprints.FormHash != "" {
		surfaces = append(surfaces, "form_body")
	}
	if fingerprints.JSONHash != "" {
		surfaces = append(surfaces, "json_body")
	}
	if fingerprints.BodyHash != "" && fingerprints.FormHash == "" && fingerprints.JSONHash == "" {
		surfaces = append(surfaces, "body")
	}
	if fingerprints.HeaderHash != "" {
		surfaces = append(surfaces, "headers")
	}
	if len(surfaces) > 0 {
		context.SurfaceClass = strings.Join(surfaces, "+")
		for _, surface := range surfaces {
			buckets = append(buckets, "surface:"+surface)
		}
	}
	if context.PathClass != "" {
		buckets = append(buckets, "path:"+context.PathClass)
	}
	if context.TargetClass != "" {
		buckets = append(buckets, "target:"+context.TargetClass)
	}

	fingerprints.CombinedHash = semanticCombinedFingerprint(fingerprints)
	buckets = unique(buckets)

	if semanticTelemetryIsEmpty(context, fingerprints, buckets) {
		return nil
	}
	return &semanticTelemetry{
		Context:        context,
		Fingerprints:   fingerprints,
		FeatureBuckets: buckets,
	}
}

func semanticTelemetryIsEmpty(
	context semanticCorrelationContext,
	fingerprints semanticFingerprintSet,
	buckets []string,
) bool {
	return context == (semanticCorrelationContext{}) &&
		fingerprints == (semanticFingerprintSet{}) &&
		len(buckets) == 0
}

func semanticHashedKey(kind, raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("tukuyomi-semantic-v1|" + kind + "|" + value))
	return kind + ":" + hex.EncodeToString(sum[:8])
}

func semanticPathClass(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || path == "/" {
		return "/"
	}
	segments := strings.Split(path, "/")
	out := make([]string, 0, len(segments))
	for _, rawSegment := range segments {
		if rawSegment == "" {
			continue
		}
		segment := strings.ToLower(strings.TrimSpace(rawSegment))
		switch {
		case semanticPatternUUID.MatchString(segment):
			out = append(out, "{uuid}")
		case semanticPatternSegmentDigits.MatchString(segment):
			out = append(out, "{num}")
		case semanticPatternLongHex.MatchString(segment):
			out = append(out, "{hex}")
		case len(segment) > 24 && strings.IndexFunc(segment, func(r rune) bool { return r >= '0' && r <= '9' }) >= 0:
			out = append(out, "{id}")
		default:
			if len(segment) > 24 {
				segment = segment[:24]
			}
			out = append(out, segment)
		}
		if len(out) == 6 {
			break
		}
	}
	if len(out) == 0 {
		return "/"
	}
	return "/" + strings.Join(out, "/")
}

func semanticTargetClass(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	path := strings.ToLower(strings.TrimSpace(r.URL.Path))
	method := strings.ToUpper(strings.TrimSpace(r.Method))

	if semanticIsStaticPath(path) {
		return "public_static"
	}
	if semanticContainsAny(path, "/admin", "/manage", "/management", "/manager", "/console", "/internal", "/ops", "/superadmin") {
		return "admin_management"
	}
	if semanticContainsAny(path, "/login", "/logout", "/signin", "/signup", "/register", "/auth", "/oauth", "/account", "/profile", "/password", "/passwd", "/token", "/session", "/security", "/mfa", "/otp", "/2fa") {
		return "account_security"
	}
	if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
		return "write_action"
	}
	if semanticContainsAny(path, "/create", "/update", "/delete", "/remove", "/reset", "/apply", "/import", "/export", "/upload", "/save", "/edit") {
		return "write_action"
	}
	return "authenticated_app"
}

func semanticIsStaticPath(path string) bool {
	if path == "" || path == "/" {
		return false
	}
	if semanticContainsAny(path, "/assets/", "/static/", "/images/", "/img/", "/fonts/", "/css/", "/js/", "/favicon", "/robots.txt", "/sitemap") {
		return true
	}
	lastSlash := strings.LastIndex(path, "/")
	segment := path
	if lastSlash >= 0 {
		segment = path[lastSlash+1:]
	}
	return strings.HasSuffix(segment, ".css") ||
		strings.HasSuffix(segment, ".js") ||
		strings.HasSuffix(segment, ".png") ||
		strings.HasSuffix(segment, ".jpg") ||
		strings.HasSuffix(segment, ".jpeg") ||
		strings.HasSuffix(segment, ".gif") ||
		strings.HasSuffix(segment, ".svg") ||
		strings.HasSuffix(segment, ".ico") ||
		strings.HasSuffix(segment, ".woff") ||
		strings.HasSuffix(segment, ".woff2")
}

func semanticContainsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if needle != "" && strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func semanticSubjectFromRequest(r *http.Request) (string, string) {
	if r == nil {
		return "", ""
	}
	for _, name := range semanticSubjectHeaderCandidates {
		if value := strings.TrimSpace(r.Header.Get(name)); value != "" {
			return value, "header:" + strings.ToLower(name)
		}
	}
	if username, _, ok := r.BasicAuth(); ok && strings.TrimSpace(username) != "" {
		return username, "basic_auth"
	}
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if subject := semanticJWTSubjectFromAuthorization(authHeader); subject != "" {
		return subject, "bearer_jwt_sub"
	}
	return "", ""
}

func semanticSessionFromRequest(r *http.Request) (string, string) {
	if r == nil {
		return "", ""
	}
	for _, name := range semanticSessionHeaderCandidates {
		if value := strings.TrimSpace(r.Header.Get(name)); value != "" {
			return strings.ToLower(name) + "=" + value, "header:" + strings.ToLower(name)
		}
	}
	cookies := r.Cookies()
	if len(cookies) == 0 {
		return "", ""
	}
	cookieByName := make(map[string]*http.Cookie, len(cookies))
	for _, cookie := range cookies {
		if cookie == nil {
			continue
		}
		cookieByName[strings.ToLower(strings.TrimSpace(cookie.Name))] = cookie
	}
	for _, name := range semanticSessionCookieCandidates {
		cookie := cookieByName[strings.ToLower(name)]
		if cookie == nil {
			continue
		}
		value := strings.TrimSpace(cookie.Value)
		if value == "" {
			continue
		}
		return strings.ToLower(cookie.Name) + "=" + value, "cookie:" + strings.ToLower(cookie.Name)
	}
	return "", ""
}

func semanticJWTSubjectFromAuthorization(authHeader string) string {
	authHeader = strings.TrimSpace(authHeader)
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return ""
	}
	token := strings.TrimSpace(authHeader[len("bearer "):])
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	subject := strings.TrimSpace(fmt.Sprint(claims["sub"]))
	if subject == "" || subject == "<nil>" {
		return ""
	}
	return subject
}

func semanticQueryFingerprint(rawQuery string) string {
	if strings.TrimSpace(rawQuery) == "" {
		return ""
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return semanticFingerprintHash("query", normalizeSemanticFingerprintText(rawQuery))
	}
	normalizedValues := make(map[string][]string, len(values))
	for key, items := range values {
		normalizedKey := strings.ToLower(strings.TrimSpace(key))
		normalizedValues[normalizedKey] = append(normalizedValues[normalizedKey], items...)
	}
	keys := make([]string, 0, len(normalizedValues))
	for key := range normalizedValues {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		sortedValues := append([]string(nil), normalizedValues[key]...)
		sort.Strings(sortedValues)
		normValues := make([]string, 0, len(sortedValues))
		for _, value := range sortedValues {
			norm := normalizeSemanticFingerprintText(value)
			if norm == "" {
				norm = "<empty>"
			}
			normValues = append(normValues, norm)
		}
		parts = append(parts, key+"="+strings.Join(normValues, "|"))
	}
	return semanticFingerprintHash("query", strings.Join(parts, "&"))
}

func semanticFormFingerprint(body []byte, contentType string) string {
	if len(body) == 0 || contentType != "application/x-www-form-urlencoded" {
		return ""
	}
	return semanticQueryFingerprint(string(body))
}

func semanticJSONFingerprint(body []byte, contentType string) string {
	if len(body) == 0 {
		return ""
	}
	if !(contentType == "application/json" || strings.HasSuffix(contentType, "+json") || semanticLooksLikeJSON(body)) {
		return ""
	}
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	return semanticFingerprintHash("json", semanticCanonicalJSONFingerprint(payload, 0))
}

func semanticBodyFingerprint(body []byte, contentType string) string {
	if len(body) == 0 {
		return ""
	}
	switch {
	case contentType == "application/x-www-form-urlencoded":
		return ""
	case contentType == "application/json", strings.HasSuffix(contentType, "+json"), semanticLooksLikeJSON(body):
		return ""
	default:
		return semanticFingerprintHash("body", normalizeSemanticFingerprintText(string(body)))
	}
}

func semanticHeaderFingerprint(header http.Header) string {
	if header == nil {
		return ""
	}
	pairs := make([]string, 0, 3)
	for _, name := range []string{"User-Agent", "Referer", "Content-Type"} {
		value := strings.TrimSpace(header.Get(name))
		if value == "" {
			continue
		}
		pairs = append(pairs, strings.ToLower(name)+"="+normalizeSemanticFingerprintText(value))
	}
	if len(pairs) == 0 {
		return ""
	}
	return semanticFingerprintHash("headers", strings.Join(pairs, "\n"))
}

func semanticCombinedFingerprint(fingerprints semanticFingerprintSet) string {
	parts := make([]string, 0, 5)
	for _, item := range []string{
		fingerprints.QueryHash,
		fingerprints.FormHash,
		fingerprints.JSONHash,
		fingerprints.BodyHash,
		fingerprints.HeaderHash,
	} {
		if item != "" {
			parts = append(parts, item)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return semanticFingerprintHash("combined", strings.Join(parts, "\n"))
}

func semanticFingerprintHash(kind, normalized string) string {
	normalized = strings.TrimSpace(normalized)
	if normalized == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("tukuyomi-semantic-fingerprint-v1|" + kind + "|" + normalized))
	return "semfp:" + kind + ":" + hex.EncodeToString(sum[:8])
}

func normalizeSemanticFingerprintText(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	for i := 0; i < 2; i++ {
		decoded, err := url.QueryUnescape(v)
		if err != nil || decoded == v {
			break
		}
		v = decoded
	}
	v = strings.ToLower(v)
	v = strings.ReplaceAll(v, "\u0000", "")
	v = strings.ReplaceAll(v, "+", " ")
	v = semanticPatternJWT.ReplaceAllString(v, "<jwt>")
	v = semanticPatternEmail.ReplaceAllString(v, "<email>")
	v = semanticPatternUUID.ReplaceAllString(v, "<uuid>")
	v = semanticPatternLongHex.ReplaceAllString(v, "<hex>")
	v = semanticPatternNumber.ReplaceAllString(v, "<num>")
	v = collapseRepeatedSemanticFingerprintPunctuation(v)
	v = semanticPatternWhitespace.ReplaceAllString(v, " ")
	v = strings.TrimSpace(v)
	if len(v) > 1024 {
		v = v[:1024]
	}
	return v
}

func semanticCanonicalJSONFingerprint(value any, depth int) string {
	if depth >= 6 {
		return "<depth>"
	}
	switch current := value.(type) {
	case map[string]any:
		if len(current) == 0 {
			return "{}"
		}
		keys := make([]string, 0, len(current))
		for key := range current {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if len(keys) > 32 {
			keys = keys[:32]
		}
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			parts = append(parts, strconv.Quote(strings.ToLower(strings.TrimSpace(key)))+":"+semanticCanonicalJSONFingerprint(current[key], depth+1))
		}
		return "{" + strings.Join(parts, ",") + "}"
	case []any:
		if len(current) == 0 {
			return "[]"
		}
		limit := len(current)
		if limit > 16 {
			limit = 16
		}
		parts := make([]string, 0, limit)
		for i := 0; i < limit; i++ {
			parts = append(parts, semanticCanonicalJSONFingerprint(current[i], depth+1))
		}
		return "[" + strings.Join(parts, ",") + "]"
	case string:
		return strconv.Quote(normalizeSemanticFingerprintText(current))
	case float64:
		return `"<num>"`
	case bool:
		if current {
			return "true"
		}
		return "false"
	case nil:
		return "null"
	default:
		return strconv.Quote(normalizeSemanticFingerprintText(fmt.Sprint(current)))
	}
}

func semanticLooksLikeJSON(body []byte) bool {
	trimmed := strings.TrimSpace(string(body))
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

func semanticNormalizedContentType(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if idx := strings.IndexByte(raw, ';'); idx >= 0 {
		raw = raw[:idx]
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

func collapseRepeatedSemanticFingerprintPunctuation(raw string) string {
	if raw == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(raw))
	var prev rune
	prevRepeatable := false
	for _, current := range raw {
		repeatable := strings.ContainsRune("/._:-=", current)
		if repeatable && prevRepeatable && current == prev {
			continue
		}
		b.WriteRune(current)
		prev = current
		prevRepeatable = repeatable
	}
	return b.String()
}
