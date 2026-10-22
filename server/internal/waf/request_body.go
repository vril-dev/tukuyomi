package waf

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"strings"

	"tukuyomi/internal/config"
)

// Rule IDs 1090200-1090299 are reserved for rules that tukuyomi appends after
// the configured rule assets.
const (
	requestBodyRuleIDMin           = 1090200
	requestBodyRuleIDMax           = 1090299
	requestBodyRuleJSONProcessor   = 1090201
	requestBodyRuleXMLProcessor    = 1090202
	requestBodyRuleBodyError       = 1090210
	requestBodyRuleMultipartStrict = 1090211
	requestBodyRuleArgumentsLimit  = 1090212
	requestBodyRuleOversize        = 1090220
)

// builtinRequestBodyDirectives selects the JSON and XML body processors, which
// Coraza only enables through ctl actions, and flags parser and argument-limit
// failures for the Go-side request body policy. The flag rules never block.
const builtinRequestBodyDirectives = `
SecRequestBodyAccess On
SecRule REQUEST_HEADERS:Content-Type "@rx ^application/(?:[a-z0-9.+-]+\+)?json(?:\s*;.*)?$" "id:1090201,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQUEST_HEADERS:Content-Type "@rx ^(?:application|text)/(?:[a-z0-9.+-]+\+)?xml(?:\s*;.*)?$" "id:1090202,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQBODY_ERROR "!@eq 0" "id:1090210,phase:2,t:none,pass,nolog"
SecRule MULTIPART_STRICT_ERROR "!@eq 0" "id:1090211,phase:2,t:none,pass,nolog"
SecRule ARGUMENTS_LIMIT_REACHED "!@eq 0" "id:1090212,phase:2,t:none,pass,nolog"
`

// RequestBodyResult describes how the request body took part in an inspection.
type RequestBodyResult struct {
	Inspected bool
	Bytes     int
	Truncated bool
	Oversize  bool
	// Reason names the body policy that blocked or, in detect mode, would
	// have blocked the request: rule, oversize, parse_error or arguments_limit.
	Reason string
	// DryRun is the interruption that enforce mode would have applied.
	DryRun *Interruption
}

// RequestBodyReplayer is implemented by request bodies that can serve an
// already-read prefix again without counting it twice.
type RequestBodyReplayer interface {
	ReplayRequestBodyPrefix(prefix []byte)
}

type requestBodyPolicy struct {
	Mode           string
	InspectLimit   int64
	OversizeAction string
	SkipBody       bool
}

// RequestBodyOverride narrows the process-wide request body policy for the
// requests of one route.
type RequestBodyOverride struct {
	Skip              bool
	InspectLimitBytes int64
}

// WithRequestBodyOverride returns an engine that applies o on top of the
// process-wide request body policy.
func WithRequestBodyOverride(e Engine, o RequestBodyOverride) Engine {
	ce, ok := e.(corazaEngine)
	if !ok {
		return e
	}
	ce.bodyOverride = &o
	return ce
}

func (p requestBodyPolicy) withOverride(o RequestBodyOverride) requestBodyPolicy {
	if o.Skip {
		p.SkipBody = true
	}
	if o.InspectLimitBytes >= config.MinWAFRequestBodyInspectLimit && o.InspectLimitBytes <= config.MaxWAFRequestBodyInspectLimit {
		p.InspectLimit = o.InspectLimitBytes
	}
	return p
}

type requestBodySample struct {
	Eligible  bool
	Data      []byte
	Truncated bool
	Oversize  bool
}

const (
	requestBodyReasonRule           = "rule"
	requestBodyReasonOversize       = "oversize"
	requestBodyReasonParseError     = "parse_error"
	requestBodyReasonArgumentsLimit = "arguments_limit"
)

type requestBodySignals struct {
	BodyError       bool
	MultipartStrict bool
	ArgumentsLimit  bool
}

func currentRequestBodyPolicy() requestBodyPolicy {
	policy := requestBodyPolicy{
		Mode:           strings.ToLower(strings.TrimSpace(config.WAFRequestBodyMode)),
		InspectLimit:   config.WAFRequestBodyInspectLimitBytes,
		OversizeAction: strings.ToLower(strings.TrimSpace(config.WAFRequestBodyOversizeAction)),
	}
	switch policy.Mode {
	case config.WAFRequestBodyModeEnforce, config.WAFRequestBodyModeDetect, config.WAFRequestBodyModeOff:
	default:
		policy.Mode = config.DefaultWAFRequestBodyMode
	}
	if policy.InspectLimit < config.MinWAFRequestBodyInspectLimit || policy.InspectLimit > config.MaxWAFRequestBodyInspectLimit {
		policy.InspectLimit = config.DefaultWAFRequestBodyInspectLimit
	}
	switch policy.OversizeAction {
	case config.WAFRequestBodyOversizeInspectPrefix, config.WAFRequestBodyOversizeReject:
	default:
		policy.OversizeAction = config.DefaultWAFRequestBodyOversizeAction
	}
	return policy
}

// readInspectionBody reads at most InspectLimit+1 bytes of a supported body and
// puts everything it read back in front of the unread remainder, so the
// upstream receives the complete body.
func readInspectionBody(req *http.Request, policy requestBodyPolicy) (requestBodySample, error) {
	var sample requestBodySample
	if policy.Mode == config.WAFRequestBodyModeOff || policy.SkipBody || req == nil || req.Body == nil || req.Body == http.NoBody {
		return sample, nil
	}
	if req.ContentLength == 0 || !requestBodyContentTypeSupported(req.Header.Values("Content-Type")) {
		return sample, nil
	}
	sample.Eligible = true
	if req.ContentLength > policy.InspectLimit {
		sample.Oversize = true
		if policy.OversizeAction == config.WAFRequestBodyOversizeReject && policy.Mode == config.WAFRequestBodyModeEnforce {
			return sample, nil
		}
	}
	read, err := readRequestBodyPrefix(req, policy.InspectLimit+1)
	replayRequestBodyPrefix(req, read)
	if int64(len(read)) > policy.InspectLimit {
		sample.Oversize = true
		sample.Truncated = true
		read = read[:policy.InspectLimit]
	}
	if err != nil {
		sample.Truncated = true
	}
	sample.Data = read
	return sample, err
}

// readRequestBodyPrefix reads at most limit bytes. A declared Content-Length
// sizes the buffer once instead of letting it grow while reading.
func readRequestBodyPrefix(req *http.Request, limit int64) ([]byte, error) {
	if req.ContentLength <= 0 {
		return io.ReadAll(io.LimitReader(req.Body, limit))
	}
	buf := make([]byte, min(req.ContentLength, limit))
	n, err := io.ReadFull(req.Body, buf)
	return buf[:n], err
}

func replayRequestBodyPrefix(req *http.Request, prefix []byte) {
	if len(prefix) == 0 {
		return
	}
	if replayer, ok := req.Body.(RequestBodyReplayer); ok {
		replayer.ReplayRequestBodyPrefix(prefix)
		return
	}
	req.Body = &prefixReplayBody{prefix: bytes.NewReader(prefix), rest: req.Body}
}

type prefixReplayBody struct {
	prefix *bytes.Reader
	rest   io.ReadCloser
}

func (b *prefixReplayBody) Read(p []byte) (int, error) {
	if b.prefix.Len() > 0 {
		return b.prefix.Read(p)
	}
	return b.rest.Read(p)
}

func (b *prefixReplayBody) Close() error {
	return b.rest.Close()
}

// requestBodyContentTypeSupported reports whether Coraza has a body processor
// for the first Content-Type header, which is the one Coraza uses.
func requestBodyContentTypeSupported(values []string) bool {
	if len(values) == 0 {
		return false
	}
	mediaType := strings.TrimSpace(values[0])
	if parsed, _, err := mime.ParseMediaType(mediaType); err == nil {
		mediaType = parsed
	} else if idx := strings.IndexByte(mediaType, ';'); idx >= 0 {
		mediaType = strings.TrimSpace(mediaType[:idx])
	}
	mediaType = strings.ToLower(mediaType)
	switch mediaType {
	case "application/x-www-form-urlencoded", "multipart/form-data", "application/json", "application/xml", "text/xml":
		return true
	}
	return strings.HasSuffix(mediaType, "+json") || strings.HasSuffix(mediaType, "+xml")
}

// splitRequestBodySignals removes the reserved built-in rules from the matches
// and reports which flag rules fired.
func splitRequestBodySignals(matches []Match) ([]Match, requestBodySignals) {
	var signals requestBodySignals
	out := matches[:0]
	for _, matched := range matches {
		if matched.RuleID < requestBodyRuleIDMin || matched.RuleID > requestBodyRuleIDMax {
			out = append(out, matched)
			continue
		}
		switch matched.RuleID {
		case requestBodyRuleBodyError:
			signals.BodyError = true
		case requestBodyRuleMultipartStrict:
			signals.MultipartStrict = true
		case requestBodyRuleArgumentsLimit:
			signals.ArgumentsLimit = true
		}
	}
	return out, signals
}
