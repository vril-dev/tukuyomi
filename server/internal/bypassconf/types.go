package bypassconf

type Action int

const (
	ACTION_NONE Action = iota
	ACTION_BYPASS
	ACTION_RULE
)

// RequestBodySkip turns off request body inspection for matching paths.
// An empty RequestBody inherits the process-wide waf.request_body setting.
const RequestBodySkip = "skip"

type Entry struct {
	Path                         string `json:"path"`
	ExtraRule                    string `json:"extra_rule,omitempty"`
	RequestBody                  string `json:"request_body,omitempty"`
	RequestBodyInspectLimitBytes int64  `json:"request_body_inspect_limit_bytes,omitempty"`
}

type Scope struct {
	Entries []Entry `json:"entries"`
}

type File struct {
	Default Scope            `json:"default"`
	Hosts   map[string]Scope `json:"hosts,omitempty"`
}

// RequestBodyOptions overrides the process-wide request body inspection for
// one request path.
type RequestBodyOptions struct {
	Skip              bool
	InspectLimitBytes int64
}

type MatchResult struct {
	Action      Action
	ExtraRule   string
	RequestBody *RequestBodyOptions
}

func (e Entry) hasRequestBodyOptions() bool {
	return e.RequestBody != "" || e.RequestBodyInspectLimitBytes != 0
}
