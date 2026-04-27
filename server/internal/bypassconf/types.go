package bypassconf

type Action int

const (
	ACTION_NONE Action = iota
	ACTION_BYPASS
	ACTION_RULE
)

type Entry struct {
	Path      string `json:"path"`
	ExtraRule string `json:"extra_rule,omitempty"`
}

type Scope struct {
	Entries []Entry `json:"entries"`
}

type File struct {
	Default Scope            `json:"default"`
	Hosts   map[string]Scope `json:"hosts,omitempty"`
}

type MatchResult struct {
	Action    Action
	ExtraRule string
}
