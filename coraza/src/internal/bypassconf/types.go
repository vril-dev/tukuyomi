package bypassconf

type Action int

const (
	ACTION_NONE Action = iota
	ACTION_BYPASS
	ACTION_RULE
)

type Entry struct {
	Path      string
	ExtraRule string
}

type MatchResult struct {
	Action    Action
	ExtraRule string
}
