package cacheconf

type Match struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type RuleDTO struct {
	Kind    string   `json:"kind"`
	Match   Match    `json:"match"`
	Methods []string `json:"methods,omitempty"`
	TTL     int      `json:"ttl,omitempty"`
	Vary    []string `json:"vary,omitempty"`
}

type RulesDTO struct {
	ETag   string    `json:"etag"`
	Raw    string    `json:"raw"`
	Rules  []RuleDTO `json:"rules"`
	Errors []string  `json:"errors"`
}
