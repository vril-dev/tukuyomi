package cacheconf

type Match struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type ScopeDTO struct {
	Rules []RuleDTO `json:"rules"`
}

type RuleDTO struct {
	Kind    string   `json:"kind"`
	Match   Match    `json:"match"`
	Methods []string `json:"methods,omitempty"`
	TTL     int      `json:"ttl,omitempty"`
	Vary    []string `json:"vary,omitempty"`
}

type RulesFile struct {
	Default ScopeDTO            `json:"default"`
	Hosts   map[string]ScopeDTO `json:"hosts,omitempty"`
}

type RulesDTO struct {
	ETag    string    `json:"etag"`
	Raw     string    `json:"raw"`
	Rules   RulesFile `json:"rules"`
	Errors  []string  `json:"errors"`
	SavedAt string    `json:"saved_at,omitempty"`
}
