package botdecisions

import "sync"

const DefaultLimit = 100

type Record struct {
	Timestamp  string   `json:"timestamp"`
	RequestID  string   `json:"request_id,omitempty"`
	ClientIP   string   `json:"client_ip,omitempty"`
	Country    string   `json:"country,omitempty"`
	Method     string   `json:"method,omitempty"`
	Path       string   `json:"path,omitempty"`
	UserAgent  string   `json:"user_agent,omitempty"`
	HostScope  string   `json:"host_scope,omitempty"`
	FlowPolicy string   `json:"flow_policy,omitempty"`
	Action     string   `json:"action"`
	DryRun     bool     `json:"dry_run,omitempty"`
	Status     int      `json:"status,omitempty"`
	Mode       string   `json:"mode,omitempty"`
	RiskScore  int      `json:"risk_score"`
	Signals    []string `json:"signals,omitempty"`
}

type History struct {
	mu      sync.Mutex
	limit   int
	records []Record
}

func NewHistory(limit int) *History {
	if limit <= 0 {
		limit = DefaultLimit
	}
	return &History{limit: limit}
}

func (h *History) Add(record Record) {
	if h == nil {
		return
	}
	if record.Action == "" {
		record.Action = "allow"
	}
	record = cloneRecord(record)

	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, record)
	if len(h.records) > h.limit {
		h.records = append([]Record(nil), h.records[len(h.records)-h.limit:]...)
	}
}

func (h *History) Recent(limit int) []Record {
	if h == nil {
		return nil
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > h.limit {
		limit = h.limit
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.records) == 0 {
		return nil
	}
	start := len(h.records) - limit
	if start < 0 {
		start = 0
	}
	src := h.records[start:]
	out := make([]Record, 0, len(src))
	for i := len(src) - 1; i >= 0; i-- {
		out = append(out, cloneRecord(src[i]))
	}
	return out
}

func (h *History) Latest() (Record, bool) {
	if h == nil {
		return Record{}, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.records) == 0 {
		return Record{}, false
	}
	return cloneRecord(h.records[len(h.records)-1]), true
}

func (h *History) Reset() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = nil
}

func cloneRecord(in Record) Record {
	in.Signals = append([]string(nil), in.Signals...)
	return in
}
