package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	notificationCategorySecurity = "security"
	notificationCategoryUpstream = "upstream"

	notificationStateQuiet     = "quiet"
	notificationStateActive    = "active"
	notificationStateEscalated = "escalated"

	notificationSinkTypeWebhook = "webhook"
	notificationSinkTypeEmail   = "email"

	defaultNotificationCooldownSeconds    = 900
	defaultNotificationUpstreamWindow     = 60
	defaultNotificationUpstreamActive     = 3
	defaultNotificationUpstreamEscalated  = 10
	defaultNotificationSecurityWindow     = 300
	defaultNotificationSecurityActive     = 20
	defaultNotificationSecurityEscalated  = 100
	defaultNotificationWebhookTimeout     = 5
	defaultNotificationEmailSubjectPrefix = "[tukuyomi]"
	defaultNotificationTickerInterval     = time.Second
	maxNotificationWindowSeconds          = 3600
	maxNotificationTopPathCount           = 3
)

var defaultNotificationSecuritySources = []string{
	"waf_block",
	"rate_limited",
	"semantic_anomaly",
	"bot_challenge",
	"ip_reputation",
}

type notificationConfig struct {
	Enabled         bool                        `json:"enabled"`
	CooldownSeconds int                         `json:"cooldown_seconds,omitempty"`
	Sinks           []notificationSinkConfig    `json:"sinks,omitempty"`
	Upstream        notificationTriggerConfig   `json:"upstream,omitempty"`
	Security        notificationSecurityTrigger `json:"security,omitempty"`
}

type notificationTriggerConfig struct {
	Enabled            bool `json:"enabled"`
	WindowSeconds      int  `json:"window_seconds,omitempty"`
	ActiveThreshold    int  `json:"active_threshold,omitempty"`
	EscalatedThreshold int  `json:"escalated_threshold,omitempty"`
}

type notificationSecurityTrigger struct {
	Enabled            bool     `json:"enabled"`
	WindowSeconds      int      `json:"window_seconds,omitempty"`
	ActiveThreshold    int      `json:"active_threshold,omitempty"`
	EscalatedThreshold int      `json:"escalated_threshold,omitempty"`
	Sources            []string `json:"sources,omitempty"`
}

type notificationSinkConfig struct {
	Name          string            `json:"name,omitempty"`
	Type          string            `json:"type"`
	Enabled       bool              `json:"enabled"`
	TimeoutSec    int               `json:"timeout_seconds,omitempty"`
	WebhookURL    string            `json:"webhook_url,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	SMTPAddress   string            `json:"smtp_address,omitempty"`
	SMTPUsername  string            `json:"smtp_username,omitempty"`
	SMTPPassword  string            `json:"smtp_password,omitempty"`
	From          string            `json:"from,omitempty"`
	To            []string          `json:"to,omitempty"`
	SubjectPrefix string            `json:"subject_prefix,omitempty"`
}

type runtimeNotificationConfig struct {
	Raw notificationConfig
}

type notificationObservation struct {
	Category   string
	Source     string
	Path       string
	RemoteIP   string
	RequestID  string
	StatusCode int
	Score      int
	ObservedAt time.Time
}

type notificationStats struct {
	Attempts atomic.Uint64
	Sent     atomic.Uint64
	Failed   atomic.Uint64
}

type notificationManager struct {
	mu              sync.Mutex
	productLabel    string
	cfg             notificationConfig
	states          map[string]*notificationAlertState
	stats           notificationStats
	lastDispatchErr string
	tickerOnce      sync.Once
	httpClientMu    sync.Mutex
	httpClients     map[int]*http.Client
}

type notificationAlertState struct {
	Key            string
	Category       string
	Source         string
	Status         string
	CurrentBucket  int64
	CurrentSummary notificationWindowSummary
	LastSummary    notificationSummaryView
	LastTransition time.Time
	LastSentAt     time.Time
}

type notificationWindowSummary struct {
	Count      int
	UniqueIPs  map[string]struct{}
	PathCounts map[string]int
	LastStatus int
	MaxScore   int
	LastReqID  string
}

type notificationSummaryView struct {
	Count      int      `json:"count"`
	UniqueIPs  int      `json:"unique_ips"`
	TopPaths   []string `json:"top_paths,omitempty"`
	LastStatus int      `json:"last_status,omitempty"`
	MaxScore   int      `json:"max_score,omitempty"`
	LastReqID  string   `json:"last_request_id,omitempty"`
}

type notificationStatusSnapshot struct {
	Enabled          bool                        `json:"enabled"`
	Product          string                      `json:"product"`
	SinkCount        int                         `json:"sink_count"`
	EnabledSinkCount int                         `json:"enabled_sink_count"`
	ActiveAlerts     int                         `json:"active_alerts"`
	Attempted        uint64                      `json:"attempted"`
	Sent             uint64                      `json:"sent"`
	Failed           uint64                      `json:"failed"`
	LastDispatchErr  string                      `json:"last_dispatch_error,omitempty"`
	Alerts           []notificationAlertSnapshot `json:"alerts,omitempty"`
}

type notificationAlertSnapshot struct {
	Key            string                  `json:"key"`
	Category       string                  `json:"category"`
	Source         string                  `json:"source"`
	Status         string                  `json:"status"`
	LastTransition string                  `json:"last_transition,omitempty"`
	LastSentAt     string                  `json:"last_sent_at,omitempty"`
	LastSummary    notificationSummaryView `json:"last_summary"`
}

type notificationDispatch struct {
	Product     string         `json:"product"`
	AlertKey    string         `json:"alert_key"`
	Category    string         `json:"category"`
	Source      string         `json:"source"`
	State       string         `json:"state"`
	Title       string         `json:"title"`
	Summary     string         `json:"summary"`
	ObservedAt  string         `json:"observed_at"`
	WindowSecs  int            `json:"window_seconds,omitempty"`
	Count       int            `json:"count,omitempty"`
	UniqueIPs   int            `json:"unique_ips,omitempty"`
	TopPaths    []string       `json:"top_paths,omitempty"`
	StatusCode  int            `json:"status_code,omitempty"`
	MaxScore    int            `json:"max_score,omitempty"`
	LastRequest string         `json:"last_request_id,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
}

var (
	notificationMu         sync.RWMutex
	notificationPath       string
	notificationRuntime    *runtimeNotificationConfig
	notificationRuntimeMgr = newNotificationManager("tukuyomi")
)

func SetNotificationProductLabel(label string) {
	notificationRuntimeMgr.SetProductLabel(label)
}

func InitNotifications(path string) error {
	target := strings.TrimSpace(path)
	if target == "" {
		return fmt.Errorf("notification path is empty")
	}
	notificationMu.Lock()
	notificationPath = target
	notificationMu.Unlock()

	if store := getLogsStatsStore(); store != nil {
		raw, _, found, err := loadRuntimePolicyJSONConfig(store, mustPolicyJSONSpec(notificationConfigBlobKey), normalizeNotificationPolicyRaw, "notification rules")
		if err != nil {
			return fmt.Errorf("read notification config db: %w", err)
		}
		if !found {
			return fmt.Errorf("normalized notification config missing in db; run make db-import before removing seed files")
		}
		return applyNotificationPolicyRaw(raw)
	}

	if err := ensureNotificationFile(target); err != nil {
		return err
	}
	return ReloadNotifications()
}

func GetNotificationsPath() string {
	notificationMu.RLock()
	defer notificationMu.RUnlock()
	return notificationPath
}

func GetNotificationConfig() notificationConfig {
	notificationMu.RLock()
	defer notificationMu.RUnlock()
	if notificationRuntime == nil {
		return notificationConfig{}
	}
	return notificationRuntime.Raw
}

func GetNotificationStatus() notificationStatusSnapshot {
	return notificationRuntimeMgr.Status()
}

func ReloadNotifications() error {
	path := GetNotificationsPath()
	if path == "" {
		return fmt.Errorf("notification path is empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	rt, err := buildNotificationRuntimeFromRaw(raw)
	if err != nil {
		return err
	}
	notificationMu.Lock()
	notificationRuntime = rt
	notificationMu.Unlock()
	notificationRuntimeMgr.Update(rt.Raw)
	return nil
}

func ValidateNotificationRaw(raw string) (*runtimeNotificationConfig, error) {
	return buildNotificationRuntimeFromRaw([]byte(raw))
}

func TestNotificationSend(note string) error {
	return notificationRuntimeMgr.TestSend(strings.TrimSpace(note))
}

func ObserveNotificationLogEvent(event map[string]any) {
	if len(event) == 0 {
		return
	}
	name := strings.TrimSpace(stringValue(event["event"]))
	category := ""
	switch name {
	case "proxy_error":
		category = notificationCategoryUpstream
	case "waf_block", "rate_limited", "semantic_anomaly", "bot_challenge", "ip_reputation":
		category = notificationCategorySecurity
	default:
		return
	}
	notificationRuntimeMgr.Observe(notificationObservation{
		Category:   category,
		Source:     name,
		Path:       stringValue(event["path"]),
		RemoteIP:   stringValue(event["ip"]),
		RequestID:  stringValue(event["req_id"]),
		StatusCode: intValue(event["status"]),
		Score:      maxNotificationInt(intValue(event["score"]), intValue(event["risk_score"])),
		ObservedAt: time.Now().UTC(),
	})
}

func (m *notificationManager) SetProductLabel(label string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := strings.TrimSpace(label)
	if v == "" {
		return
	}
	m.productLabel = v
}

func newNotificationManager(product string) *notificationManager {
	m := &notificationManager{
		productLabel: strings.TrimSpace(product),
		states:       make(map[string]*notificationAlertState),
		httpClients:  make(map[int]*http.Client),
	}
	m.start()
	return m
}

func (m *notificationManager) start() {
	m.tickerOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(defaultNotificationTickerInterval)
			defer ticker.Stop()
			for range ticker.C {
				m.flushExpired(time.Now().UTC())
			}
		}()
	})
}

func (m *notificationManager) Update(cfg notificationConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cfg
	m.states = make(map[string]*notificationAlertState)
	m.lastDispatchErr = ""
}

func (m *notificationManager) Status() notificationStatusSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	alerts := make([]notificationAlertSnapshot, 0, len(m.states))
	active := 0
	for _, state := range m.states {
		if state == nil || state.Status == notificationStateQuiet {
			continue
		}
		active++
		alerts = append(alerts, notificationAlertSnapshot{
			Key:            state.Key,
			Category:       state.Category,
			Source:         state.Source,
			Status:         state.Status,
			LastTransition: formatOptionalTime(state.LastTransition),
			LastSentAt:     formatOptionalTime(state.LastSentAt),
			LastSummary:    state.LastSummary,
		})
	}
	sort.Slice(alerts, func(i, j int) bool {
		if alerts[i].Category != alerts[j].Category {
			return alerts[i].Category < alerts[j].Category
		}
		return alerts[i].Source < alerts[j].Source
	})

	return notificationStatusSnapshot{
		Enabled:          m.cfg.Enabled,
		Product:          m.productLabel,
		SinkCount:        len(m.cfg.Sinks),
		EnabledSinkCount: countEnabledNotificationSinks(m.cfg.Sinks),
		ActiveAlerts:     active,
		Attempted:        m.stats.Attempts.Load(),
		Sent:             m.stats.Sent.Load(),
		Failed:           m.stats.Failed.Load(),
		LastDispatchErr:  m.lastDispatchErr,
		Alerts:           alerts,
	}
}

func (m *notificationManager) TestSend(note string) error {
	m.mu.Lock()
	cfg := m.cfg
	product := m.productLabel
	m.mu.Unlock()

	if countEnabledNotificationSinks(cfg.Sinks) == 0 {
		return fmt.Errorf("no enabled notification sinks configured")
	}
	if note == "" {
		note = "notification test"
	}
	dispatch := notificationDispatch{
		Product:    product,
		AlertKey:   "test",
		Category:   "test",
		Source:     "manual",
		State:      "test",
		Title:      fmt.Sprintf("[%s] notification test", product),
		Summary:    note,
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Details: map[string]any{
			"trigger": "manual_test",
		},
	}
	return m.dispatch(cfg, dispatch)
}

func (m *notificationManager) Observe(obs notificationObservation) {
	if obs.ObservedAt.IsZero() {
		obs.ObservedAt = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.cfg.Enabled {
		return
	}
	trigger, ok := notificationTriggerForObservation(m.cfg, obs)
	if !ok {
		return
	}

	key := obs.Category + ":" + obs.Source
	state := m.states[key]
	if state == nil {
		state = &notificationAlertState{
			Key:      key,
			Category: obs.Category,
			Source:   obs.Source,
			Status:   notificationStateQuiet,
		}
		m.states[key] = state
	}

	windowSeconds := trigger.WindowSeconds
	bucket := obs.ObservedAt.Unix() / int64(windowSeconds)
	m.advanceStateLocked(state, trigger, bucket, obs.ObservedAt)
	if state.CurrentBucket == 0 {
		state.CurrentBucket = bucket
	}
	if state.CurrentBucket != bucket {
		state.CurrentBucket = bucket
		state.CurrentSummary = notificationWindowSummary{}
	}
	observeNotificationSummary(&state.CurrentSummary, obs)
}

func (m *notificationManager) flushExpired(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, state := range m.states {
		if state == nil {
			continue
		}
		trigger, ok := notificationTriggerForCategory(m.cfg, state.Category, state.Source)
		if !ok {
			continue
		}
		bucket := now.Unix() / int64(trigger.WindowSeconds)
		m.advanceStateLocked(state, trigger, bucket, now)
	}
}

func (m *notificationManager) advanceStateLocked(state *notificationAlertState, trigger notificationTriggerConfig, nextBucket int64, now time.Time) {
	if state == nil || state.CurrentBucket == 0 || state.CurrentBucket >= nextBucket {
		return
	}
	prevStatus := state.Status
	summaryView := notificationSummaryFromWindow(state.CurrentSummary)
	nextStatus := classifyNotificationState(trigger, summaryView.Count)
	state.LastSummary = summaryView
	state.CurrentSummary = notificationWindowSummary{}
	state.CurrentBucket = nextBucket
	if nextStatus == prevStatus {
		return
	}
	state.Status = nextStatus
	state.LastTransition = now
	if m.shouldDispatchLocked(state, now) {
		dispatch := buildNotificationDispatch(m.productLabel, state, summaryView, trigger.WindowSeconds)
		state.LastSentAt = now
		cfg := m.cfg
		go m.dispatchAsync(cfg, dispatch)
	}
}

func (m *notificationManager) shouldDispatchLocked(state *notificationAlertState, now time.Time) bool {
	if state == nil {
		return false
	}
	if countEnabledNotificationSinks(m.cfg.Sinks) == 0 {
		return false
	}
	if state.LastSentAt.IsZero() {
		return true
	}
	return now.Sub(state.LastSentAt) >= time.Duration(m.cfg.CooldownSeconds)*time.Second
}

func (m *notificationManager) dispatchAsync(cfg notificationConfig, dispatch notificationDispatch) {
	err := m.dispatch(cfg, dispatch)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.stats.Failed.Add(1)
		m.lastDispatchErr = err.Error()
		return
	}
	m.stats.Sent.Add(1)
	m.lastDispatchErr = ""
}

func (m *notificationManager) dispatch(cfg notificationConfig, dispatch notificationDispatch) error {
	m.stats.Attempts.Add(1)
	var errs []string
	for _, sink := range cfg.Sinks {
		if !sink.Enabled {
			continue
		}
		switch sink.Type {
		case notificationSinkTypeWebhook:
			if err := m.sendWebhook(sink, dispatch); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", sinkDisplayName(sink), err))
			}
		case notificationSinkTypeEmail:
			if err := sendNotificationEmail(sink, dispatch); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", sinkDisplayName(sink), err))
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func (m *notificationManager) sendWebhook(sink notificationSinkConfig, dispatch notificationDispatch) error {
	body, err := json.Marshal(dispatch)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, sink.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range sink.Headers {
		if strings.TrimSpace(k) == "" {
			continue
		}
		req.Header.Set(k, v)
	}
	res, err := m.httpClient(sink.TimeoutSec).Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("unexpected webhook status: %d", res.StatusCode)
	}
	return nil
}

func (m *notificationManager) httpClient(timeoutSec int) *http.Client {
	if timeoutSec <= 0 {
		timeoutSec = defaultNotificationWebhookTimeout
	}
	m.httpClientMu.Lock()
	defer m.httpClientMu.Unlock()
	if c := m.httpClients[timeoutSec]; c != nil {
		return c
	}
	c := &http.Client{Timeout: time.Duration(timeoutSec) * time.Second}
	m.httpClients[timeoutSec] = c
	return c
}

func sendNotificationEmail(sink notificationSinkConfig, dispatch notificationDispatch) error {
	host, _, found := strings.Cut(strings.TrimSpace(sink.SMTPAddress), ":")
	if !found || strings.TrimSpace(host) == "" {
		return fmt.Errorf("smtp_address must include host:port")
	}
	to := make([]string, 0, len(sink.To))
	for _, addr := range sink.To {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		to = append(to, addr)
	}
	if len(to) == 0 {
		return fmt.Errorf("email recipients are empty")
	}
	auth := smtp.Auth(nil)
	if sink.SMTPUsername != "" {
		auth = smtp.PlainAuth("", sink.SMTPUsername, sink.SMTPPassword, host)
	}
	subjectPrefix := strings.TrimSpace(sink.SubjectPrefix)
	if subjectPrefix == "" {
		subjectPrefix = defaultNotificationEmailSubjectPrefix
	}
	var msg strings.Builder
	msg.WriteString("From: " + sink.From + "\r\n")
	msg.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	msg.WriteString("Subject: " + subjectPrefix + " " + dispatch.Title + "\r\n")
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(dispatch.Summary + "\n\n")
	msg.WriteString("Category: " + dispatch.Category + "\n")
	msg.WriteString("Source: " + dispatch.Source + "\n")
	msg.WriteString("State: " + dispatch.State + "\n")
	if dispatch.WindowSecs > 0 {
		msg.WriteString(fmt.Sprintf("Window: %ds\n", dispatch.WindowSecs))
	}
	if dispatch.Count > 0 {
		msg.WriteString(fmt.Sprintf("Count: %d\n", dispatch.Count))
	}
	if dispatch.UniqueIPs > 0 {
		msg.WriteString(fmt.Sprintf("Unique IPs: %d\n", dispatch.UniqueIPs))
	}
	if len(dispatch.TopPaths) > 0 {
		msg.WriteString("Top paths: " + strings.Join(dispatch.TopPaths, ", ") + "\n")
	}
	if dispatch.StatusCode > 0 {
		msg.WriteString(fmt.Sprintf("Status code: %d\n", dispatch.StatusCode))
	}
	if dispatch.MaxScore > 0 {
		msg.WriteString(fmt.Sprintf("Max score: %d\n", dispatch.MaxScore))
	}
	if dispatch.LastRequest != "" {
		msg.WriteString("Last request: " + dispatch.LastRequest + "\n")
	}
	return smtp.SendMail(sink.SMTPAddress, auth, sink.From, to, []byte(msg.String()))
}

func buildNotificationRuntimeFromRaw(raw []byte) (*runtimeNotificationConfig, error) {
	var cfg notificationConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	cfg = normalizeNotificationConfig(cfg)
	if err := validateNotificationConfig(cfg); err != nil {
		return nil, err
	}
	return &runtimeNotificationConfig{Raw: cfg}, nil
}

func normalizeNotificationConfig(cfg notificationConfig) notificationConfig {
	if cfg.CooldownSeconds <= 0 {
		cfg.CooldownSeconds = defaultNotificationCooldownSeconds
	}
	cfg.Upstream = normalizeNotificationTrigger(cfg.Upstream, defaultNotificationUpstreamWindow, defaultNotificationUpstreamActive, defaultNotificationUpstreamEscalated)
	cfg.Security = normalizeNotificationSecurityTrigger(cfg.Security)
	for i := range cfg.Sinks {
		cfg.Sinks[i] = normalizeNotificationSink(cfg.Sinks[i], i)
	}
	return cfg
}

func normalizeNotificationTrigger(cfg notificationTriggerConfig, windowSec, active, escalated int) notificationTriggerConfig {
	if cfg.WindowSeconds <= 0 {
		cfg.WindowSeconds = windowSec
	}
	if cfg.ActiveThreshold <= 0 {
		cfg.ActiveThreshold = active
	}
	if cfg.EscalatedThreshold <= 0 {
		cfg.EscalatedThreshold = escalated
	}
	return cfg
}

func normalizeNotificationSecurityTrigger(cfg notificationSecurityTrigger) notificationSecurityTrigger {
	if cfg.WindowSeconds <= 0 {
		cfg.WindowSeconds = defaultNotificationSecurityWindow
	}
	if cfg.ActiveThreshold <= 0 {
		cfg.ActiveThreshold = defaultNotificationSecurityActive
	}
	if cfg.EscalatedThreshold <= 0 {
		cfg.EscalatedThreshold = defaultNotificationSecurityEscalated
	}
	cfg.Sources = normalizeNotificationSources(cfg.Sources)
	return cfg
}

func normalizeNotificationSources(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		v = strings.ToLower(v)
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	if len(out) > 0 {
		return out
	}
	return append([]string(nil), defaultNotificationSecuritySources...)
}

func normalizeNotificationSink(cfg notificationSinkConfig, idx int) notificationSinkConfig {
	cfg.Name = strings.TrimSpace(cfg.Name)
	if cfg.Name == "" {
		cfg.Name = fmt.Sprintf("sink-%d", idx+1)
	}
	cfg.Type = strings.ToLower(strings.TrimSpace(cfg.Type))
	if cfg.TimeoutSec <= 0 {
		cfg.TimeoutSec = defaultNotificationWebhookTimeout
	}
	cfg.WebhookURL = strings.TrimSpace(cfg.WebhookURL)
	cfg.SMTPAddress = strings.TrimSpace(cfg.SMTPAddress)
	cfg.SMTPUsername = strings.TrimSpace(cfg.SMTPUsername)
	cfg.SMTPPassword = strings.TrimSpace(cfg.SMTPPassword)
	cfg.From = strings.TrimSpace(cfg.From)
	cfg.SubjectPrefix = strings.TrimSpace(cfg.SubjectPrefix)
	if cfg.SubjectPrefix == "" {
		cfg.SubjectPrefix = defaultNotificationEmailSubjectPrefix
	}
	if cfg.Headers == nil {
		cfg.Headers = map[string]string{}
	}
	headers := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		headers[k] = strings.TrimSpace(v)
	}
	cfg.Headers = headers
	to := make([]string, 0, len(cfg.To))
	for _, addr := range cfg.To {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		to = append(to, addr)
	}
	cfg.To = to
	return cfg
}

func validateNotificationConfig(cfg notificationConfig) error {
	if cfg.CooldownSeconds < 0 || cfg.CooldownSeconds > 86400 {
		return fmt.Errorf("cooldown_seconds must be between 0 and 86400")
	}
	if err := validateNotificationTrigger("upstream", cfg.Upstream); err != nil {
		return err
	}
	if err := validateNotificationTrigger("security", notificationTriggerConfig{
		Enabled:            cfg.Security.Enabled,
		WindowSeconds:      cfg.Security.WindowSeconds,
		ActiveThreshold:    cfg.Security.ActiveThreshold,
		EscalatedThreshold: cfg.Security.EscalatedThreshold,
	}); err != nil {
		return err
	}
	if cfg.Enabled && countEnabledNotificationSinks(cfg.Sinks) == 0 {
		return fmt.Errorf("at least one enabled sink is required when notifications.enabled=true")
	}
	for i, sink := range cfg.Sinks {
		if err := validateNotificationSink(i, sink); err != nil {
			return err
		}
	}
	return nil
}

func validateNotificationTrigger(field string, cfg notificationTriggerConfig) error {
	if cfg.WindowSeconds <= 0 || cfg.WindowSeconds > maxNotificationWindowSeconds {
		return fmt.Errorf("%s.window_seconds must be between 1 and %d", field, maxNotificationWindowSeconds)
	}
	if cfg.ActiveThreshold <= 0 {
		return fmt.Errorf("%s.active_threshold must be > 0", field)
	}
	if cfg.EscalatedThreshold < cfg.ActiveThreshold {
		return fmt.Errorf("%s.escalated_threshold must be >= %s.active_threshold", field, field)
	}
	return nil
}

func validateNotificationSink(idx int, sink notificationSinkConfig) error {
	field := fmt.Sprintf("sinks[%d]", idx)
	if sink.Type != notificationSinkTypeWebhook && sink.Type != notificationSinkTypeEmail {
		return fmt.Errorf("%s.type must be webhook|email", field)
	}
	switch sink.Type {
	case notificationSinkTypeWebhook:
		if sink.WebhookURL == "" {
			return fmt.Errorf("%s.webhook_url is required", field)
		}
		u, err := url.Parse(sink.WebhookURL)
		if err != nil {
			return fmt.Errorf("%s.webhook_url parse error: %w", field, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("%s.webhook_url must use http or https", field)
		}
		if u.Host == "" {
			return fmt.Errorf("%s.webhook_url must include host", field)
		}
		if sink.TimeoutSec <= 0 || sink.TimeoutSec > 120 {
			return fmt.Errorf("%s.timeout_seconds must be between 1 and 120", field)
		}
	case notificationSinkTypeEmail:
		if sink.SMTPAddress == "" {
			return fmt.Errorf("%s.smtp_address is required", field)
		}
		if sink.From == "" {
			return fmt.Errorf("%s.from is required", field)
		}
		if _, err := mail.ParseAddress(sink.From); err != nil {
			return fmt.Errorf("%s.from is invalid: %w", field, err)
		}
		if len(sink.To) == 0 {
			return fmt.Errorf("%s.to must contain at least one recipient", field)
		}
		for j, addr := range sink.To {
			if _, err := mail.ParseAddress(addr); err != nil {
				return fmt.Errorf("%s.to[%d] is invalid: %w", field, j, err)
			}
		}
	}
	return nil
}

func ensureNotificationFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(defaultNotificationPolicyRaw()), 0o644)
}

func defaultNotificationPolicyRaw() string {
	return `{
  "enabled": false,
  "cooldown_seconds": 900,
  "sinks": [
    {
      "name": "primary-webhook",
      "type": "webhook",
      "enabled": false,
      "webhook_url": "https://hooks.example.invalid/tukuyomi",
      "timeout_seconds": 5,
      "headers": {
        "X-Tukuyomi-Token": "change-me"
      }
    },
    {
      "name": "ops-email",
      "type": "email",
      "enabled": false,
      "smtp_address": "smtp.example.invalid:587",
      "smtp_username": "alerts@example.invalid",
      "smtp_password": "change-me",
      "from": "alerts@example.invalid",
      "to": ["secops@example.invalid"],
      "subject_prefix": "[tukuyomi]"
    }
  ],
  "upstream": {
    "enabled": true,
    "window_seconds": 60,
    "active_threshold": 3,
    "escalated_threshold": 10
  },
  "security": {
    "enabled": true,
    "window_seconds": 300,
    "active_threshold": 20,
    "escalated_threshold": 100,
    "sources": ["waf_block", "rate_limited", "semantic_anomaly", "bot_challenge"]
  }
}
`
}

func observeNotificationSummary(summary *notificationWindowSummary, obs notificationObservation) {
	if summary.UniqueIPs == nil {
		summary.UniqueIPs = make(map[string]struct{})
	}
	if summary.PathCounts == nil {
		summary.PathCounts = make(map[string]int)
	}
	summary.Count++
	if ip := strings.TrimSpace(obs.RemoteIP); ip != "" {
		summary.UniqueIPs[ip] = struct{}{}
	}
	if path := strings.TrimSpace(obs.Path); path != "" {
		summary.PathCounts[path]++
	}
	if obs.StatusCode > 0 {
		summary.LastStatus = obs.StatusCode
	}
	if obs.Score > summary.MaxScore {
		summary.MaxScore = obs.Score
	}
	summary.LastReqID = strings.TrimSpace(obs.RequestID)
}

func notificationSummaryFromWindow(summary notificationWindowSummary) notificationSummaryView {
	return notificationSummaryView{
		Count:      summary.Count,
		UniqueIPs:  len(summary.UniqueIPs),
		TopPaths:   notificationTopPaths(summary.PathCounts),
		LastStatus: summary.LastStatus,
		MaxScore:   summary.MaxScore,
		LastReqID:  summary.LastReqID,
	}
}

func notificationTopPaths(pathCounts map[string]int) []string {
	if len(pathCounts) == 0 {
		return nil
	}
	type pathStat struct {
		Path  string
		Count int
	}
	stats := make([]pathStat, 0, len(pathCounts))
	for path, count := range pathCounts {
		stats = append(stats, pathStat{Path: path, Count: count})
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Count != stats[j].Count {
			return stats[i].Count > stats[j].Count
		}
		return stats[i].Path < stats[j].Path
	})
	limit := maxNotificationTopPathCount
	if len(stats) < limit {
		limit = len(stats)
	}
	out := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		out = append(out, fmt.Sprintf("%s (%d)", stats[i].Path, stats[i].Count))
	}
	return out
}

func buildNotificationDispatch(product string, state *notificationAlertState, summary notificationSummaryView, windowSeconds int) notificationDispatch {
	stateLabel := state.Status
	title := fmt.Sprintf("[%s] %s %s", product, state.Source, stateLabel)
	summaryText := fmt.Sprintf("%s %s transitioned to %s", state.Category, state.Source, stateLabel)
	if state.Status == notificationStateQuiet {
		title = fmt.Sprintf("[%s] %s recovered", product, state.Source)
		summaryText = fmt.Sprintf("%s %s recovered after %d events in the last %ds window", state.Category, state.Source, summary.Count, windowSeconds)
	} else {
		summaryText = fmt.Sprintf("%s %s %s: %d events in %ds", state.Category, state.Source, stateLabel, summary.Count, windowSeconds)
	}
	if summary.UniqueIPs > 0 {
		summaryText += fmt.Sprintf(", unique_ips=%d", summary.UniqueIPs)
	}
	if len(summary.TopPaths) > 0 {
		summaryText += ", top_paths=" + strings.Join(summary.TopPaths, ", ")
	}
	if summary.MaxScore > 0 {
		summaryText += fmt.Sprintf(", max_score=%d", summary.MaxScore)
	}
	return notificationDispatch{
		Product:     product,
		AlertKey:    state.Key,
		Category:    state.Category,
		Source:      state.Source,
		State:       state.Status,
		Title:       title,
		Summary:     summaryText,
		ObservedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		WindowSecs:  windowSeconds,
		Count:       summary.Count,
		UniqueIPs:   summary.UniqueIPs,
		TopPaths:    summary.TopPaths,
		StatusCode:  summary.LastStatus,
		MaxScore:    summary.MaxScore,
		LastRequest: summary.LastReqID,
		Details: map[string]any{
			"count":       summary.Count,
			"unique_ips":  summary.UniqueIPs,
			"top_paths":   summary.TopPaths,
			"status_code": summary.LastStatus,
			"max_score":   summary.MaxScore,
		},
	}
}

func notificationTriggerForObservation(cfg notificationConfig, obs notificationObservation) (notificationTriggerConfig, bool) {
	return notificationTriggerForCategory(cfg, obs.Category, obs.Source)
}

func notificationTriggerForCategory(cfg notificationConfig, category, source string) (notificationTriggerConfig, bool) {
	switch category {
	case notificationCategoryUpstream:
		if !cfg.Upstream.Enabled {
			return notificationTriggerConfig{}, false
		}
		return cfg.Upstream, true
	case notificationCategorySecurity:
		if !cfg.Security.Enabled {
			return notificationTriggerConfig{}, false
		}
		if !notificationSourceAllowed(cfg.Security.Sources, source) {
			return notificationTriggerConfig{}, false
		}
		return notificationTriggerConfig{
			Enabled:            cfg.Security.Enabled,
			WindowSeconds:      cfg.Security.WindowSeconds,
			ActiveThreshold:    cfg.Security.ActiveThreshold,
			EscalatedThreshold: cfg.Security.EscalatedThreshold,
		}, true
	default:
		return notificationTriggerConfig{}, false
	}
}

func notificationSourceAllowed(sources []string, source string) bool {
	source = strings.ToLower(strings.TrimSpace(source))
	for _, allowed := range sources {
		if strings.ToLower(strings.TrimSpace(allowed)) == source {
			return true
		}
	}
	return false
}

func classifyNotificationState(trigger notificationTriggerConfig, count int) string {
	if count >= trigger.EscalatedThreshold {
		return notificationStateEscalated
	}
	if count >= trigger.ActiveThreshold {
		return notificationStateActive
	}
	return notificationStateQuiet
}

func countEnabledNotificationSinks(sinks []notificationSinkConfig) int {
	count := 0
	for _, sink := range sinks {
		if sink.Enabled {
			count++
		}
	}
	return count
}

func sinkDisplayName(sink notificationSinkConfig) string {
	if sink.Name != "" {
		return sink.Name
	}
	return sink.Type
}

func stringValue(v any) string {
	switch value := v.(type) {
	case string:
		return strings.TrimSpace(value)
	default:
		return ""
	}
}

func intValue(v any) int {
	switch value := v.(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	default:
		return 0
	}
}

func maxNotificationInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func formatOptionalTime(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return ts.UTC().Format(time.RFC3339Nano)
}
