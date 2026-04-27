package proxydiscovery

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type DNSLookup interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupSRV(ctx context.Context, service string, proto string, name string) (string, []*net.SRV, error)
}

type DefaultDNSLookup struct{}

func (DefaultDNSLookup) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

func (DefaultDNSLookup) LookupSRV(ctx context.Context, service string, proto string, name string) (string, []*net.SRV, error) {
	return net.DefaultResolver.LookupSRV(ctx, service, proto, name)
}

type Config struct {
	Type               string
	Hostname           string
	Scheme             string
	Port               int
	RecordTypes        []string
	Service            string
	Proto              string
	Name               string
	RefreshIntervalSec int
	TimeoutMS          int
	MaxTargets         int
}

type Upstream struct {
	Name      string
	Enabled   bool
	Discovery Config
}

type State struct {
	UpstreamName  string
	Type          string
	Source        string
	Targets       []string
	LastLookupAt  time.Time
	LastSuccessAt time.Time
	LastFailureAt time.Time
	LastError     string
	NextRefreshAt time.Time
}

type Status struct {
	UpstreamName  string
	Type          string
	Source        string
	Targets       []string
	TargetCount   int
	LastLookupAt  time.Time
	LastSuccessAt time.Time
	LastFailureAt time.Time
	LastError     string
	NextRefreshAt time.Time
}

func HasDiscovery(upstreams []Upstream) bool {
	for _, upstream := range upstreams {
		if upstream.Enabled && Enabled(upstream.Discovery) {
			return true
		}
	}
	return false
}

func StatesInitial(upstreams []Upstream, lookup DNSLookup) map[string]State {
	return RefreshStates(upstreams, nil, time.Now().UTC(), true, lookup)
}

func RefreshStates(upstreams []Upstream, prev map[string]State, now time.Time, force bool, lookup DNSLookup) map[string]State {
	out := make(map[string]State)
	for _, upstream := range upstreams {
		if !upstream.Enabled || !Enabled(upstream.Discovery) {
			continue
		}
		current := prev[strings.TrimSpace(upstream.Name)]
		if !force && !current.NextRefreshAt.IsZero() && now.Before(current.NextRefreshAt) {
			out[upstream.Name] = current
			continue
		}
		next := ResolveUpstream(upstream, current, now, lookup)
		out[upstream.Name] = next
	}
	return out
}

func ResolveUpstream(upstream Upstream, prev State, now time.Time, lookup DNSLookup) State {
	cfg := upstream.Discovery
	next := State{
		UpstreamName:  strings.TrimSpace(upstream.Name),
		Type:          cfg.Type,
		Source:        Source(cfg),
		Targets:       append([]string(nil), prev.Targets...),
		LastSuccessAt: prev.LastSuccessAt,
		LastFailureAt: prev.LastFailureAt,
		LastError:     prev.LastError,
		LastLookupAt:  now,
		NextRefreshAt: now.Add(time.Duration(cfg.RefreshIntervalSec) * time.Second),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.TimeoutMS)*time.Millisecond)
	defer cancel()

	targets, err := LookupTargets(ctx, cfg, lookup)
	if err != nil {
		next.LastFailureAt = now
		next.LastError = err.Error()
		return next
	}
	next.Targets = targets
	next.LastSuccessAt = now
	next.LastError = ""
	return next
}

func LookupTargets(ctx context.Context, cfg Config, lookup DNSLookup) ([]string, error) {
	if lookup == nil {
		lookup = DefaultDNSLookup{}
	}
	var targets []string
	var err error
	switch cfg.Type {
	case "dns":
		targets, err = lookupDNSAddressTargets(ctx, cfg, lookup)
	case "dns_srv":
		targets, err = lookupDNSSRVTargets(ctx, cfg, lookup)
	default:
		return nil, fmt.Errorf("unsupported discovery type: %s", cfg.Type)
	}
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no discovery targets resolved")
	}
	sort.Strings(targets)
	targets = UniqueStrings(targets)
	if len(targets) > cfg.MaxTargets {
		targets = targets[:cfg.MaxTargets]
	}
	return targets, nil
}

func lookupDNSAddressTargets(ctx context.Context, cfg Config, lookup DNSLookup) ([]string, error) {
	ips, err := lookup.LookupIPAddr(ctx, cfg.Hostname)
	if err != nil {
		return nil, err
	}
	allowA, allowAAAA := RecordTypeFlags(cfg.RecordTypes)
	targets := make([]string, 0, len(ips))
	for _, ipAddr := range ips {
		ip := ipAddr.IP
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			if !allowA {
				continue
			}
		} else if !allowAAAA {
			continue
		}
		targets = append(targets, URL(cfg.Scheme, ip.String(), cfg.Port))
	}
	return targets, nil
}

func lookupDNSSRVTargets(ctx context.Context, cfg Config, lookup DNSLookup) ([]string, error) {
	_, records, err := lookup.LookupSRV(ctx, cfg.Service, cfg.Proto, cfg.Name)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Priority != records[j].Priority {
			return records[i].Priority < records[j].Priority
		}
		if records[i].Target != records[j].Target {
			return records[i].Target < records[j].Target
		}
		return records[i].Port < records[j].Port
	})
	targets := make([]string, 0, len(records))
	for _, record := range records {
		if record == nil || record.Port == 0 {
			continue
		}
		host := strings.TrimSuffix(strings.TrimSpace(record.Target), ".")
		if host == "" {
			continue
		}
		targets = append(targets, URL(cfg.Scheme, host, int(record.Port)))
	}
	return targets, nil
}

func RecordTypeFlags(recordTypes []string) (allowA bool, allowAAAA bool) {
	for _, recordType := range recordTypes {
		switch strings.ToUpper(strings.TrimSpace(recordType)) {
		case "A":
			allowA = true
		case "AAAA":
			allowAAAA = true
		}
	}
	return allowA, allowAAAA
}

func URL(scheme string, host string, port int) string {
	return (&url.URL{
		Scheme: strings.ToLower(strings.TrimSpace(scheme)),
		Host:   net.JoinHostPort(strings.TrimSpace(host), strconv.Itoa(port)),
	}).String()
}

func Source(cfg Config) string {
	switch cfg.Type {
	case "dns":
		return cfg.Hostname
	case "dns_srv":
		return fmt.Sprintf("_%s._%s.%s", cfg.Service, cfg.Proto, strings.TrimSuffix(cfg.Name, "."))
	default:
		return ""
	}
}

func Enabled(cfg Config) bool {
	return strings.TrimSpace(cfg.Type) != ""
}

func UniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, raw := range in {
		next := strings.TrimSpace(raw)
		if next == "" {
			continue
		}
		if _, ok := seen[next]; ok {
			continue
		}
		seen[next] = struct{}{}
		out = append(out, next)
	}
	return out
}

func NextRefreshDelay(states map[string]State, now time.Time) time.Duration {
	var out time.Duration
	for _, state := range states {
		if state.NextRefreshAt.IsZero() {
			return time.Second
		}
		delay := state.NextRefreshAt.Sub(now)
		if delay <= 0 {
			return time.Millisecond
		}
		if out == 0 || delay < out {
			out = delay
		}
	}
	return out
}

func StatusSnapshot(states map[string]State) []Status {
	if len(states) == 0 {
		return nil
	}
	keys := make([]string, 0, len(states))
	for key := range states {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]Status, 0, len(keys))
	for _, key := range keys {
		state := states[key]
		targets := append([]string(nil), state.Targets...)
		sort.Strings(targets)
		out = append(out, Status{
			UpstreamName:  state.UpstreamName,
			Type:          state.Type,
			Source:        state.Source,
			Targets:       targets,
			TargetCount:   len(targets),
			LastLookupAt:  state.LastLookupAt,
			LastSuccessAt: state.LastSuccessAt,
			LastFailureAt: state.LastFailureAt,
			LastError:     state.LastError,
			NextRefreshAt: state.NextRefreshAt,
		})
	}
	return out
}

func CopyStates(in map[string]State) map[string]State {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]State, len(in))
	for key, value := range in {
		value.Targets = append([]string(nil), value.Targets...)
		out[key] = value
	}
	return out
}

func StatesEqual(left map[string]State, right map[string]State) bool {
	if len(left) != len(right) {
		return false
	}
	for key, leftState := range left {
		rightState, ok := right[key]
		if !ok {
			return false
		}
		if leftState.LastLookupAt != rightState.LastLookupAt ||
			leftState.LastSuccessAt != rightState.LastSuccessAt ||
			leftState.LastFailureAt != rightState.LastFailureAt ||
			leftState.LastError != rightState.LastError ||
			leftState.NextRefreshAt != rightState.NextRefreshAt ||
			strings.Join(leftState.Targets, "\x00") != strings.Join(rightState.Targets, "\x00") {
			return false
		}
	}
	return true
}
