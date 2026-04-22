package handler

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

type proxyDNSLookup interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupSRV(ctx context.Context, service string, proto string, name string) (string, []*net.SRV, error)
}

type defaultProxyDNSLookup struct{}

func (defaultProxyDNSLookup) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

func (defaultProxyDNSLookup) LookupSRV(ctx context.Context, service string, proto string, name string) (string, []*net.SRV, error) {
	return net.DefaultResolver.LookupSRV(ctx, service, proto, name)
}

var proxyDNSLookupProvider proxyDNSLookup = defaultProxyDNSLookup{}

type proxyDiscoveryRuntimeState struct {
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

func proxyConfigHasDiscovery(cfg ProxyRulesConfig) bool {
	for _, upstream := range proxyConfiguredUpstreams(cfg) {
		if upstream.Enabled && proxyUpstreamDiscoveryEnabled(upstream) {
			return true
		}
	}
	return false
}

func proxyDiscoveryStatesInitial(cfg ProxyRulesConfig) map[string]proxyDiscoveryRuntimeState {
	return refreshProxyDiscoveryStates(cfg, nil, time.Now().UTC(), true)
}

func refreshProxyDiscoveryStates(cfg ProxyRulesConfig, prev map[string]proxyDiscoveryRuntimeState, now time.Time, force bool) map[string]proxyDiscoveryRuntimeState {
	out := make(map[string]proxyDiscoveryRuntimeState)
	for _, upstream := range proxyConfiguredUpstreams(cfg) {
		if !upstream.Enabled || !proxyUpstreamDiscoveryEnabled(upstream) {
			continue
		}
		current := prev[strings.TrimSpace(upstream.Name)]
		if !force && !current.NextRefreshAt.IsZero() && now.Before(current.NextRefreshAt) {
			out[upstream.Name] = current
			continue
		}
		next := resolveProxyDiscoveryUpstream(upstream, current, now)
		out[upstream.Name] = next
	}
	return out
}

func resolveProxyDiscoveryUpstream(upstream ProxyUpstream, prev proxyDiscoveryRuntimeState, now time.Time) proxyDiscoveryRuntimeState {
	cfg := upstream.Discovery
	next := proxyDiscoveryRuntimeState{
		UpstreamName:  strings.TrimSpace(upstream.Name),
		Type:          cfg.Type,
		Source:        proxyDiscoverySource(cfg),
		Targets:       append([]string(nil), prev.Targets...),
		LastSuccessAt: prev.LastSuccessAt,
		LastFailureAt: prev.LastFailureAt,
		LastError:     prev.LastError,
		LastLookupAt:  now,
		NextRefreshAt: now.Add(time.Duration(cfg.RefreshIntervalSec) * time.Second),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.TimeoutMS)*time.Millisecond)
	defer cancel()

	targets, err := lookupProxyDiscoveryTargets(ctx, cfg)
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

func lookupProxyDiscoveryTargets(ctx context.Context, cfg ProxyDiscoveryConfig) ([]string, error) {
	var targets []string
	var err error
	switch cfg.Type {
	case "dns":
		targets, err = lookupProxyDNSAddressTargets(ctx, cfg)
	case "dns_srv":
		targets, err = lookupProxyDNSSRVTargets(ctx, cfg)
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
	targets = uniqueProxyStrings(targets)
	if len(targets) > cfg.MaxTargets {
		targets = targets[:cfg.MaxTargets]
	}
	return targets, nil
}

func lookupProxyDNSAddressTargets(ctx context.Context, cfg ProxyDiscoveryConfig) ([]string, error) {
	ips, err := proxyDNSLookupProvider.LookupIPAddr(ctx, cfg.Hostname)
	if err != nil {
		return nil, err
	}
	allowA, allowAAAA := proxyDiscoveryRecordTypeFlags(cfg.RecordTypes)
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
		targets = append(targets, proxyDiscoveryURL(cfg.Scheme, ip.String(), cfg.Port))
	}
	return targets, nil
}

func lookupProxyDNSSRVTargets(ctx context.Context, cfg ProxyDiscoveryConfig) ([]string, error) {
	_, records, err := proxyDNSLookupProvider.LookupSRV(ctx, cfg.Service, cfg.Proto, cfg.Name)
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
		targets = append(targets, proxyDiscoveryURL(cfg.Scheme, host, int(record.Port)))
	}
	return targets, nil
}

func proxyDiscoveryRecordTypeFlags(recordTypes []string) (allowA bool, allowAAAA bool) {
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

func proxyDiscoveryURL(scheme string, host string, port int) string {
	return (&url.URL{
		Scheme: strings.ToLower(strings.TrimSpace(scheme)),
		Host:   net.JoinHostPort(strings.TrimSpace(host), strconv.Itoa(port)),
	}).String()
}

func proxyDiscoverySource(cfg ProxyDiscoveryConfig) string {
	switch cfg.Type {
	case "dns":
		return cfg.Hostname
	case "dns_srv":
		return fmt.Sprintf("_%s._%s.%s", cfg.Service, cfg.Proto, strings.TrimSuffix(cfg.Name, "."))
	default:
		return ""
	}
}

func uniqueProxyStrings(in []string) []string {
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

func proxyDiscoveryNextRefreshDelay(states map[string]proxyDiscoveryRuntimeState, now time.Time) time.Duration {
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

func proxyDiscoveryStatusSnapshot(states map[string]proxyDiscoveryRuntimeState) []upstreamDiscoveryStatus {
	if len(states) == 0 {
		return nil
	}
	keys := make([]string, 0, len(states))
	for key := range states {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]upstreamDiscoveryStatus, 0, len(keys))
	for _, key := range keys {
		state := states[key]
		targets := append([]string(nil), state.Targets...)
		sort.Strings(targets)
		out = append(out, upstreamDiscoveryStatus{
			UpstreamName:  state.UpstreamName,
			Type:          state.Type,
			Source:        state.Source,
			Targets:       targets,
			TargetCount:   len(targets),
			LastLookupAt:  formatProxyTime(state.LastLookupAt),
			LastSuccessAt: formatProxyTime(state.LastSuccessAt),
			LastFailureAt: formatProxyTime(state.LastFailureAt),
			LastError:     state.LastError,
			NextRefreshAt: formatProxyTime(state.NextRefreshAt),
		})
	}
	return out
}
