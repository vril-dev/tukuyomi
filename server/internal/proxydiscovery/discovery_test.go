package proxydiscovery

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type fakeDNSLookup struct {
	ips    []net.IPAddr
	srv    []*net.SRV
	ipErr  error
	srvErr error
}

func (f *fakeDNSLookup) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	if f.ipErr != nil {
		return nil, f.ipErr
	}
	return append([]net.IPAddr(nil), f.ips...), nil
}

func (f *fakeDNSLookup) LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error) {
	if f.srvErr != nil {
		return "", nil, f.srvErr
	}
	return "", append([]*net.SRV(nil), f.srv...), nil
}

func TestLookupTargetsDNSFiltersAndSortsRecords(t *testing.T) {
	lookup := &fakeDNSLookup{ips: []net.IPAddr{
		{IP: net.ParseIP("2001:db8::10")},
		{IP: net.ParseIP("127.0.0.10")},
		{IP: net.ParseIP("127.0.0.10")},
	}}
	targets, err := LookupTargets(context.Background(), Config{
		Type:        "dns",
		Hostname:    "app.local",
		Scheme:      "http",
		Port:        8080,
		RecordTypes: []string{"A"},
		MaxTargets:  32,
	}, lookup)
	if err != nil {
		t.Fatalf("LookupTargets: %v", err)
	}
	if len(targets) != 1 || targets[0] != "http://127.0.0.10:8080" {
		t.Fatalf("targets=%#v", targets)
	}
}

func TestLookupTargetsSRVOrdersByPriorityTargetPort(t *testing.T) {
	lookup := &fakeDNSLookup{srv: []*net.SRV{
		{Target: "b.local.", Port: 8082, Priority: 20},
		{Target: "a.local.", Port: 8081, Priority: 10},
	}}
	targets, err := LookupTargets(context.Background(), Config{
		Type:       "dns_srv",
		Service:    "http",
		Proto:      "tcp",
		Name:       "svc.local",
		Scheme:     "https",
		MaxTargets: 32,
	}, lookup)
	if err != nil {
		t.Fatalf("LookupTargets: %v", err)
	}
	want := []string{
		"https://a.local:8081",
		"https://b.local:8082",
	}
	if len(targets) != len(want) || targets[0] != want[0] || targets[1] != want[1] {
		t.Fatalf("targets=%#v want=%#v", targets, want)
	}
}

func TestResolveUpstreamKeepsPreviousTargetsOnFailure(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	prev := State{
		Targets:       []string{"http://127.0.0.20:8080"},
		LastSuccessAt: now.Add(-time.Minute),
	}
	state := ResolveUpstream(Upstream{
		Name:    "app",
		Enabled: true,
		Discovery: Config{
			Type:               "dns",
			Hostname:           "app.local",
			Scheme:             "http",
			Port:               8080,
			RefreshIntervalSec: 10,
			TimeoutMS:          1000,
			MaxTargets:         32,
		},
	}, prev, now, &fakeDNSLookup{ipErr: errors.New("dns down")})
	if len(state.Targets) != 1 || state.Targets[0] != "http://127.0.0.20:8080" {
		t.Fatalf("targets=%#v", state.Targets)
	}
	if state.LastError == "" || state.LastFailureAt != now {
		t.Fatalf("state=%#v", state)
	}
}
