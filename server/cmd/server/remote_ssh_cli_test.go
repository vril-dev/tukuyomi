package main

import "testing"

func TestParseRemoteSSHCommandConfig(t *testing.T) {
	cfg, err := parseRemoteSSHCommandConfig([]string{
		"--center", "https://center.example.test",
		"--device", "edge-1",
		"--local", "127.0.0.1:2222",
		"--ttl", "120",
		"--reason", "maintenance",
	}, []string{"TUKUYOMI_ADMIN_TOKEN=tky_pat_test"})
	if err != nil {
		t.Fatalf("parseRemoteSSHCommandConfig: %v", err)
	}
	if cfg.CenterURL != "https://center.example.test" || cfg.APIBase != "/center-api" || cfg.DeviceID != "edge-1" ||
		cfg.LocalAddr != "127.0.0.1:2222" || cfg.TTLSec != 120 || cfg.Reason != "maintenance" || cfg.Token != "tky_pat_test" {
		t.Fatalf("unexpected cfg: %+v", cfg)
	}
}

func TestParseRemoteSSHCommandConfigRejectsMissingReason(t *testing.T) {
	_, err := parseRemoteSSHCommandConfig([]string{
		"--center", "https://center.example.test",
		"--device", "edge-1",
		"--token", "tky_pat_test",
	}, nil)
	if err == nil {
		t.Fatal("expected missing reason error")
	}
}

func TestParseRemoteSSHCommandConfigRejectsHTTPByDefault(t *testing.T) {
	_, err := parseRemoteSSHCommandConfig([]string{
		"--center", "http://center.example.test",
		"--device", "edge-1",
		"--token", "tky_pat_test",
		"--reason", "maintenance",
	}, nil)
	if err == nil {
		t.Fatal("expected http center URL rejection")
	}

	cfg, err := parseRemoteSSHCommandConfig([]string{
		"--center", "http://center.example.test",
		"--device", "edge-1",
		"--token", "tky_pat_test",
		"--reason", "maintenance",
		"--allow-insecure-http",
	}, nil)
	if err != nil {
		t.Fatalf("parseRemoteSSHCommandConfig with --allow-insecure-http: %v", err)
	}
	if !cfg.AllowInsecureHTTP {
		t.Fatalf("AllowInsecureHTTP=false: %+v", cfg)
	}
}

func TestParseRemoteSSHCommandConfigAcceptsCenterTLSFlags(t *testing.T) {
	cfg, err := parseRemoteSSHCommandConfig([]string{
		"--center", "https://center.example.test",
		"--device", "edge-1",
		"--token", "tky_pat_test",
		"--reason", "maintenance",
		"--center-ca-bundle", " conf/center-ca.pem ",
		"--center-server-name", " center.example.local ",
	}, nil)
	if err != nil {
		t.Fatalf("parseRemoteSSHCommandConfig: %v", err)
	}
	if cfg.CenterCABundle != "conf/center-ca.pem" || cfg.CenterServerName != "center.example.local" {
		t.Fatalf("unexpected center tls settings: %+v", cfg)
	}
}

func TestRemoteSSHLocalHostPort(t *testing.T) {
	host, port := remoteSSHLocalHostPort("[::]:2222")
	if host != "127.0.0.1" || port != "2222" {
		t.Fatalf("host=%q port=%q", host, port)
	}
	host, port = remoteSSHLocalHostPort("[::1]:2022")
	if host != "[::1]" || port != "2022" {
		t.Fatalf("host=%q port=%q", host, port)
	}
}

func TestRemoteSSHKnownHostsHost(t *testing.T) {
	if got := remoteSSHKnownHostsHost("127.0.0.1", "2222"); got != "[127.0.0.1]:2222" {
		t.Fatalf("known hosts host=%q", got)
	}
	if got := remoteSSHKnownHostsHost("[::1]", "2022"); got != "[::1]:2022" {
		t.Fatalf("known hosts IPv6 host=%q", got)
	}
	if got := remoteSSHKnownHostsHost("localhost", "22"); got != "localhost" {
		t.Fatalf("known hosts default port host=%q", got)
	}
}
