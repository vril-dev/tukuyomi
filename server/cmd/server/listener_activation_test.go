package main

import (
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestSystemdActivationTakesNamedTCPListener(t *testing.T) {
	base, file := testTCPActivationFile(t)
	defer base.Close()
	defer file.Close()

	activation := &systemdActivation{
		active: true,
		fds: []systemdActivatedFD{{
			fd:   int(file.Fd()),
			name: "public",
		}},
		used: map[int]struct{}{},
	}

	ln, inherited, err := activation.TakeTCP("public", base.Addr().String())
	if err != nil {
		t.Fatalf("TakeTCP: %v", err)
	}
	defer ln.Close()
	if !inherited {
		t.Fatal("expected inherited listener")
	}
	if got, want := ln.Addr().String(), base.Addr().String(); got != want {
		t.Fatalf("addr=%q want %q", got, want)
	}
}

func TestSystemdActivationRejectsAddressMismatch(t *testing.T) {
	base, file := testTCPActivationFile(t)
	defer base.Close()
	defer file.Close()

	activation := &systemdActivation{
		active: true,
		fds: []systemdActivatedFD{{
			fd:   int(file.Fd()),
			name: "public",
		}},
		used: map[int]struct{}{},
	}

	badPort := testTCPPort(t, base) + 1
	if badPort > 65535 {
		badPort = testTCPPort(t, base) - 1
	}
	badAddr := "127.0.0.1:" + strconv.Itoa(badPort)
	ln, inherited, err := activation.TakeTCP("public", badAddr)
	if err == nil {
		if ln != nil {
			_ = ln.Close()
		}
		t.Fatal("expected mismatch error")
	}
	if !inherited {
		t.Fatal("expected inherited=true on rejected systemd fd")
	}
	if !strings.Contains(err.Error(), "port") {
		t.Fatalf("err=%v want port mismatch", err)
	}
}

func TestSystemdActivationRejectsMissingNamedRole(t *testing.T) {
	base, file := testTCPActivationFile(t)
	defer base.Close()
	defer file.Close()

	activation := &systemdActivation{
		active: true,
		fds: []systemdActivatedFD{{
			fd:   int(file.Fd()),
			name: "public",
		}},
		used: map[int]struct{}{},
	}

	ln, inherited, err := activation.TakeTCP("admin", base.Addr().String())
	if err == nil {
		if ln != nil {
			_ = ln.Close()
		}
		t.Fatal("expected missing named role error")
	}
	if inherited {
		t.Fatal("expected inherited=false when role is missing")
	}
}

func TestValidateActivatedAddrAcceptsLocalhostConfigForLoopbackSocket(t *testing.T) {
	if err := validateActivatedAddr("admin", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9091}, "localhost:9091"); err != nil {
		t.Fatalf("validateActivatedAddr: %v", err)
	}
}

func TestSystemdActivationTakesNamedUDPPacketConn(t *testing.T) {
	base, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer base.Close()
	udp, ok := base.(*net.UDPConn)
	if !ok {
		t.Fatalf("listener type=%T want *net.UDPConn", base)
	}
	file, err := udp.File()
	if err != nil {
		t.Fatalf("UDPConn.File: %v", err)
	}
	defer file.Close()

	activation := &systemdActivation{
		active: true,
		fds: []systemdActivatedFD{{
			fd:   int(file.Fd()),
			name: "http3",
		}},
		used: map[int]struct{}{},
	}

	conn, inherited, err := activation.TakePacketConn("http3", base.LocalAddr().String())
	if err != nil {
		t.Fatalf("TakePacketConn: %v", err)
	}
	defer conn.Close()
	if !inherited {
		t.Fatal("expected inherited packet conn")
	}
}

func TestLoadSystemdActivationIgnoresOtherPID(t *testing.T) {
	env := map[string]string{
		"LISTEN_PID": "999999",
		"LISTEN_FDS": "1",
	}
	activation, err := loadSystemdActivation(func(key string) string { return env[key] }, os.Getpid())
	if err != nil {
		t.Fatalf("loadSystemdActivation: %v", err)
	}
	if activation.Active() {
		t.Fatal("activation should be ignored for a different LISTEN_PID")
	}
}

func TestLoadSystemdActivationRejectsMissingPID(t *testing.T) {
	env := map[string]string{
		"LISTEN_FDS": "1",
	}
	if _, err := loadSystemdActivation(func(key string) string { return env[key] }, os.Getpid()); err == nil {
		t.Fatal("expected LISTEN_PID requirement error")
	}
}

func testTCPActivationFile(t *testing.T) (net.Listener, *os.File) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	tcp, ok := ln.(*net.TCPListener)
	if !ok {
		_ = ln.Close()
		t.Fatalf("listener type=%T want *net.TCPListener", ln)
	}
	file, err := tcp.File()
	if err != nil {
		_ = ln.Close()
		t.Fatalf("TCPListener.File: %v", err)
	}
	return ln, file
}

func testTCPPort(t *testing.T, ln net.Listener) int {
	t.Helper()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}
	return n
}
