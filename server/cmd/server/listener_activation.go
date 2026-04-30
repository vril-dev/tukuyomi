package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const systemdListenFDStart = 3

type systemdActivatedFD struct {
	fd   int
	name string
}

type systemdActivation struct {
	active bool
	fds    []systemdActivatedFD
	used   map[int]struct{}
}

func loadSystemdActivationFromEnv() (*systemdActivation, error) {
	if internalProcessRoleFromEnv(os.Environ()) == internalProcessRoleWorker && strings.TrimSpace(os.Getenv(workerListenFDsEnv)) != "" {
		activation, err := loadWorkerListenerActivation(os.Getenv)
		os.Unsetenv(workerListenFDsEnv)
		os.Unsetenv(workerListenFDNamesEnv)
		return activation, err
	}

	activation, err := loadSystemdActivation(os.Getenv, os.Getpid())
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_FDNAMES")
	return activation, err
}

func loadWorkerListenerActivation(getenv func(string) string) (*systemdActivation, error) {
	rawFDS := strings.TrimSpace(getenv(workerListenFDsEnv))
	if rawFDS == "" || rawFDS == "0" {
		return &systemdActivation{}, nil
	}
	count, err := strconv.Atoi(rawFDS)
	if err != nil {
		return nil, fmt.Errorf("%s is invalid: %w", workerListenFDsEnv, err)
	}
	if count < 0 || count > 16 {
		return nil, fmt.Errorf("%s must be between 0 and 16", workerListenFDsEnv)
	}
	names := splitSystemdFDNames(getenv(workerListenFDNamesEnv))
	out := &systemdActivation{
		active: count > 0,
		fds:    make([]systemdActivatedFD, 0, count),
		used:   make(map[int]struct{}, count),
	}
	for i := 0; i < count; i++ {
		name := ""
		if i < len(names) {
			name = names[i]
		}
		out.fds = append(out.fds, systemdActivatedFD{
			fd:   workerListenFDStart + i,
			name: name,
		})
	}
	return out, nil
}

func loadSystemdActivation(getenv func(string) string, pid int) (*systemdActivation, error) {
	rawFDS := strings.TrimSpace(getenv("LISTEN_FDS"))
	if rawFDS == "" || rawFDS == "0" {
		return &systemdActivation{}, nil
	}
	rawPID := strings.TrimSpace(getenv("LISTEN_PID"))
	if rawPID == "" {
		return nil, fmt.Errorf("LISTEN_PID is required when LISTEN_FDS is set")
	}
	listenPID, err := strconv.Atoi(rawPID)
	if err != nil {
		return nil, fmt.Errorf("LISTEN_PID is invalid: %w", err)
	}
	if listenPID != pid {
		return &systemdActivation{}, nil
	}
	count, err := strconv.Atoi(rawFDS)
	if err != nil {
		return nil, fmt.Errorf("LISTEN_FDS is invalid: %w", err)
	}
	if count < 0 || count > 16 {
		return nil, fmt.Errorf("LISTEN_FDS must be between 0 and 16")
	}
	names := splitSystemdFDNames(getenv("LISTEN_FDNAMES"))
	out := &systemdActivation{
		active: count > 0,
		fds:    make([]systemdActivatedFD, 0, count),
		used:   make(map[int]struct{}, count),
	}
	for i := 0; i < count; i++ {
		name := ""
		if i < len(names) {
			name = names[i]
		}
		out.fds = append(out.fds, systemdActivatedFD{
			fd:   systemdListenFDStart + i,
			name: name,
		})
	}
	return out, nil
}

func splitSystemdFDNames(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ":")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, strings.TrimSpace(part))
	}
	return out
}

func (a *systemdActivation) Active() bool {
	return a != nil && a.active && len(a.fds) > 0
}

func (a *systemdActivation) CloseUnused() {
	if !a.Active() {
		return
	}
	for _, entry := range a.fds {
		if _, used := a.used[entry.fd]; used {
			continue
		}
		_ = syscall.Close(entry.fd)
	}
}

func (a *systemdActivation) TakeTCP(role string, configuredAddr string) (net.Listener, bool, error) {
	entry, ok, err := a.take(role)
	if err != nil || !ok {
		return nil, ok, err
	}
	file := os.NewFile(uintptr(entry.fd), "systemd-"+role)
	if file == nil {
		return nil, true, fmt.Errorf("systemd fd for %s is invalid", role)
	}
	defer file.Close()
	ln, err := net.FileListener(file)
	if err != nil {
		return nil, true, fmt.Errorf("systemd fd for %s is not a listener: %w", role, err)
	}
	if !strings.HasPrefix(ln.Addr().Network(), "tcp") {
		_ = ln.Close()
		return nil, true, fmt.Errorf("systemd fd for %s is %s, want tcp", role, ln.Addr().Network())
	}
	if err := validateActivatedAddr(role, ln.Addr(), configuredAddr); err != nil {
		_ = ln.Close()
		return nil, true, err
	}
	return ln, true, nil
}

func (a *systemdActivation) TakePacketConn(role string, configuredAddr string) (net.PacketConn, bool, error) {
	entry, ok, err := a.take(role)
	if err != nil || !ok {
		return nil, ok, err
	}
	file := os.NewFile(uintptr(entry.fd), "systemd-"+role)
	if file == nil {
		return nil, true, fmt.Errorf("systemd fd for %s is invalid", role)
	}
	defer file.Close()
	conn, err := net.FilePacketConn(file)
	if err != nil {
		return nil, true, fmt.Errorf("systemd fd for %s is not a packet conn: %w", role, err)
	}
	if !strings.HasPrefix(conn.LocalAddr().Network(), "udp") {
		_ = conn.Close()
		return nil, true, fmt.Errorf("systemd fd for %s is %s, want udp", role, conn.LocalAddr().Network())
	}
	if err := validateActivatedAddr(role, conn.LocalAddr(), configuredAddr); err != nil {
		_ = conn.Close()
		return nil, true, err
	}
	return conn, true, nil
}

func (a *systemdActivation) take(role string) (systemdActivatedFD, bool, error) {
	if !a.Active() {
		return systemdActivatedFD{}, false, nil
	}
	if entry, ok := a.takeNamed(role); ok {
		return entry, true, nil
	}
	if systemdActivationHasNames(a.fds) {
		return systemdActivatedFD{}, false, fmt.Errorf("systemd activation is enabled but no fd name matches role %q", role)
	}
	idx := systemdActivationRoleIndex(role)
	if idx < 0 || idx >= len(a.fds) {
		return systemdActivatedFD{}, false, fmt.Errorf("systemd activation is enabled but no positional fd exists for role %q", role)
	}
	entry := a.fds[idx]
	if _, used := a.used[entry.fd]; used {
		return systemdActivatedFD{}, false, fmt.Errorf("systemd fd for role %q was already used", role)
	}
	a.used[entry.fd] = struct{}{}
	return entry, true, nil
}

func (a *systemdActivation) takeNamed(role string) (systemdActivatedFD, bool) {
	aliases := systemdActivationRoleNames(role)
	for _, entry := range a.fds {
		if _, used := a.used[entry.fd]; used {
			continue
		}
		for _, alias := range aliases {
			if entry.name == alias {
				a.used[entry.fd] = struct{}{}
				return entry, true
			}
		}
	}
	return systemdActivatedFD{}, false
}

func systemdActivationRoleNames(role string) []string {
	role = strings.TrimSpace(role)
	return []string{
		role,
		"tukuyomi-" + role,
		"tukuyomi-" + role,
	}
}

func systemdActivationHasNames(fds []systemdActivatedFD) bool {
	for _, entry := range fds {
		if strings.TrimSpace(entry.name) != "" {
			return true
		}
	}
	return false
}

func systemdActivationRoleIndex(role string) int {
	switch strings.TrimSpace(role) {
	case "public":
		return 0
	case "admin":
		return 1
	case "redirect":
		return 2
	case "http3":
		return 3
	default:
		return -1
	}
}

func validateActivatedAddr(role string, local net.Addr, configuredAddr string) error {
	if local == nil {
		return fmt.Errorf("systemd fd for %s has no local address", role)
	}
	localHost, localPort, err := splitNetAddr(local.String())
	if err != nil {
		return fmt.Errorf("parse systemd fd local address for %s: %w", role, err)
	}
	configHost, configPort, err := splitNetAddr(configuredAddr)
	if err != nil {
		return fmt.Errorf("parse configured listener address for %s: %w", role, err)
	}
	if localPort != configPort {
		return fmt.Errorf("systemd fd for %s listens on port %s, want %s", role, localPort, configPort)
	}
	if isWildcardHost(configHost) {
		return nil
	}
	if isWildcardHost(localHost) {
		return fmt.Errorf("systemd fd for %s listens on wildcard host, want %s", role, configHost)
	}
	if sameHostLiteral(localHost, configHost) {
		return nil
	}
	return fmt.Errorf("systemd fd for %s listens on host %s, want %s", role, localHost, configHost)
}

func splitNetAddr(addr string) (string, string, error) {
	addr = strings.TrimSpace(addr)
	if strings.HasPrefix(addr, ":") {
		return "", strings.TrimPrefix(addr, ":"), nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", err
	}
	return strings.Trim(host, "[]"), port, nil
}

func isWildcardHost(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	return host == "" || host == "*" || host == "0.0.0.0" || host == "::" || host == "::0"
}

func sameHostLiteral(left string, right string) bool {
	left = strings.TrimSpace(strings.Trim(left, "[]"))
	right = strings.TrimSpace(strings.Trim(right, "[]"))
	if strings.EqualFold(left, right) {
		return true
	}
	leftAddr, leftErr := netip.ParseAddr(left)
	rightAddr, rightErr := netip.ParseAddr(right)
	if leftErr == nil && rightErr == nil {
		return leftAddr == rightAddr
	}
	if strings.EqualFold(left, "localhost") && rightErr == nil {
		return rightAddr.IsLoopback()
	}
	if strings.EqualFold(right, "localhost") && leftErr == nil {
		return leftAddr.IsLoopback()
	}
	return false
}
