package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/pires/go-proxyproto"
)

type listenerProxyProtocolRuntime struct {
	enabled           bool
	trustedCIDRs      []string
	readHeaderTimeout time.Duration
}

func buildManagedTCPListener(addr string, runtime listenerProxyProtocolRuntime) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	wrapped, err := wrapManagedTCPListener(ln, runtime)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	return wrapped, nil
}

func buildManagedTCPListenerForRole(role string, addr string, runtime listenerProxyProtocolRuntime, activation *systemdActivation) (net.Listener, bool, error) {
	if activation != nil && activation.Active() {
		ln, ok, err := activation.TakeTCP(role, addr)
		if err != nil || ok {
			if err != nil {
				return nil, ok, err
			}
			wrapped, wrapErr := wrapManagedTCPListener(ln, runtime)
			if wrapErr != nil {
				_ = ln.Close()
				return nil, ok, wrapErr
			}
			return wrapped, ok, nil
		}
		return nil, false, fmt.Errorf("systemd activation is enabled but no fd exists for role %q", role)
	}
	ln, err := buildManagedTCPListener(addr, runtime)
	return ln, false, err
}

func wrapManagedTCPListener(ln net.Listener, runtime listenerProxyProtocolRuntime) (net.Listener, error) {
	if ln == nil {
		return nil, fmt.Errorf("listener is required")
	}
	if !runtime.enabled {
		return ln, nil
	}
	trusted := make([]string, 0, len(runtime.trustedCIDRs))
	for _, raw := range runtime.trustedCIDRs {
		cidr := strings.TrimSpace(raw)
		if cidr != "" {
			trusted = append(trusted, cidr)
		}
	}
	if len(trusted) == 0 {
		return nil, fmt.Errorf("trusted_cidrs required when proxy protocol is enabled")
	}
	policy, err := proxyproto.ConnStrictWhiteListPolicy(trusted)
	if err != nil {
		return nil, err
	}
	return &proxyproto.Listener{
		Listener:          ln,
		ConnPolicy:        policy,
		ReadHeaderTimeout: runtime.readHeaderTimeout,
	}, nil
}
