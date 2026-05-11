package config

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	PublicListenerProtocolHTTP  = "http"
	PublicListenerProtocolHTTPS = "https"

	PublicListenerHTTPBehaviorServe    = "serve"
	PublicListenerHTTPBehaviorRedirect = "redirect"
)

var publicListenerNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

type ServerPublicListener struct {
	Name         string
	ListenAddr   string
	Protocol     string
	HTTPBehavior string
	RedirectTo   string
	Enabled      bool
}

func normalizeAppServerPublicListeners(listeners []appServerPublicListenerConfig) {
	for i := range listeners {
		listeners[i].Name = strings.ToLower(strings.TrimSpace(listeners[i].Name))
		listeners[i].ListenAddr = strings.TrimSpace(listeners[i].ListenAddr)
		listeners[i].Protocol = normalizePublicListenerProtocol(listeners[i].Protocol)
		listeners[i].HTTPBehavior = normalizePublicListenerHTTPBehavior(listeners[i].HTTPBehavior)
		listeners[i].RedirectTo = strings.ToLower(strings.TrimSpace(listeners[i].RedirectTo))
	}
}

func normalizePublicListenerProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "", PublicListenerProtocolHTTP:
		return PublicListenerProtocolHTTP
	case PublicListenerProtocolHTTPS:
		return PublicListenerProtocolHTTPS
	default:
		return strings.ToLower(strings.TrimSpace(protocol))
	}
}

func normalizePublicListenerHTTPBehavior(behavior string) string {
	switch strings.ToLower(strings.TrimSpace(behavior)) {
	case "", PublicListenerHTTPBehaviorServe:
		return PublicListenerHTTPBehaviorServe
	case PublicListenerHTTPBehaviorRedirect:
		return PublicListenerHTTPBehaviorRedirect
	default:
		return strings.ToLower(strings.TrimSpace(behavior))
	}
}

func validateAppServerPublicListenersConfig(cfg appConfigFile) error {
	listeners := cfg.Server.PublicListeners
	if len(listeners) == 0 {
		return nil
	}
	if cfg.Server.TLS.RedirectHTTP {
		return fmt.Errorf("server.tls.redirect_http is replaced by server.public_listeners[].http_behavior=redirect")
	}

	names := make(map[string]struct{}, len(listeners))
	addrs := make(map[string]string, len(listeners))
	httpsNames := make(map[string]struct{}, len(listeners))
	enabledCount := 0
	for i, listener := range listeners {
		field := fmt.Sprintf("server.public_listeners[%d]", i)
		if listener.Name == "" {
			return fmt.Errorf("%s.name is required", field)
		}
		if !publicListenerNamePattern.MatchString(listener.Name) {
			return fmt.Errorf("%s.name must use lowercase letters, digits, '-' or '_'", field)
		}
		if _, ok := names[listener.Name]; ok {
			return fmt.Errorf("%s.name duplicates another public listener", field)
		}
		names[listener.Name] = struct{}{}

		switch listener.Protocol {
		case PublicListenerProtocolHTTP, PublicListenerProtocolHTTPS:
		default:
			return fmt.Errorf("%s.protocol must be http or https", field)
		}
		switch listener.HTTPBehavior {
		case PublicListenerHTTPBehaviorServe, PublicListenerHTTPBehaviorRedirect:
		default:
			return fmt.Errorf("%s.http_behavior must be serve or redirect", field)
		}
		if listener.Protocol == PublicListenerProtocolHTTPS && listener.HTTPBehavior != PublicListenerHTTPBehaviorServe {
			return fmt.Errorf("%s.http_behavior must be serve for https listeners", field)
		}
		if listener.Protocol == PublicListenerProtocolHTTP && listener.HTTPBehavior == PublicListenerHTTPBehaviorRedirect && listener.RedirectTo == listener.Name {
			return fmt.Errorf("%s.redirect_to must point to a different https listener", field)
		}
		if !listener.Enabled {
			continue
		}
		enabledCount++
		addr, err := normalizeValidatedListenAddr(listener.ListenAddr)
		if err != nil {
			return fmt.Errorf("%s.listen_addr invalid: %w", field, err)
		}
		for priorName, priorAddr := range addrs {
			if listenAddrsCollide(addr, priorAddr) {
				return fmt.Errorf("%s.listen_addr collides with server.public_listeners[%s].listen_addr", field, priorName)
			}
		}
		if adminAddr := strings.TrimSpace(cfg.Admin.ListenAddr); adminAddr != "" {
			normalizedAdminAddr, err := normalizeValidatedListenAddr(adminAddr)
			if err != nil {
				return fmt.Errorf("admin.listen_addr invalid: %w", err)
			}
			if listenAddrsCollide(addr, normalizedAdminAddr) {
				return fmt.Errorf("%s.listen_addr must be different from admin.listen_addr", field)
			}
		}
		addrs[listener.Name] = addr
		if listener.Protocol == PublicListenerProtocolHTTPS {
			httpsNames[listener.Name] = struct{}{}
		}
	}
	if enabledCount == 0 {
		return fmt.Errorf("server.public_listeners must include at least one enabled listener")
	}

	for i, listener := range listeners {
		if !listener.Enabled || listener.Protocol != PublicListenerProtocolHTTP || listener.HTTPBehavior != PublicListenerHTTPBehaviorRedirect {
			continue
		}
		field := fmt.Sprintf("server.public_listeners[%d]", i)
		redirectTo := listener.RedirectTo
		if redirectTo == "" {
			if len(httpsNames) != 1 {
				return fmt.Errorf("%s.redirect_to is required unless exactly one enabled https listener exists", field)
			}
			continue
		}
		if _, ok := httpsNames[redirectTo]; !ok {
			return fmt.Errorf("%s.redirect_to must point to an enabled https listener", field)
		}
	}
	if len(httpsNames) > 0 && !cfg.Server.TLS.Enabled {
		return fmt.Errorf("server.tls.enabled must be true when an https public listener is enabled")
	}
	if cfg.Server.HTTP3.Enabled && len(httpsNames) == 0 {
		return fmt.Errorf("server.http3.enabled requires at least one enabled https public listener")
	}
	return nil
}

func effectiveServerPublicListeners(cfg appConfigFile) []ServerPublicListener {
	if len(cfg.Server.PublicListeners) == 0 {
		return nil
	}
	out := make([]ServerPublicListener, 0, len(cfg.Server.PublicListeners))
	for _, listener := range cfg.Server.PublicListeners {
		listenAddr := ""
		if listener.ListenAddr != "" {
			listenAddr = parseListenAddr(listener.ListenAddr)
		}
		out = append(out, ServerPublicListener{
			Name:         listener.Name,
			ListenAddr:   listenAddr,
			Protocol:     listener.Protocol,
			HTTPBehavior: listener.HTTPBehavior,
			RedirectTo:   listener.RedirectTo,
			Enabled:      listener.Enabled,
		})
	}
	return out
}

func primaryPublicListenAddr(listeners []ServerPublicListener, fallback string) string {
	for _, listener := range listeners {
		if listener.Enabled && listener.Protocol == PublicListenerProtocolHTTPS && listener.ListenAddr != "" {
			return listener.ListenAddr
		}
	}
	for _, listener := range listeners {
		if listener.Enabled && listener.ListenAddr != "" {
			return listener.ListenAddr
		}
	}
	return fallback
}

func PublicListenerRedirectTargetAddr(listeners []ServerPublicListener, redirectTo string) (string, bool) {
	redirectTo = strings.TrimSpace(redirectTo)
	if redirectTo != "" {
		for _, listener := range listeners {
			if listener.Enabled && listener.Name == redirectTo && listener.Protocol == PublicListenerProtocolHTTPS {
				return listener.ListenAddr, true
			}
		}
		return "", false
	}
	for _, listener := range listeners {
		if listener.Enabled && listener.Protocol == PublicListenerProtocolHTTPS {
			return listener.ListenAddr, true
		}
	}
	return "", false
}
