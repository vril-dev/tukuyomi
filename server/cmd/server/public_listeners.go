package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"

	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
)

func publicListenersNeedTLS(listeners []config.ServerPublicListener) bool {
	for _, listener := range listeners {
		if listener.Enabled && listener.Protocol == config.PublicListenerProtocolHTTPS {
			return true
		}
	}
	return false
}

func publicListenerRole(listener config.ServerPublicListener) string {
	name := strings.TrimSpace(listener.Name)
	if name == "" || name == "public" {
		return "public"
	}
	return "public-" + name
}

func runConfiguredPublicListeners(
	lifecycle *managedServerLifecycle,
	activation *systemdActivation,
	publicHandler http.Handler,
	baseServer *handler.NativeHTTP1Server,
	listenerRuntime listenerProxyProtocolRuntime,
	tlsConfig *tls.Config,
	tlsRuntime *managedServerTLSRuntime,
) error {
	if len(config.ServerPublicListeners) == 0 {
		return fmt.Errorf("server public listeners are not configured")
	}
	serverFor := func(first bool) *handler.NativeHTTP1Server {
		if first && baseServer != nil {
			return baseServer
		}
		return &handler.NativeHTTP1Server{
			Handler:           publicHandler,
			ReadTimeout:       config.ServerReadTimeout,
			ReadHeaderTimeout: config.ServerReadHeaderTimeout,
			WriteTimeout:      config.ServerWriteTimeout,
			IdleTimeout:       config.ServerIdleTimeout,
			MaxHeaderBytes:    config.ServerMaxHeaderBytes,
		}
	}

	firstServeListener := true
	for _, listener := range config.ServerPublicListeners {
		if !listener.Enabled {
			continue
		}
		role := publicListenerRole(listener)
		ln, inherited, err := buildManagedTCPListenerForRole(role, listener.ListenAddr, listenerRuntime, activation)
		if err != nil {
			return fmt.Errorf("create %s listener: %w", role, err)
		}
		ln = lifecycle.TrackListener(role, ln)

		switch listener.Protocol {
		case config.PublicListenerProtocolHTTPS:
			if tlsConfig == nil {
				_ = ln.Close()
				return fmt.Errorf("%s listener requires server TLS config", role)
			}
			srv := serverFor(firstServeListener)
			firstServeListener = false
			lifecycle.Go(role, func() error {
				log.Printf("[INFO] starting HTTPS public listener name=%s addr=%s inherited=%t engine=native_http1", listener.Name, listener.ListenAddr, inherited)
				return srv.ServeTLS(ln, tlsConfig)
			}, srv.Shutdown, srv.Close)
		case config.PublicListenerProtocolHTTP:
			if listener.HTTPBehavior == config.PublicListenerHTTPBehaviorRedirect {
				targetAddr, ok := config.PublicListenerRedirectTargetAddr(config.ServerPublicListeners, listener.RedirectTo)
				if !ok {
					_ = ln.Close()
					return fmt.Errorf("%s redirect target is not available", role)
				}
				redirectSrv := newDynamicHTTPRedirectServer(listener.ListenAddr, targetAddr, tlsRuntime)
				lifecycle.Go(role, func() error {
					log.Printf("[INFO] starting HTTP redirect listener name=%s addr=%s target=%s inherited=%t", listener.Name, listener.ListenAddr, targetAddr, inherited)
					return redirectSrv.Serve(ln)
				}, redirectSrv.Shutdown, redirectSrv.Close)
				continue
			}
			srv := serverFor(firstServeListener)
			firstServeListener = false
			lifecycle.Go(role, func() error {
				log.Printf("[INFO] starting HTTP public listener name=%s addr=%s inherited=%t engine=native_http1", listener.Name, listener.ListenAddr, inherited)
				return srv.Serve(ln)
			}, srv.Shutdown, srv.Close)
		default:
			_ = ln.Close()
			return fmt.Errorf("%s listener has unsupported protocol %q", role, listener.Protocol)
		}
	}
	return nil
}
