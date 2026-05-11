package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"

	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
	"tukuyomi/internal/serverruntime"
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

func publicListenerHTTP3Role(listener config.ServerPublicListener) string {
	role := publicListenerRole(listener)
	if role == "public" {
		return "http3"
	}
	return role + "-http3"
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
	newServer := func(httpHandler http.Handler) *handler.NativeHTTP1Server {
		return &handler.NativeHTTP1Server{
			Handler:           httpHandler,
			ReadTimeout:       config.ServerReadTimeout,
			ReadHeaderTimeout: config.ServerReadHeaderTimeout,
			WriteTimeout:      config.ServerWriteTimeout,
			IdleTimeout:       config.ServerIdleTimeout,
			MaxHeaderBytes:    config.ServerMaxHeaderBytes,
		}
	}
	serverFor := func(first bool, httpHandler http.Handler) *handler.NativeHTTP1Server {
		if first && baseServer != nil {
			baseServer.Handler = httpHandler
			return baseServer
		}
		return newServer(httpHandler)
	}

	firstServeListener := true
	started := 0
	for _, listener := range config.ServerPublicListeners {
		if !listener.Enabled {
			continue
		}
		role := publicListenerRole(listener)

		switch listener.Protocol {
		case config.PublicListenerProtocolHTTPS:
			if tlsConfig == nil {
				log.Printf("[SERVER][WARN] skipping HTTPS public listener name=%s addr=%s because server TLS is not configured", listener.Name, listener.ListenAddr)
				continue
			}
			ln, inherited, err := buildManagedTCPListenerForRole(role, listener.ListenAddr, listenerRuntime, activation)
			if err != nil {
				return fmt.Errorf("create %s listener: %w", role, err)
			}
			ln = lifecycle.TrackListener(role, ln)
			httpsHandler := publicHandler
			if config.ServerHTTP3Enabled {
				http3Srv, altSvc, err := buildManagedServerHTTP3ServerForAddr(listener.ListenAddr, tlsConfig, publicHandler)
				if err != nil {
					return fmt.Errorf("build %s HTTP/3 config: %w", role, err)
				}
				if altSvc != "" {
					httpsHandler = wrapHTTP3AltSvcHandler(publicHandler, altSvc)
				}
				if err := runHTTP3ServerForRole(lifecycle, activation, publicListenerHTTP3Role(listener), listener.ListenAddr, http3Srv); err != nil {
					return fmt.Errorf("start %s HTTP/3 listener: %w", role, err)
				}
			}
			srv := serverFor(firstServeListener, httpsHandler)
			firstServeListener = false
			started++
			lifecycle.Go(role, func() error {
				if config.ServerHTTP2Enabled {
					serverruntime.RecordHTTP2Configured(true)
					log.Printf("[INFO] starting HTTPS public listener name=%s addr=%s inherited=%t engine=native_http1_http2", listener.Name, listener.ListenAddr, inherited)
					return srv.ServeTLSHTTP2(ln, tlsConfig)
				}
				log.Printf("[INFO] starting HTTPS public listener name=%s addr=%s inherited=%t engine=native_http1", listener.Name, listener.ListenAddr, inherited)
				return srv.ServeTLS(ln, tlsConfig)
			}, srv.Shutdown, srv.Close)
		case config.PublicListenerProtocolHTTP:
			if listener.HTTPBehavior == config.PublicListenerHTTPBehaviorRedirect {
				if tlsConfig == nil {
					log.Printf("[SERVER][WARN] skipping HTTP redirect listener name=%s addr=%s because server TLS is not configured", listener.Name, listener.ListenAddr)
					continue
				}
				targetAddr, ok := config.PublicListenerRedirectTargetAddr(config.ServerPublicListeners, listener.RedirectTo)
				if !ok {
					return fmt.Errorf("%s redirect target is not available", role)
				}
				ln, inherited, err := buildManagedTCPListenerForRole(role, listener.ListenAddr, listenerRuntime, activation)
				if err != nil {
					return fmt.Errorf("create %s listener: %w", role, err)
				}
				ln = lifecycle.TrackListener(role, ln)
				redirectSrv := newDynamicHTTPRedirectServer(listener.ListenAddr, targetAddr, tlsRuntime)
				started++
				lifecycle.Go(role, func() error {
					log.Printf("[INFO] starting HTTP redirect listener name=%s addr=%s target=%s inherited=%t", listener.Name, listener.ListenAddr, targetAddr, inherited)
					return redirectSrv.Serve(ln)
				}, redirectSrv.Shutdown, redirectSrv.Close)
				continue
			}
			ln, inherited, err := buildManagedTCPListenerForRole(role, listener.ListenAddr, listenerRuntime, activation)
			if err != nil {
				return fmt.Errorf("create %s listener: %w", role, err)
			}
			ln = lifecycle.TrackListener(role, ln)
			serveHandler := withACMEHTTPChallengeHandler(publicHandler, tlsRuntime)
			srv := serverFor(firstServeListener, serveHandler)
			firstServeListener = false
			started++
			lifecycle.Go(role, func() error {
				log.Printf("[INFO] starting HTTP public listener name=%s addr=%s inherited=%t engine=native_http1", listener.Name, listener.ListenAddr, inherited)
				return srv.Serve(ln)
			}, srv.Shutdown, srv.Close)
		default:
			return fmt.Errorf("%s listener has unsupported protocol %q", role, listener.Protocol)
		}
	}
	if started == 0 {
		return fmt.Errorf("no enabled public listener could start")
	}
	return nil
}
