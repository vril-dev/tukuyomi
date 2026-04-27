package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/quic-go/quic-go/http3"

	"tukuyomi/internal/config"
	"tukuyomi/internal/serverruntime"
)

func buildManagedServerHTTP3Server(tlsConfig *tls.Config, appHandler http.Handler) (*http3.Server, string, error) {
	if !config.ServerHTTP3Enabled {
		return nil, "", nil
	}
	if !config.ServerTLSEnabled {
		err := fmt.Errorf("server http3 requires tls listener")
		serverruntime.RecordHTTP3Error(err)
		return nil, "", err
	}
	if tlsConfig == nil {
		err := fmt.Errorf("server http3 requires tls config")
		serverruntime.RecordHTTP3Error(err)
		return nil, "", err
	}
	altSvc, err := serverHTTP3AltSvcHeader(config.ListenAddr, config.ServerHTTP3AltSvcMaxAgeSec)
	if err != nil {
		serverruntime.RecordHTTP3Error(err)
		return nil, "", err
	}
	srv := &http3.Server{
		Addr:           config.ListenAddr,
		Handler:        appHandler,
		TLSConfig:      tlsConfig.Clone(),
		MaxHeaderBytes: config.ServerMaxHeaderBytes,
		IdleTimeout:    config.ServerIdleTimeout,
	}
	serverruntime.RecordHTTP3Configured(altSvc)
	return srv, altSvc, nil
}

func wrapHTTP3AltSvcHandler(next http.Handler, altSvc string) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	altSvc = strings.TrimSpace(altSvc)
	if altSvc == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Alt-Svc", altSvc)
		next.ServeHTTP(w, r)
	})
}

func serverHTTP3AltSvcHeader(listenAddr string, maxAgeSec int) (string, error) {
	port, err := serverHTTP3Port(listenAddr)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`h3=":%d"; ma=%d`, port, maxAgeSec), nil
}

func serverHTTP3Port(listenAddr string) (int, error) {
	_, port, err := net.SplitHostPort(strings.TrimSpace(listenAddr))
	if err != nil {
		return 0, fmt.Errorf("parse server.listen_addr for http3 alt-svc: %w", err)
	}
	value, err := net.LookupPort("tcp", port)
	if err != nil {
		return 0, fmt.Errorf("resolve server.listen_addr port for http3 alt-svc: %w", err)
	}
	return value, nil
}

func runHTTP3Server(lifecycle *managedServerLifecycle, activation *systemdActivation, srv *http3.Server) error {
	if srv == nil {
		return nil
	}
	var packetConn net.PacketConn
	var inherited bool
	if activation != nil && activation.Active() {
		conn, ok, err := activation.TakePacketConn("http3", config.ListenAddr)
		if err != nil {
			serverruntime.RecordHTTP3Error(err)
			return err
		}
		if !ok {
			err := fmt.Errorf("systemd activation is enabled but no fd exists for role %q", "http3")
			serverruntime.RecordHTTP3Error(err)
			return err
		}
		packetConn = conn
		inherited = true
	}
	lifecycle.Go(
		"http3",
		func() error {
			log.Printf("[INFO] starting HTTP/3 server on %s/udp inherited=%t", config.ListenAddr, inherited)
			if packetConn != nil {
				return srv.Serve(packetConn)
			}
			return srv.ListenAndServe()
		},
		srv.Shutdown,
		func() error {
			err := srv.Close()
			if packetConn != nil {
				if closeErr := packetConn.Close(); err == nil {
					err = closeErr
				}
			}
			return err
		},
	)
	return nil
}

func closeHTTP3Server(srv *http3.Server) {
	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
