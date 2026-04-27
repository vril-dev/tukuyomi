package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"strconv"
	"strings"
	"time"
)

const pprofAddrEnv = "TUKUYOMI_PPROF_ADDR"

func startOptionalPprofServerFromEnv() (func(context.Context) error, error) {
	rawAddr := strings.TrimSpace(os.Getenv(pprofAddrEnv))
	if rawAddr == "" {
		return func(context.Context) error { return nil }, nil
	}

	addr, err := validatePprofListenAddr(rawAddr)
	if err != nil {
		return nil, err
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen pprof: %w", err)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           newPprofMux(),
		ReadHeaderTimeout: 2 * time.Second,
	}
	go func() {
		log.Printf("[PPROF] listening on %s", addr)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[PPROF][FATAL] server stopped: %v", err)
		}
	}()

	return srv.Shutdown, nil
}

func validatePprofListenAddr(rawAddr string) (string, error) {
	addr := strings.TrimSpace(rawAddr)
	if addr == "" {
		return "", fmt.Errorf("%s is empty", pprofAddrEnv)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("%s must be loopback host:port: %w", pprofAddrEnv, err)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("%s host must be explicit loopback", pprofAddrEnv)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return "", fmt.Errorf("%s port must be between 1 and 65535", pprofAddrEnv)
	}
	if strings.EqualFold(host, "localhost") {
		return net.JoinHostPort(host, port), nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("%s must bind to localhost or loopback IP, got %q", pprofAddrEnv, host)
	}
	return net.JoinHostPort(host, port), nil
}

func newPprofMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	for _, name := range []string{
		"allocs",
		"block",
		"goroutine",
		"heap",
		"mutex",
		"threadcreate",
	} {
		mux.Handle("/debug/pprof/"+name, pprof.Handler(name))
	}
	return mux
}
