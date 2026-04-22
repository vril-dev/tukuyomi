package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	benchPath := flag.String("path", "/bench", "benchmark response path")
	portFile := flag.String("port-file", "", "file to write the selected TCP port")
	body := flag.String("body", "ok\n", "response body")
	flag.Parse()

	if err := validatePath(*benchPath); err != nil {
		log.Fatalf("invalid path: %v", err)
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	defer ln.Close()

	selectedPort, err := selectedTCPPort(ln.Addr())
	if err != nil {
		log.Fatalf("resolve selected port: %v", err)
	}
	if *portFile != "" {
		if err := writePortFile(*portFile, selectedPort); err != nil {
			log.Fatalf("write port file: %v", err)
		}
	}

	responseBody := []byte(*body)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL == nil || r.URL.Path != *benchPath {
			http.NotFound(w, r)
			return
		}
		_, _ = io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, 1<<20))
		_ = r.Body.Close()

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Tukuyomi-Benchmark-Upstream", "go")
		w.Header().Set("Content-Length", strconv.Itoa(len(responseBody)))
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(responseBody)
		}
	})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("benchmark upstream listening on %s path=%s", ln.Addr().String(), *benchPath)
		errCh <- server.Serve(ln)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("received %s, shutting down", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Fatalf("shutdown: %v", err)
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve: %v", err)
		}
	}
}

func validatePath(p string) error {
	if p == "" || !strings.HasPrefix(p, "/") {
		return fmt.Errorf("path must start with '/'")
	}
	if strings.Contains(p, "..") || strings.ContainsAny(p, "?#") {
		return fmt.Errorf("path must not contain '..', query, or fragment")
	}
	if strings.HasSuffix(p, "/") {
		return fmt.Errorf("path must not end with '/'")
	}
	return nil
}

func selectedTCPPort(addr net.Addr) (int, error) {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("unexpected address type %T", addr)
	}
	if tcpAddr.Port <= 0 || tcpAddr.Port > 65535 {
		return 0, fmt.Errorf("invalid port %d", tcpAddr.Port)
	}
	return tcpAddr.Port, nil
}

func writePortFile(path string, port int) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(port)+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
