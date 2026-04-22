package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
)

const letsEncryptStagingDirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

type managedServerTLSRuntime struct {
	minVersion uint16

	mu                 sync.RWMutex
	legacyCert         *tls.Certificate
	legacyNotAfter     time.Time
	acmeManager        *autocert.Manager
	acmeGetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	hasManual          bool
	hasACME            bool
	siteManualNotAfter time.Time
}

func newHTTPRedirectServer(addr string, tlsListenAddr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := &url.URL{
				Scheme:   "https",
				Host:     redirectTargetHost(r.Host, tlsListenAddr),
				Path:     r.URL.Path,
				RawPath:  r.URL.RawPath,
				RawQuery: r.URL.RawQuery,
			}
			http.Redirect(w, r, target.String(), http.StatusPermanentRedirect)
		}),
	}
}

func newDynamicHTTPRedirectServer(addr string, tlsListenAddr string, runtime *managedServerTLSRuntime) *http.Server {
	redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := &url.URL{
			Scheme:   "https",
			Host:     redirectTargetHost(r.Host, tlsListenAddr),
			Path:     r.URL.Path,
			RawPath:  r.URL.RawPath,
			RawQuery: r.URL.RawQuery,
		}
		http.Redirect(w, r, target.String(), http.StatusPermanentRedirect)
	})
	return &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if runtime != nil {
				if manager := runtime.acmeManagerSnapshot(); manager != nil {
					manager.HTTPHandler(redirect).ServeHTTP(w, r)
					return
				}
			}
			redirect.ServeHTTP(w, r)
		}),
	}
}

func buildManagedServerTLSConfig() (*tls.Config, *http.Server, error) {
	handler.ResetServerTLSRuntimeStatus()
	if !config.ServerTLSEnabled {
		return nil, nil, nil
	}
	minVersion, err := parseServerTLSMinVersion(config.ServerTLSMinVersion)
	if err != nil {
		handler.RecordServerTLSError(err)
		return nil, nil, err
	}

	_, _, sites, statuses, _ := handler.SiteConfigSnapshot()
	runtime := &managedServerTLSRuntime{minVersion: minVersion}
	if err := runtime.Reload(sites, statuses); err != nil {
		handler.RecordServerTLSError(err)
		return nil, nil, err
	}
	handler.SetServerTLSReloadHook(runtime.Reload)

	tlsConfig := &tls.Config{MinVersion: minVersion}
	tlsConfig.GetCertificate = runtime.GetCertificate
	var redirectSrv *http.Server
	if config.ServerTLSRedirectHTTP {
		redirectSrv = newDynamicHTTPRedirectServer(config.ServerTLSHTTPRedirectAddr, config.ListenAddr, runtime)
	}
	return tlsConfig, redirectSrv, nil
}

func buildACMEManager(domains []string) *autocert.Manager {
	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Email:      strings.TrimSpace(config.ServerTLSACMEEmail),
		HostPolicy: autocert.HostWhitelist(domains...),
		Cache:      autocert.DirCache(config.ServerTLSACMECacheDir),
	}
	if config.ServerTLSACMEStaging {
		manager.Client = &acme.Client{DirectoryURL: letsEncryptStagingDirectoryURL}
	}
	return manager
}

func (rt *managedServerTLSRuntime) Reload(sites handler.SiteConfigFile, statuses []handler.SiteRuntimeStatus) error {
	var (
		legacyTLSConfig *tls.Config
		legacyCert      *tls.Certificate
		legacyNotAfter  time.Time
	)
	if strings.TrimSpace(config.ServerTLSCertFile) != "" || strings.TrimSpace(config.ServerTLSKeyFile) != "" {
		tlsConfig, err := config.BuildServerTLSConfig(config.ServerTLSCertFile, config.ServerTLSKeyFile, config.ServerTLSMinVersion)
		if err != nil {
			handler.RecordServerTLSError(err)
			return err
		}
		legacyTLSConfig = tlsConfig
		legacyCert = &legacyTLSConfig.Certificates[0]
		if notAfter, parseErr := certificateNotAfter(*legacyCert); parseErr == nil {
			legacyNotAfter = notAfter
		}
	}

	var (
		manager            *autocert.Manager
		baseGetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
		hasACME            = config.ServerTLSACMEEnabled
	)
	if hasACME {
		domains := handler.EffectiveServerTLSACMEDomainsForSites(sites)
		if len(domains) == 0 {
			err := fmt.Errorf("server tls acme enabled but no ACME host domains are configured")
			handler.RecordServerTLSError(err)
			return err
		}
		manager = buildACMEManager(domains)
		baseCfg := manager.TLSConfig()
		baseCfg.MinVersion = rt.minVersion
		baseGetCertificate = baseCfg.GetCertificate
	}

	hasManual := legacyCert != nil
	siteManualNotAfter := latestManualSiteNotAfter(statuses)
	for _, site := range statuses {
		if site.Enabled && site.TLSMode == "manual" {
			hasManual = true
			break
		}
	}
	if !hasManual && !hasACME {
		err := fmt.Errorf("server tls enabled but no legacy or site-managed certificate source is configured")
		handler.RecordServerTLSError(err)
		return err
	}

	rt.mu.Lock()
	rt.legacyCert = legacyCert
	rt.legacyNotAfter = legacyNotAfter
	rt.acmeManager = manager
	rt.acmeGetCertificate = baseGetCertificate
	rt.hasManual = hasManual
	rt.hasACME = hasACME
	rt.siteManualNotAfter = siteManualNotAfter
	rt.mu.Unlock()

	source := tlsSourceLabel(hasManual, hasACME)
	switch {
	case !legacyNotAfter.IsZero():
		handler.RecordServerTLSConfigured(source, legacyNotAfter)
	case !siteManualNotAfter.IsZero():
		handler.RecordServerTLSConfigured(source, siteManualNotAfter)
	default:
		handler.RecordServerTLSConfigured(source, time.Time{})
	}
	return nil
}

func (rt *managedServerTLSRuntime) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	rt.mu.RLock()
	legacyCert := rt.legacyCert
	baseGetCertificate := rt.acmeGetCertificate
	rt.mu.RUnlock()

	if hello != nil {
		if match := handler.SiteBindingForHost(hello.ServerName); match.Mode != "" {
			switch match.Mode {
			case "manual":
				if match.Certificate != nil {
					return match.Certificate, nil
				}
			case "acme":
				if baseGetCertificate == nil {
					err := fmt.Errorf("acme certificate source is not configured")
					handler.RecordServerTLSError(err)
					return nil, err
				}
				cert, err := baseGetCertificate(hello)
				if err != nil {
					handler.RecordServerTLSACMEFailure(err)
					return nil, err
				}
				if notAfter, parseErr := certificateNotAfter(*cert); parseErr != nil {
					handler.RecordServerTLSACMEFailure(parseErr)
				} else {
					handler.RecordServerTLSACMESuccess(notAfter)
				}
				return cert, nil
			case "legacy":
				// fall through to legacy selection below.
			}
		}
	}
	if legacyCert != nil {
		return legacyCert, nil
	}
	if baseGetCertificate != nil {
		cert, err := baseGetCertificate(hello)
		if err != nil {
			handler.RecordServerTLSACMEFailure(err)
			return nil, err
		}
		if notAfter, parseErr := certificateNotAfter(*cert); parseErr != nil {
			handler.RecordServerTLSACMEFailure(parseErr)
		} else {
			handler.RecordServerTLSACMESuccess(notAfter)
		}
		return cert, nil
	}
	err := fmt.Errorf("no certificate configured for requested host")
	handler.RecordServerTLSError(err)
	return nil, err
}

func (rt *managedServerTLSRuntime) acmeManagerSnapshot() *autocert.Manager {
	if rt == nil {
		return nil
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.acmeManager
}

func latestManualSiteNotAfter(statuses []handler.SiteRuntimeStatus) time.Time {
	var best time.Time
	for _, status := range statuses {
		if !status.Enabled || status.TLSMode != "manual" || strings.TrimSpace(status.TLSCertNotAfter) == "" {
			continue
		}
		parsed, err := time.Parse(time.RFC3339Nano, status.TLSCertNotAfter)
		if err != nil {
			continue
		}
		if best.IsZero() || parsed.Before(best) {
			best = parsed
		}
	}
	return best
}

func tlsSourceLabel(hasManual bool, hasACME bool) string {
	switch {
	case hasManual && hasACME:
		return "composite"
	case hasACME:
		return "acme"
	default:
		return "manual"
	}
}

func parseServerTLSMinVersion(v string) (uint16, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "tls1.2", "1.2", "tls12", "1_2":
		return tls.VersionTLS12, nil
	case "tls1.3", "1.3", "tls13", "1_3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("server tls min_version must be tls1.2 or tls1.3")
	}
}

func certificateNotAfter(cert tls.Certificate) (time.Time, error) {
	if cert.Leaf != nil {
		return cert.Leaf.NotAfter, nil
	}
	if len(cert.Certificate) == 0 {
		return time.Time{}, fmt.Errorf("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return time.Time{}, err
	}
	return leaf.NotAfter, nil
}

func redirectTargetHost(requestHost string, tlsListenAddr string) string {
	tlsPort := tlsListenPort(tlsListenAddr)
	host := strings.TrimSpace(requestHost)
	if host == "" {
		if tlsPort == "443" {
			return "127.0.0.1"
		}
		return net.JoinHostPort("127.0.0.1", tlsPort)
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		if tlsPort == "443" {
			return strings.Trim(parsedHost, "[]")
		}
		return net.JoinHostPort(strings.Trim(parsedHost, "[]"), tlsPort)
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		if tlsPort == "443" {
			return host
		}
		return net.JoinHostPort(strings.Trim(host, "[]"), tlsPort)
	}
	if tlsPort == "443" {
		return host
	}
	return net.JoinHostPort(host, tlsPort)
}

func tlsListenPort(listenAddr string) string {
	s := strings.TrimSpace(listenAddr)
	if s == "" {
		return "443"
	}
	if strings.HasPrefix(s, ":") {
		return strings.TrimPrefix(s, ":")
	}
	if _, port, err := net.SplitHostPort(s); err == nil && strings.TrimSpace(port) != "" {
		return port
	}
	return "443"
}
