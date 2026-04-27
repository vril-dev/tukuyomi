package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
	"tukuyomi/internal/persistentstore"
)

const letsEncryptStagingDirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

type managedServerTLSRuntime struct {
	minVersion uint16

	mu                 sync.RWMutex
	legacyCert         *tls.Certificate
	legacyNotAfter     time.Time
	acmeManagers       map[string]*autocert.Manager
	acmeGetCertificate map[string]func(*tls.ClientHelloInfo) (*tls.Certificate, error)
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
				if manager := runtime.acmeManagerForHost(r.Host); manager != nil {
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

func buildACMEManager(profile handler.ServerTLSACMEProfile, cache autocert.Cache) *autocert.Manager {
	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Email:      strings.TrimSpace(profile.Email),
		HostPolicy: autocert.HostWhitelist(profile.Domains...),
		Cache:      cache,
	}
	if profile.Environment == "staging" {
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
		managers            map[string]*autocert.Manager
		getCertificateFuncs map[string]func(*tls.ClientHelloInfo) (*tls.Certificate, error)
		profiles            = handler.EffectiveServerTLSACMEProfilesForSites(sites)
		hasACME             = len(profiles) > 0
	)
	if hasACME {
		managers = make(map[string]*autocert.Manager, len(profiles))
		getCertificateFuncs = make(map[string]func(*tls.ClientHelloInfo) (*tls.Certificate, error), len(profiles))
		for _, profile := range profiles {
			if len(profile.Domains) == 0 {
				err := fmt.Errorf("server tls acme profile %q has no host domains", profile.Key)
				handler.RecordServerTLSError(err)
				return err
			}
			cache, err := buildServerTLSACMECache(profile)
			if err != nil {
				handler.RecordServerTLSError(err)
				return err
			}
			manager := buildACMEManager(profile, cache)
			baseCfg := manager.TLSConfig()
			baseCfg.MinVersion = rt.minVersion
			managers[profile.Key] = manager
			getCertificateFuncs[profile.Key] = baseCfg.GetCertificate
		}
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
	rt.acmeManagers = managers
	rt.acmeGetCertificate = getCertificateFuncs
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
	rt.mu.RUnlock()

	if hello != nil {
		if match := handler.SiteBindingForHost(hello.ServerName); match.Mode != "" {
			switch match.Mode {
			case "manual":
				if match.Certificate != nil {
					return match.Certificate, nil
				}
			case "acme":
				getCertificate := rt.acmeGetCertificateForProfile(match.ACMEProfile)
				if getCertificate == nil {
					err := fmt.Errorf("acme certificate source is not configured")
					handler.RecordServerTLSError(err)
					return nil, err
				}
				cert, err := getCertificate(hello)
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
	err := fmt.Errorf("no certificate configured for requested host")
	handler.RecordServerTLSError(err)
	return nil, err
}

func (rt *managedServerTLSRuntime) acmeManagerForHost(host string) *autocert.Manager {
	if rt == nil {
		return nil
	}
	match := handler.SiteBindingForHost(host)
	if match.Mode != "acme" || strings.TrimSpace(match.ACMEProfile) == "" {
		return nil
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.acmeManagers[match.ACMEProfile]
}

func (rt *managedServerTLSRuntime) acmeGetCertificateForProfile(profile string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if rt == nil || strings.TrimSpace(profile) == "" {
		return nil
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.acmeGetCertificate[profile]
}

func serverTLSACMEProfileCacheDir(baseDir string, profile handler.ServerTLSACMEProfile) string {
	return filepath.Join(strings.TrimSpace(baseDir), filepath.FromSlash(serverTLSACMEProfileCacheNamespace(profile)))
}

func serverTLSACMEProfileCacheNamespace(profile handler.ServerTLSACMEProfile) string {
	account := "default"
	if email := strings.TrimSpace(profile.Email); email != "" {
		sum := sha256.Sum256([]byte(strings.ToLower(email)))
		account = "email-" + hex.EncodeToString(sum[:8])
	}
	return strings.Join([]string{"acme", profile.Environment, account}, "/")
}

func buildServerTLSACMECache(profile handler.ServerTLSACMEProfile) (autocert.Cache, error) {
	return persistentstore.NewAutocertCacheFromConfig(persistentstore.AutocertCacheConfig{
		Backend:      config.PersistentStorageBackend,
		LocalBaseDir: config.PersistentStorageLocalBaseDir,
		S3: persistentstore.S3CacheConfig{
			Bucket:         config.PersistentStorageS3Bucket,
			Region:         config.PersistentStorageS3Region,
			Endpoint:       config.PersistentStorageS3Endpoint,
			Prefix:         config.PersistentStorageS3Prefix,
			ForcePathStyle: config.PersistentStorageS3ForcePathStyle,
		},
	}, serverTLSACMEProfileCacheNamespace(profile))
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
