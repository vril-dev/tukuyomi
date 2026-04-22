package handler

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
)

const defaultSiteConfigRaw = "{\n  \"sites\": []\n}\n"

type SiteConfigFile struct {
	Sites []SiteConfig `json:"sites,omitempty"`
}

type SiteConfig struct {
	Name            string        `json:"name,omitempty"`
	Enabled         *bool         `json:"enabled,omitempty"`
	Hosts           []string      `json:"hosts,omitempty"`
	DefaultUpstream string        `json:"default_upstream"`
	TLS             SiteTLSConfig `json:"tls"`
}

type SiteTLSConfig struct {
	Mode     string `json:"mode"`
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
}

type SiteRuntimeStatus struct {
	Name            string   `json:"name"`
	Enabled         bool     `json:"enabled"`
	Hosts           []string `json:"hosts,omitempty"`
	DefaultUpstream string   `json:"default_upstream,omitempty"`
	TLSMode         string   `json:"tls_mode"`
	TLSStatus       string   `json:"tls_status"`
	TLSWarning      string   `json:"tls_warning,omitempty"`
	TLSCertNotAfter string   `json:"tls_cert_not_after,omitempty"`
	GeneratedRoute  string   `json:"generated_route,omitempty"`
}

type siteTLSBinding struct {
	Name        string
	Hosts       []string
	Mode        string
	Certificate *tls.Certificate
	NotAfter    string
}

type sitePreparedConfig struct {
	cfg      SiteConfigFile
	raw      string
	etag     string
	statuses []SiteRuntimeStatus
	bindings []siteTLSBinding
}

type siteRuntimeSnapshot struct {
	raw      string
	etag     string
	cfg      SiteConfigFile
	statuses []SiteRuntimeStatus
	bindings []siteTLSBinding
}

type siteRuntime struct {
	mu            sync.RWMutex
	configPath    string
	raw           string
	etag          string
	cfg           SiteConfigFile
	statuses      []SiteRuntimeStatus
	bindings      []siteTLSBinding
	rollbackMax   int
	rollbackStack []proxyRollbackEntry
}

type siteBindingMatch struct {
	Name        string
	Mode        string
	Certificate *tls.Certificate
	NotAfter    string
}

var (
	siteRuntimeMu sync.RWMutex
	siteRt        *siteRuntime
)

func InitSiteRuntime(path string, rollbackMax int) error {
	cfgPath := strings.TrimSpace(path)
	if cfgPath == "" {
		cfgPath = "conf/sites.json"
	}
	rawBytes, _, err := readFileMaybe(cfgPath)
	if err != nil {
		return fmt.Errorf("read sites config (%s): %w", cfgPath, err)
	}
	raw := string(rawBytes)
	if strings.TrimSpace(raw) == "" {
		raw = defaultSiteConfigRaw
	}
	prepared, err := prepareSiteConfigRaw(raw)
	if err != nil {
		return fmt.Errorf("invalid sites config (%s): %w", cfgPath, err)
	}
	rt := &siteRuntime{
		configPath:    cfgPath,
		raw:           prepared.raw,
		etag:          prepared.etag,
		cfg:           prepared.cfg,
		statuses:      cloneSiteRuntimeStatuses(prepared.statuses),
		bindings:      cloneSiteTLSBindings(prepared.bindings),
		rollbackMax:   clampProxyRollbackMax(rollbackMax),
		rollbackStack: make([]proxyRollbackEntry, 0, clampProxyRollbackMax(rollbackMax)),
	}
	siteRuntimeMu.Lock()
	siteRt = rt
	siteRuntimeMu.Unlock()
	return nil
}

func siteRuntimeInstance() *siteRuntime {
	siteRuntimeMu.RLock()
	defer siteRuntimeMu.RUnlock()
	return siteRt
}

func SiteConfigSnapshot() (raw string, etag string, cfg SiteConfigFile, statuses []SiteRuntimeStatus, rollbackDepth int) {
	rt := siteRuntimeInstance()
	if rt == nil {
		return defaultSiteConfigRaw, bypassconf.ComputeETag([]byte(defaultSiteConfigRaw)), SiteConfigFile{}, nil, 0
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.raw, rt.etag, rt.cfg, cloneSiteRuntimeStatuses(rt.statuses), len(rt.rollbackStack)
}

func SiteRollbackPreview() (proxyRollbackEntry, error) {
	rt := siteRuntimeInstance()
	if rt == nil {
		return proxyRollbackEntry{}, fmt.Errorf("site runtime is not initialized")
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	if len(rt.rollbackStack) == 0 {
		return proxyRollbackEntry{}, fmt.Errorf("no rollback snapshot")
	}
	return rt.rollbackStack[len(rt.rollbackStack)-1], nil
}

func ValidateSiteConfigRaw(raw string) (SiteConfigFile, []SiteRuntimeStatus, error) {
	prepared, err := prepareSiteConfigRaw(raw)
	if err != nil {
		return SiteConfigFile{}, nil, err
	}
	if _, err := prepareProxyRulesRawWithSites(currentProxyRawConfigRaw(), prepared.cfg); err != nil {
		return SiteConfigFile{}, nil, err
	}
	return prepared.cfg, cloneSiteRuntimeStatuses(prepared.statuses), nil
}

func ApplySiteConfigRaw(ifMatch string, raw string) (string, SiteConfigFile, []SiteRuntimeStatus, error) {
	rt := siteRuntimeInstance()
	if rt == nil {
		return "", SiteConfigFile{}, nil, fmt.Errorf("site runtime is not initialized")
	}
	prepared, err := prepareSiteConfigRaw(raw)
	if err != nil {
		return "", SiteConfigFile{}, nil, err
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if ifMatch = strings.TrimSpace(ifMatch); ifMatch != "" && ifMatch != rt.etag {
		return "", SiteConfigFile{}, nil, proxyRulesConflictError{CurrentETag: rt.etag}
	}

	prevRaw := rt.raw
	prevETag := rt.etag
	if _, err := prepareProxyRulesRawWithSites(currentProxyRawConfigRaw(), prepared.cfg); err != nil {
		return "", SiteConfigFile{}, nil, err
	}
	if err := persistSiteConfigRaw(rt.configPath, prepared.raw); err != nil {
		return "", SiteConfigFile{}, nil, err
	}
	prev := rt.snapshotLocked()
	rt.applyPreparedLocked(prepared)
	if err := reloadProxyRuntimeWithSites(prepared.cfg); err != nil {
		rt.restoreLocked(prev)
		_ = persistSiteConfigRaw(rt.configPath, prevRaw)
		return "", SiteConfigFile{}, nil, err
	}
	if err := ReloadServerTLSRuntimeForSites(prepared.cfg, prepared.statuses); err != nil {
		rt.restoreLocked(prev)
		_ = persistSiteConfigRaw(rt.configPath, prevRaw)
		if restoreErr := reloadProxyRuntimeWithSites(prev.cfg); restoreErr != nil {
			log.Printf("[TLS][WARN] failed to restore proxy runtime after tls reload error: %v", restoreErr)
		}
		if restoreErr := ReloadServerTLSRuntimeForSites(prev.cfg, prev.statuses); restoreErr != nil {
			log.Printf("[TLS][WARN] failed to restore tls runtime after reload error: %v", restoreErr)
		}
		return "", SiteConfigFile{}, nil, err
	}

	rt.pushRollbackLocked(proxyRollbackEntry{
		Raw:       prevRaw,
		ETag:      prevETag,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	})
	return rt.etag, rt.cfg, cloneSiteRuntimeStatuses(rt.statuses), nil
}

func RollbackSiteConfig() (string, SiteConfigFile, []SiteRuntimeStatus, proxyRollbackEntry, error) {
	rt := siteRuntimeInstance()
	if rt == nil {
		return "", SiteConfigFile{}, nil, proxyRollbackEntry{}, fmt.Errorf("site runtime is not initialized")
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if len(rt.rollbackStack) == 0 {
		return "", SiteConfigFile{}, nil, proxyRollbackEntry{}, fmt.Errorf("no rollback snapshot")
	}
	entry := rt.rollbackStack[len(rt.rollbackStack)-1]
	rt.rollbackStack = rt.rollbackStack[:len(rt.rollbackStack)-1]

	prepared, err := prepareSiteConfigRaw(entry.Raw)
	if err != nil {
		rt.pushRollbackLocked(entry)
		return "", SiteConfigFile{}, nil, proxyRollbackEntry{}, err
	}

	prevRaw := rt.raw
	if _, err := prepareProxyRulesRawWithSites(currentProxyRawConfigRaw(), prepared.cfg); err != nil {
		rt.pushRollbackLocked(entry)
		return "", SiteConfigFile{}, nil, proxyRollbackEntry{}, err
	}
	if err := persistSiteConfigRaw(rt.configPath, prepared.raw); err != nil {
		rt.pushRollbackLocked(entry)
		return "", SiteConfigFile{}, nil, proxyRollbackEntry{}, err
	}
	prev := rt.snapshotLocked()
	rt.applyPreparedLocked(prepared)
	if err := reloadProxyRuntimeWithSites(prepared.cfg); err != nil {
		rt.restoreLocked(prev)
		_ = persistSiteConfigRaw(rt.configPath, prevRaw)
		rt.pushRollbackLocked(entry)
		return "", SiteConfigFile{}, nil, proxyRollbackEntry{}, err
	}
	if err := ReloadServerTLSRuntimeForSites(prepared.cfg, prepared.statuses); err != nil {
		rt.restoreLocked(prev)
		_ = persistSiteConfigRaw(rt.configPath, prevRaw)
		if restoreErr := reloadProxyRuntimeWithSites(prev.cfg); restoreErr != nil {
			log.Printf("[TLS][WARN] failed to restore proxy runtime after tls reload error: %v", restoreErr)
		}
		if restoreErr := ReloadServerTLSRuntimeForSites(prev.cfg, prev.statuses); restoreErr != nil {
			log.Printf("[TLS][WARN] failed to restore tls runtime after reload error: %v", restoreErr)
		}
		rt.pushRollbackLocked(entry)
		return "", SiteConfigFile{}, nil, proxyRollbackEntry{}, err
	}

	return rt.etag, rt.cfg, cloneSiteRuntimeStatuses(rt.statuses), entry, nil
}

func currentSiteConfig() SiteConfigFile {
	rt := siteRuntimeInstance()
	if rt == nil {
		return SiteConfigFile{}
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return cloneSiteConfigFile(rt.cfg)
}

func currentEnabledSitesProvideFallback() bool {
	cfg := currentSiteConfig()
	for _, site := range cfg.Sites {
		if siteEnabled(site.Enabled) {
			return true
		}
	}
	return false
}

func SiteStatusSnapshot() []SiteRuntimeStatus {
	rt := siteRuntimeInstance()
	if rt == nil {
		return nil
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return cloneSiteRuntimeStatuses(rt.statuses)
}

func SiteBindingForHost(host string) siteBindingMatch {
	rt := siteRuntimeInstance()
	if rt == nil {
		return siteBindingMatch{}
	}
	reqHost := normalizeProxyRequestHost(host)
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	for _, binding := range rt.bindings {
		if siteHostsMatch(binding.Hosts, reqHost) {
			return siteBindingMatch{
				Name:        binding.Name,
				Mode:        binding.Mode,
				Certificate: binding.Certificate,
				NotAfter:    binding.NotAfter,
			}
		}
	}
	return siteBindingMatch{}
}

func siteGeneratedRoutes(cfg SiteConfigFile) []ProxyRoute {
	if len(cfg.Sites) == 0 {
		return nil
	}
	routes := make([]ProxyRoute, 0, len(cfg.Sites))
	for _, site := range cfg.Sites {
		if !siteEnabled(site.Enabled) {
			continue
		}
		routes = append(routes, ProxyRoute{
			Name:      "site:" + site.Name,
			Priority:  0,
			Generated: true,
			Match: ProxyRouteMatch{
				Hosts: append([]string(nil), site.Hosts...),
			},
			Action: ProxyRouteAction{
				Upstream: siteGeneratedUpstreamName(site),
			},
		})
	}
	if len(routes) == 0 {
		return nil
	}
	return routes
}

func siteGeneratedUpstreams(cfg SiteConfigFile) []ProxyUpstream {
	if len(cfg.Sites) == 0 {
		return nil
	}
	out := make([]ProxyUpstream, 0, len(cfg.Sites))
	for _, site := range cfg.Sites {
		if !siteEnabled(site.Enabled) {
			continue
		}
		out = append(out, ProxyUpstream{
			Name:          siteGeneratedUpstreamName(site),
			URL:           site.DefaultUpstream,
			Weight:        1,
			Enabled:       true,
			ProviderClass: proxyUpstreamProviderClassDirect,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func siteGeneratedUpstreamName(site SiteConfig) string {
	return "site:" + strings.TrimSpace(site.Name)
}

func prepareSiteConfigRaw(raw string) (sitePreparedConfig, error) {
	cfg, statuses, bindings, err := parseSiteConfigRaw(raw)
	if err != nil {
		return sitePreparedConfig{}, err
	}
	normalizedRaw := mustJSON(cfg)
	return sitePreparedConfig{
		cfg:      cfg,
		raw:      normalizedRaw,
		etag:     bypassconf.ComputeETag([]byte(normalizedRaw)),
		statuses: statuses,
		bindings: bindings,
	}, nil
}

func parseSiteConfigRaw(raw string) (SiteConfigFile, []SiteRuntimeStatus, []siteTLSBinding, error) {
	if strings.TrimSpace(raw) == "" {
		raw = defaultSiteConfigRaw
	}
	var in SiteConfigFile
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return SiteConfigFile{}, nil, nil, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return SiteConfigFile{}, nil, nil, fmt.Errorf("invalid json")
	}
	return normalizeAndValidateSiteConfig(in)
}

func normalizeAndValidateSiteConfig(in SiteConfigFile) (SiteConfigFile, []SiteRuntimeStatus, []siteTLSBinding, error) {
	cfg := normalizeSiteConfigFile(in)
	statuses := make([]SiteRuntimeStatus, 0, len(cfg.Sites))
	bindings := make([]siteTLSBinding, 0, len(cfg.Sites))
	seenNames := map[string]struct{}{}
	hostOwners := make([]siteHostOwnership, 0)

	for i := range cfg.Sites {
		site := cfg.Sites[i]
		if _, ok := seenNames[site.Name]; ok {
			return SiteConfigFile{}, nil, nil, fmt.Errorf("sites[%d].name duplicates %q", i, site.Name)
		}
		seenNames[site.Name] = struct{}{}
		if len(site.Hosts) == 0 {
			return SiteConfigFile{}, nil, nil, fmt.Errorf("sites[%d].hosts is required", i)
		}
		if _, err := parseProxyUpstreamURL(fmt.Sprintf("sites[%d].default_upstream", i), site.DefaultUpstream); err != nil {
			return SiteConfigFile{}, nil, nil, err
		}
		for hostIdx, host := range site.Hosts {
			if err := validateProxyRouteHostPattern(host); err != nil {
				return SiteConfigFile{}, nil, nil, fmt.Errorf("sites[%d].hosts[%d]: %w", i, hostIdx, err)
			}
			for _, owner := range hostOwners {
				if siteHostsOverlap(host, owner.Host) {
					return SiteConfigFile{}, nil, nil, fmt.Errorf("sites[%d].hosts[%d] overlaps %q owned by site %q", i, hostIdx, owner.Host, owner.SiteName)
				}
			}
			hostOwners = append(hostOwners, siteHostOwnership{SiteName: site.Name, Host: host})
		}

		status := SiteRuntimeStatus{
			Name:            site.Name,
			Enabled:         siteEnabled(site.Enabled),
			Hosts:           append([]string(nil), site.Hosts...),
			DefaultUpstream: site.DefaultUpstream,
			TLSMode:         site.TLS.Mode,
			TLSStatus:       "disabled",
			GeneratedRoute:  "site:" + site.Name,
		}
		if !status.Enabled {
			statuses = append(statuses, status)
			continue
		}

		binding, warning, err := validateSiteTLSBinding(i, site, cfg)
		if err != nil {
			return SiteConfigFile{}, nil, nil, err
		}
		status.TLSStatus = "covered"
		status.TLSWarning = warning
		status.TLSCertNotAfter = binding.NotAfter
		statuses = append(statuses, status)
		bindings = append(bindings, binding)
	}
	return cfg, statuses, bindings, nil
}

type siteHostOwnership struct {
	SiteName string
	Host     string
}

func normalizeSiteConfigFile(in SiteConfigFile) SiteConfigFile {
	if len(in.Sites) == 0 {
		return SiteConfigFile{}
	}
	out := SiteConfigFile{
		Sites: make([]SiteConfig, 0, len(in.Sites)),
	}
	for i, site := range in.Sites {
		next := site
		next.Name = strings.TrimSpace(next.Name)
		if next.Name == "" {
			next.Name = fmt.Sprintf("site-%d", i+1)
		}
		next.DefaultUpstream = strings.TrimSpace(next.DefaultUpstream)
		next.Hosts = normalizeSiteHosts(next.Hosts)
		next.TLS.Mode = normalizeSiteTLSMode(next.TLS.Mode)
		next.TLS.CertFile = strings.TrimSpace(next.TLS.CertFile)
		next.TLS.KeyFile = strings.TrimSpace(next.TLS.KeyFile)
		out.Sites = append(out.Sites, next)
	}
	return out
}

func normalizeSiteHosts(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, host := range in {
		next := normalizeProxyHostPattern(host)
		if next == "" {
			continue
		}
		if _, ok := seen[next]; ok {
			continue
		}
		seen[next] = struct{}{}
		out = append(out, next)
	}
	return out
}

func normalizeSiteTLSMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "legacy":
		return "legacy"
	case "manual":
		return "manual"
	case "acme":
		return "acme"
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}

func siteEnabled(v *bool) bool {
	return v == nil || *v
}

func validateSiteTLSBinding(index int, site SiteConfig, cfg SiteConfigFile) (siteTLSBinding, string, error) {
	if !config.ServerTLSEnabled {
		return siteTLSBinding{}, "", fmt.Errorf("sites[%d] requires server.tls.enabled=true", index)
	}
	switch site.TLS.Mode {
	case "manual":
		if siteHasWildcardHost(site.Hosts) && (site.TLS.CertFile == "" || site.TLS.KeyFile == "") {
			return siteTLSBinding{}, "", fmt.Errorf("sites[%d].tls.manual wildcard hosts require cert_file and key_file", index)
		}
		if site.TLS.CertFile == "" || site.TLS.KeyFile == "" {
			return siteTLSBinding{}, "", fmt.Errorf("sites[%d].tls.cert_file and sites[%d].tls.key_file are required for manual mode", index, index)
		}
		cert, leaf, notAfter, err := loadSiteCertificate(site.TLS.CertFile, site.TLS.KeyFile)
		if err != nil {
			return siteTLSBinding{}, "", fmt.Errorf("sites[%d].tls manual certificate load error: %w", index, err)
		}
		for _, host := range site.Hosts {
			if !siteCertificateCoversHostPattern(leaf, host) {
				return siteTLSBinding{}, "", fmt.Errorf("sites[%d].tls manual certificate does not cover host %q", index, host)
			}
		}
		return siteTLSBinding{
			Name:        site.Name,
			Hosts:       append([]string(nil), site.Hosts...),
			Mode:        site.TLS.Mode,
			Certificate: cert,
			NotAfter:    notAfter,
		}, "", nil
	case "acme":
		if siteHasWildcardHost(site.Hosts) {
			return siteTLSBinding{}, "", fmt.Errorf("sites[%d].tls.mode=acme supports exact hosts only", index)
		}
		if !config.ServerTLSACMEEnabled {
			return siteTLSBinding{}, "", fmt.Errorf("sites[%d].tls.mode=acme requires server.tls.acme.enabled=true", index)
		}
		return siteTLSBinding{
			Name:  site.Name,
			Hosts: append([]string(nil), site.Hosts...),
			Mode:  site.TLS.Mode,
		}, "", nil
	case "legacy":
		notAfter, warning, err := validateLegacySiteCoverage(site.Hosts, cfg)
		if err != nil {
			return siteTLSBinding{}, "", fmt.Errorf("sites[%d].tls.mode=legacy: %w", index, err)
		}
		return siteTLSBinding{
			Name:     site.Name,
			Hosts:    append([]string(nil), site.Hosts...),
			Mode:     site.TLS.Mode,
			NotAfter: notAfter,
		}, warning, nil
	default:
		return siteTLSBinding{}, "", fmt.Errorf("sites[%d].tls.mode must be manual, acme, or legacy", index)
	}
}

func validateLegacySiteCoverage(hosts []string, sites SiteConfigFile) (string, string, error) {
	if config.ServerTLSACMEEnabled {
		acmeHosts := map[string]struct{}{}
		for _, host := range EffectiveServerTLSACMEDomainsForSites(sites) {
			acmeHosts[host] = struct{}{}
		}
		for _, host := range hosts {
			if strings.HasPrefix(host, "*.") {
				return "", "", fmt.Errorf("wildcard host %q is not covered by legacy ACME", host)
			}
			if _, ok := acmeHosts[host]; !ok {
				return "", "", fmt.Errorf("host %q is not covered by legacy ACME domains", host)
			}
		}
		return "", "coverage follows ACME issuance", nil
	}
	if config.ServerTLSCertFile == "" || config.ServerTLSKeyFile == "" {
		return "", "", fmt.Errorf("legacy listener certificate is not configured")
	}
	_, leaf, notAfter, err := loadSiteCertificate(config.ServerTLSCertFile, config.ServerTLSKeyFile)
	if err != nil {
		return "", "", fmt.Errorf("legacy listener certificate load error: %w", err)
	}
	for _, host := range hosts {
		if !siteCertificateCoversHostPattern(leaf, host) {
			return "", "", fmt.Errorf("legacy listener certificate does not cover host %q", host)
		}
	}
	return notAfter, "", nil
}

func EffectiveServerTLSACMEDomains() []string {
	return EffectiveServerTLSACMEDomainsForSites(currentSiteConfig())
}

func EffectiveServerTLSACMEDomainsForSites(sites SiteConfigFile) []string {
	domains := make([]string, 0, len(config.ServerTLSACMEDomains))
	seen := map[string]struct{}{}
	for _, host := range config.ServerTLSACMEDomains {
		next := normalizeProxyHostPattern(host)
		if next == "" {
			continue
		}
		if _, ok := seen[next]; ok {
			continue
		}
		seen[next] = struct{}{}
		domains = append(domains, next)
	}
	for _, site := range sites.Sites {
		if !siteEnabled(site.Enabled) || site.TLS.Mode != "acme" {
			continue
		}
		for _, host := range site.Hosts {
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			domains = append(domains, host)
		}
	}
	return domains
}

func (rt *siteRuntime) snapshotLocked() siteRuntimeSnapshot {
	return siteRuntimeSnapshot{
		raw:      rt.raw,
		etag:     rt.etag,
		cfg:      cloneSiteConfigFile(rt.cfg),
		statuses: cloneSiteRuntimeStatuses(rt.statuses),
		bindings: cloneSiteTLSBindings(rt.bindings),
	}
}

func (rt *siteRuntime) applyPreparedLocked(prepared sitePreparedConfig) {
	rt.raw = prepared.raw
	rt.etag = prepared.etag
	rt.cfg = cloneSiteConfigFile(prepared.cfg)
	rt.statuses = cloneSiteRuntimeStatuses(prepared.statuses)
	rt.bindings = cloneSiteTLSBindings(prepared.bindings)
}

func (rt *siteRuntime) restoreLocked(snapshot siteRuntimeSnapshot) {
	rt.raw = snapshot.raw
	rt.etag = snapshot.etag
	rt.cfg = cloneSiteConfigFile(snapshot.cfg)
	rt.statuses = cloneSiteRuntimeStatuses(snapshot.statuses)
	rt.bindings = cloneSiteTLSBindings(snapshot.bindings)
}

func loadSiteCertificate(certFile string, keyFile string) (*tls.Certificate, *x509.Certificate, string, error) {
	cert, err := tls.LoadX509KeyPair(strings.TrimSpace(certFile), strings.TrimSpace(keyFile))
	if err != nil {
		return nil, nil, "", err
	}
	leaf, err := siteCertificateLeaf(cert)
	if err != nil {
		return nil, nil, "", err
	}
	return &cert, leaf, leaf.NotAfter.UTC().Format(time.RFC3339Nano), nil
}

func siteCertificateLeaf(cert tls.Certificate) (*x509.Certificate, error) {
	if cert.Leaf != nil {
		return cert.Leaf, nil
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	return leaf, nil
}

func siteCertificateCoversHostPattern(cert *x509.Certificate, host string) bool {
	host = normalizeProxyHostPattern(host)
	if cert == nil || host == "" {
		return false
	}
	if strings.HasPrefix(host, "*.") {
		for _, name := range cert.DNSNames {
			if normalizeProxyHostPattern(name) == host {
				return true
			}
		}
		if normalizeProxyHostPattern(cert.Subject.CommonName) == host {
			return true
		}
		return false
	}
	return cert.VerifyHostname(host) == nil
}

func siteHasWildcardHost(hosts []string) bool {
	for _, host := range hosts {
		if strings.HasPrefix(host, "*.") {
			return true
		}
	}
	return false
}

func siteHostsOverlap(a string, b string) bool {
	a = normalizeProxyHostPattern(a)
	b = normalizeProxyHostPattern(b)
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	aWildcard := strings.HasPrefix(a, "*.")
	bWildcard := strings.HasPrefix(b, "*.")
	if aWildcard && bWildcard {
		return a == b
	}
	if aWildcard {
		return siteWildcardMatchesExact(a, b)
	}
	if bWildcard {
		return siteWildcardMatchesExact(b, a)
	}
	return false
}

func siteWildcardMatchesExact(pattern string, host string) bool {
	suffix := strings.TrimPrefix(pattern, "*.")
	host = normalizeProxyHostPattern(host)
	if suffix == "" || host == "" || host == suffix {
		return false
	}
	if !strings.HasSuffix(host, "."+suffix) {
		return false
	}
	rest := strings.TrimSuffix(host, "."+suffix)
	return rest != "" && !strings.Contains(rest, ".")
}

func siteHostsMatch(patterns []string, host string) bool {
	for _, pattern := range patterns {
		if strings.HasPrefix(pattern, "*.") {
			if siteWildcardMatchesExact(pattern, host) {
				return true
			}
			continue
		}
		if normalizeProxyHostPattern(pattern) == host {
			return true
		}
	}
	return false
}

func cloneSiteConfigFile(in SiteConfigFile) SiteConfigFile {
	if len(in.Sites) == 0 {
		return SiteConfigFile{}
	}
	out := SiteConfigFile{Sites: make([]SiteConfig, 0, len(in.Sites))}
	for _, site := range in.Sites {
		next := site
		if len(site.Hosts) > 0 {
			next.Hosts = append([]string(nil), site.Hosts...)
		}
		out.Sites = append(out.Sites, next)
	}
	return out
}

func cloneSiteRuntimeStatuses(in []SiteRuntimeStatus) []SiteRuntimeStatus {
	if len(in) == 0 {
		return nil
	}
	out := make([]SiteRuntimeStatus, 0, len(in))
	for _, status := range in {
		next := status
		if len(status.Hosts) > 0 {
			next.Hosts = append([]string(nil), status.Hosts...)
		}
		out = append(out, next)
	}
	return out
}

func cloneSiteTLSBindings(in []siteTLSBinding) []siteTLSBinding {
	if len(in) == 0 {
		return nil
	}
	out := make([]siteTLSBinding, 0, len(in))
	for _, binding := range in {
		next := binding
		if len(binding.Hosts) > 0 {
			next.Hosts = append([]string(nil), binding.Hosts...)
		}
		out = append(out, next)
	}
	return out
}

func (rt *siteRuntime) pushRollbackLocked(entry proxyRollbackEntry) {
	if strings.TrimSpace(entry.Raw) == "" {
		return
	}
	if rt.rollbackMax <= 0 {
		return
	}
	rt.rollbackStack = append(rt.rollbackStack, entry)
	if len(rt.rollbackStack) > rt.rollbackMax {
		trim := len(rt.rollbackStack) - rt.rollbackMax
		rt.rollbackStack = append([]proxyRollbackEntry(nil), rt.rollbackStack[trim:]...)
	}
}

func persistSiteConfigRaw(path string, raw string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("sites config path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return bypassconf.AtomicWriteWithBackup(path, []byte(raw))
}

func currentProxyRawConfigRaw() string {
	rt := proxyRuntimeInstance()
	if rt != nil {
		rt.mu.RLock()
		defer rt.mu.RUnlock()
		return rt.raw
	}
	rawFile, _, err := readFileMaybe(config.ProxyConfigFile)
	if err != nil || len(strings.TrimSpace(string(rawFile))) == 0 {
		return "{}\n"
	}
	return string(rawFile)
}
