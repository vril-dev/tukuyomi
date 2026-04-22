package handler

import (
	"net/url"
	"strings"
)

func proxyRouteConfiguredTargetField(cfg ProxyRulesConfig, field string, ref string) (*url.URL, bool, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, false, nil
	}
	for _, upstream := range cfg.Upstreams {
		if upstream.Name != ref {
			continue
		}
		if !proxyUpstreamAllowedAsRouteTarget(upstream) {
			return nil, false, nil
		}
		if proxyUpstreamDiscoveryEnabled(upstream) {
			return nil, true, nil
		}
		target, err := parseProxyUpstreamURL(field, upstream.URL)
		if err != nil {
			return nil, false, err
		}
		return target, true, nil
	}
	return nil, false, nil
}
