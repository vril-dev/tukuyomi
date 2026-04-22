package handler

import (
	"net/http"
	"strings"
	"sync"

	"tukuyomi/internal/config"
)

const (
	requestMetadataCountrySourceUnknown = "unknown"
	requestMetadataCountrySourceHeader  = "header"
	requestMetadataCountrySourceMMDB    = "mmdb"
)

type requestMetadataResolver interface {
	Name() string
	Resolve(req *http.Request, ctx *requestMetadataResolverContext) error
}

type requestMetadataResolverContext struct {
	ClientIP      string
	Country       string
	CountrySource string
}

type requestMetadataResolverFactory func() requestMetadataResolver

var (
	requestMetadataResolverRegistryMu sync.RWMutex
	requestMetadataResolverFactories  []requestMetadataResolverFactory
)

func init() {
	registerRequestMetadataResolver(newHeaderCountryRequestMetadataResolver)
	registerRequestMetadataResolver(newMMDBCountryRequestMetadataResolver)
}

func registerRequestMetadataResolver(factory requestMetadataResolverFactory) {
	if factory == nil {
		return
	}
	requestMetadataResolverRegistryMu.Lock()
	defer requestMetadataResolverRegistryMu.Unlock()
	requestMetadataResolverFactories = append(requestMetadataResolverFactories, factory)
}

func newRequestMetadataResolvers() []requestMetadataResolver {
	requestMetadataResolverRegistryMu.RLock()
	factories := append([]requestMetadataResolverFactory(nil), requestMetadataResolverFactories...)
	requestMetadataResolverRegistryMu.RUnlock()

	out := make([]requestMetadataResolver, 0, len(factories))
	for _, factory := range factories {
		if factory == nil {
			continue
		}
		r := factory()
		if r == nil {
			continue
		}
		out = append(out, r)
	}
	return out
}

func newRequestMetadataResolverContext(clientIP string) *requestMetadataResolverContext {
	return &requestMetadataResolverContext{
		ClientIP:      strings.TrimSpace(clientIP),
		Country:       "UNKNOWN",
		CountrySource: requestMetadataCountrySourceUnknown,
	}
}

func runRequestMetadataResolvers(req *http.Request, resolvers []requestMetadataResolver, ctx *requestMetadataResolverContext) error {
	for _, resolver := range resolvers {
		if resolver == nil {
			continue
		}
		if err := resolver.Resolve(req, ctx); err != nil {
			return err
		}
	}
	ctx.Country = normalizeCountryCode(ctx.Country)
	if strings.TrimSpace(ctx.CountrySource) == "" {
		ctx.CountrySource = requestMetadataCountrySourceUnknown
	}
	return nil
}

type headerCountryRequestMetadataResolver struct{}

func newHeaderCountryRequestMetadataResolver() requestMetadataResolver {
	return &headerCountryRequestMetadataResolver{}
}

func (r *headerCountryRequestMetadataResolver) Name() string {
	return "header_country"
}

func (r *headerCountryRequestMetadataResolver) Resolve(req *http.Request, ctx *requestMetadataResolverContext) error {
	if req == nil || ctx == nil {
		return nil
	}
	if mode := strings.ToLower(strings.TrimSpace(config.RequestCountryMode)); mode != "" && mode != "header" {
		return nil
	}
	raw := strings.TrimSpace(req.Header.Get("X-Country-Code"))
	if raw == "" {
		return nil
	}
	ctx.Country = normalizeCountryCode(raw)
	ctx.CountrySource = requestMetadataCountrySourceHeader
	return nil
}

type mmdbCountryRequestMetadataResolver struct{}

func newMMDBCountryRequestMetadataResolver() requestMetadataResolver {
	return &mmdbCountryRequestMetadataResolver{}
}

func (r *mmdbCountryRequestMetadataResolver) Name() string {
	return "mmdb_country"
}

func (r *mmdbCountryRequestMetadataResolver) Resolve(_ *http.Request, ctx *requestMetadataResolverContext) error {
	if ctx == nil {
		return nil
	}
	if strings.ToLower(strings.TrimSpace(config.RequestCountryMode)) != "mmdb" {
		return nil
	}
	country, ok, err := lookupRequestCountryMMDB(ctx.ClientIP)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	ctx.Country = country
	ctx.CountrySource = requestMetadataCountrySourceMMDB
	return nil
}
