package requestmeta

import (
	"errors"
	"net/http"
	"strings"
)

type Resolver interface {
	Name() string
	Resolve(req *http.Request, ctx *ResolverContext) error
}

type ResolverContext struct {
	ClientIP      string
	Country       string
	CountrySource string
}

type ModeGetter func() string

type CountryLookup func(clientIP string) (country string, ok bool, err error)

func NewResolverContext(clientIP string) *ResolverContext {
	return &ResolverContext{
		ClientIP:      strings.TrimSpace(clientIP),
		Country:       "UNKNOWN",
		CountrySource: CountrySourceUnknown,
	}
}

func NewDefaultResolvers(modeGetter ModeGetter, countryLookup CountryLookup) []Resolver {
	return []Resolver{
		NewHeaderCountryResolver(modeGetter),
		NewMMDBCountryResolver(modeGetter, countryLookup),
	}
}

func RunResolvers(req *http.Request, resolvers []Resolver, ctx *ResolverContext) error {
	if ctx == nil {
		return errors.New("request metadata resolver context is required")
	}
	for _, resolver := range resolvers {
		if resolver == nil {
			continue
		}
		if err := resolver.Resolve(req, ctx); err != nil {
			return err
		}
	}
	ctx.Country = NormalizeCountryCode(ctx.Country)
	if strings.TrimSpace(ctx.CountrySource) == "" {
		ctx.CountrySource = CountrySourceUnknown
	}
	return nil
}

type headerCountryResolver struct {
	modeGetter ModeGetter
}

func NewHeaderCountryResolver(modeGetter ModeGetter) Resolver {
	return &headerCountryResolver{modeGetter: modeGetter}
}

func (r *headerCountryResolver) Name() string {
	return "header_country"
}

func (r *headerCountryResolver) Resolve(req *http.Request, ctx *ResolverContext) error {
	if req == nil || ctx == nil {
		return nil
	}
	if mode := normalizedMode(r.modeGetter); mode != "" && mode != "header" {
		return nil
	}
	raw := strings.TrimSpace(req.Header.Get("X-Country-Code"))
	if raw == "" {
		return nil
	}
	ctx.Country = NormalizeCountryCode(raw)
	ctx.CountrySource = CountrySourceHeader
	return nil
}

type mmdbCountryResolver struct {
	modeGetter    ModeGetter
	countryLookup CountryLookup
}

func NewMMDBCountryResolver(modeGetter ModeGetter, countryLookup CountryLookup) Resolver {
	return &mmdbCountryResolver{modeGetter: modeGetter, countryLookup: countryLookup}
}

func (r *mmdbCountryResolver) Name() string {
	return "mmdb_country"
}

func (r *mmdbCountryResolver) Resolve(_ *http.Request, ctx *ResolverContext) error {
	if ctx == nil || r.countryLookup == nil {
		return nil
	}
	if normalizedMode(r.modeGetter) != "mmdb" {
		return nil
	}
	country, ok, err := r.countryLookup(ctx.ClientIP)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	ctx.Country = country
	ctx.CountrySource = CountrySourceMMDB
	return nil
}

func normalizedMode(modeGetter ModeGetter) string {
	if modeGetter == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(modeGetter()))
}
