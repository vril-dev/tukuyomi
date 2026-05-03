package middleware

import (
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/adminauth"
	"tukuyomi/internal/config"
)

type AdminAuthResult struct {
	Principal     adminauth.Principal
	Mode          string
	FallbackActor string
}

type AdminAuthResolver func(*gin.Context) (AdminAuthResult, bool, error)

var (
	adminAuthResolverMu sync.RWMutex
	adminAuthResolver   AdminAuthResolver
)

func SetAdminAuthResolver(resolver AdminAuthResolver) {
	adminAuthResolverMu.Lock()
	defer adminAuthResolverMu.Unlock()
	adminAuthResolver = resolver
}

func AdminAuth() gin.HandlerFunc {
	return AdminAuthWithResolver(resolveConfiguredAdminAuth)
}

func AdminAuthWithResolver(resolver AdminAuthResolver) gin.HandlerFunc {
	return adminAuthWithResolver(resolver, true)
}

func AdminAuthRequiredWithResolver(resolver AdminAuthResolver) gin.HandlerFunc {
	return adminAuthWithResolver(resolver, false)
}

func adminAuthWithResolver(resolver AdminAuthResolver, allowDisabled bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if allowDisabled && config.APIAuthDisable {
			c.Next()
			return
		}

		if resolver == nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if result, ok, err := resolver(c); err != nil {
			if errors.Is(err, adminauth.ErrCSRFRequired) || errors.Is(err, adminauth.ErrCSRFMismatch) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		} else if ok {
			if !adminPrincipalAllowsMethod(result.Principal, c.Request.Method) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "admin token scope does not allow this request"})
				return
			}
			setAdminAuthContext(c, result)
			c.Next()
			return
		}

		c.AbortWithStatus(http.StatusUnauthorized)
	}
}

func adminPrincipalAllowsMethod(principal adminauth.Principal, method string) bool {
	if principal.AuthKind != adminauth.AuthKindToken {
		return true
	}
	required := "admin:write"
	if isAdminReadMethod(method) {
		required = "admin:read"
	}
	for _, scope := range principal.Scopes {
		switch strings.ToLower(strings.TrimSpace(scope)) {
		case "admin:write":
			return true
		case required:
			return true
		}
	}
	return false
}

func isAdminReadMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func resolveConfiguredAdminAuth(c *gin.Context) (AdminAuthResult, bool, error) {
	adminAuthResolverMu.RLock()
	resolver := adminAuthResolver
	adminAuthResolverMu.RUnlock()
	if resolver == nil {
		return AdminAuthResult{}, false, nil
	}
	return resolver(c)
}

func setAdminAuthContext(c *gin.Context, result AdminAuthResult) {
	if strings.TrimSpace(result.Mode) != "" {
		c.Set("tukuyomi.admin_auth_mode", strings.TrimSpace(result.Mode))
	}
	if strings.TrimSpace(result.FallbackActor) != "" {
		c.Set("tukuyomi.admin_auth_fallback_actor", strings.TrimSpace(result.FallbackActor))
	}
	if result.Principal.Authenticated() {
		c.Set("tukuyomi.admin_principal", result.Principal)
		c.Set("tukuyomi.admin_actor", result.Principal.Username)
	}
}
