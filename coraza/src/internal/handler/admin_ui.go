package handler

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/config"
)

//go:embed admin_ui_dist
var adminUIEmbedFS embed.FS

func RegisterAdminUIRoutes(r *gin.Engine) {
	if r == nil {
		return
	}
	uiFS, err := fs.Sub(adminUIEmbedFS, "admin_ui_dist")
	if err != nil {
		return
	}
	base := strings.TrimSpace(config.UIBasePath)
	if base == "" {
		base = "/tukuyomi-ui"
	}
	if !strings.HasPrefix(base, "/") {
		base = "/" + base
	}

	serveFile := func(c *gin.Context, relPath string) {
		raw, resolvedPath, placeholder, err := readAdminUIAsset(uiFS, relPath)
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		ct := mime.TypeByExtension(path.Ext(resolvedPath))
		if ct == "" {
			ct = http.DetectContentType(raw)
		}
		if placeholder {
			ct = "text/html; charset=utf-8"
		}
		c.Data(http.StatusOK, ct, raw)
	}

	r.GET(base, func(c *gin.Context) {
		if !CheckAdminUIAccess(c.Request) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		if decision := EvaluateAdminUIRateLimit(c.Request); !decision.Allowed {
			if decision.RetryAfterSeconds > 0 {
				c.Header("Retry-After", strconv.Itoa(decision.RetryAfterSeconds))
			}
			c.AbortWithStatusJSON(decision.StatusCode, gin.H{"error": "admin rate limit exceeded"})
			return
		}
		serveFile(c, "index.html")
	})
	r.HEAD(base, func(c *gin.Context) {
		if !CheckAdminUIAccess(c.Request) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		if decision := EvaluateAdminUIRateLimit(c.Request); !decision.Allowed {
			if decision.RetryAfterSeconds > 0 {
				c.Header("Retry-After", strconv.Itoa(decision.RetryAfterSeconds))
			}
			c.AbortWithStatus(decision.StatusCode)
			return
		}
		serveFile(c, "index.html")
	})
	r.GET(base+"/*filepath", func(c *gin.Context) {
		if !CheckAdminUIAccess(c.Request) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		if decision := EvaluateAdminUIRateLimit(c.Request); !decision.Allowed {
			if decision.RetryAfterSeconds > 0 {
				c.Header("Retry-After", strconv.Itoa(decision.RetryAfterSeconds))
			}
			c.AbortWithStatusJSON(decision.StatusCode, gin.H{"error": "admin rate limit exceeded"})
			return
		}
		p := strings.TrimPrefix(c.Param("filepath"), "/")
		serveFile(c, p)
	})
	r.HEAD(base+"/*filepath", func(c *gin.Context) {
		if !CheckAdminUIAccess(c.Request) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		if decision := EvaluateAdminUIRateLimit(c.Request); !decision.Allowed {
			if decision.RetryAfterSeconds > 0 {
				c.Header("Retry-After", strconv.Itoa(decision.RetryAfterSeconds))
			}
			c.AbortWithStatus(decision.StatusCode)
			return
		}
		p := strings.TrimPrefix(c.Param("filepath"), "/")
		serveFile(c, p)
	})
}

func readAdminUIAsset(uiFS fs.FS, relPath string) ([]byte, string, bool, error) {
	if relPath == "" {
		relPath = "index.html"
	}
	relPath = strings.TrimPrefix(path.Clean("/"+relPath), "/")
	if relPath == "." {
		relPath = "index.html"
	}

	if relPath != "index.html" {
		if _, err := fs.Stat(uiFS, relPath); err != nil {
			relPath = "index.html"
		}
	}

	raw, err := fs.ReadFile(uiFS, relPath)
	if err == nil {
		return raw, relPath, false, nil
	}
	if relPath != "index.html" {
		return nil, "", false, err
	}

	raw, err = fs.ReadFile(uiFS, "placeholder.html")
	if err != nil {
		return nil, "", false, err
	}
	return raw, "placeholder.html", true, nil
}
