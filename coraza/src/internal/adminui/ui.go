package adminui

import (
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type RateLimitDecision struct {
	Allowed           bool
	StatusCode        int
	RetryAfterSeconds int
}

type Options struct {
	FS          fs.FS
	BasePath    string
	CheckAccess func(*http.Request) bool
	RateLimit   func(*http.Request) RateLimitDecision
}

func RegisterRoutes(r *gin.Engine, opts Options) {
	if r == nil || opts.FS == nil {
		return
	}
	base := normalizeBasePath(opts.BasePath)
	serveFile := func(c *gin.Context, relPath string) {
		raw, resolvedPath, placeholder, err := ReadAsset(opts.FS, relPath)
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		c.Data(http.StatusOK, contentType(raw, resolvedPath, placeholder), raw)
	}

	r.GET(base, func(c *gin.Context) {
		if !allowAccess(c, opts) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		if !allowRate(c, opts, true) {
			return
		}
		serveFile(c, "index.html")
	})
	r.HEAD(base, func(c *gin.Context) {
		if !allowAccess(c, opts) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		if !allowRate(c, opts, false) {
			return
		}
		serveFile(c, "index.html")
	})
	r.GET(base+"/*filepath", func(c *gin.Context) {
		if !allowAccess(c, opts) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		if !allowRate(c, opts, true) {
			return
		}
		serveFile(c, strings.TrimPrefix(c.Param("filepath"), "/"))
	})
	r.HEAD(base+"/*filepath", func(c *gin.Context) {
		if !allowAccess(c, opts) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		if !allowRate(c, opts, false) {
			return
		}
		serveFile(c, strings.TrimPrefix(c.Param("filepath"), "/"))
	})
}

func ReadAsset(uiFS fs.FS, relPath string) ([]byte, string, bool, error) {
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

func normalizeBasePath(base string) string {
	base = strings.TrimSpace(base)
	if base == "" {
		base = "/tukuyomi-ui"
	}
	if !strings.HasPrefix(base, "/") {
		base = "/" + base
	}
	return base
}

func contentType(raw []byte, resolvedPath string, placeholder bool) string {
	ct := mime.TypeByExtension(path.Ext(resolvedPath))
	if ct == "" {
		ct = http.DetectContentType(raw)
	}
	if placeholder {
		ct = "text/html; charset=utf-8"
	}
	return ct
}

func allowAccess(c *gin.Context, opts Options) bool {
	if opts.CheckAccess == nil {
		return true
	}
	return opts.CheckAccess(c.Request)
}

func allowRate(c *gin.Context, opts Options, jsonError bool) bool {
	if opts.RateLimit == nil {
		return true
	}
	decision := opts.RateLimit(c.Request)
	if decision.Allowed {
		return true
	}
	if decision.RetryAfterSeconds > 0 {
		c.Header("Retry-After", strconv.Itoa(decision.RetryAfterSeconds))
	}
	if jsonError {
		c.AbortWithStatusJSON(decision.StatusCode, gin.H{"error": "admin rate limit exceeded"})
	} else {
		c.AbortWithStatus(decision.StatusCode)
	}
	return false
}
