package center

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/adminui"
	"tukuyomi/internal/handler"
)

//go:embed center_ui_dist
var centerUIEmbedFS embed.FS

func registerCenterUI(r *gin.Engine, apiBase, gatewayAPIBase, uiBase string) {
	uiFS, err := fs.Sub(centerUIEmbedFS, "center_ui_dist")
	if err != nil {
		return
	}
	serve := func(c *gin.Context, relPath string) {
		decision := handler.EvaluateAdminUIRateLimit(c.Request)
		if !decision.Allowed {
			if decision.RetryAfterSeconds > 0 {
				c.Header("Retry-After", fmt.Sprintf("%d", decision.RetryAfterSeconds))
			}
			c.AbortWithStatusJSON(decision.StatusCode, gin.H{"error": "admin rate limit exceeded"})
			return
		}
		raw, resolvedPath, placeholder, err := adminui.ReadAsset(uiFS, relPath)
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		if resolvedPath == "index.html" {
			raw = centerHTML(raw, centerHTMLAPIBase(c.Request, apiBase, gatewayAPIBase), uiBase)
		}
		c.Data(http.StatusOK, centerContentType(raw, resolvedPath, placeholder), raw)
	}
	r.GET(uiBase, func(c *gin.Context) {
		serve(c, "index.html")
	})
	r.HEAD(uiBase, func(c *gin.Context) {
		serve(c, "index.html")
	})
	r.GET(uiBase+"/*filepath", func(c *gin.Context) {
		serve(c, c.Param("filepath"))
	})
	r.HEAD(uiBase+"/*filepath", func(c *gin.Context) {
		serve(c, c.Param("filepath"))
	})
}

func centerHTML(raw []byte, apiBase, uiBase string) []byte {
	settings, _ := json.Marshal(map[string]string{
		"apiBasePath": apiBase,
		"uiBasePath":  uiBase,
	})
	raw = bytes.Replace(raw, []byte("__CENTER_SETTINGS__"), settings, 1)
	return bytes.Replace(raw, []byte("__CENTER_UI_BASE_HREF__"), []byte(uiBase+"/"), 1)
}

func centerHTMLAPIBase(r *http.Request, apiBase, gatewayAPIBase string) string {
	if r != nil && strings.TrimSpace(r.Header.Get("X-Forwarded-Host")) != "" {
		if gatewayAPIBase = strings.TrimSpace(gatewayAPIBase); gatewayAPIBase != "" {
			return gatewayAPIBase
		}
	}
	return apiBase
}

func centerContentType(raw []byte, resolvedPath string, placeholder bool) string {
	ct := mime.TypeByExtension(path.Ext(resolvedPath))
	if ct == "" {
		ct = http.DetectContentType(raw)
	}
	if placeholder {
		ct = "text/html; charset=utf-8"
	}
	return ct
}
