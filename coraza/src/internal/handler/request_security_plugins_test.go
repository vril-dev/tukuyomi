package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

type testRequestSecurityPlugin struct {
	name    string
	phase   requestSecurityPluginPhase
	enabled bool
	handle  func(*gin.Context, *requestSecurityPluginContext) bool
}

func (p testRequestSecurityPlugin) Name() string {
	return p.name
}

func (p testRequestSecurityPlugin) Phase() requestSecurityPluginPhase {
	return p.phase
}

func (p testRequestSecurityPlugin) Enabled() bool {
	return p.enabled
}

func (p testRequestSecurityPlugin) Handle(c *gin.Context, ctx *requestSecurityPluginContext) bool {
	if p.handle == nil {
		return true
	}
	return p.handle(c, ctx)
}

func TestNewRequestSecurityPluginsBuiltins(t *testing.T) {
	plugins := newRequestSecurityPlugins()
	if len(plugins) != 3 {
		t.Fatalf("plugin count=%d want=3", len(plugins))
	}
	got := []string{
		plugins[0].Name(),
		plugins[1].Name(),
		plugins[2].Name(),
	}
	want := []string{"ip_reputation", "bot_defense", "semantic"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("plugin[%d]=%q want=%q", i, got[i], want[i])
		}
		if plugins[i].Phase() != requestSecurityPluginPhasePreWAF {
			t.Fatalf("plugin[%d] phase=%q want=%q", i, plugins[i].Phase(), requestSecurityPluginPhasePreWAF)
		}
	}
}

func TestRunRequestSecurityPluginsStopsOnHandledResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/demo", nil)

	var order []string
	plugins := []requestSecurityPlugin{
		testRequestSecurityPlugin{
			name:    "first",
			phase:   requestSecurityPluginPhasePreWAF,
			enabled: true,
			handle: func(_ *gin.Context, _ *requestSecurityPluginContext) bool {
				order = append(order, "first")
				return true
			},
		},
		testRequestSecurityPlugin{
			name:    "second",
			phase:   requestSecurityPluginPhasePreWAF,
			enabled: true,
			handle: func(_ *gin.Context, _ *requestSecurityPluginContext) bool {
				order = append(order, "second")
				return false
			},
		},
		testRequestSecurityPlugin{
			name:    "third",
			phase:   requestSecurityPluginPhasePreWAF,
			enabled: true,
			handle: func(_ *gin.Context, _ *requestSecurityPluginContext) bool {
				order = append(order, "third")
				return true
			},
		},
	}

	ctx := newRequestSecurityPluginContext("req-1", "10.0.0.1", "JP", time.Unix(1, 0))
	if ok := runRequestSecurityPlugins(c, requestSecurityPluginPhasePreWAF, plugins, ctx); ok {
		t.Fatal("expected plugin chain to stop")
	}
	if len(order) != 2 || order[0] != "first" || order[1] != "second" {
		t.Fatalf("unexpected order: %#v", order)
	}
}

func TestRunRequestSecurityPluginsSkipsDisabledAndWrongPhase(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/demo", nil)

	var order []string
	plugins := []requestSecurityPlugin{
		testRequestSecurityPlugin{
			name:    "disabled",
			phase:   requestSecurityPluginPhasePreWAF,
			enabled: false,
			handle: func(_ *gin.Context, _ *requestSecurityPluginContext) bool {
				order = append(order, "disabled")
				return true
			},
		},
		testRequestSecurityPlugin{
			name:    "wrong-phase",
			phase:   requestSecurityPluginPhasePostWAF,
			enabled: true,
			handle: func(_ *gin.Context, _ *requestSecurityPluginContext) bool {
				order = append(order, "wrong-phase")
				return true
			},
		},
		testRequestSecurityPlugin{
			name:    "active",
			phase:   requestSecurityPluginPhasePreWAF,
			enabled: true,
			handle: func(_ *gin.Context, _ *requestSecurityPluginContext) bool {
				order = append(order, "active")
				return true
			},
		},
	}

	ctx := newRequestSecurityPluginContext("req-1", "10.0.0.1", "JP", time.Unix(1, 0))
	if ok := runRequestSecurityPlugins(c, requestSecurityPluginPhasePreWAF, plugins, ctx); !ok {
		t.Fatal("expected plugin chain to continue")
	}
	if len(order) != 1 || order[0] != "active" {
		t.Fatalf("unexpected order: %#v", order)
	}
}
