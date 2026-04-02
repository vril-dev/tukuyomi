package handler

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type requestSecurityPluginPhase string

const (
	requestSecurityPluginPhasePreWAF  requestSecurityPluginPhase = "pre_waf"
	requestSecurityPluginPhasePostWAF requestSecurityPluginPhase = "post_waf"
)

type requestSecurityPlugin interface {
	Name() string
	Phase() requestSecurityPluginPhase
	Enabled() bool
	Handle(c *gin.Context, ctx *requestSecurityPluginContext) bool
}

type requestSecurityPluginContext struct {
	RequestID string
	ClientIP  string
	Country   string
	Now       time.Time
	Semantic  semanticEvaluation
}

type requestSecurityPluginFactory func() requestSecurityPlugin

var (
	requestSecurityPluginRegistryMu sync.RWMutex
	requestSecurityPluginFactories  []requestSecurityPluginFactory
)

func init() {
	registerRequestSecurityPlugin(newIPReputationRequestSecurityPlugin)
	registerRequestSecurityPlugin(newBotDefenseRequestSecurityPlugin)
	registerRequestSecurityPlugin(newSemanticRequestSecurityPlugin)
}

func registerRequestSecurityPlugin(factory requestSecurityPluginFactory) {
	if factory == nil {
		return
	}
	requestSecurityPluginRegistryMu.Lock()
	defer requestSecurityPluginRegistryMu.Unlock()
	requestSecurityPluginFactories = append(requestSecurityPluginFactories, factory)
}

func newRequestSecurityPlugins() []requestSecurityPlugin {
	requestSecurityPluginRegistryMu.RLock()
	factories := append([]requestSecurityPluginFactory(nil), requestSecurityPluginFactories...)
	requestSecurityPluginRegistryMu.RUnlock()

	out := make([]requestSecurityPlugin, 0, len(factories))
	for _, factory := range factories {
		if factory == nil {
			continue
		}
		p := factory()
		if p == nil {
			continue
		}
		out = append(out, p)
	}
	return out
}

func newRequestSecurityPluginContext(reqID, clientIP, country string, now time.Time) *requestSecurityPluginContext {
	return &requestSecurityPluginContext{
		RequestID: reqID,
		ClientIP:  clientIP,
		Country:   country,
		Now:       now.UTC(),
		Semantic: semanticEvaluation{
			Action: semanticActionNone,
		},
	}
}

func runRequestSecurityPlugins(c *gin.Context, phase requestSecurityPluginPhase, plugins []requestSecurityPlugin, ctx *requestSecurityPluginContext) bool {
	for _, p := range plugins {
		if p == nil || p.Phase() != phase || !p.Enabled() {
			continue
		}
		if ok := p.Handle(c, ctx); !ok {
			return false
		}
	}
	return true
}

func (ctx *requestSecurityPluginContext) newEvent(req *http.Request, level, event string) map[string]any {
	evt := map[string]any{
		"ts":      time.Now().UTC().Format(time.RFC3339Nano),
		"service": "coraza",
		"level":   level,
		"event":   event,
		"req_id":  ctx.RequestID,
		"ip":      ctx.ClientIP,
		"country": ctx.Country,
	}
	if req != nil && req.URL != nil {
		evt["path"] = req.URL.Path
	}
	return evt
}

func (ctx *requestSecurityPluginContext) emitEvent(evt map[string]any) {
	emitJSONLog(evt)
	_ = appendEventToFile(evt)
}

type ipReputationRequestSecurityPlugin struct{}

func newIPReputationRequestSecurityPlugin() requestSecurityPlugin {
	return &ipReputationRequestSecurityPlugin{}
}

func (p *ipReputationRequestSecurityPlugin) Name() string {
	return "ip_reputation"
}

func (p *ipReputationRequestSecurityPlugin) Phase() requestSecurityPluginPhase {
	return requestSecurityPluginPhasePreWAF
}

func (p *ipReputationRequestSecurityPlugin) Enabled() bool {
	return currentIPReputationStore().Enabled()
}

func (p *ipReputationRequestSecurityPlugin) Handle(c *gin.Context, ctx *requestSecurityPluginContext) bool {
	blocked, statusCode := EvaluateIPReputation(ctx.ClientIP)
	if !blocked {
		return true
	}
	evt := ctx.newEvent(c.Request, "WARN", "ip_reputation")
	evt["status"] = statusCode
	evt["decision"] = "block"
	ctx.emitEvent(evt)
	c.AbortWithStatus(statusCode)
	return false
}

type botDefenseRequestSecurityPlugin struct{}

func newBotDefenseRequestSecurityPlugin() requestSecurityPlugin {
	return &botDefenseRequestSecurityPlugin{}
}

func (p *botDefenseRequestSecurityPlugin) Name() string {
	return "bot_defense"
}

func (p *botDefenseRequestSecurityPlugin) Phase() requestSecurityPluginPhase {
	return requestSecurityPluginPhasePreWAF
}

func (p *botDefenseRequestSecurityPlugin) Enabled() bool {
	rt := currentBotDefenseRuntime()
	return rt != nil && rt.Raw.Enabled
}

func (p *botDefenseRequestSecurityPlugin) Handle(c *gin.Context, ctx *requestSecurityPluginContext) bool {
	botDecision := EvaluateBotDefense(c.Request, ctx.ClientIP, ctx.Now)
	recordBotDefenseDecision(c.Request, ctx, botDecision)
	if botDecision.Allowed {
		if botDecision.Action == botDefenseActionChallenge && botDecision.DryRun {
			evt := ctx.newEvent(c.Request, "WARN", "bot_challenge_dry_run")
			evt["status"] = botDecision.Status
			evt["mode"] = botDecision.Mode
			evt["flow_policy"] = botDecision.FlowPolicy
			evt["risk_score"] = botDecision.RiskScore
			evt["signals"] = append([]string(nil), botDecision.Signals...)
			ctx.emitEvent(evt)
		}
		return true
	}
	evt := ctx.newEvent(c.Request, "WARN", "bot_challenge")
	evt["status"] = botDecision.Status
	evt["mode"] = botDecision.Mode
	evt["flow_policy"] = botDecision.FlowPolicy
	evt["risk_score"] = botDecision.RiskScore
	evt["signals"] = append([]string(nil), botDecision.Signals...)
	ctx.emitEvent(evt)
	WriteBotDefenseChallenge(c.Writer, c.Request, botDecision)
	c.Abort()
	return false
}

type semanticRequestSecurityPlugin struct{}

func newSemanticRequestSecurityPlugin() requestSecurityPlugin {
	return &semanticRequestSecurityPlugin{}
}

func (p *semanticRequestSecurityPlugin) Name() string {
	return "semantic"
}

func (p *semanticRequestSecurityPlugin) Phase() requestSecurityPluginPhase {
	return requestSecurityPluginPhasePreWAF
}

func (p *semanticRequestSecurityPlugin) Enabled() bool {
	rt := currentSemanticRuntime()
	return rt != nil && rt.Raw.Enabled && rt.Raw.Mode != semanticModeOff
}

func (p *semanticRequestSecurityPlugin) Handle(c *gin.Context, ctx *requestSecurityPluginContext) bool {
	eval := EvaluateSemanticWithContext(c.Request, ctx.ClientIP, ctx.Now)
	ctx.Semantic = eval
	if eval.Score > 0 {
			c.Header("X-Tukuyomi-Semantic-Score", strconv.Itoa(eval.Score))
	}
	if eval.Action == semanticActionNone {
		return true
	}

	evt := ctx.newEvent(c.Request, "WARN", "semantic_anomaly")
	evt["action"] = eval.Action
	evt["score"] = eval.Score
	evt["reasons"] = strings.Join(eval.Reasons, ",")
	evt["reason_list"] = append([]string(nil), eval.Reasons...)
	evt["score_breakdown"] = semanticSignalLogObjects(eval.Signals)
	ctx.emitEvent(evt)

	switch eval.Action {
	case semanticActionChallenge:
		if !HasValidSemanticChallengeCookie(c.Request, ctx.ClientIP, ctx.Now) {
			WriteSemanticChallenge(c.Writer, c.Request, ctx.ClientIP)
			c.Abort()
			return false
		}
	case semanticActionBlock:
		c.AbortWithStatus(http.StatusForbidden)
		return false
	}
	return true
}
