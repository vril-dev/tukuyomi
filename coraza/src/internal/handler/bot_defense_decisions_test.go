package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestRecordBotDefenseDecisionKeepsMostRecentFirst(t *testing.T) {
	resetBotDefenseDecisionHistory()
	t.Cleanup(resetBotDefenseDecisionHistory)

	recordBotDefenseDecision(nil, &requestSecurityPluginContext{RequestID: "req-1", ClientIP: "10.0.0.1"}, botDefenseDecision{
		Allowed:   true,
		RiskScore: 3,
		Signals:   []string{"burst:12"},
	})
	recordBotDefenseDecision(nil, &requestSecurityPluginContext{RequestID: "req-2", ClientIP: "10.0.0.2"}, botDefenseDecision{
		Allowed:    true,
		Action:     botDefenseActionChallenge,
		DryRun:     true,
		Status:     http.StatusTooManyRequests,
		FlowPolicy: "login",
		RiskScore:  4,
		Signals:    []string{"burst:14"},
	})

	items := recentBotDefenseDecisions(10)
	if len(items) != 2 {
		t.Fatalf("decision count=%d want=2", len(items))
	}
	if items[0].RequestID != "req-2" || items[0].Action != botDefenseActionChallenge {
		t.Fatalf("latest record mismatch: %#v", items[0])
	}
	if !items[0].DryRun {
		t.Fatalf("dry_run=%v want=true", items[0].DryRun)
	}
	if items[1].Action != "allow" {
		t.Fatalf("allowed record should be normalized to allow: %#v", items[1])
	}
}

func TestGetBotDefenseDecisionsReturnsRecentItems(t *testing.T) {
	resetBotDefenseDecisionHistory()
	t.Cleanup(resetBotDefenseDecisionHistory)

	recordBotDefenseDecision(
		httptest.NewRequest(http.MethodGet, "https://example.test/login", nil),
		&requestSecurityPluginContext{RequestID: "req-3", ClientIP: "10.0.0.3", Country: "JP", Now: time.Now().UTC()},
		botDefenseDecision{
			Allowed:    true,
			Action:     botDefenseActionChallenge,
			DryRun:     true,
			Status:     http.StatusTooManyRequests,
			Mode:       botDefenseModeSuspicious,
			FlowPolicy: "checkout",
			RiskScore:  8,
			Signals:    []string{"path_fanout:5"},
		},
	)

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/tukuyomi-api/bot-defense-decisions?limit=5", nil)

	GetBotDefenseDecisions(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rec.Code, http.StatusOK)
	}

	var payload struct {
		Items []botDefenseDecisionRecord `json:"items"`
		Count int                        `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if payload.Count != 1 || len(payload.Items) != 1 {
		t.Fatalf("unexpected payload: %#v", payload)
	}
	if payload.Items[0].Action != botDefenseActionChallenge || payload.Items[0].Path != "/login" {
		t.Fatalf("unexpected item: %#v", payload.Items[0])
	}
	if payload.Items[0].FlowPolicy != "checkout" {
		t.Fatalf("flow policy=%q want=%q", payload.Items[0].FlowPolicy, "checkout")
	}
	if !payload.Items[0].DryRun {
		t.Fatalf("dry_run=%v want=true", payload.Items[0].DryRun)
	}
}
