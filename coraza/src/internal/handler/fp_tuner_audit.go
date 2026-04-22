package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

const (
	defaultFPTunerAuditFile = "/app/logs/coraza/fp-tuner-audit.ndjson"
)

type fpTunerAuditEntry struct {
	TS               string `json:"ts"`
	Service          string `json:"service,omitempty"`
	Event            string `json:"event,omitempty"`
	Actor            string `json:"actor,omitempty"`
	IP               string `json:"ip,omitempty"`
	ProposalID       string `json:"proposal_id,omitempty"`
	ProposalHash     string `json:"proposal_hash,omitempty"`
	TargetPath       string `json:"target_path,omitempty"`
	Mode             string `json:"mode,omitempty"`
	Source           string `json:"source,omitempty"`
	Count            int    `json:"count,omitempty"`
	Simulate         *bool  `json:"simulate,omitempty"`
	ApprovalRequired *bool  `json:"approval_required,omitempty"`
	ApprovalToken    any    `json:"approval_token,omitempty"`
	ApprovalError    string `json:"approval_error,omitempty"`
	HotReloaded      *bool  `json:"hot_reloaded,omitempty"`
	Error            string `json:"error,omitempty"`
}

func GetFPTunerAudit(c *gin.Context) {
	entries, err := readFPTunerAudit(parseFPTunerAuditLimit(c.Query("limit")))
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"entries": entries,
	})
}

func readFPTunerAudit(limit int) ([]fpTunerAuditEntry, error) {
	path := strings.TrimSpace(config.FPTunerAuditFile)
	if path == "" {
		path = defaultFPTunerAuditFile
	}
	return readAdminAuditLatest[fpTunerAuditEntry](path, limit, "fp tuner")
}

func parseFPTunerAuditLimit(raw string) int {
	return parseAdminAuditLimit(raw)
}
