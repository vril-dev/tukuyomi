package handler

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
)

const bypassConfigBlobKey = "bypass_rules"

type bypassPutBody struct {
	Raw string `json:"raw"`
}

func bindBypassPutBody(c *gin.Context) (bypassPutBody, bool) {
	var in bypassPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return bypassPutBody{}, false
	}

	return in, true
}

func GetBypassRules(c *gin.Context) {
	path := bypassconf.GetActivePath()
	if strings.TrimSpace(path) == "" {
		path = config.BypassFile
	}
	raw, _ := os.ReadFile(path)
	displayRaw := string(raw)
	savedAt := fileSavedAt(path)
	if store := getLogsStatsStore(); store != nil {
		dbRaw, rec, found, err := loadRuntimePolicyJSONConfig(store, mustPolicyJSONSpec(bypassConfigBlobKey), normalizeBypassPolicyRaw, "bypass rules")
		if err != nil {
			respondConfigBlobDBError(c, "bypass db read failed", err)
			return
		} else if found {
			file, parseErr := bypassconf.Parse(string(dbRaw))
			if parseErr != nil {
				respondConfigBlobDBError(c, "bypass db rows parse failed", parseErr)
				return
			} else {
				if normalized, err := bypassconf.MarshalJSON(file); err == nil {
					displayRaw = string(normalized)
				}
				savedAt = configVersionSavedAt(rec)
				c.JSON(http.StatusOK, gin.H{
					"etag":     rec.ETag,
					"raw":      displayRaw,
					"saved_at": savedAt,
				})
				return
			}
		}
	}
	if file, err := bypassconf.Parse(displayRaw); err == nil {
		if normalized, nerr := bypassconf.MarshalJSON(file); nerr == nil {
			displayRaw = string(normalized)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"etag":     bypassconf.ComputeETag(raw),
		"raw":      displayRaw,
		"saved_at": savedAt,
	})
}

func ValidateBypassRules(c *gin.Context) {
	in, ok := bindBypassPutBody(c)
	if !ok {
		return
	}

	if _, err := validateRaw(in.Raw); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "messages": []string{}})
}

func PutBypassRules(c *gin.Context) {
	store, err := requireConfigDBStore()
	if err != nil {
		respondConfigDBStoreRequired(c)
		return
	}

	in, ok := bindBypassPutBody(c)
	if !ok {
		return
	}

	if _, err := validateRaw(in.Raw); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	file, _ := bypassconf.Parse(in.Raw)
	normalizedRaw, err := bypassconf.MarshalJSON(file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	spec := mustPolicyJSONSpec(bypassConfigBlobKey)
	currentRaw, currentRec, _, err := loadRuntimePolicyJSONConfig(store, spec, normalizeBypassPolicyRaw, "bypass rules")
	if err != nil {
		respondConfigBlobDBError(c, "bypass db seed failed", err)
		return
	}
	expectedETag := policyWriteExpectedETag(c.GetHeader("If-Match"), currentRaw, currentRec)
	rec, err := store.writePolicyJSONConfigVersion(expectedETag, spec, normalizedRaw, configVersionSourceApply, "", "bypass rules update", 0)
	if err != nil {
		if errors.Is(err, errConfigVersionConflict) {
			c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": policyConfigConflictETag(store, bypassConfigBlobKey)})
			return
		}
		respondConfigBlobDBError(c, "bypass db update failed", err)
		return
	}
	if err := applyBypassPolicyRaw(normalizedRaw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "etag": rec.ETag, "raw": string(normalizedRaw), "saved_at": rec.ActivatedAt.Format(time.RFC3339Nano)})
}

func SyncBypassStorage() error {
	store := getLogsStatsStore()
	if store == nil {
		return nil
	}
	raw, _, found, err := loadRuntimePolicyJSONConfig(store, mustPolicyJSONSpec(bypassConfigBlobKey), normalizeBypassPolicyRaw, "bypass rules")
	if err != nil || !found {
		return err
	}
	return applyBypassPolicyRaw(raw)
}

func validateRaw(s string) (int, error) {
	file, err := bypassconf.Parse(s)
	if err != nil {
		return 0, err
	}
	for _, e := range bypassconf.GetEntries(file) {
		if e.ExtraRule == "" {
			continue
		}
		if _, statErr := os.Stat(e.ExtraRule); statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) && !config.StrictOverride {
				continue
			}
			return 0, fmt.Errorf("extra rule not found: %s", e.ExtraRule)
		}
	}

	return len(bypassconf.GetEntries(file)), nil
}
