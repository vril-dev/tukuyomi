package handler

import (
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/bypassconf"
)

const rateLimitConfigBlobKey = "rate_limit_rules"

type rateLimitPutBody struct {
	Raw string `json:"raw"`
}

func bindRateLimitPutBody(c *gin.Context) (rateLimitPutBody, bool) {
	var in rateLimitPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return rateLimitPutBody{}, false
	}

	return in, true
}

func GetRateLimitRules(c *gin.Context) {
	path := GetRateLimitPath()
	raw, _ := os.ReadFile(path)
	savedAt := fileSavedAt(path)
	if store := getLogsStatsStore(); store != nil {
		dbRaw, rec, found, err := loadRuntimePolicyJSONConfig(store, mustPolicyJSONSpec(rateLimitConfigBlobKey), normalizeRateLimitPolicyRaw, "rate limit rules")
		if err != nil {
			respondConfigBlobDBError(c, "rate-limit db read failed", err)
			return
		} else if found {
			rt, parseErr := ValidateRateLimitRaw(string(dbRaw))
			if parseErr != nil {
				respondConfigBlobDBError(c, "rate-limit db rows parse failed", parseErr)
				return
			} else {
				savedAt = configVersionSavedAt(rec)
				c.JSON(http.StatusOK, gin.H{
					"etag":     rec.ETag,
					"raw":      string(dbRaw),
					"enabled":  rateLimitEnabled(rt.Raw),
					"rules":    rateLimitRuleCount(rt.Raw),
					"saved_at": savedAt,
				})
				return
			}
		}
	}

	cfg := GetRateLimitConfig()
	c.JSON(http.StatusOK, gin.H{
		"etag":     bypassconf.ComputeETag(raw),
		"raw":      string(raw),
		"enabled":  rateLimitEnabled(cfg),
		"rules":    rateLimitRuleCount(cfg),
		"saved_at": savedAt,
	})
}

func ValidateRateLimitRules(c *gin.Context) {
	in, ok := bindRateLimitPutBody(c)
	if !ok {
		return
	}

	rt, err := ValidateRateLimitRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":       true,
		"messages": []string{},
		"enabled":  rateLimitEnabled(rt.Raw),
		"rules":    rateLimitRuleCount(rt.Raw),
	})
}

func PutRateLimitRules(c *gin.Context) {
	store, err := requireConfigDBStore()
	if err != nil {
		respondConfigDBStoreRequired(c)
		return
	}

	in, ok := bindRateLimitPutBody(c)
	if !ok {
		return
	}

	rt, err := ValidateRateLimitRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	normalizedRaw, err := normalizeRateLimitPolicyRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	spec := mustPolicyJSONSpec(rateLimitConfigBlobKey)
	currentRaw, currentRec, _, err := loadRuntimePolicyJSONConfig(store, spec, normalizeRateLimitPolicyRaw, "rate limit rules")
	if err != nil {
		respondConfigBlobDBError(c, "rate-limit db seed failed", err)
		return
	}
	expectedETag := policyWriteExpectedETag(c.GetHeader("If-Match"), currentRaw, currentRec)
	rec, err := store.writePolicyJSONConfigVersion(expectedETag, spec, normalizedRaw, configVersionSourceApply, "", "rate limit rules update", 0)
	if err != nil {
		if errors.Is(err, errConfigVersionConflict) {
			c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": policyConfigConflictETag(store, rateLimitConfigBlobKey)})
			return
		}
		respondConfigBlobDBError(c, "rate-limit db update failed", err)
		return
	}
	if err := applyRateLimitPolicyRaw(normalizedRaw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":       true,
		"etag":     rec.ETag,
		"enabled":  rateLimitEnabled(rt.Raw),
		"rules":    rateLimitRuleCount(rt.Raw),
		"saved_at": rec.ActivatedAt.Format(time.RFC3339Nano),
	})
}

func SyncRateLimitStorage() error {
	store := getLogsStatsStore()
	if store == nil {
		return nil
	}
	raw, _, found, err := loadRuntimePolicyJSONConfig(store, mustPolicyJSONSpec(rateLimitConfigBlobKey), normalizeRateLimitPolicyRaw, "rate limit rules")
	if err != nil || !found {
		return err
	}
	return applyRateLimitPolicyRaw(raw)
}
