package handler

import (
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/bypassconf"
)

const semanticConfigBlobKey = "semantic_rules"

type semanticPutBody struct {
	Raw string `json:"raw"`
}

func bindSemanticPutBody(c *gin.Context) (semanticPutBody, bool) {
	var in semanticPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return semanticPutBody{}, false
	}

	return in, true
}

func GetSemanticRules(c *gin.Context) {
	path := GetSemanticPath()
	raw, _ := os.ReadFile(path)
	savedAt := fileSavedAt(path)
	if store := getLogsStatsStore(); store != nil {
		dbRaw, rec, found, err := loadRuntimePolicyJSONConfig(store, mustPolicyJSONSpec(semanticConfigBlobKey), normalizeSemanticPolicyRaw, "semantic rules")
		if err != nil {
			respondConfigBlobDBError(c, "semantic db read failed", err)
			return
		} else if found {
			rt, parseErr := ValidateSemanticRaw(string(dbRaw))
			if parseErr != nil {
				respondConfigBlobDBError(c, "semantic db rows parse failed", parseErr)
				return
			} else {
				savedAt = configVersionSavedAt(rec)
				c.JSON(http.StatusOK, gin.H{
					"etag":                 rec.ETag,
					"raw":                  string(dbRaw),
					"enabled":              rt.Raw.Enabled,
					"mode":                 rt.Raw.Mode,
					"exempt_path_prefixes": rt.Raw.ExemptPathPrefixes,
					"log_threshold":        rt.Raw.LogThreshold,
					"challenge_threshold":  rt.Raw.ChallengeThreshold,
					"block_threshold":      rt.Raw.BlockThreshold,
					"max_inspect_body":     rt.Raw.MaxInspectBody,
					"provider_enabled":     rt.Raw.Provider.Enabled,
					"provider_name":        rt.Raw.Provider.Name,
					"provider_timeout_ms":  rt.Raw.Provider.TimeoutMS,
					"stats":                GetSemanticStats(),
					"saved_at":             savedAt,
				})
				return
			}
		}
	}
	cfg := GetSemanticConfig()
	stats := GetSemanticStats()

	c.JSON(http.StatusOK, gin.H{
		"etag":                 bypassconf.ComputeETag(raw),
		"raw":                  string(raw),
		"enabled":              cfg.Enabled,
		"mode":                 cfg.Mode,
		"exempt_path_prefixes": cfg.ExemptPathPrefixes,
		"log_threshold":        cfg.LogThreshold,
		"challenge_threshold":  cfg.ChallengeThreshold,
		"block_threshold":      cfg.BlockThreshold,
		"max_inspect_body":     cfg.MaxInspectBody,
		"provider_enabled":     cfg.Provider.Enabled,
		"provider_name":        cfg.Provider.Name,
		"provider_timeout_ms":  cfg.Provider.TimeoutMS,
		"stats":                stats,
		"saved_at":             savedAt,
	})
}

func ValidateSemanticRules(c *gin.Context) {
	in, ok := bindSemanticPutBody(c)
	if !ok {
		return
	}

	rt, err := ValidateSemanticRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":                   true,
		"messages":             []string{},
		"enabled":              rt.Raw.Enabled,
		"mode":                 rt.Raw.Mode,
		"exempt_path_prefixes": rt.Raw.ExemptPathPrefixes,
		"log_threshold":        rt.Raw.LogThreshold,
		"challenge_threshold":  rt.Raw.ChallengeThreshold,
		"block_threshold":      rt.Raw.BlockThreshold,
		"max_inspect_body":     rt.Raw.MaxInspectBody,
		"provider_enabled":     rt.Raw.Provider.Enabled,
		"provider_name":        rt.Raw.Provider.Name,
		"provider_timeout_ms":  rt.Raw.Provider.TimeoutMS,
	})
}

func PutSemanticRules(c *gin.Context) {
	path := GetSemanticPath()
	store := getLogsStatsStore()

	in, ok := bindSemanticPutBody(c)
	if !ok {
		return
	}

	rt, err := ValidateSemanticRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	normalizedRaw, err := normalizeSemanticPolicyRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	if store != nil {
		spec := mustPolicyJSONSpec(semanticConfigBlobKey)
		currentRaw, currentRec, _, err := loadRuntimePolicyJSONConfig(store, spec, normalizeSemanticPolicyRaw, "semantic rules")
		if err != nil {
			respondConfigBlobDBError(c, "semantic db seed failed", err)
			return
		}
		expectedETag := policyWriteExpectedETag(c.GetHeader("If-Match"), currentRaw, currentRec)
		rec, err := store.writePolicyJSONConfigVersion(expectedETag, spec, normalizedRaw, configVersionSourceApply, "", "semantic rules update", 0)
		if err != nil {
			if errors.Is(err, errConfigVersionConflict) {
				c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": policyConfigConflictETag(store, semanticConfigBlobKey)})
				return
			}
			respondConfigBlobDBError(c, "semantic db update failed", err)
			return
		}
		if err := applySemanticPolicyRaw(normalizedRaw); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"ok":                   true,
			"etag":                 rec.ETag,
			"enabled":              rt.Raw.Enabled,
			"mode":                 rt.Raw.Mode,
			"exempt_path_prefixes": rt.Raw.ExemptPathPrefixes,
			"log_threshold":        rt.Raw.LogThreshold,
			"challenge_threshold":  rt.Raw.ChallengeThreshold,
			"block_threshold":      rt.Raw.BlockThreshold,
			"max_inspect_body":     rt.Raw.MaxInspectBody,
			"provider_enabled":     rt.Raw.Provider.Enabled,
			"provider_name":        rt.Raw.Provider.Name,
			"provider_timeout_ms":  rt.Raw.Provider.TimeoutMS,
			"saved_at":             rec.ActivatedAt.Format(time.RFC3339Nano),
		})
		return
	}

	ifMatch := c.GetHeader("If-Match")
	curRaw, _ := os.ReadFile(path)
	curETag := bypassconf.ComputeETag(curRaw)
	if ifMatch != "" && ifMatch != curETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": curETag})
		return
	}

	if err := bypassconf.AtomicWriteWithBackup(path, []byte(in.Raw)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := ReloadSemantic(); err != nil {
		_ = bypassconf.AtomicWriteWithBackup(path, curRaw)
		_ = ReloadSemantic()
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	now := time.Now().UTC()
	newETag := bypassconf.ComputeETag([]byte(in.Raw))

	c.JSON(http.StatusOK, gin.H{
		"ok":                   true,
		"etag":                 newETag,
		"enabled":              rt.Raw.Enabled,
		"mode":                 rt.Raw.Mode,
		"exempt_path_prefixes": rt.Raw.ExemptPathPrefixes,
		"log_threshold":        rt.Raw.LogThreshold,
		"challenge_threshold":  rt.Raw.ChallengeThreshold,
		"block_threshold":      rt.Raw.BlockThreshold,
		"max_inspect_body":     rt.Raw.MaxInspectBody,
		"provider_enabled":     rt.Raw.Provider.Enabled,
		"provider_name":        rt.Raw.Provider.Name,
		"provider_timeout_ms":  rt.Raw.Provider.TimeoutMS,
		"saved_at":             now.Format(time.RFC3339Nano),
	})
}

func SyncSemanticStorage() error {
	store := getLogsStatsStore()
	if store == nil {
		return nil
	}
	raw, _, found, err := loadRuntimePolicyJSONConfig(store, mustPolicyJSONSpec(semanticConfigBlobKey), normalizeSemanticPolicyRaw, "semantic rules")
	if err != nil || !found {
		return err
	}
	return applySemanticPolicyRaw(raw)
}
