package handler

import (
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/cacheconf"
	"tukuyomi/internal/config"
)

const (
	cacheConfPath       = config.DefaultCacheRulesFilePath
	legacyCacheConfPath = config.LegacyDefaultCacheRulesPath
	cacheConfigBlobKey  = "cache_rules"
)

type crPutBody struct {
	RawMode bool                `json:"rawMode"`
	Raw     string              `json:"raw"`
	Rules   cacheconf.RulesFile `json:"rules"`
}

func GetCacheRules(c *gin.Context) {
	readPath := config.ResolveReadablePolicyPath(cacheConfPath, legacyCacheConfPath)
	raw, _ := os.ReadFile(readPath)
	savedAt := fileSavedAt(readPath)
	if store := getLogsStatsStore(); store != nil {
		spec := mustPolicyJSONSpec(cacheConfigBlobKey)
		dbRaw, rec, found, err := loadRuntimePolicyJSONConfig(store, spec, normalizeCacheRulesPolicyRaw, "cache rules")
		if err != nil {
			respondConfigBlobDBError(c, "cache-rules db read failed", err)
			return
		} else if found {
			rsDB, parseErr := cacheconf.LoadFromBytes(dbRaw)
			if parseErr != nil {
				respondConfigBlobDBError(c, "cache-rules db rows parse failed", parseErr)
				return
			}
			savedAt = configVersionSavedAt(rec)
			c.JSON(http.StatusOK, cacheconf.RulesDTO{
				ETag:    rec.ETag,
				Raw:     string(dbRaw),
				Rules:   cacheconf.ToDTO(rsDB),
				SavedAt: savedAt,
			})
			return
		}
	}

	rs := cacheconf.Get()
	dto := cacheconf.RulesDTO{
		ETag:    cacheconf.ComputeETag(raw),
		Raw:     string(mustCacheRulesJSON(rs)),
		Rules:   cacheconf.ToDTO(rs),
		SavedAt: savedAt,
	}

	c.JSON(http.StatusOK, dto)
}

func ValidateCacheRules(c *gin.Context) {
	var in crPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if in.RawMode {
		if _, err := cacheconf.LoadFromBytes([]byte(in.Raw)); err != nil {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
			return
		}

		c.JSON(http.StatusOK, gin.H{"ok": true, "messages": []string{}})
		return
	}

	if _, errs := cacheconf.FromDTO(in.Rules); len(errs) > 0 {
		msgs := make([]string, 0, len(errs))
		for _, e := range errs {
			msgs = append(msgs, e.Error())
		}

		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": msgs})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "messages": []string{}})
}

func PutCacheRules(c *gin.Context) {
	var in crPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var outBytes []byte
	if in.RawMode {
		rs, err := cacheconf.LoadFromBytes([]byte(in.Raw))
		if err != nil {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
			return
		}

		outBytes, err = cacheconf.RulesetToJSON(rs)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	} else {
		rs, errs := cacheconf.FromDTO(in.Rules)
		if len(errs) > 0 {
			msgs := make([]string, 0, len(errs))
			for _, e := range errs {
				msgs = append(msgs, e.Error())
			}
			c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": msgs})
			return
		}

		var err error
		outBytes, err = cacheconf.RulesetToJSON(rs)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	if store := getLogsStatsStore(); store != nil {
		spec := mustPolicyJSONSpec(cacheConfigBlobKey)
		currentRaw, currentRec, _, err := loadRuntimePolicyJSONConfig(store, spec, normalizeCacheRulesPolicyRaw, "cache rules")
		if err != nil {
			respondConfigBlobDBError(c, "cache-rules db seed failed", err)
			return
		}
		expectedETag := policyWriteExpectedETag(c.GetHeader("If-Match"), currentRaw, currentRec)
		rec, err := store.writePolicyJSONConfigVersion(expectedETag, spec, outBytes, configVersionSourceApply, "", "cache rules update", 0)
		if err != nil {
			if errors.Is(err, errConfigVersionConflict) {
				c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": policyConfigConflictETag(store, cacheConfigBlobKey)})
				return
			}
			respondConfigBlobDBError(c, "cache-rules db update failed", err)
			return
		}
		if err := applyCacheRulesPolicyRaw(outBytes); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "etag": rec.ETag, "saved_at": rec.ActivatedAt.Format(time.RFC3339Nano)})
		return
	}

	ifMatch := c.GetHeader("If-Match")
	curRaw, _ := os.ReadFile(config.ResolveReadablePolicyPath(cacheConfPath, legacyCacheConfPath))
	curETag := cacheconf.ComputeETag(curRaw)
	if ifMatch != "" && ifMatch != curETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": curETag})
		return
	}

	if err := cacheconf.AtomicWriteWithBackup(cacheConfPath, outBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	now := time.Now().UTC()
	newETag := cacheconf.ComputeETag(outBytes)

	c.JSON(http.StatusOK, gin.H{"ok": true, "etag": newETag, "saved_at": now.Format(time.RFC3339Nano)})
}

func mustCacheRulesJSON(rs *cacheconf.Ruleset) []byte {
	out, err := cacheconf.RulesetToJSON(rs)
	if err != nil {
		return []byte("{\n  \"default\": {\n    \"rules\": []\n  }\n}\n")
	}
	return out
}

func SyncCacheRulesStorage() error {
	store := getLogsStatsStore()
	if store == nil {
		return nil
	}
	raw, _, found, err := loadRuntimePolicyJSONConfig(store, mustPolicyJSONSpec(cacheConfigBlobKey), normalizeCacheRulesPolicyRaw, "cache rules")
	if err != nil || !found {
		return err
	}
	return applyCacheRulesPolicyRaw(raw)
}
