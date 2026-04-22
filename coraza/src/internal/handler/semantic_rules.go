package handler

import (
	"log"
	"net/http"
	"os"
	"strings"
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
		dbRaw, dbETag, found, err := store.GetConfigBlob(semanticConfigBlobKey)
		if err != nil {
			log.Printf("[SEMANTIC][DB][WARN] get config blob failed: %v", err)
		} else if found {
			rt, parseErr := ValidateSemanticRaw(string(dbRaw))
			if parseErr != nil {
				log.Printf("[SEMANTIC][DB][WARN] cached blob parse failed (fallback=file): %v", parseErr)
			} else {
				if strings.TrimSpace(dbETag) == "" {
					dbETag = bypassconf.ComputeETag(dbRaw)
				}
				savedAt = configBlobSavedAt(store, semanticConfigBlobKey)
				c.JSON(http.StatusOK, gin.H{
					"etag":                 dbETag,
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
		} else if len(raw) > 0 {
			if err := store.UpsertConfigBlob(semanticConfigBlobKey, raw, bypassconf.ComputeETag(raw), time.Now().UTC()); err != nil {
				log.Printf("[SEMANTIC][DB][WARN] seed config blob failed: %v", err)
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
	ifMatch := c.GetHeader("If-Match")
	curRaw, _ := os.ReadFile(path)
	curETag := bypassconf.ComputeETag(curRaw)
	if store != nil {
		dbRaw, dbETag, found, err := store.GetConfigBlob(semanticConfigBlobKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if found {
			if _, parseErr := ValidateSemanticRaw(string(dbRaw)); parseErr == nil {
				curRaw = dbRaw
				if strings.TrimSpace(dbETag) == "" {
					dbETag = bypassconf.ComputeETag(dbRaw)
				}
				curETag = dbETag
			} else {
				log.Printf("[SEMANTIC][DB][WARN] cached blob parse failed for conflict check (fallback=file): %v", parseErr)
			}
		}
	}
	if ifMatch != "" && ifMatch != curETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": curETag})
		return
	}

	in, ok := bindSemanticPutBody(c)
	if !ok {
		return
	}

	rt, err := ValidateSemanticRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
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
	if store != nil {
		if err := store.UpsertConfigBlob(semanticConfigBlobKey, []byte(in.Raw), newETag, now); err != nil {
			_ = bypassconf.AtomicWriteWithBackup(path, curRaw)
			_ = ReloadSemantic()
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":    "semantic db sync failed and rollback applied",
				"db_error": err.Error(),
			})
			return
		}
	}

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
	return syncConfigBlobFilePath(configBlobSyncOptions{
		ConfigKey: semanticConfigBlobKey,
		Path:      GetSemanticPath(),
		ValidateRaw: func(raw string) error {
			_, err := ValidateSemanticRaw(raw)
			return err
		},
		Reload:           ReloadSemantic,
		SkipWriteIfEqual: true,
	})
}
