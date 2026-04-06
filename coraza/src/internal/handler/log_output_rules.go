package handler

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/bypassconf"
)

type logOutputPutBody struct {
	Raw string `json:"raw"`
}

func bindLogOutputPutBody(c *gin.Context) (logOutputPutBody, bool) {
	var in logOutputPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return logOutputPutBody{}, false
	}
	return in, true
}

func GetLogOutputConfigHandler(c *gin.Context) {
	path := GetLogOutputPath()
	raw, _ := os.ReadFile(path)
	if store := getLogsStatsStore(); store != nil {
		dbRaw, dbETag, found, err := store.GetConfigBlob(logOutputConfigBlobKey)
		if err != nil {
			log.Printf("[LOG_OUTPUT][DB][WARN] get config blob failed: %v", err)
		} else if found {
			rt, parseErr := ParseLogOutputRaw(string(dbRaw))
			if parseErr != nil {
				log.Printf("[LOG_OUTPUT][DB][WARN] cached blob parse failed (fallback=file): %v", parseErr)
			} else {
				if strings.TrimSpace(dbETag) == "" {
					dbETag = currentLogOutputETag(dbRaw)
				}
				c.JSON(http.StatusOK, renderLogOutputResponse(string(dbRaw), dbETag, rt))
				return
			}
		} else if len(raw) > 0 {
			if err := store.UpsertConfigBlob(logOutputConfigBlobKey, raw, currentLogOutputETag(raw), logOutputUpdatedAt()); err != nil {
				log.Printf("[LOG_OUTPUT][DB][WARN] seed config blob failed: %v", err)
			}
		}
	}

	rt, err := ParseLogOutputRaw(string(raw))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
			"etag":  currentLogOutputETag(raw),
			"raw":   string(raw),
		})
		return
	}
	c.JSON(http.StatusOK, renderLogOutputResponse(string(raw), currentLogOutputETag(raw), rt))
}

func ValidateLogOutputConfigHandler(c *gin.Context) {
	in, ok := bindLogOutputPutBody(c)
	if !ok {
		return
	}
	rt, err := ValidateLogOutputRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	resp := renderLogOutputResponse(in.Raw, "", rt)
	resp["ok"] = true
	resp["messages"] = []string{}
	c.JSON(http.StatusOK, resp)
}

func PutLogOutputConfigHandler(c *gin.Context) {
	path := GetLogOutputPath()
	store := getLogsStatsStore()

	ifMatch := c.GetHeader("If-Match")
	curRaw, _ := os.ReadFile(path)
	curETag := currentLogOutputETag(curRaw)
	if store != nil {
		dbRaw, dbETag, found, err := store.GetConfigBlob(logOutputConfigBlobKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if found {
			if _, parseErr := ParseLogOutputRaw(string(dbRaw)); parseErr == nil {
				curRaw = dbRaw
				if strings.TrimSpace(dbETag) == "" {
					dbETag = currentLogOutputETag(dbRaw)
				}
				curETag = dbETag
			} else {
				log.Printf("[LOG_OUTPUT][DB][WARN] cached blob parse failed for conflict check (fallback=file): %v", parseErr)
			}
		}
	}
	if ifMatch != "" && ifMatch != curETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": curETag})
		return
	}

	in, ok := bindLogOutputPutBody(c)
	if !ok {
		return
	}
	rt, err := ValidateLogOutputRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	if err := bypassconf.AtomicWriteWithBackup(path, []byte(in.Raw)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := ReloadLogOutput(); err != nil {
		_ = bypassconf.AtomicWriteWithBackup(path, curRaw)
		_ = ReloadLogOutput()
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	newETag := currentLogOutputETag([]byte(in.Raw))
	if store != nil {
		if err := store.UpsertConfigBlob(logOutputConfigBlobKey, []byte(in.Raw), newETag, logOutputUpdatedAt()); err != nil {
			_ = bypassconf.AtomicWriteWithBackup(path, curRaw)
			_ = ReloadLogOutput()
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":    "log-output db sync failed and rollback applied",
				"db_error": err.Error(),
			})
			return
		}
	}

	resp := renderLogOutputResponse(in.Raw, newETag, rt)
	resp["ok"] = true
	c.JSON(http.StatusOK, resp)
}
