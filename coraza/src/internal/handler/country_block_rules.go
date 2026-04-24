package handler

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/bypassconf"
)

const countryBlockConfigBlobKey = "country_block_rules"

type countryBlockPutBody struct {
	Raw string `json:"raw"`
}

func bindCountryBlockPutBody(c *gin.Context) (countryBlockPutBody, bool) {
	var in countryBlockPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return countryBlockPutBody{}, false
	}

	return in, true
}

func GetCountryBlockRules(c *gin.Context) {
	path := GetCountryBlockActivePath()
	if strings.TrimSpace(path) == "" {
		path = GetCountryBlockPath()
	}
	raw, _ := os.ReadFile(path)
	displayRaw := string(raw)
	savedAt := fileSavedAt(path)
	if store := getLogsStatsStore(); store != nil {
		dbRaw, rec, found, err := loadRuntimePolicyJSONConfig(store, mustPolicyJSONSpec(countryBlockConfigBlobKey), normalizeCountryBlockPolicyRaw, "country block rules")
		if err != nil {
			respondConfigBlobDBError(c, "country-block db read failed", err)
			return
		} else if found {
			file, parseErr := ParseCountryBlockRaw(string(dbRaw))
			if parseErr != nil {
				respondConfigBlobDBError(c, "country-block db rows parse failed", parseErr)
				return
			} else {
				if normalized, err := MarshalCountryBlockJSON(file); err == nil {
					displayRaw = string(normalized)
				}
				savedAt = configVersionSavedAt(rec)
				c.JSON(http.StatusOK, gin.H{
					"etag":     rec.ETag,
					"raw":      displayRaw,
					"blocked":  flattenCountryBlockCodes(file),
					"saved_at": savedAt,
				})
				return
			}
		}
	}
	if file, err := ParseCountryBlockRaw(displayRaw); err == nil {
		if normalized, nerr := MarshalCountryBlockJSON(file); nerr == nil {
			displayRaw = string(normalized)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"etag":     bypassconf.ComputeETag(raw),
		"raw":      displayRaw,
		"blocked":  GetBlockedCountries(),
		"saved_at": savedAt,
	})
}

func ValidateCountryBlockRules(c *gin.Context) {
	in, ok := bindCountryBlockPutBody(c)
	if !ok {
		return
	}

	file, err := ParseCountryBlockRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "messages": []string{}, "blocked": flattenCountryBlockCodes(file)})
}

func PutCountryBlockRules(c *gin.Context) {
	store, err := requireConfigDBStore()
	if err != nil {
		respondConfigDBStoreRequired(c)
		return
	}

	in, ok := bindCountryBlockPutBody(c)
	if !ok {
		return
	}

	file, err := ParseCountryBlockRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	normalizedRaw, err := MarshalCountryBlockJSON(file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	spec := mustPolicyJSONSpec(countryBlockConfigBlobKey)
	currentRaw, currentRec, _, err := loadRuntimePolicyJSONConfig(store, spec, normalizeCountryBlockPolicyRaw, "country block rules")
	if err != nil {
		respondConfigBlobDBError(c, "country-block db seed failed", err)
		return
	}
	expectedETag := policyWriteExpectedETag(c.GetHeader("If-Match"), currentRaw, currentRec)
	rec, err := store.writePolicyJSONConfigVersion(expectedETag, spec, normalizedRaw, configVersionSourceApply, "", "country block rules update", 0)
	if err != nil {
		if errors.Is(err, errConfigVersionConflict) {
			c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": policyConfigConflictETag(store, countryBlockConfigBlobKey)})
			return
		}
		respondConfigBlobDBError(c, "country-block db update failed", err)
		return
	}
	if err := applyCountryBlockPolicyRaw(normalizedRaw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "etag": rec.ETag, "blocked": flattenCountryBlockCodes(file), "raw": string(normalizedRaw), "saved_at": rec.ActivatedAt.Format(time.RFC3339Nano)})
}

func SyncCountryBlockStorage() error {
	store := getLogsStatsStore()
	if store == nil {
		return nil
	}
	raw, _, found, err := loadRuntimePolicyJSONConfig(store, mustPolicyJSONSpec(countryBlockConfigBlobKey), normalizeCountryBlockPolicyRaw, "country block rules")
	if err != nil || !found {
		return err
	}
	return applyCountryBlockPolicyRaw(raw)
}
