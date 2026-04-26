package handler

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/cacheconf"
	"tukuyomi/internal/config"
	"tukuyomi/internal/crsselection"
	"tukuyomi/internal/runtimefiles"
)

const (
	policyJSONConfigSchemaVersion = 1
	cacheConfigBlobKey            = "cache_rules"
	bypassConfigBlobKey           = "bypass_rules"
	crsDisabledConfigDomain       = "crs_disabled_rules"
	crsDisabledSchemaVersion      = 1
	overrideRulesConfigDomain     = "override_rules"
	overrideRulesSchemaVersion    = 1
)

var errConfigDBStoreRequired = errors.New("configuration db store is not initialized")

type rawPolicyPutBody struct {
	Raw string `json:"raw"`
}

type crPutBody struct {
	RawMode bool                `json:"rawMode"`
	Raw     string              `json:"raw"`
	Rules   cacheconf.RulesFile `json:"rules"`
}

type policyJSONConfigUpdate struct {
	Spec          policyJSONConfigSpec
	NormalizedRaw []byte
	Normalize     func(string) ([]byte, error)
	ReadReason    string
	UpdateReason  string
	DBErrorLabel  string
}

type policyJSONConfigSync struct {
	Spec       policyJSONConfigSpec
	Normalize  func(string) ([]byte, error)
	ReadReason string
	Apply      func([]byte) error
}

type policyJSONConfigDBInit struct {
	Spec        policyJSONConfigSpec
	Normalize   func(string) ([]byte, error)
	ReadReason  string
	ConfigLabel string
	Apply       func([]byte) error
}

type policyJSONConfigAdminRead struct {
	Spec         policyJSONConfigSpec
	Normalize    func(string) ([]byte, error)
	ReadReason   string
	DBErrorLabel string
}

type policyJSONConfigSpec struct {
	Domain string
}

type policyJSONConfigDomain struct {
	Spec         policyJSONConfigSpec
	Normalize    func(string) ([]byte, error)
	ReadReason   string
	UpdateReason string
	DBErrorLabel string
	ConfigLabel  string
}

var policyJSONSpecs = map[string]policyJSONConfigSpec{
	cacheConfigBlobKey: {
		Domain: cacheConfigBlobKey,
	},
	bypassConfigBlobKey: {
		Domain: bypassConfigBlobKey,
	},
	countryBlockConfigBlobKey: {
		Domain: countryBlockConfigBlobKey,
	},
	rateLimitConfigBlobKey: {
		Domain: rateLimitConfigBlobKey,
	},
	botDefenseConfigBlobKey: {
		Domain: botDefenseConfigBlobKey,
	},
	semanticConfigBlobKey: {
		Domain: semanticConfigBlobKey,
	},
	notificationConfigBlobKey: {
		Domain: notificationConfigBlobKey,
	},
	ipReputationConfigBlobKey: {
		Domain: ipReputationConfigBlobKey,
	},
}

var (
	cachePolicyJSONDomain = policyJSONConfigDomain{
		Spec:         mustPolicyJSONSpec(cacheConfigBlobKey),
		Normalize:    normalizeCacheRulesPolicyRaw,
		ReadReason:   "cache rules",
		UpdateReason: "cache rules update",
		DBErrorLabel: "cache-rules",
		ConfigLabel:  "cache rules",
	}
	bypassPolicyJSONDomain = policyJSONConfigDomain{
		Spec:         mustPolicyJSONSpec(bypassConfigBlobKey),
		Normalize:    normalizeBypassPolicyRaw,
		ReadReason:   "bypass rules",
		UpdateReason: "bypass rules update",
		DBErrorLabel: "bypass",
		ConfigLabel:  "bypass rules",
	}
	countryBlockPolicyJSONDomain = policyJSONConfigDomain{
		Spec:         mustPolicyJSONSpec(countryBlockConfigBlobKey),
		Normalize:    normalizeCountryBlockPolicyRaw,
		ReadReason:   "country block rules",
		UpdateReason: "country block rules update",
		DBErrorLabel: "country-block",
		ConfigLabel:  "country block",
	}
	rateLimitPolicyJSONDomain = policyJSONConfigDomain{
		Spec:         mustPolicyJSONSpec(rateLimitConfigBlobKey),
		Normalize:    normalizeRateLimitPolicyRaw,
		ReadReason:   "rate limit rules",
		UpdateReason: "rate limit rules update",
		DBErrorLabel: "rate-limit",
		ConfigLabel:  "rate limit",
	}
	botDefensePolicyJSONDomain = policyJSONConfigDomain{
		Spec:         mustPolicyJSONSpec(botDefenseConfigBlobKey),
		Normalize:    normalizeBotDefensePolicyRaw,
		ReadReason:   "bot defense rules",
		UpdateReason: "bot defense rules update",
		DBErrorLabel: "bot-defense",
		ConfigLabel:  "bot defense",
	}
	semanticPolicyJSONDomain = policyJSONConfigDomain{
		Spec:         mustPolicyJSONSpec(semanticConfigBlobKey),
		Normalize:    normalizeSemanticPolicyRaw,
		ReadReason:   "semantic rules",
		UpdateReason: "semantic rules update",
		DBErrorLabel: "semantic",
		ConfigLabel:  "semantic",
	}
	notificationPolicyJSONDomain = policyJSONConfigDomain{
		Spec:         mustPolicyJSONSpec(notificationConfigBlobKey),
		Normalize:    normalizeNotificationPolicyRaw,
		ReadReason:   "notification rules",
		UpdateReason: "notification rules update",
		DBErrorLabel: "notification",
		ConfigLabel:  "notification",
	}
	ipReputationPolicyJSONDomain = policyJSONConfigDomain{
		Spec:         mustPolicyJSONSpec(ipReputationConfigBlobKey),
		Normalize:    normalizeIPReputationPolicyRaw,
		ReadReason:   "ip reputation rules",
		UpdateReason: "ip reputation rules update",
		DBErrorLabel: "ip-reputation",
		ConfigLabel:  "ip reputation",
	}
)

func mustPolicyJSONSpec(domain string) policyJSONConfigSpec {
	spec, ok := policyJSONSpecs[strings.TrimSpace(domain)]
	if !ok {
		panic("unknown policy json domain")
	}
	return spec
}

func (d policyJSONConfigDomain) adminRead() policyJSONConfigAdminRead {
	return policyJSONConfigAdminRead{
		Spec:         d.Spec,
		Normalize:    d.Normalize,
		ReadReason:   d.ReadReason,
		DBErrorLabel: d.DBErrorLabel,
	}
}

func (d policyJSONConfigDomain) update(normalizedRaw []byte) policyJSONConfigUpdate {
	return policyJSONConfigUpdate{
		Spec:          d.Spec,
		NormalizedRaw: normalizedRaw,
		Normalize:     d.Normalize,
		ReadReason:    d.ReadReason,
		UpdateReason:  d.UpdateReason,
		DBErrorLabel:  d.DBErrorLabel,
	}
}

func (d policyJSONConfigDomain) sync(apply func([]byte) error) policyJSONConfigSync {
	return policyJSONConfigSync{
		Spec:       d.Spec,
		Normalize:  d.Normalize,
		ReadReason: d.ReadReason,
		Apply:      apply,
	}
}

func (d policyJSONConfigDomain) dbInit(apply func([]byte) error) policyJSONConfigDBInit {
	return policyJSONConfigDBInit{
		Spec:        d.Spec,
		Normalize:   d.Normalize,
		ReadReason:  d.ReadReason,
		ConfigLabel: d.ConfigLabel,
		Apply:       apply,
	}
}

func requireConfigDBStore() (*wafEventStore, error) {
	store := getLogsStatsStore()
	if store == nil {
		return nil, errConfigDBStoreRequired
	}
	return store, nil
}

func bindRawPolicyPutBody(c *gin.Context) (rawPolicyPutBody, bool) {
	var in rawPolicyPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return rawPolicyPutBody{}, false
	}

	return in, true
}

func respondPolicyValidationError(c *gin.Context, err error) {
	c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
}

func respondPolicyValidationMessages(c *gin.Context, messages []string) {
	c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": messages})
}

func loadPolicyJSONConfigForAdmin(c *gin.Context, read policyJSONConfigAdminRead) ([]byte, configVersionRecord, bool, bool) {
	store := getLogsStatsStore()
	if store == nil {
		return nil, configVersionRecord{}, false, true
	}
	raw, rec, found, err := loadRuntimePolicyJSONConfig(store, read.Spec, read.Normalize, read.ReadReason)
	if err != nil {
		respondConfigBlobDBError(c, read.DBErrorLabel+" db read failed", err)
		return nil, configVersionRecord{}, false, false
	}
	return raw, rec, found, true
}

func GetBypassRules(c *gin.Context) {
	path := bypassconf.GetActivePath()
	if strings.TrimSpace(path) == "" {
		path = config.BypassFile
	}
	raw, _ := os.ReadFile(path)
	displayRaw := string(raw)
	savedAt := runtimefiles.FileSavedAt(path)
	dbRaw, rec, found, ok := loadPolicyJSONConfigForAdmin(c, bypassPolicyJSONDomain.adminRead())
	if !ok {
		return
	}
	if found {
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
	in, ok := bindRawPolicyPutBody(c)
	if !ok {
		return
	}

	if _, err := validateRaw(in.Raw); err != nil {
		respondPolicyValidationError(c, err)
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

	in, ok := bindRawPolicyPutBody(c)
	if !ok {
		return
	}

	if _, err := validateRaw(in.Raw); err != nil {
		respondPolicyValidationError(c, err)
		return
	}

	file, _ := bypassconf.Parse(in.Raw)
	normalizedRaw, err := bypassconf.MarshalJSON(file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	rec, ok := writePolicyJSONConfigUpdate(c, store, bypassPolicyJSONDomain.update(normalizedRaw))
	if !ok {
		return
	}
	if err := applyBypassPolicyRaw(normalizedRaw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "etag": rec.ETag, "raw": string(normalizedRaw), "saved_at": rec.ActivatedAt.Format(time.RFC3339Nano)})
}

func SyncBypassStorage() error {
	return syncPolicyJSONConfigStorage(bypassPolicyJSONDomain.sync(applyBypassPolicyRaw))
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
		target, found, err := wafRuleAssetExistsForKind(e.ExtraRule, wafRuleAssetKindBypassExtra)
		if err != nil {
			return 0, fmt.Errorf("extra rule lookup failed: %s: %w", e.ExtraRule, err)
		}
		if !found {
			if target == "" {
				target = e.ExtraRule
			}
			return 0, fmt.Errorf("extra rule not found in DB-managed rule assets: %s", target)
		}
	}

	return len(bypassconf.GetEntries(file)), nil
}

func configuredCacheRulesPath() string {
	path := strings.TrimSpace(config.CacheRulesFile)
	if path == "" {
		return config.DefaultCacheRulesFilePath
	}
	return path
}

func configuredLegacyCacheRulesPath() string {
	return config.LegacyCompatPath(configuredCacheRulesPath(), config.DefaultCacheRulesFilePath, config.LegacyDefaultCacheRulesPath)
}

func GetCacheRules(c *gin.Context) {
	readPath := config.ResolveReadablePolicyPath(configuredCacheRulesPath(), configuredLegacyCacheRulesPath())
	raw, _ := os.ReadFile(readPath)
	savedAt := runtimefiles.FileSavedAt(readPath)
	dbRaw, rec, found, ok := loadPolicyJSONConfigForAdmin(c, cachePolicyJSONDomain.adminRead())
	if !ok {
		return
	}
	if found {
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
			respondPolicyValidationError(c, err)
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

		respondPolicyValidationMessages(c, msgs)
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "messages": []string{}})
}

func PutCacheRules(c *gin.Context) {
	store, err := requireConfigDBStore()
	if err != nil {
		respondConfigDBStoreRequired(c)
		return
	}

	var in crPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var outBytes []byte
	if in.RawMode {
		rs, err := cacheconf.LoadFromBytes([]byte(in.Raw))
		if err != nil {
			respondPolicyValidationError(c, err)
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
			respondPolicyValidationMessages(c, msgs)
			return
		}

		var err error
		outBytes, err = cacheconf.RulesetToJSON(rs)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	rec, ok := writePolicyJSONConfigUpdate(c, store, cachePolicyJSONDomain.update(outBytes))
	if !ok {
		return
	}
	if err := applyCacheRulesPolicyRaw(outBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "etag": rec.ETag, "saved_at": rec.ActivatedAt.Format(time.RFC3339Nano)})
}

func mustCacheRulesJSON(rs *cacheconf.Ruleset) []byte {
	out, err := cacheconf.RulesetToJSON(rs)
	if err != nil {
		return []byte("{\n  \"default\": {\n    \"rules\": []\n  }\n}\n")
	}
	return out
}

func SyncCacheRulesStorage() error {
	return syncPolicyJSONConfigStorage(cachePolicyJSONDomain.sync(applyCacheRulesPolicyRaw))
}

func writePolicyJSONConfigUpdate(c *gin.Context, store *wafEventStore, update policyJSONConfigUpdate) (configVersionRecord, bool) {
	currentRaw, currentRec, _, err := loadRuntimePolicyJSONConfig(store, update.Spec, update.Normalize, update.ReadReason)
	if err != nil {
		respondConfigBlobDBError(c, update.DBErrorLabel+" db seed failed", err)
		return configVersionRecord{}, false
	}
	expectedETag := policyWriteExpectedETag(c.GetHeader("If-Match"), currentRaw, currentRec)
	rec, err := store.writePolicyJSONConfigVersion(expectedETag, update.Spec, update.NormalizedRaw, configVersionSourceApply, "", update.UpdateReason, 0)
	if err != nil {
		if errors.Is(err, errConfigVersionConflict) {
			c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": policyConfigConflictETag(store, update.Spec.Domain)})
			return configVersionRecord{}, false
		}
		respondConfigBlobDBError(c, update.DBErrorLabel+" db update failed", err)
		return configVersionRecord{}, false
	}
	return rec, true
}

func syncPolicyJSONConfigStorage(sync policyJSONConfigSync) error {
	store := getLogsStatsStore()
	if store == nil {
		return nil
	}
	raw, _, found, err := loadRuntimePolicyJSONConfig(store, sync.Spec, sync.Normalize, sync.ReadReason)
	if err != nil || !found {
		return err
	}
	return sync.Apply(raw)
}

func initPolicyJSONConfigFromDB(init policyJSONConfigDBInit) (bool, error) {
	store := getLogsStatsStore()
	if store == nil {
		return false, nil
	}
	raw, _, found, err := loadRuntimePolicyJSONConfig(store, init.Spec, init.Normalize, init.ReadReason)
	if err != nil {
		return true, fmt.Errorf("read %s config db: %w", init.ConfigLabel, err)
	}
	if !found {
		return true, fmt.Errorf("normalized %s config missing in db; run make db-import before removing seed files", init.ConfigLabel)
	}
	return true, init.Apply(raw)
}

func (s *wafEventStore) loadActivePolicyJSONConfig(spec policyJSONConfigSpec) ([]byte, configVersionRecord, bool, error) {
	rec, found, err := s.loadActiveConfigVersion(spec.Domain)
	if err != nil || !found {
		return nil, configVersionRecord{}, false, err
	}
	raw, err := s.loadPolicyJSONConfigVersion(spec, rec.VersionID)
	if err != nil {
		return nil, configVersionRecord{}, false, err
	}
	return raw, rec, true, nil
}

func (s *wafEventStore) writePolicyJSONConfigVersion(expectedETag string, spec policyJSONConfigSpec, canonicalRaw []byte, source string, actor string, reason string, restoredFromVersionID int64) (configVersionRecord, error) {
	return s.writeExplicitPolicyConfigVersion(expectedETag, spec, canonicalRaw, source, actor, reason, restoredFromVersionID)
}

func (s *wafEventStore) loadPolicyJSONConfigVersion(spec policyJSONConfigSpec, versionID int64) ([]byte, error) {
	return s.loadExplicitPolicyConfigVersion(spec, versionID)
}

func normalizePolicyJSONFromFile(path string, normalize func(string) ([]byte, error)) ([]byte, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if strings.TrimSpace(string(raw)) == "" {
		return nil, false, nil
	}
	normalized, err := normalize(string(raw))
	if err != nil {
		return nil, false, err
	}
	return normalized, true, nil
}

func loadRuntimePolicyJSONConfig(store *wafEventStore, spec policyJSONConfigSpec, normalize func(string) ([]byte, error), reason string) ([]byte, configVersionRecord, bool, error) {
	raw, rec, found, err := store.loadActivePolicyJSONConfig(spec)
	if err != nil || found {
		return raw, rec, found, err
	}
	if legacyRaw, _, legacyFound, legacyErr := store.GetConfigBlob(spec.Domain); legacyErr != nil {
		return nil, configVersionRecord{}, false, legacyErr
	} else if legacyFound {
		normalized, normalizeErr := normalize(string(legacyRaw))
		if normalizeErr != nil {
			return nil, configVersionRecord{}, false, normalizeErr
		}
		rec, writeErr := store.writePolicyJSONConfigVersion("", spec, normalized, configVersionSourceImport, "", "legacy "+reason+" import", 0)
		if writeErr != nil {
			return nil, configVersionRecord{}, false, writeErr
		}
		_ = store.DeleteConfigBlob(spec.Domain)
		return normalized, rec, true, nil
	}
	return nil, configVersionRecord{}, false, nil
}

func loadOrSeedPolicyJSONConfig(store *wafEventStore, spec policyJSONConfigSpec, filePath string, normalize func(string) ([]byte, error), reason string) ([]byte, configVersionRecord, bool, error) {
	raw, rec, found, err := loadRuntimePolicyJSONConfig(store, spec, normalize, reason)
	if err != nil || found {
		return raw, rec, found, err
	}
	if strings.TrimSpace(filePath) == "" {
		return nil, configVersionRecord{}, false, nil
	}
	normalized, ok, err := normalizePolicyJSONFromFile(filePath, normalize)
	if err != nil || !ok {
		return nil, configVersionRecord{}, false, err
	}
	rec, err = store.writePolicyJSONConfigVersion("", spec, normalized, configVersionSourceImport, "", reason+" file import", 0)
	if err != nil {
		return nil, configVersionRecord{}, false, err
	}
	return normalized, rec, true, nil
}

func configVersionSavedAt(rec configVersionRecord) string {
	if rec.ActivatedAt.IsZero() {
		return ""
	}
	return rec.ActivatedAt.Format(time.RFC3339Nano)
}

func policyConfigConflictETag(store *wafEventStore, domain string) string {
	rec, found, err := store.loadActiveConfigVersion(domain)
	if err != nil || !found {
		return ""
	}
	return rec.ETag
}

func policyWriteExpectedETag(ifMatch string, currentRaw []byte, currentRec configVersionRecord) string {
	ifMatch = strings.TrimSpace(ifMatch)
	if ifMatch == "" {
		return ""
	}
	if currentRec.VersionID == 0 || currentRec.ETag == "" {
		return ""
	}
	if currentRec.ETag != "" && ifMatch == currentRec.ETag {
		return currentRec.ETag
	}
	if currentRec.ContentHash != "" && weakSHA256ETagHash(ifMatch) == currentRec.ContentHash {
		return currentRec.ETag
	}
	if len(currentRaw) > 0 && ifMatch == bypassconf.ComputeETag(currentRaw) {
		return currentRec.ETag
	}
	return ifMatch
}

func weakSHA256ETagHash(etag string) string {
	etag = strings.TrimSpace(etag)
	if !strings.HasPrefix(etag, `W/"sha256:`) || !strings.HasSuffix(etag, `"`) {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(etag, `W/"sha256:`), `"`)
}

func normalizeCacheRulesPolicyRaw(raw string) ([]byte, error) {
	rs, err := cacheconf.LoadFromString(raw)
	if err != nil {
		return nil, err
	}
	return cacheconf.RulesetToJSON(rs)
}

func applyCacheRulesPolicyRaw(raw []byte) error {
	rs, err := cacheconf.LoadFromBytes(raw)
	if err != nil {
		return err
	}
	cacheconf.Set(rs)
	return nil
}

func normalizeBypassPolicyRaw(raw string) ([]byte, error) {
	if _, err := validateRaw(raw); err != nil {
		return nil, err
	}
	file, _ := bypassconf.Parse(raw)
	return bypassconf.MarshalJSON(file)
}

func applyBypassPolicyRaw(raw []byte) error {
	file, err := bypassconf.Parse(string(raw))
	if err != nil {
		return err
	}
	bypassconf.SetFile(file)
	return nil
}

func normalizeCountryBlockPolicyRaw(raw string) ([]byte, error) {
	file, err := ParseCountryBlockRaw(raw)
	if err != nil {
		return nil, err
	}
	return MarshalCountryBlockJSON(file)
}

func applyCountryBlockPolicyRaw(raw []byte) error {
	file, err := ParseCountryBlockRaw(string(raw))
	if err != nil {
		return err
	}
	countryBlockMu.Lock()
	countryBlockState = compileCountryBlock(file)
	countryBlockActivePath = ""
	countryBlockMu.Unlock()
	return nil
}

func normalizeRateLimitPolicyRaw(raw string) ([]byte, error) {
	rt, err := ValidateRateLimitRaw(raw)
	if err != nil {
		return nil, err
	}
	return []byte(mustJSON(rt.Raw)), nil
}

func applyRateLimitPolicyRaw(raw []byte) error {
	rt, err := buildRateLimitRuntimeFromRaw(raw)
	if err != nil {
		return err
	}
	rateLimitMu.Lock()
	rateLimitRuntime = rt
	rateLimitMu.Unlock()
	rateCounterMu.Lock()
	rateCounters = map[string]rateCounter{}
	rateCounterSweep = 0
	rateCounterMu.Unlock()
	resetRateLimitFeedbackState()
	return nil
}

func normalizeBotDefensePolicyRaw(raw string) ([]byte, error) {
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		return nil, err
	}
	return []byte(mustJSON(rt.File)), nil
}

func applyBotDefensePolicyRaw(raw []byte) error {
	rt, err := buildBotDefenseRuntimeFromRaw(raw)
	if err != nil {
		return err
	}
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()
	resetBotDefenseBehaviorState()
	resetBotDefenseQuarantineState()
	resetBotDefenseChallengeState()
	if botDefenseHasEnabledEphemeralSecret(rt) {
		log.Printf("[BOT_DEFENSE][WARN] challenge_secret is empty; generated ephemeral secret for this process")
	}
	return nil
}

func normalizeSemanticPolicyRaw(raw string) ([]byte, error) {
	rt, err := ValidateSemanticRaw(raw)
	if err != nil {
		return nil, err
	}
	return []byte(mustJSON(rt.File)), nil
}

func applySemanticPolicyRaw(raw []byte) error {
	rt, err := buildSemanticRuntimeFromRaw(raw)
	if err != nil {
		return err
	}
	semanticMu.Lock()
	semanticRuntime = rt
	semanticMu.Unlock()
	return nil
}

func normalizeNotificationPolicyRaw(raw string) ([]byte, error) {
	rt, err := ValidateNotificationRaw(raw)
	if err != nil {
		return nil, err
	}
	return []byte(mustJSON(rt.Raw)), nil
}

func applyNotificationPolicyRaw(raw []byte) error {
	rt, err := buildNotificationRuntimeFromRaw(raw)
	if err != nil {
		return err
	}
	notificationMu.Lock()
	notificationRuntime = rt
	notificationMu.Unlock()
	notificationRuntimeMgr.Update(rt.Raw)
	return nil
}

func normalizeIPReputationPolicyRaw(raw string) ([]byte, error) {
	rt, err := ValidateIPReputationRaw(raw)
	if err != nil {
		return nil, err
	}
	return []byte(mustJSON(rt.Raw)), nil
}

func applyIPReputationPolicyRaw(raw []byte) error {
	rt, err := ValidateIPReputationRaw(string(raw))
	if err != nil {
		return err
	}
	ipReputationMu.Lock()
	closeRuntimeIPReputation(ipReputationRuntime)
	ipReputationRuntime = &rt
	ipReputationStoreRT = rt.Default.Store
	ipReputationMu.Unlock()
	return nil
}

func crsDisabledNamesFromRaw(raw []byte) []string {
	disabled := crsselection.ParseDisabled(string(raw))
	names := make([]string, 0, len(disabled))
	for name := range disabled {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func crsDisabledHash(names []string) string {
	return configContentHash(string(crsselection.SerializeDisabled(names)))
}

func (s *wafEventStore) loadActiveCRSDisabledConfig() ([]string, configVersionRecord, bool, error) {
	rec, found, err := s.loadActiveConfigVersion(crsDisabledConfigDomain)
	if err != nil || !found {
		return nil, configVersionRecord{}, false, err
	}
	names, err := s.loadCRSDisabledConfigVersion(rec.VersionID)
	if err != nil {
		return nil, configVersionRecord{}, false, err
	}
	return names, rec, true, nil
}

func (s *wafEventStore) writeCRSDisabledConfigVersion(expectedETag string, names []string, source string, actor string, reason string, restoredFromVersionID int64) (configVersionRecord, error) {
	names = normalizeCRSDisabledNames(names)
	return s.writeConfigVersion(
		crsDisabledConfigDomain,
		crsDisabledSchemaVersion,
		expectedETag,
		source,
		actor,
		reason,
		crsDisabledHash(names),
		restoredFromVersionID,
		func(tx *sql.Tx, versionID int64) error {
			for i, name := range names {
				if _, err := s.txExec(tx, `INSERT INTO crs_disabled_rules (version_id, position, rule_name) VALUES (?, ?, ?)`, versionID, i, name); err != nil {
					return err
				}
			}
			return nil
		},
	)
}

func (s *wafEventStore) loadCRSDisabledConfigVersion(versionID int64) ([]string, error) {
	rows, err := s.query(`SELECT rule_name FROM crs_disabled_rules WHERE version_id = ? ORDER BY position`, versionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return normalizeCRSDisabledNames(names), nil
}

func loadRuntimeCRSDisabledConfig(store *wafEventStore) ([]string, configVersionRecord, bool, error) {
	names, rec, found, err := store.loadActiveCRSDisabledConfig()
	if err != nil || found {
		return names, rec, found, err
	}
	if legacyRaw, _, legacyFound, legacyErr := store.GetConfigBlob(crsDisabledConfigBlobKey); legacyErr != nil {
		return nil, configVersionRecord{}, false, legacyErr
	} else if legacyFound {
		names = crsDisabledNamesFromRaw(legacyRaw)
		rec, err := store.writeCRSDisabledConfigVersion("", names, configVersionSourceImport, "", "legacy crs disabled import", 0)
		if err != nil {
			return nil, configVersionRecord{}, false, err
		}
		_ = store.DeleteConfigBlob(crsDisabledConfigBlobKey)
		return names, rec, true, nil
	}
	return nil, configVersionRecord{}, false, nil
}

func loadOrSeedCRSDisabledConfig(store *wafEventStore, filePath string) ([]string, configVersionRecord, bool, error) {
	names, rec, found, err := loadRuntimeCRSDisabledConfig(store)
	if err != nil || found {
		return names, rec, found, err
	}
	raw, err := os.ReadFile(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, configVersionRecord{}, false, nil
		}
		return nil, configVersionRecord{}, false, err
	}
	if strings.TrimSpace(string(raw)) == "" {
		return nil, configVersionRecord{}, false, nil
	}
	names = crsDisabledNamesFromRaw(raw)
	rec, err = store.writeCRSDisabledConfigVersion("", names, configVersionSourceImport, "", "crs disabled file import", 0)
	if err != nil {
		return nil, configVersionRecord{}, false, err
	}
	return names, rec, true, nil
}

func normalizeCRSDisabledNames(names []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(names))
	for _, name := range names {
		normalized := crsselection.NormalizeName(strings.TrimSpace(name))
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

type managedOverrideRuleVersion struct {
	Name string
	Raw  []byte
	ETag string
}

func overrideRulesHash(rules []managedOverrideRuleVersion) string {
	var b strings.Builder
	for _, rule := range rules {
		b.WriteString(rule.Name)
		b.WriteByte('\t')
		b.WriteString(configContentHash(string(rule.Raw)))
		b.WriteByte('\n')
	}
	return configContentHash(b.String())
}

func normalizeManagedOverrideRules(rules []managedOverrideRuleVersion) []managedOverrideRuleVersion {
	byName := make(map[string]managedOverrideRuleVersion, len(rules))
	for _, rule := range rules {
		name, _, err := managedOverrideRuleTarget(rule.Name)
		if err != nil {
			continue
		}
		rule.Name = name
		if strings.TrimSpace(rule.ETag) == "" {
			rule.ETag = bypassconf.ComputeETag(rule.Raw)
		}
		byName[name] = rule
	}
	out := make([]managedOverrideRuleVersion, 0, len(byName))
	for _, rule := range byName {
		out = append(out, rule)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *wafEventStore) loadActiveManagedOverrideRules() ([]managedOverrideRuleVersion, configVersionRecord, bool, error) {
	rec, found, err := s.loadActiveConfigVersion(overrideRulesConfigDomain)
	if err != nil || !found {
		return nil, configVersionRecord{}, false, err
	}
	rules, err := s.loadManagedOverrideRulesVersion(rec.VersionID)
	if err != nil {
		return nil, configVersionRecord{}, false, err
	}
	return rules, rec, true, nil
}

func (s *wafEventStore) writeManagedOverrideRulesVersion(expectedETag string, rules []managedOverrideRuleVersion, source string, actor string, reason string, restoredFromVersionID int64) (configVersionRecord, []managedOverrideRuleVersion, error) {
	rules = normalizeManagedOverrideRules(rules)
	rec, err := s.writeConfigVersion(
		overrideRulesConfigDomain,
		overrideRulesSchemaVersion,
		expectedETag,
		source,
		actor,
		reason,
		overrideRulesHash(rules),
		restoredFromVersionID,
		func(tx *sql.Tx, versionID int64) error {
			for i, rule := range rules {
				contentHash := configContentHash(string(rule.Raw))
				if _, err := s.txExec(tx, `INSERT INTO override_rules (version_id, position, name, content_hash) VALUES (?, ?, ?, ?)`, versionID, i, rule.Name, contentHash); err != nil {
					return err
				}
				if _, err := s.txExec(tx, `INSERT INTO override_rule_versions (version_id, name, raw_text, etag) VALUES (?, ?, ?, ?)`, versionID, rule.Name, string(rule.Raw), rule.ETag); err != nil {
					return err
				}
			}
			return nil
		},
	)
	if err != nil {
		return configVersionRecord{}, nil, err
	}
	return rec, rules, nil
}

func (s *wafEventStore) loadManagedOverrideRulesVersion(versionID int64) ([]managedOverrideRuleVersion, error) {
	rows, err := s.query(
		`SELECT r.name, v.raw_text, v.etag
		   FROM override_rules r
		   JOIN override_rule_versions v ON v.version_id = r.version_id AND v.name = r.name
		  WHERE r.version_id = ?
		  ORDER BY r.position`,
		versionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []managedOverrideRuleVersion
	for rows.Next() {
		var rule managedOverrideRuleVersion
		var raw string
		if err := rows.Scan(&rule.Name, &raw, &rule.ETag); err != nil {
			return nil, err
		}
		rule.Raw = []byte(raw)
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return normalizeManagedOverrideRules(rules), nil
}

func loadRuntimeManagedOverrideRules(store *wafEventStore) ([]managedOverrideRuleVersion, configVersionRecord, bool, error) {
	rules, rec, found, err := store.loadActiveManagedOverrideRules()
	if err != nil || found {
		return rules, rec, found, err
	}

	legacyBlobs, err := store.ListConfigBlobs(overrideRuleConfigBlobPrefix)
	if err != nil {
		return nil, configVersionRecord{}, false, err
	}
	if len(legacyBlobs) == 0 {
		return nil, configVersionRecord{}, false, nil
	}
	for _, blob := range legacyBlobs {
		name := strings.TrimPrefix(blob.ConfigKey, overrideRuleConfigBlobPrefix)
		if _, _, targetErr := managedOverrideRuleTarget(name); targetErr != nil {
			continue
		}
		rules = append(rules, managedOverrideRuleVersion{Name: name, Raw: blob.Raw, ETag: blob.ETag})
	}
	rules = normalizeManagedOverrideRules(rules)
	rec, rules, err = store.writeManagedOverrideRulesVersion("", rules, configVersionSourceImport, "", "legacy override rules import", 0)
	if err != nil {
		return nil, configVersionRecord{}, false, err
	}
	for _, blob := range legacyBlobs {
		_ = store.DeleteConfigBlob(blob.ConfigKey)
	}
	return rules, rec, true, nil
}

func managedOverrideRuleMap(rules []managedOverrideRuleVersion) map[string]managedOverrideRuleVersion {
	out := make(map[string]managedOverrideRuleVersion, len(rules))
	for _, rule := range normalizeManagedOverrideRules(rules) {
		out[rule.Name] = rule
	}
	return out
}
