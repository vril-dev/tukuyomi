package center

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/adminauth"
)

type enrollmentDecisionRequest struct {
	Reason string `json:"reason"`
}

type enrollmentTokenCreateRequest struct {
	Label         string `json:"label"`
	MaxUses       int64  `json:"max_uses"`
	ExpiresAtUnix int64  `json:"expires_at_unix"`
}

func registerDeviceEnrollmentRoutes(r *gin.Engine) {
	r.POST("/v1/enroll", postDeviceEnrollment)
	r.POST("/v1/device-status", postDeviceStatus)
	r.POST("/v1/device-config-snapshot", postDeviceConfigSnapshot)
}

func registerCenterDeviceAdminRoutes(api *gin.RouterGroup) {
	api.GET("/devices", getCenterDevices)
	api.POST("/devices/:device_id/revoke", postCenterDeviceRevoke)
	api.POST("/devices/:device_id/archive", postCenterDeviceArchive)
	api.GET("/devices/:device_id/config-snapshot", getCenterDeviceConfigSnapshot)
	api.GET("/devices/enrollments", getCenterDeviceEnrollments)
	api.POST("/devices/enrollments/:enrollment_id/approve", postCenterDeviceEnrollmentApprove)
	api.POST("/devices/enrollments/:enrollment_id/reject", postCenterDeviceEnrollmentReject)
	api.GET("/enrollment-tokens", getCenterEnrollmentTokens)
	api.POST("/enrollment-tokens", postCenterEnrollmentToken)
	api.POST("/enrollment-tokens/:token_id/revoke", postCenterEnrollmentTokenRevoke)
}

func postDeviceEnrollment(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxEnrollmentBodyBytes)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var req EnrollmentRequest
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid enrollment payload"})
		return
	}
	verified, err := VerifyEnrollmentRequest(req, time.Now().UTC())
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}

	record, err := CreatePendingEnrollment(c.Request.Context(), enrollmentInsert{
		DeviceID:                   verified.DeviceID,
		KeyID:                      verified.KeyID,
		PublicKeyPEM:               verified.PublicKeyPEM,
		PublicKeyFingerprintSHA256: verified.PublicKeyFingerprintSHA256,
		LicenseKeyHash:             enrollmentLicenseKeyHash(c.Request),
		NonceHash:                  verified.NonceHash,
		BodyHash:                   verified.BodyHash,
		SignatureB64:               verified.SignatureB64,
		RemoteAddr:                 requestRemoteAddr(c.Request),
		UserAgent:                  c.Request.UserAgent(),
		RequestedAt:                time.Now().UTC(),
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrEnrollmentTokenRequired):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "enrollment token required"})
			return
		case errors.Is(err, ErrEnrollmentTokenInvalid):
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid enrollment token"})
			return
		case errors.Is(err, ErrEnrollmentReplay):
			c.JSON(http.StatusConflict, gin.H{"error": "enrollment replay rejected"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store enrollment"})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"status":        record.Status,
		"enrollment_id": record.EnrollmentID,
		"device_id":     record.DeviceID,
		"key_id":        record.KeyID,
	})
}

func postDeviceStatus(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8*1024)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var req DeviceStatusRequest
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid device status payload"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid device status payload"})
		return
	}
	normalizedReq, _, err := normalizeDeviceStatusRequest(req, time.Now().UTC())
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	req = normalizedReq
	record, err := LookupDeviceStatus(c.Request.Context(), req.DeviceID, req.KeyID, req.PublicKeyFingerprintSHA256)
	if err != nil {
		switch {
		case errors.Is(err, ErrDeviceStatusNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "device status not found"})
		case errors.Is(err, ErrDeviceStatusKeyMismatch):
			c.JSON(http.StatusForbidden, gin.H{"error": "device key mismatch"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load device status"})
		}
		return
	}
	verified, err := VerifyDeviceStatusRequest(req, record.PublicKeyPEM, time.Now().UTC())
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	checkedAt := time.Now().UTC().Unix()
	if record.FromApprovedDevice {
		if err := TouchApprovedDeviceHeartbeat(c.Request.Context(), verified.DeviceID, checkedAt, DeviceRuntimeInventory{
			RuntimeRole:  verified.RuntimeRole,
			BuildVersion: verified.BuildVersion,
			GoVersion:    verified.GoVersion,
		}); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update device last seen"})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"status":          record.Status,
		"device_id":       verified.DeviceID,
		"key_id":          verified.KeyID,
		"product_id":      record.ProductID,
		"checked_at_unix": checkedAt,
	})
}

func postDeviceConfigSnapshot(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxDeviceConfigSnapshotBodyBytes)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var req DeviceConfigSnapshotRequest
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid config snapshot payload"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid config snapshot payload"})
		return
	}
	normalizedReq, _, _, err := normalizeDeviceConfigSnapshotRequest(req, time.Now().UTC())
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	req = normalizedReq
	record, err := LookupDeviceStatus(c.Request.Context(), req.DeviceID, req.KeyID, req.PublicKeyFingerprintSHA256)
	if err != nil {
		switch {
		case errors.Is(err, ErrDeviceStatusNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "device status not found"})
		case errors.Is(err, ErrDeviceStatusKeyMismatch):
			c.JSON(http.StatusForbidden, gin.H{"error": "device key mismatch"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load device status"})
		}
		return
	}
	if !record.FromApprovedDevice || record.Status != DeviceStatusApproved {
		c.JSON(http.StatusForbidden, gin.H{"error": "device is not approved"})
		return
	}
	verified, err := VerifyDeviceConfigSnapshotRequest(req, record.PublicKeyPEM, time.Now().UTC())
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	receivedAt := time.Now().UTC().Unix()
	snapshot, err := StoreDeviceConfigSnapshot(c.Request.Context(), DeviceConfigSnapshotInsert{
		DeviceID:       verified.DeviceID,
		Revision:       verified.ConfigRevision,
		PayloadHash:    verified.PayloadHash,
		PayloadJSON:    verified.PayloadJSON,
		ReceivedAtUnix: receivedAt,
	})
	if err != nil {
		if errors.Is(err, ErrDeviceStatusNotFound) {
			c.JSON(http.StatusForbidden, gin.H{"error": "device is not approved"})
			return
		}
		if errors.Is(err, ErrInvalidEnrollment) {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "invalid config snapshot payload"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store config snapshot"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":           "stored",
		"config_revision":  snapshot.Revision,
		"received_at_unix": snapshot.CreatedAtUnix,
	})
}

func getCenterDevices(c *gin.Context) {
	devices, err := ListDevices(c.Request.Context(), parseBoolQuery(c.Query("include_archived")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list devices"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"devices": devices})
}

func postCenterDeviceRevoke(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	record, err := RevokeDeviceApproval(c.Request.Context(), deviceID, centerAdminActor(c))
	if err != nil {
		if errors.Is(err, ErrDeviceStatusNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke device approval"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"device": record})
}

func getCenterDeviceConfigSnapshot(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	snapshot, err := LoadLatestDeviceConfigSnapshot(c.Request.Context(), deviceID)
	if err != nil {
		if errors.Is(err, ErrDeviceStatusNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "config snapshot not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load config snapshot"})
		return
	}
	name := safeConfigSnapshotFilename(snapshot.DeviceID, snapshot.Revision)
	c.Header("Content-Disposition", `attachment; filename="`+name+`"`)
	c.Data(http.StatusOK, "application/json; charset=utf-8", snapshot.PayloadJSON)
}

func postCenterDeviceArchive(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	record, err := ArchiveDeviceApproval(c.Request.Context(), deviceID, centerAdminActor(c))
	if err != nil {
		switch {
		case errors.Is(err, ErrDeviceStatusNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		case errors.Is(err, ErrDeviceArchiveInvalid):
			c.JSON(http.StatusConflict, gin.H{"error": "device must be revoked before archive"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to archive device"})
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"device": record})
}

func getCenterDeviceEnrollments(c *gin.Context) {
	limit := parseBoundedInt(c.Query("limit"), 100, 1, 500)
	status := strings.ToLower(strings.TrimSpace(c.Query("status")))
	if status == "" {
		status = EnrollmentStatusPending
	}
	enrollments, err := ListEnrollments(c.Request.Context(), status, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list enrollments"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"enrollments": enrollments})
}

func getCenterEnrollmentTokens(c *gin.Context) {
	limit := parseBoundedInt(c.Query("limit"), 100, 1, 500)
	tokens, err := ListEnrollmentTokens(c.Request.Context(), limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list enrollment tokens"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tokens": tokens})
}

func postCenterEnrollmentToken(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8*1024)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var req enrollmentTokenCreateRequest
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid enrollment token payload"})
		return
	}
	record, token, err := CreateEnrollmentToken(c.Request.Context(), EnrollmentTokenCreate{
		Label:         req.Label,
		MaxUses:       req.MaxUses,
		ExpiresAtUnix: req.ExpiresAtUnix,
		CreatedBy:     centerAdminActor(c),
	})
	if err != nil {
		if errors.Is(err, ErrEnrollmentTokenRequest) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid enrollment token payload"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create enrollment token"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"token":  token,
		"record": record,
	})
}

func postCenterEnrollmentTokenRevoke(c *gin.Context) {
	id, ok := parseTokenIDParam(c)
	if !ok {
		return
	}
	record, err := RevokeEnrollmentToken(c.Request.Context(), id, centerAdminActor(c))
	if err != nil {
		if errors.Is(err, ErrEnrollmentTokenNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "enrollment token not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke enrollment token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": record})
}

func postCenterDeviceEnrollmentApprove(c *gin.Context) {
	id, ok := parseEnrollmentIDParam(c)
	if !ok {
		return
	}
	record, err := ApproveEnrollment(c.Request.Context(), id, centerAdminActor(c))
	respondEnrollmentDecision(c, record, err)
}

func postCenterDeviceEnrollmentReject(c *gin.Context) {
	id, ok := parseEnrollmentIDParam(c)
	if !ok {
		return
	}
	var req enrollmentDecisionRequest
	if c.Request.Body != nil {
		_ = c.ShouldBindJSON(&req)
	}
	record, err := RejectEnrollment(c.Request.Context(), id, centerAdminActor(c), req.Reason)
	respondEnrollmentDecision(c, record, err)
}

func respondEnrollmentDecision(c *gin.Context, record EnrollmentRecord, err error) {
	if err == nil {
		c.JSON(http.StatusOK, gin.H{"enrollment": record})
		return
	}
	switch {
	case errors.Is(err, ErrEnrollmentNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "enrollment not found"})
	case errors.Is(err, ErrEnrollmentAlreadyClosed):
		c.JSON(http.StatusConflict, gin.H{"error": "enrollment is already closed"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update enrollment"})
	}
}

func parseEnrollmentIDParam(c *gin.Context) (int64, bool) {
	raw := strings.TrimSpace(c.Param("enrollment_id"))
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid enrollment_id"})
		return 0, false
	}
	return id, true
}

func parseTokenIDParam(c *gin.Context) (int64, bool) {
	raw := strings.TrimSpace(c.Param("token_id"))
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid token_id"})
		return 0, false
	}
	return id, true
}

func parseDeviceIDParam(c *gin.Context) (string, bool) {
	deviceID := strings.TrimSpace(c.Param("device_id"))
	if !deviceIDPattern.MatchString(deviceID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid device_id"})
		return "", false
	}
	return deviceID, true
}

func safeConfigSnapshotFilename(deviceID string, revision string) string {
	deviceID = strings.TrimSpace(deviceID)
	var b strings.Builder
	for _, r := range deviceID {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
		if b.Len() >= 64 {
			break
		}
	}
	if b.Len() == 0 {
		b.WriteString("device")
	}
	revision = strings.ToLower(strings.TrimSpace(revision))
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if revision == "" {
		revision = "snapshot"
	}
	return b.String() + "-config-" + revision + ".json"
}

func centerAdminActor(c *gin.Context) string {
	if c == nil {
		return "unknown"
	}
	if v, ok := c.Get("tukuyomi.admin_principal"); ok {
		if principal, ok := v.(adminauth.Principal); ok && strings.TrimSpace(principal.Username) != "" {
			return principal.Username
		}
	}
	if actor := strings.TrimSpace(c.GetString("tukuyomi.admin_actor")); actor != "" {
		return actor
	}
	if actor := strings.TrimSpace(c.GetString("tukuyomi.admin_auth_fallback_actor")); actor != "" {
		return actor
	}
	return "unknown"
}

func requestRemoteAddr(r *http.Request) string {
	if r == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func parseBoundedInt(raw string, def int, min int, max int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

func parseBoolQuery(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
