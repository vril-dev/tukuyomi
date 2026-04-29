package center

import (
	"encoding/json"
	"errors"
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

func registerDeviceEnrollmentRoutes(r *gin.Engine) {
	r.POST("/v1/enroll", postDeviceEnrollment)
}

func registerCenterDeviceAdminRoutes(api *gin.RouterGroup) {
	api.GET("/devices", getCenterDevices)
	api.GET("/devices/enrollments", getCenterDeviceEnrollments)
	api.POST("/devices/enrollments/:enrollment_id/approve", postCenterDeviceEnrollmentApprove)
	api.POST("/devices/enrollments/:enrollment_id/reject", postCenterDeviceEnrollmentReject)
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
		if errors.Is(err, ErrEnrollmentReplay) {
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

func getCenterDevices(c *gin.Context) {
	devices, err := ListDevices(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list devices"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"devices": devices})
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
