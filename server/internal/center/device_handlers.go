package center

import (
	"encoding/base64"
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
	"tukuyomi/internal/edgeartifactbundle"
	"tukuyomi/internal/handler"
)

type enrollmentDecisionRequest struct {
	Reason string `json:"reason"`
}

type enrollmentTokenCreateRequest struct {
	Label         string `json:"label"`
	MaxUses       int64  `json:"max_uses"`
	ExpiresAtUnix int64  `json:"expires_at_unix"`
}

type runtimeAssignmentRequest struct {
	RuntimeFamily    string `json:"runtime_family"`
	RuntimeID        string `json:"runtime_id"`
	ArtifactRevision string `json:"artifact_revision"`
	Reason           string `json:"reason"`
}

type runtimeAssignmentClearRequest struct {
	RuntimeFamily string `json:"runtime_family"`
	RuntimeID     string `json:"runtime_id"`
}

type runtimeAssignmentRemovalRequest struct {
	RuntimeFamily string `json:"runtime_family"`
	RuntimeID     string `json:"runtime_id"`
	Reason        string `json:"reason"`
}

type runtimeArtifactImportRequest struct {
	ArtifactB64 string `json:"artifact_b64"`
}

type runtimeBuildStartRequest struct {
	RuntimeFamily string `json:"runtime_family"`
	RuntimeID     string `json:"runtime_id"`
	Assign        bool   `json:"assign"`
	Reason        string `json:"reason"`
}

type proxyRuleBundleBuildRequest struct {
	Raw                  string `json:"raw"`
	SourceConfigRevision string `json:"source_config_revision"`
	SourceProxyETag      string `json:"source_proxy_etag"`
	Assign               bool   `json:"assign"`
	Reason               string `json:"reason"`
}

type proxyRuleAssignmentRequest struct {
	BundleRevision string `json:"bundle_revision"`
	Reason         string `json:"reason"`
}

type wafRuleAssignmentRequest struct {
	BundleRevision string `json:"bundle_revision"`
	Reason         string `json:"reason"`
}

type proxyRuleValidateRequest struct {
	Raw string `json:"raw"`
}

func registerDeviceEnrollmentRoutes(r *gin.Engine) {
	r.POST("/v1/enroll", postDeviceEnrollment)
	r.POST("/v1/device-status", postDeviceStatus)
	r.POST("/v1/device-config-snapshot", postDeviceConfigSnapshot)
	r.POST("/v1/rule-artifact-bundle", postRuleArtifactBundle)
	r.POST("/v1/runtime-artifact-download", postRuntimeArtifactDownload)
	r.POST("/v1/proxy-rules-bundle-download", postProxyRulesBundleDownload)
	r.POST("/v1/waf-rule-artifact-download", postWAFRuleArtifactDownload)
}

func registerCenterDeviceAdminRoutes(api *gin.RouterGroup) {
	api.GET("/devices", getCenterDevices)
	api.POST("/devices/:device_id/revoke", postCenterDeviceRevoke)
	api.POST("/devices/:device_id/archive", postCenterDeviceArchive)
	api.GET("/devices/:device_id/config-snapshot", getCenterDeviceConfigSnapshot)
	api.GET("/devices/:device_id/config-snapshots", getCenterDeviceConfigSnapshots)
	api.GET("/devices/:device_id/config-snapshots/:revision", getCenterDeviceConfigSnapshotRevision)
	api.GET("/devices/:device_id/runtime-deployment", getCenterDeviceRuntimeDeployment)
	api.GET("/devices/:device_id/proxy-rules", getCenterDeviceProxyRules)
	api.POST("/devices/:device_id/proxy-rules/validate", postCenterDeviceProxyRulesValidate)
	api.POST("/devices/:device_id/proxy-rules/bundles", postCenterDeviceProxyRuleBundle)
	api.GET("/devices/:device_id/proxy-rules/bundles/:revision", getCenterDeviceProxyRuleBundle)
	api.POST("/devices/:device_id/proxy-rules/assignments", postCenterDeviceProxyRuleAssignment)
	api.POST("/devices/:device_id/proxy-rules/assignments/clear", postCenterDeviceProxyRuleAssignmentClear)
	api.GET("/devices/:device_id/waf-rules", getCenterDeviceWAFRules)
	api.GET("/devices/:device_id/waf-rules/bundles/:revision", getCenterDeviceWAFRuleBundle)
	api.GET("/devices/:device_id/waf-rules/bundles/:revision/download", getCenterDeviceWAFRuleBundleDownload)
	api.POST("/devices/:device_id/waf-rules/bundles/import", postCenterDeviceWAFRuleBundleImport)
	api.GET("/devices/:device_id/waf-rules/bundles/:revision/files", getCenterDeviceWAFRuleBundleFile)
	api.POST("/devices/:device_id/waf-rules/assignments", postCenterDeviceWAFRuleAssignment)
	api.POST("/devices/:device_id/waf-rules/assignments/clear", postCenterDeviceWAFRuleAssignmentClear)
	api.POST("/devices/:device_id/runtime-assignments", postCenterDeviceRuntimeAssignment)
	api.POST("/devices/:device_id/runtime-assignments/remove", postCenterDeviceRuntimeAssignmentRemoval)
	api.POST("/devices/:device_id/runtime-assignments/clear", postCenterDeviceRuntimeAssignmentClear)
	api.POST("/runtime-artifacts/import", postCenterRuntimeArtifactImport)
	api.GET("/runtime-builder/capabilities", getCenterRuntimeBuilderCapabilities)
	api.GET("/devices/:device_id/runtime-builds", getCenterDeviceRuntimeBuilds)
	api.POST("/devices/:device_id/runtime-builds", postCenterDeviceRuntimeBuild)
	api.GET("/runtime-builds/:job_id", getCenterRuntimeBuildJob)
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
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxDeviceStatusBodyBytes)
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
	runtimeAssignments := []RuntimeDeviceAssignment{}
	var proxyRuleAssignment *ProxyRuleDeviceAssignment
	var wafRuleAssignment *WAFRuleDeviceAssignment
	if record.FromApprovedDevice {
		if err := TouchApprovedDeviceHeartbeat(c.Request.Context(), verified.DeviceID, checkedAt, DeviceRuntimeInventory{
			RuntimeRole:                verified.RuntimeRole,
			BuildVersion:               verified.BuildVersion,
			GoVersion:                  verified.GoVersion,
			OS:                         verified.OS,
			Arch:                       verified.Arch,
			KernelVersion:              verified.KernelVersion,
			DistroID:                   verified.DistroID,
			DistroIDLike:               verified.DistroIDLike,
			DistroVersion:              verified.DistroVersion,
			RuntimeDeploymentSupported: verified.RuntimeDeploymentSupported,
			RuntimeInventory:           verified.RuntimeInventory,
			ProxyRuleApplyStatus:       verified.ProxyRuleApplyStatus,
			WAFRuleApplyStatus:         verified.WAFRuleApplyStatus,
		}); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update device last seen"})
			return
		}
		if record.Status == DeviceStatusApproved {
			assignment, err := PendingProxyRuleAssignmentForDevice(c.Request.Context(), verified.DeviceID, checkedAt)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load proxy rule assignment"})
				return
			}
			proxyRuleAssignment = assignment
		}
		if record.Status == DeviceStatusApproved {
			assignment, err := PendingWAFRuleAssignmentForDevice(c.Request.Context(), verified.DeviceID, checkedAt)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load WAF rule assignment"})
				return
			}
			wafRuleAssignment = assignment
		}
		if record.Status == DeviceStatusApproved && verified.RuntimeDeploymentSupported {
			assignments, err := PendingRuntimeAssignmentsForDevice(c.Request.Context(), verified.DeviceID, checkedAt)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load runtime assignments"})
				return
			}
			runtimeAssignments = assignments
		}
	}
	resp := gin.H{
		"status":          record.Status,
		"device_id":       verified.DeviceID,
		"key_id":          verified.KeyID,
		"product_id":      record.ProductID,
		"checked_at_unix": checkedAt,
	}
	if len(runtimeAssignments) > 0 {
		resp["runtime_assignments"] = runtimeAssignments
	}
	if proxyRuleAssignment != nil {
		resp["proxy_rule_assignment"] = proxyRuleAssignment
	}
	if wafRuleAssignment != nil {
		resp["waf_rule_assignment"] = wafRuleAssignment
	}
	c.JSON(http.StatusOK, resp)
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

func postRuleArtifactBundle(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxRuleArtifactBundleBodyBytes)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var req RuleArtifactBundleRequest
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule artifact bundle payload"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule artifact bundle payload"})
		return
	}
	normalizedReq, _, _, err := normalizeRuleArtifactBundleRequest(req, time.Now().UTC())
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
	verified, err := VerifyRuleArtifactBundleRequest(req, record.PublicKeyPEM, time.Now().UTC())
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	parsed, err := edgeartifactbundle.Parse(verified.BundleBytes)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	if err := validateParsedRuleArtifactUpload(verified, parsed); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	receivedAt := time.Now().UTC().Unix()
	stored, err := StoreRuleArtifactBundle(c.Request.Context(), RuleArtifactBundleInsert{
		DeviceID:         verified.DeviceID,
		BundleRevision:   parsed.Revision,
		BundleHash:       parsed.BundleHash,
		CompressedSize:   parsed.CompressedSize,
		UncompressedSize: parsed.UncompressedSize,
		FileCount:        parsed.FileCount,
		Files:            parsed.Files,
		ReceivedAtUnix:   receivedAt,
	})
	if err != nil {
		if errors.Is(err, ErrDeviceStatusNotFound) {
			c.JSON(http.StatusForbidden, gin.H{"error": "device is not approved"})
			return
		}
		if errors.Is(err, ErrInvalidEnrollment) {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "invalid rule artifact bundle payload"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store rule artifact bundle"})
		return
	}
	status := "stored"
	if !stored.Stored {
		status = "duplicate"
	}
	c.JSON(http.StatusOK, gin.H{
		"status":           status,
		"bundle_revision":  stored.BundleRevision,
		"bundle_hash":      stored.BundleHash,
		"file_count":       stored.FileCount,
		"received_at_unix": stored.CreatedAtUnix,
	})
}

func postRuntimeArtifactDownload(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxRuntimeArtifactDownloadBodyBytes)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var req RuntimeArtifactDownloadRequest
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid runtime artifact download payload"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid runtime artifact download payload"})
		return
	}
	normalizedReq, _, err := normalizeRuntimeArtifactDownloadRequest(req, time.Now().UTC())
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
	verified, err := VerifyRuntimeArtifactDownloadRequest(req, record.PublicKeyPEM, time.Now().UTC())
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	artifact, body, err := RuntimeArtifactDownloadForDevice(
		c.Request.Context(),
		verified.DeviceID,
		verified.RuntimeFamily,
		verified.RuntimeID,
		verified.ArtifactRevision,
		verified.ArtifactHash,
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrDeviceStatusNotFound), errors.Is(err, ErrRuntimeArtifactNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "runtime artifact not found"})
		case errors.Is(err, ErrRuntimeArtifactIncompatible):
			c.JSON(http.StatusForbidden, gin.H{"error": "runtime artifact is not assigned to this device"})
		case errors.Is(err, ErrRuntimeArtifactInvalid):
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "runtime artifact storage is invalid"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load runtime artifact"})
		}
		return
	}
	filename := artifact.RuntimeID + "-" + artifact.ArtifactRevision[:12] + ".tar.gz"
	c.Header("Content-Disposition", "attachment; filename=\""+filename+"\"")
	c.Header("Content-Length", strconv.FormatInt(int64(len(body)), 10))
	c.Header("X-Tukuyomi-Runtime-Family", artifact.RuntimeFamily)
	c.Header("X-Tukuyomi-Runtime-ID", artifact.RuntimeID)
	c.Header("X-Tukuyomi-Runtime-Artifact-Revision", artifact.ArtifactRevision)
	c.Header("X-Tukuyomi-Runtime-Artifact-Hash", artifact.ArtifactHash)
	c.Data(http.StatusOK, "application/gzip", body)
}

func postProxyRulesBundleDownload(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxProxyRulesBundleDownloadBodyBytes)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var req ProxyRulesBundleDownloadRequest
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid proxy rules bundle download payload"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid proxy rules bundle download payload"})
		return
	}
	normalizedReq, _, err := normalizeProxyRulesBundleDownloadRequest(req, time.Now().UTC())
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
	verified, err := VerifyProxyRulesBundleDownloadRequest(req, record.PublicKeyPEM, time.Now().UTC())
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	bundle, body, err := ProxyRuleBundleDownloadForDevice(c.Request.Context(), verified.DeviceID, verified.BundleRevision, verified.PayloadHash)
	if err != nil {
		switch {
		case errors.Is(err, ErrDeviceStatusNotFound), errors.Is(err, ErrProxyRuleBundleNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "proxy rules bundle not found"})
		case errors.Is(err, ErrProxyRuleInvalid):
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "invalid proxy rules bundle"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load proxy rules bundle"})
		}
		return
	}
	c.Header("Content-Disposition", "attachment; filename=\"proxy-rules-"+bundle.BundleRevision[:12]+".json\"")
	c.Header("Content-Length", strconv.FormatInt(int64(len(body)), 10))
	c.Header("X-Tukuyomi-Proxy-Rules-Bundle-Revision", bundle.BundleRevision)
	c.Header("X-Tukuyomi-Proxy-Rules-Payload-Hash", bundle.PayloadHash)
	c.Header("X-Tukuyomi-Proxy-Rules-Payload-ETag", bundle.PayloadETag)
	c.Header("X-Tukuyomi-Proxy-Rules-Source-ETag", bundle.SourceProxyETag)
	c.Data(http.StatusOK, "application/json", body)
}

func postWAFRuleArtifactDownload(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxWAFRuleArtifactDownloadBodyBytes)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var req WAFRuleArtifactDownloadRequest
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid WAF rule artifact download payload"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid WAF rule artifact download payload"})
		return
	}
	normalizedReq, _, err := normalizeWAFRuleArtifactDownloadRequest(req, time.Now().UTC())
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
	verified, err := VerifyWAFRuleArtifactDownloadRequest(req, record.PublicKeyPEM, time.Now().UTC())
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	bundle, body, err := WAFRuleArtifactDownloadForDevice(c.Request.Context(), verified.DeviceID, verified.BundleRevision)
	if err != nil {
		switch {
		case errors.Is(err, ErrDeviceStatusNotFound), errors.Is(err, ErrWAFRuleBundleNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "WAF rule artifact not found"})
		case errors.Is(err, ErrWAFRuleInvalid):
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "invalid WAF rule artifact"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load WAF rule artifact"})
		}
		return
	}
	filename := "waf-rules-" + bundle.BundleRevision[:12] + ".tar.gz"
	c.Header("Content-Disposition", "attachment; filename=\""+filename+"\"")
	c.Header("Content-Length", strconv.FormatInt(int64(len(body)), 10))
	c.Header("X-Tukuyomi-WAF-Rule-Bundle-Revision", bundle.BundleRevision)
	c.Data(http.StatusOK, "application/gzip", body)
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

func getCenterDeviceConfigSnapshots(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	limit := parseBoundedInt(c.Query("limit"), 6, 1, 6)
	offset := parseBoundedInt(c.Query("offset"), 0, 0, 1000000)
	result, err := ListDeviceConfigSnapshots(c.Request.Context(), deviceID, limit, offset)
	if err != nil {
		if errors.Is(err, ErrDeviceStatusNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list config snapshots"})
		return
	}
	c.JSON(http.StatusOK, result)
}

func getCenterDeviceConfigSnapshotRevision(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	revision, ok := parseConfigRevisionParam(c)
	if !ok {
		return
	}
	snapshot, err := LoadDeviceConfigSnapshot(c.Request.Context(), deviceID, revision)
	if err != nil {
		if errors.Is(err, ErrDeviceStatusNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "config snapshot not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load config snapshot"})
		return
	}
	if parseBoolQuery(c.Query("download")) {
		name := safeConfigSnapshotFilename(snapshot.DeviceID, snapshot.Revision)
		c.Header("Content-Disposition", `attachment; filename="`+name+`"`)
	}
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

func getCenterDeviceRuntimeDeployment(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	view, err := RuntimeDeploymentForDevice(c.Request.Context(), deviceID)
	if err != nil {
		if errors.Is(err, ErrDeviceStatusNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load runtime deployment"})
		return
	}
	c.JSON(http.StatusOK, view)
}

func getCenterDeviceProxyRules(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	view, err := ProxyRulesDeploymentForDevice(c.Request.Context(), deviceID)
	if err != nil {
		respondProxyRuleError(c, err)
		return
	}
	c.JSON(http.StatusOK, view)
}

func postCenterDeviceProxyRulesValidate(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxProxyRulePayloadBytes+8*1024)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var req proxyRuleValidateRequest
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid proxy rules payload"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid proxy rules payload"})
		return
	}
	_ = deviceID
	raw, etag, proxy, err := handler.NormalizeProxyRulesRawStandalone(req.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":       true,
		"messages": []string{},
		"raw":      raw,
		"etag":     etag,
		"proxy":    proxy,
	})
}

func postCenterDeviceProxyRuleBundle(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxProxyRulePayloadBytes+16*1024)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var req proxyRuleBundleBuildRequest
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid proxy rules bundle payload"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid proxy rules bundle payload"})
		return
	}
	bundle, err := BuildProxyRuleBundleForDevice(c.Request.Context(), ProxyRuleBundleBuild{
		DeviceID:             deviceID,
		Raw:                  req.Raw,
		SourceConfigRevision: req.SourceConfigRevision,
		SourceProxyETag:      req.SourceProxyETag,
		CreatedBy:            centerAdminActor(c),
	})
	if err != nil {
		respondProxyRuleError(c, err)
		return
	}
	resp := gin.H{"bundle": bundle}
	if req.Assign {
		assignment, err := AssignProxyRuleBundleToDevice(c.Request.Context(), ProxyRuleAssignmentUpdate{
			DeviceID:       deviceID,
			BundleRevision: bundle.BundleRevision,
			Reason:         req.Reason,
			AssignedBy:     centerAdminActor(c),
		})
		if err != nil {
			respondProxyRuleError(c, err)
			return
		}
		resp["assignment"] = assignment
	}
	c.JSON(http.StatusCreated, resp)
}

func getCenterDeviceProxyRuleBundle(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	revision, ok := parseConfigRevisionParam(c)
	if !ok {
		return
	}
	bundle, err := LoadProxyRuleBundleForDevice(c.Request.Context(), deviceID, revision)
	if err != nil {
		respondProxyRuleError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"bundle": bundle,
		"raw":    string(bundle.PayloadJSON),
	})
}

func postCenterDeviceProxyRuleAssignment(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8*1024)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var req proxyRuleAssignmentRequest
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid proxy rule assignment payload"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid proxy rule assignment payload"})
		return
	}
	assignment, err := AssignProxyRuleBundleToDevice(c.Request.Context(), ProxyRuleAssignmentUpdate{
		DeviceID:       deviceID,
		BundleRevision: req.BundleRevision,
		Reason:         req.Reason,
		AssignedBy:     centerAdminActor(c),
	})
	if err != nil {
		respondProxyRuleError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"assignment": assignment})
}

func postCenterDeviceProxyRuleAssignmentClear(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	cleared, err := ClearProxyRuleAssignment(c.Request.Context(), deviceID)
	if err != nil {
		respondProxyRuleError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"cleared": cleared})
}

func getCenterDeviceWAFRules(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	view, err := WAFRulesDeploymentForDevice(c.Request.Context(), deviceID)
	if err != nil {
		respondWAFRuleError(c, err)
		return
	}
	c.JSON(http.StatusOK, view)
}

func getCenterDeviceWAFRuleBundle(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	revision, ok := parseConfigRevisionParam(c)
	if !ok {
		return
	}
	bundle, err := LoadWAFRuleBundleForDevice(c.Request.Context(), deviceID, revision)
	if err != nil {
		respondWAFRuleError(c, err)
		return
	}
	c.JSON(http.StatusOK, bundle)
}

func getCenterDeviceWAFRuleBundleDownload(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	revision, ok := parseConfigRevisionParam(c)
	if !ok {
		return
	}
	bundle, body, err := DownloadWAFRuleBundleForDevice(c.Request.Context(), deviceID, revision)
	if err != nil {
		respondWAFRuleError(c, err)
		return
	}
	filename := safeWAFRuleBundleFilename(deviceID, bundle.BundleRevision)
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Header("X-Tukuyomi-WAF-Rule-Bundle-Revision", bundle.BundleRevision)
	c.Header("X-Tukuyomi-WAF-Rule-Bundle-Hash", bundle.BundleHash)
	c.Data(http.StatusOK, "application/zip", body)
}

func postCenterDeviceWAFRuleBundleImport(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxRuleArtifactBundleBodyBytes)
	if err := c.Request.ParseMultipartForm(MaxRuleArtifactBundleBodyBytes); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid WAF rule bundle upload"})
		return
	}
	file, _, err := c.Request.FormFile("bundle")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bundle file is required"})
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, MaxRuleArtifactBundleBodyBytes+1))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read WAF rule bundle upload"})
		return
	}
	if len(raw) == 0 || len(raw) > MaxRuleArtifactBundleBodyBytes {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid WAF rule bundle upload size"})
		return
	}
	assign := parseBoolQuery(c.PostForm("assign"))
	reason := strings.TrimSpace(c.PostForm("reason"))
	if reason == "" {
		reason = "center WAF rule bundle upload"
	}
	result, err := ImportWAFRuleBundleForDevice(c.Request.Context(), WAFRuleBundleImport{
		DeviceID: deviceID,
		Archive:  raw,
		Assign:   assign,
		Reason:   reason,
		Actor:    centerAdminActor(c),
	})
	if err != nil {
		respondWAFRuleError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

func getCenterDeviceWAFRuleBundleFile(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	revision, ok := parseConfigRevisionParam(c)
	if !ok {
		return
	}
	assetPath := strings.TrimSpace(c.Query("path"))
	if assetPath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "path is required"})
		return
	}
	file, err := LoadWAFRuleBundleFileForDevice(c.Request.Context(), deviceID, revision, assetPath)
	if err != nil {
		respondWAFRuleError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"file": file,
		"raw":  string(file.Body),
	})
}

func postCenterDeviceWAFRuleAssignment(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8*1024)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var req wafRuleAssignmentRequest
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid WAF rule assignment payload"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid WAF rule assignment payload"})
		return
	}
	assignment, err := AssignWAFRuleBundleToDevice(c.Request.Context(), WAFRuleAssignmentUpdate{
		DeviceID:       deviceID,
		BundleRevision: req.BundleRevision,
		Reason:         req.Reason,
		AssignedBy:     centerAdminActor(c),
	})
	if err != nil {
		respondWAFRuleError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"assignment": assignment})
}

func postCenterDeviceWAFRuleAssignmentClear(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	cleared, err := ClearWAFRuleAssignment(c.Request.Context(), deviceID)
	if err != nil {
		respondWAFRuleError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"cleared": cleared})
}

func postCenterDeviceRuntimeAssignment(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8*1024)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var req runtimeAssignmentRequest
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid runtime assignment payload"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid runtime assignment payload"})
		return
	}
	record, err := AssignRuntimeArtifactToDevice(c.Request.Context(), RuntimeAssignmentUpdate{
		DeviceID:         deviceID,
		RuntimeFamily:    req.RuntimeFamily,
		RuntimeID:        req.RuntimeID,
		ArtifactRevision: req.ArtifactRevision,
		Reason:           req.Reason,
		AssignedBy:       centerAdminActor(c),
	})
	if err != nil {
		respondRuntimeAssignmentError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"assignment": record})
}

func postCenterDeviceRuntimeAssignmentClear(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8*1024)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var req runtimeAssignmentClearRequest
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid runtime assignment payload"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid runtime assignment payload"})
		return
	}
	cleared, err := ClearRuntimeAssignment(c.Request.Context(), deviceID, req.RuntimeFamily, req.RuntimeID)
	if err != nil {
		respondRuntimeAssignmentError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"cleared": cleared})
}

func postCenterDeviceRuntimeAssignmentRemoval(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8*1024)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var req runtimeAssignmentRemovalRequest
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid runtime assignment payload"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid runtime assignment payload"})
		return
	}
	record, err := RequestRuntimeRemovalForDevice(c.Request.Context(), RuntimeAssignmentUpdate{
		DeviceID:      deviceID,
		RuntimeFamily: req.RuntimeFamily,
		RuntimeID:     req.RuntimeID,
		Reason:        req.Reason,
		AssignedBy:    centerAdminActor(c),
	})
	if err != nil {
		respondRuntimeAssignmentError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"assignment": record})
}

func postCenterRuntimeArtifactImport(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxRuntimeArtifactImportBodyBytes)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var req runtimeArtifactImportRequest
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid runtime artifact import payload"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid runtime artifact import payload"})
		return
	}
	compressed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.ArtifactB64))
	if err != nil || len(compressed) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid runtime artifact import payload"})
		return
	}
	record, err := StoreRuntimeArtifactBundle(c.Request.Context(), compressed, centerAdminActor(c))
	if err != nil {
		if errors.Is(err, ErrRuntimeArtifactInvalid) {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to import runtime artifact"})
		return
	}
	status := "stored"
	code := http.StatusCreated
	if !record.Stored {
		status = "duplicate"
		code = http.StatusOK
	}
	c.JSON(code, gin.H{
		"status":   status,
		"artifact": record,
	})
}

func getCenterRuntimeBuilderCapabilities(c *gin.Context) {
	c.JSON(http.StatusOK, RuntimeBuilderCapabilityStatus(c.Request.Context()))
}

func getCenterDeviceRuntimeBuilds(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	limit := parseBoundedInt(c.Query("limit"), 20, 1, 100)
	jobs, err := RuntimeBuildJobsForDevice(deviceID, limit)
	if err != nil {
		respondRuntimeBuildError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"jobs": jobs})
}

func postCenterDeviceRuntimeBuild(c *gin.Context) {
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8*1024)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var req runtimeBuildStartRequest
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid runtime build payload"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid runtime build payload"})
		return
	}
	job, err := StartRuntimeBuild(c.Request.Context(), RuntimeBuildStart{
		DeviceID:      deviceID,
		RuntimeFamily: req.RuntimeFamily,
		RuntimeID:     req.RuntimeID,
		Assign:        req.Assign,
		Reason:        req.Reason,
		Actor:         centerAdminActor(c),
	})
	if err != nil {
		respondRuntimeBuildError(c, err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"job": job})
}

func getCenterRuntimeBuildJob(c *gin.Context) {
	jobID := strings.TrimSpace(c.Param("job_id"))
	if len(jobID) < 5 || len(jobID) > 64 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid job_id"})
		return
	}
	job, found := RuntimeBuildJobStatus(jobID)
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "runtime build job not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"job": job})
}

func respondRuntimeAssignmentError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrDeviceStatusNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
	case errors.Is(err, ErrRuntimeArtifactNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "runtime artifact not found"})
	case errors.Is(err, ErrRuntimeArtifactInvalid):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid runtime assignment payload"})
	case errors.Is(err, ErrRuntimeAssignmentDispatched):
		c.JSON(http.StatusConflict, gin.H{"error": "runtime assignment has already been dispatched"})
	case errors.Is(err, ErrRuntimeArtifactIncompatible):
		c.JSON(http.StatusConflict, gin.H{"error": "runtime artifact is incompatible with device"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update runtime assignment"})
	}
}

func respondProxyRuleError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrDeviceStatusNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
	case errors.Is(err, ErrProxyRuleBundleNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "proxy rules bundle not found"})
	case errors.Is(err, ErrProxyRuleAssignmentDispatched):
		c.JSON(http.StatusConflict, gin.H{"error": "proxy rules assignment has already been dispatched"})
	case errors.Is(err, ErrProxyRuleInvalid):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid proxy rules payload"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update proxy rules"})
	}
}

func respondWAFRuleError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrDeviceStatusNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
	case errors.Is(err, ErrWAFRuleBundleNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "WAF rule bundle not found"})
	case errors.Is(err, ErrWAFRuleAssignmentDispatched):
		c.JSON(http.StatusConflict, gin.H{"error": "WAF rule assignment has already been dispatched"})
	case errors.Is(err, ErrWAFRuleInvalid):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid WAF rule payload"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update WAF rules"})
	}
}

func respondRuntimeBuildError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrDeviceStatusNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
	case errors.Is(err, ErrRuntimeBuildInProgress):
		c.JSON(http.StatusConflict, gin.H{"error": "runtime build is already running"})
	case errors.Is(err, ErrRuntimeBuilderUnavailable):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, ErrRuntimeArtifactInvalid):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid runtime build payload"})
	case errors.Is(err, ErrRuntimeArtifactIncompatible):
		c.JSON(http.StatusConflict, gin.H{"error": "runtime build is incompatible with this device"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start runtime build"})
	}
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

func parseConfigRevisionParam(c *gin.Context) (string, bool) {
	revision := strings.ToLower(strings.TrimSpace(c.Param("revision")))
	if !hex64Pattern.MatchString(revision) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid revision"})
		return "", false
	}
	return revision, true
}

func safeConfigSnapshotFilename(deviceID string, revision string) string {
	return safeDeviceFilenamePrefix(deviceID) + "-config-" + safeRevisionFilenamePart(revision, "snapshot") + ".json"
}

func safeWAFRuleBundleFilename(deviceID string, revision string) string {
	return safeDeviceFilenamePrefix(deviceID) + "-waf-rules-" + safeRevisionFilenamePart(revision, "bundle") + ".zip"
}

func safeDeviceFilenamePrefix(deviceID string) string {
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
	return b.String()
}

func safeRevisionFilenamePart(revision string, fallback string) string {
	revision = strings.ToLower(strings.TrimSpace(revision))
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if revision == "" {
		revision = fallback
	}
	return revision
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
