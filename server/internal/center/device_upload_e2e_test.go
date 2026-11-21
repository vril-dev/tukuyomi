package center

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
)

// TestGatewayConfigSnapshotUploadIsHeaderSignedOnCenter runs the Gateway
// enrollment, approval and status refresh against this Center in one process
// and checks that the configuration snapshot upload is accepted through the
// signed upload headers, not as an upload from an older Gateway.
func TestGatewayConfigSnapshotUploadIsHeaderSignedOnCenter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restore := configureCenterAuthTest(t)
	defer restore()
	if err := handler.InitLogsStatsStoreWithBackend("db", "sqlite", config.DBPath, "", 32); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer handler.InitLogsStatsStore(false, "", 0)

	oldEdgeEnabled := config.EdgeEnabled
	oldDeviceAuthEnabled := config.EdgeDeviceAuthEnabled
	oldRequireApproval := config.EdgeRequireDeviceApproval
	config.EdgeEnabled = true
	config.EdgeDeviceAuthEnabled = true
	config.EdgeRequireDeviceApproval = true
	defer func() {
		config.EdgeEnabled = oldEdgeEnabled
		config.EdgeDeviceAuthEnabled = oldDeviceAuthEnabled
		config.EdgeRequireDeviceApproval = oldRequireApproval
	}()

	logs := &lockedLogBufferForTest{}
	oldLogOutput := log.Writer()
	log.SetOutput(logs)
	defer log.SetOutput(oldLogOutput)

	var signedSnapshotUploads atomic.Int32
	centerRouter := gin.New()
	centerRouter.Use(func(c *gin.Context) {
		if c.Request.URL.Path == "/v1/device-config-snapshot" && c.GetHeader("X-Tukuyomi-Signature") != "" {
			signedSnapshotUploads.Add(1)
		}
		c.Next()
	})
	registerDeviceEnrollmentRoutes(centerRouter, RuntimeConfig{RequireSignedDeviceUploadHeaders: true})
	center := httptest.NewServer(centerRouter)
	defer center.Close()

	_, token, err := CreateEnrollmentToken(context.Background(), EnrollmentTokenCreate{Label: "e2e", MaxUses: 1, CreatedBy: "test"})
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}

	gateway := gin.New()
	gateway.POST("/edge/device-auth/enroll", handler.PostEdgeDeviceEnrollment)
	gateway.POST("/edge/device-auth/refresh", handler.PostEdgeDeviceStatusRefresh)

	enrollBody := `{"center_url":"` + center.URL + `","enrollment_token":"` + token + `","device_id":"e2e-gateway","key_id":"default"}`
	rec := serveGatewayForTest(gateway, "/edge/device-auth/enroll", enrollBody)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("enroll status=%d body=%s", rec.Code, rec.Body.String())
	}
	pending, err := ListEnrollments(context.Background(), "pending", 10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending enrollments=%+v err=%v", pending, err)
	}
	if _, err := ApproveEnrollment(context.Background(), pending[0].EnrollmentID, "test"); err != nil {
		t.Fatalf("ApproveEnrollment: %v", err)
	}

	rec = serveGatewayForTest(gateway, "/edge/device-auth/refresh", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh status=%d body=%s", rec.Code, rec.Body.String())
	}
	var status struct {
		EnrollmentStatus       string `json:"enrollment_status"`
		ConfigSnapshotRevision string `json:"config_snapshot_revision"`
		ConfigSnapshotError    string `json:"config_snapshot_error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode refresh: %v body=%s", err, rec.Body.String())
	}
	if status.EnrollmentStatus != "approved" || status.ConfigSnapshotRevision == "" || status.ConfigSnapshotError != "" {
		t.Fatalf("refresh status=%+v want approved with an uploaded snapshot", status)
	}
	if got := signedSnapshotUploads.Load(); got == 0 {
		t.Fatal("Gateway did not sign the snapshot upload in headers")
	}
	stored, err := LoadLatestDeviceConfigSnapshot(context.Background(), "e2e-gateway")
	if err != nil || stored.Revision != status.ConfigSnapshotRevision {
		t.Fatalf("stored snapshot=%+v err=%v want revision %s", stored, err, status.ConfigSnapshotRevision)
	}
	if strings.Contains(logs.String(), "[CENTER][DEVICE_UPLOAD][WARN]") {
		t.Fatalf("Center logged an unsigned upload warning: %s", logs.String())
	}
}

func serveGatewayForTest(router http.Handler, path string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

type lockedLogBufferForTest struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedLogBufferForTest) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, _ = os.Stderr.Write(p)
	return b.buf.Write(p)
}

func (b *lockedLogBufferForTest) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
