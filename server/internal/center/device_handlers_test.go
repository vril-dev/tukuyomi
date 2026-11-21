package center

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestDeviceUploadRoutesLimitConcurrentBodyReads(t *testing.T) {
	gin.SetMode(gin.TestMode)
	prevAppDeploy := centerExperimentalAppDeployDeviceAPI.Load()
	defer centerExperimentalAppDeployDeviceAPI.Store(prevAppDeploy)

	arrivals := make(chan struct{}, 16)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if c.GetHeader("X-Test-Held-Upload") != "" {
			arrivals <- struct{}{}
		}
		c.Next()
	})
	registerDeviceEnrollmentRoutes(r, RuntimeConfig{ExperimentalAppDeployEnabled: true})
	server := httptest.NewServer(r)
	defer server.Close()

	snapshotURL := server.URL + "/v1/device-config-snapshot"
	ruleArtifactURL := server.URL + "/v1/rule-artifact-bundle"
	daemonLogURL := server.URL + "/v1/daemon-log-archive-upload"
	baselineURL := server.URL + "/v1/app-deploy-baseline-upload"

	t.Run("config snapshot and rule artifact share a limit", func(t *testing.T) {
		release := holdDeviceUploadSlotsForTest(t, snapshotURL, MaxConcurrentDeviceUploadBodies, arrivals)
		defer release()
		expectDeviceUploadBusyForTest(t, ruleArtifactURL, "device_upload")
		release()
		expectDeviceUploadHandledForTest(t, ruleArtifactURL)
	})

	t.Run("daemon log uploads have their own limit", func(t *testing.T) {
		release := holdDeviceUploadSlotsForTest(t, daemonLogURL, MaxConcurrentDaemonLogArchiveUploadBodies, arrivals)
		defer release()
		expectDeviceUploadBusyForTest(t, daemonLogURL, "daemon_log_upload")
		expectDeviceUploadHandledForTest(t, baselineURL)
		release()
		expectDeviceUploadHandledForTest(t, daemonLogURL)
	})

	t.Run("baseline uploads wait for the slot", func(t *testing.T) {
		release := holdDeviceUploadSlotsForTest(t, baselineURL, MaxConcurrentAppDeployBaselineUploadBodies, arrivals)
		defer release()
		done := make(chan int, 1)
		go func() {
			res, err := http.Post(baselineURL, "application/json", strings.NewReader("{}"))
			if err != nil {
				done <- 0
				return
			}
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
			done <- res.StatusCode
		}()
		select {
		case status := <-done:
			t.Fatalf("queued baseline upload finished with %d while the slot was held", status)
		case <-time.After(300 * time.Millisecond):
		}
		release()
		select {
		case status := <-done:
			if status != http.StatusUnprocessableEntity {
				t.Fatalf("queued baseline upload status=%d want the handler to reject the empty request", status)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("queued baseline upload did not run after the slot was released")
		}
	})
}

func expectDeviceUploadBusyForTest(t *testing.T, url string, scope string) {
	t.Helper()
	res := waitForDeviceUploadStatusForTest(t, url, func(status int) bool { return status == http.StatusServiceUnavailable })
	if got := res.Header.Get("Retry-After"); got == "" {
		t.Fatal("busy response has no Retry-After")
	}
	if got := res.Header.Get("X-Tukuyomi-Overload-Scope"); got != scope {
		t.Fatalf("overload scope=%q want %q", got, scope)
	}
}

func expectDeviceUploadHandledForTest(t *testing.T, url string) {
	t.Helper()
	res := waitForDeviceUploadStatusForTest(t, url, func(status int) bool { return status != http.StatusServiceUnavailable })
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("POST %s status=%d want the handler to reject the empty request", url, res.StatusCode)
	}
}

// holdDeviceUploadSlotsForTest keeps n uploads open on url with bodies that
// never finish, and returns once the server has received all of them. Other
// requests must not start before that: a rejected upload whose body never
// finishes gets its 503 only when the body is closed.
func holdDeviceUploadSlotsForTest(t *testing.T, url string, n int, arrivals <-chan struct{}) func() {
	t.Helper()
	writers := make([]*io.PipeWriter, 0, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		pr, pw := io.Pipe()
		writers = append(writers, pw)
		req, err := http.NewRequest(http.MethodPost, url, pr)
		if err != nil {
			t.Fatalf("new held upload: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-Held-Upload", "1")
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := http.DefaultClient.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
			}
		}()
		select {
		case <-arrivals:
		case <-time.After(5 * time.Second):
			t.Fatal("held upload did not reach the server")
		}
	}
	// The limit is taken right after the arrival middleware returns.
	time.Sleep(100 * time.Millisecond)
	released := false
	return func() {
		if released {
			return
		}
		released = true
		for _, pw := range writers {
			_ = pw.Close()
		}
		wg.Wait()
	}
}

func waitForDeviceUploadStatusForTest(t *testing.T, url string, done func(int) bool) *http.Response {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		res, err := http.Post(url, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("POST %s: %v", url, err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		if done(res.StatusCode) {
			return res
		}
		if time.Now().After(deadline) {
			t.Fatalf("POST %s status=%d did not reach the expected state", url, res.StatusCode)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
