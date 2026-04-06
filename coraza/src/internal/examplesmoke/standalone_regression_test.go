package examplesmoke

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

func TestStandaloneRegressionScriptRunsDirectChecks(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("bash-based smoke script is not supported on windows")
	}

	repoRoot := t.TempDir()
	scriptPath := filepath.Join(repoRoot, "scripts", "run_standalone_regression.sh")
	writeRepoScript(t, filepath.Join(exampleRepoRoot(t), "scripts", "run_standalone_regression.sh"), scriptPath)

	exampleName := "fakeapp"
	exampleDir := filepath.Join(repoRoot, "examples", exampleName)
	logPath := filepath.Join(repoRoot, "docker.log")
	smokeLog := filepath.Join(repoRoot, "smoke.log")
	if err := os.MkdirAll(exampleDir, 0o755); err != nil {
		t.Fatalf("mkdir example dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(exampleDir, ".env"), []byte(strings.Join([]string{
		"CORAZA_PORT=19093",
		"WAF_API_BASEPATH=/tukuyomi-api",
		"VITE_APP_BASE_PATH=/tukuyomi-admin",
		"WAF_API_KEY_PRIMARY=test-api-key-123456",
	}, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	writeExecutable(t, filepath.Join(exampleDir, "setup.sh"), "#!/usr/bin/env bash\nset -euo pipefail\n:\n")
	writeExecutable(t, filepath.Join(exampleDir, "smoke.sh"), "#!/usr/bin/env bash\nset -euo pipefail\nprintf 'base=%s host=%s\\n' \"${BASE_URL}\" \"${PROTECTED_HOST}\" >> \"$SMOKE_LOG\"\n")
	writeExecutable(t, filepath.Join(repoRoot, "bin", "docker"), "#!/usr/bin/env bash\nset -euo pipefail\nprintf 'cwd=%s args=%s\\n' \"$PWD\" \"$*\" >> \"$DOCKER_LOG\"\n")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			w.WriteHeader(http.StatusOK)
		case "/tukuyomi-admin/":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>ok</html>"))
		case "/tukuyomi-api/status":
			if got := r.Header.Get("X-API-Key"); got != "test-api-key-123456" {
				http.Error(w, "bad api key", http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/tukuyomi-api/logs/read":
			if got := r.Header.Get("X-API-Key"); got != "test-api-key-123456" {
				http.Error(w, "bad api key", http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"lines":[{"event":"waf_hit_allow","status":200}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cmd := exec.Command("bash", scriptPath, exampleName)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("PATH=%s%c%s", filepath.Join(repoRoot, "bin"), os.PathListSeparator, os.Getenv("PATH")),
		fmt.Sprintf("DOCKER_LOG=%s", logPath),
		fmt.Sprintf("SMOKE_LOG=%s", smokeLog),
		"STANDALONE_SKIP_SETUP=1",
		fmt.Sprintf("STANDALONE_BASE_URL=%s", server.URL),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("standalone regression failed: %v output=%s", err, strings.TrimSpace(string(out)))
	}

	assertFileContains(t, logPath, fmt.Sprintf("cwd=%s args=compose up -d --build\n", exampleDir))
	assertFileContains(t, logPath, fmt.Sprintf("cwd=%s args=compose down --remove-orphans\n", exampleDir))
	assertFileContains(t, smokeLog, fmt.Sprintf("base=%s host=protected.example.test\n", server.URL))
	if !strings.Contains(string(out), "[standalone-regression] OK") {
		t.Fatalf("unexpected output: %s", strings.TrimSpace(string(out)))
	}
}

func TestStandaloneRegressionScriptRunsExtendedAPIGatewayRateLimitCheck(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("bash-based smoke script is not supported on windows")
	}

	repoRoot := t.TempDir()
	scriptPath := filepath.Join(repoRoot, "scripts", "run_standalone_regression.sh")
	writeRepoScript(t, filepath.Join(exampleRepoRoot(t), "scripts", "run_standalone_regression.sh"), scriptPath)

	exampleName := "api-gateway"
	exampleDir := filepath.Join(repoRoot, "examples", exampleName)
	logPath := filepath.Join(repoRoot, "docker.log")
	if err := os.MkdirAll(exampleDir, 0o755); err != nil {
		t.Fatalf("mkdir example dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(exampleDir, ".env"), []byte(strings.Join([]string{
		"CORAZA_PORT=19093",
		"WAF_API_BASEPATH=/tukuyomi-api",
		"VITE_APP_BASE_PATH=/tukuyomi-admin",
		"WAF_API_KEY_PRIMARY=test-api-key-123456",
	}, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	writeExecutable(t, filepath.Join(exampleDir, "setup.sh"), "#!/usr/bin/env bash\nset -euo pipefail\n:\n")
	writeExecutable(t, filepath.Join(exampleDir, "smoke.sh"), "#!/usr/bin/env bash\nset -euo pipefail\n:\n")
	writeExecutable(t, filepath.Join(repoRoot, "bin", "docker"), "#!/usr/bin/env bash\nset -euo pipefail\nprintf 'cwd=%s args=%s\\n' \"$PWD\" \"$*\" >> \"$DOCKER_LOG\"\n")

	var loginCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz", "/tukuyomi-admin/":
			w.WriteHeader(http.StatusOK)
		case "/tukuyomi-api/status":
			if got := r.Header.Get("X-API-Key"); got != "test-api-key-123456" {
				http.Error(w, "bad api key", http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)
		case "/tukuyomi-api/logs/read":
			if got := r.Header.Get("X-API-Key"); got != "test-api-key-123456" {
				http.Error(w, "bad api key", http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"lines":[{"event":"waf_block","status":403}]}`))
		case "/v1/auth/login":
			if r.Host != "protected.example.test" {
				http.Error(w, "bad host", http.StatusBadRequest)
				return
			}
			if atomic.AddInt32(&loginCount, 1) >= 4 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cmd := exec.Command("bash", scriptPath, exampleName, "extended")
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("PATH=%s%c%s", filepath.Join(repoRoot, "bin"), os.PathListSeparator, os.Getenv("PATH")),
		fmt.Sprintf("DOCKER_LOG=%s", logPath),
		"STANDALONE_SKIP_SETUP=1",
		fmt.Sprintf("STANDALONE_BASE_URL=%s", server.URL),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("standalone extended regression failed: %v output=%s", err, strings.TrimSpace(string(out)))
	}

	if got := atomic.LoadInt32(&loginCount); got < 4 {
		t.Fatalf("expected rate-limit check to hit login multiple times, got %d", got)
	}
	assertFileContains(t, logPath, fmt.Sprintf("cwd=%s args=compose down --remove-orphans\n", exampleDir))
	if !strings.Contains(string(out), "api-gateway rate-limit check") {
		t.Fatalf("unexpected output: %s", strings.TrimSpace(string(out)))
	}
}
