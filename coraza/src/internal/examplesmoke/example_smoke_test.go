package examplesmoke

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type smokeExample struct {
	name       string
	scriptPath string
	readyPath  string
	whoamiPath string
	blockPath  string
}

type smokeRunOptions struct {
	responseHost string
	blockStatus  int
}

type smokeServerState struct {
	mu         sync.Mutex
	seenHosts  []string
	unexpected []string
}

func TestProtectedHostSmokeScriptsSucceed(t *testing.T) {
	t.Parallel()

	for _, example := range protectedHostExamples() {
		example := example
		t.Run(example.name, func(t *testing.T) {
			t.Parallel()

			output, state, err := runProtectedHostSmokeScript(t, example, smokeRunOptions{
				blockStatus: http.StatusForbidden,
			})
			if err != nil {
				t.Fatalf("smoke script failed: %v output=%s", err, strings.TrimSpace(output))
			}
			assertSmokeServerState(t, state, "protected.example.test")
		})
	}
}

func TestProtectedHostSmokeScriptsFailOnHostMismatch(t *testing.T) {
	t.Parallel()

	for _, example := range protectedHostExamples() {
		example := example
		t.Run(example.name, func(t *testing.T) {
			t.Parallel()

			output, state, err := runProtectedHostSmokeScript(t, example, smokeRunOptions{
				responseHost: "wrong.example.test",
				blockStatus:  http.StatusForbidden,
			})
			if err == nil {
				t.Fatalf("expected host mismatch failure, got success output=%s", strings.TrimSpace(output))
			}
			assertSmokeServerState(t, state, "protected.example.test")
			if !strings.Contains(output, "expected host='protected.example.test'") &&
				!strings.Contains(output, `expected host="protected.example.test"`) {
				t.Fatalf("unexpected mismatch output: %s", strings.TrimSpace(output))
			}
		})
	}
}

func TestProtectedHostSmokeScriptsFailWhenWAFDoesNotBlock(t *testing.T) {
	t.Parallel()

	for _, example := range protectedHostExamples() {
		example := example
		t.Run(example.name, func(t *testing.T) {
			t.Parallel()

			output, state, err := runProtectedHostSmokeScript(t, example, smokeRunOptions{
				blockStatus: http.StatusOK,
			})
			if err == nil {
				t.Fatalf("expected WAF block failure, got success output=%s", strings.TrimSpace(output))
			}
			assertSmokeServerState(t, state, "protected.example.test")
			if !strings.Contains(output, "expected WAF block for protected host") {
				t.Fatalf("unexpected WAF output: %s", strings.TrimSpace(output))
			}
		})
	}
}

func TestCIExampleSmokeScriptRunsExampleFlow(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("bash-based smoke script is not supported on windows")
	}

	repoRoot := t.TempDir()
	scriptPath := filepath.Join(repoRoot, "scripts", "ci_example_smoke.sh")
	writeRepoScript(t, filepath.Join(exampleRepoRoot(t), "scripts", "ci_example_smoke.sh"), scriptPath)

	exampleName := "fakeapp"
	exampleDir := filepath.Join(repoRoot, "examples", exampleName)
	logPath := filepath.Join(repoRoot, "docker.log")
	writeExecutable(t, filepath.Join(exampleDir, "setup.sh"), "#!/usr/bin/env bash\nset -euo pipefail\nprintf 'setup\\n' >> \"$EXAMPLE_LOG\"\n")
	writeExecutable(t, filepath.Join(exampleDir, "smoke.sh"), "#!/usr/bin/env bash\nset -euo pipefail\nprintf 'smoke:%s\\n' \"${COMPOSE_PROJECT_NAME}\" >> \"$EXAMPLE_LOG\"\n")
	writeExecutable(t, filepath.Join(repoRoot, "bin", "docker"), "#!/usr/bin/env bash\nset -euo pipefail\nprintf 'project=%s uid=%s gid=%s args=%s\\n' \"${COMPOSE_PROJECT_NAME:-}\" \"${PUID:-}\" \"${GUID:-}\" \"$*\" >> \"$DOCKER_LOG\"\n")

	cmd := exec.Command("bash", scriptPath, exampleName)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("PATH=%s%c%s", filepath.Join(repoRoot, "bin"), os.PathListSeparator, os.Getenv("PATH")),
		fmt.Sprintf("DOCKER_LOG=%s", logPath),
		fmt.Sprintf("EXAMPLE_LOG=%s", filepath.Join(repoRoot, "example.log")),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ci example smoke script failed: %v output=%s", err, strings.TrimSpace(string(out)))
	}

	assertFileContains(t, filepath.Join(repoRoot, "example.log"), "setup\n")
	assertFileContains(t, filepath.Join(repoRoot, "example.log"), "smoke:tukuyomi-fakeapp-smoke\n")
	assertFileContains(t, logPath, fmt.Sprintf("project=tukuyomi-fakeapp-smoke uid=%d gid=%d args=compose --profile front-proxy up -d --build\n", os.Getuid(), os.Getgid()))
	assertFileContains(t, logPath, fmt.Sprintf("project=tukuyomi-fakeapp-smoke uid=%d gid=%d args=compose --profile front-proxy down --remove-orphans\n", os.Getuid(), os.Getgid()))
	assertPathExists(t, filepath.Join(exampleDir, "data", "logs", "nginx"))
	assertPathExists(t, filepath.Join(exampleDir, "data", "logs", "coraza"))
	assertPathExists(t, filepath.Join(exampleDir, "data", "logs", "openresty"))
	if !strings.Contains(string(out), "[ci-example-smoke][OK] fakeapp protected-host smoke passed") {
		t.Fatalf("unexpected wrapper output: %s", strings.TrimSpace(string(out)))
	}
}

func TestCIExampleSmokeScriptCollectsDockerDiagnosticsOnFailure(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("bash-based smoke script is not supported on windows")
	}

	repoRoot := t.TempDir()
	scriptPath := filepath.Join(repoRoot, "scripts", "ci_example_smoke.sh")
	writeRepoScript(t, filepath.Join(exampleRepoRoot(t), "scripts", "ci_example_smoke.sh"), scriptPath)

	exampleName := "brokenapp"
	exampleDir := filepath.Join(repoRoot, "examples", exampleName)
	logPath := filepath.Join(repoRoot, "docker.log")
	writeExecutable(t, filepath.Join(exampleDir, "setup.sh"), "#!/usr/bin/env bash\nset -euo pipefail\n:\n")
	writeExecutable(t, filepath.Join(exampleDir, "smoke.sh"), "#!/usr/bin/env bash\nset -euo pipefail\necho 'boom' >&2\nexit 1\n")
	writeExecutable(t, filepath.Join(repoRoot, "bin", "docker"), "#!/usr/bin/env bash\nset -euo pipefail\nprintf 'project=%s uid=%s gid=%s args=%s\\n' \"${COMPOSE_PROJECT_NAME:-}\" \"${PUID:-}\" \"${GUID:-}\" \"$*\" >> \"$DOCKER_LOG\"\n")

	cmd := exec.Command("bash", scriptPath, exampleName)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("PATH=%s%c%s", filepath.Join(repoRoot, "bin"), os.PathListSeparator, os.Getenv("PATH")),
		fmt.Sprintf("DOCKER_LOG=%s", logPath),
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected ci example smoke script failure, got success output=%s", strings.TrimSpace(string(out)))
	}
	output := string(out)
	if !strings.Contains(output, "[ci-example-smoke][ERROR] brokenapp smoke failed; collecting docker diagnostics") {
		t.Fatalf("unexpected failure output: %s", strings.TrimSpace(output))
	}
	assertFileContains(t, logPath, fmt.Sprintf("project=tukuyomi-brokenapp-smoke uid=%d gid=%d args=compose --profile front-proxy up -d --build\n", os.Getuid(), os.Getgid()))
	assertFileContains(t, logPath, fmt.Sprintf("project=tukuyomi-brokenapp-smoke uid=%d gid=%d args=compose ps -a\n", os.Getuid(), os.Getgid()))
	assertFileContains(t, logPath, fmt.Sprintf("project=tukuyomi-brokenapp-smoke uid=%d gid=%d args=compose logs --no-color\n", os.Getuid(), os.Getgid()))
	assertFileContains(t, logPath, fmt.Sprintf("project=tukuyomi-brokenapp-smoke uid=%d gid=%d args=compose --profile front-proxy down --remove-orphans\n", os.Getuid(), os.Getgid()))
	assertPathExists(t, filepath.Join(exampleDir, "data", "logs", "nginx"))
	assertPathExists(t, filepath.Join(exampleDir, "data", "logs", "coraza"))
	assertPathExists(t, filepath.Join(exampleDir, "data", "logs", "openresty"))
}

func protectedHostExamples() []smokeExample {
	return []smokeExample{
		{
			name:       "api-gateway",
			scriptPath: "examples/api-gateway/smoke.sh",
			readyPath:  "/v1/health",
			whoamiPath: "/v1/whoami",
			blockPath:  "/v1/whoami",
		},
		{
			name:       "nextjs",
			scriptPath: "examples/nextjs/smoke.sh",
			readyPath:  "/api/whoami",
			whoamiPath: "/api/whoami",
			blockPath:  "/",
		},
		{
			name:       "wordpress",
			scriptPath: "examples/wordpress/smoke.sh",
			readyPath:  "/tukuyomi-whoami.php",
			whoamiPath: "/tukuyomi-whoami.php",
			blockPath:  "/tukuyomi-whoami.php",
		},
	}
}

func runProtectedHostSmokeScript(t *testing.T, example smokeExample, opts smokeRunOptions) (string, *smokeServerState, error) {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("bash-based smoke script is not supported on windows")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is required for smoke script tests")
	}

	scriptAbsPath := filepath.Join(exampleRepoRoot(t), example.scriptPath)
	state := &smokeServerState{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		state.seenHosts = append(state.seenHosts, r.Host)
		state.mu.Unlock()

		switch {
		case r.URL.Path == example.blockPath && r.URL.Query().Get("q") != "":
			w.WriteHeader(opts.blockStatus)
			_, _ = w.Write([]byte(`{"status":"blocked"}`))
			return
		case r.URL.Path == example.readyPath && example.readyPath != example.whoamiPath:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		case r.URL.Path == example.whoamiPath:
			host := r.Host
			if opts.responseHost != "" {
				host = opts.responseHost
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"host": host})
			return
		default:
			state.mu.Lock()
			state.unexpected = append(state.unexpected, fmt.Sprintf("%s %s", r.Method, r.URL.String()))
			state.mu.Unlock()
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cmd := exec.Command("bash", scriptAbsPath)
	cmd.Env = append(os.Environ(),
		"PROTECTED_HOST=protected.example.test",
		fmt.Sprintf("BASE_URL=%s", server.URL),
	)
	if example.name == "wordpress" {
		cmd.Env = append(cmd.Env, "WORDPRESS_SKIP_AUTO_INSTALL=1")
	}
	output, err := cmd.CombinedOutput()
	return string(output), state, err
}

func exampleRepoRoot(t *testing.T) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve current filename")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "../../../.."))
}

func assertSmokeServerState(t *testing.T, state *smokeServerState, expectedHost string) {
	t.Helper()

	state.mu.Lock()
	defer state.mu.Unlock()

	if len(state.unexpected) != 0 {
		t.Fatalf("unexpected requests: %s", strings.Join(state.unexpected, ", "))
	}
	if len(state.seenHosts) == 0 {
		t.Fatal("expected smoke script to send at least one request")
	}
	for _, host := range state.seenHosts {
		if host != expectedHost {
			t.Fatalf("unexpected request host: %q", host)
		}
	}
}

func writeRepoScript(t *testing.T, srcPath string, dstPath string) {
	t.Helper()

	raw, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read repo script: %v", err)
	}
	writeExecutable(t, dstPath, string(raw))
}

func writeExecutable(t *testing.T, path string, contents string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func assertFileContains(t *testing.T, path string, needle string) {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !strings.Contains(string(raw), needle) {
		t.Fatalf("expected %s to contain %q, got %q", path, needle, string(raw))
	}
}

func assertPathExists(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
}
