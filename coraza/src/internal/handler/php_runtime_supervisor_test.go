package handler

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestPHPRuntimeSupervisorStartsRestartsAndStopsRuntime(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	docroot := filepath.Join(tmp, "apps", "app", "public")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatalf("MkdirAll(docroot): %v", err)
	}
	runUser := strconv.Itoa(os.Geteuid())
	runGroup := strconv.Itoa(os.Getegid())

	initialInventory := defaultPHPRuntimeInventoryRaw
	initialVhosts := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9211,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "runtime_id": "php82",
      "generated_target": "app-php",
      "linked_upstream_name": "app"
    }
  ]
}`
	proxyRaw := mustJSON(normalizeProxyRulesConfig(ProxyRulesConfig{
		Upstreams: []ProxyUpstream{
			{Name: "app", URL: "http://127.0.0.1:8081", Weight: 1, Enabled: true},
			{Name: "primary", URL: "http://127.0.0.1:8080", Weight: 1, Enabled: true},
		},
	}))
	if err := os.WriteFile(inventoryPath, []byte(initialInventory), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := os.WriteFile(vhostPath, []byte(initialVhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
	}
	writeTestPHPRuntimeArtifact(t, inventoryPath, "php82", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.2",
		Version:     "PHP 8.2.99 (fpm-fcgi)",
		Modules:     []string{"mbstring", "redis"},
		RunUser:     runUser,
		RunGroup:    runGroup,
		BinaryBody:  fakePHPRuntimeSupervisorBinaryBody(),
	})
	initConfigDBStoreForTest(t)
	inventoryCfg := importPHPRuntimeInventoryDBForTest(t, initialInventory, inventoryPath)
	importVhostRuntimeDBForTest(t, initialVhosts, inventoryCfg)
	importProxyRuntimeDBForTest(t, proxyRaw)
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}
	if err := InitPHPRuntimeSupervisor(); err != nil {
		t.Fatalf("InitPHPRuntimeSupervisor: %v", err)
	}

	waitForTCPState(t, "127.0.0.1:9211", true)
	statuses := PHPRuntimeProcessSnapshot()
	if len(statuses) != 1 {
		t.Fatalf("process count=%d want=1", len(statuses))
	}
	if !statuses[0].Running || statuses[0].PID <= 0 {
		t.Fatalf("unexpected runtime status: %+v", statuses[0])
	}
	if statuses[0].ConfiguredUser != runUser || statuses[0].ConfiguredGroup != runGroup {
		t.Fatalf("configured identity mismatch: %+v", statuses[0])
	}
	if statuses[0].EffectiveUID != os.Geteuid() || statuses[0].EffectiveGID != os.Getegid() {
		t.Fatalf("effective identity mismatch: %+v", statuses[0])
	}

	_, etag, _, _ := VhostConfigSnapshot()
	updatedVhosts := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9212,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "runtime_id": "php82",
      "generated_target": "app-php",
      "linked_upstream_name": "app"
    }
  ]
}`
	if _, _, err := ApplyVhostConfigRaw(etag, updatedVhosts); err != nil {
		t.Fatalf("ApplyVhostConfigRaw: %v", err)
	}

	waitForTCPState(t, "127.0.0.1:9211", false)
	waitForTCPState(t, "127.0.0.1:9212", true)

	_, etag, _, _ = VhostConfigSnapshot()
	if _, _, err := ApplyVhostConfigRaw(etag, defaultVhostConfigRaw); err != nil {
		t.Fatalf("ApplyVhostConfigRaw(delete): %v", err)
	}

	waitForTCPState(t, "127.0.0.1:9212", false)
	if len(PHPRuntimeProcessSnapshot()) != 0 {
		t.Fatalf("process snapshot should be empty after deleting the last vhost: %+v", PHPRuntimeProcessSnapshot())
	}
}

func fakePHPRuntimeSupervisorBinaryBody() string {
	return `#!/bin/sh
CONFIG=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -y|--fpm-config)
      CONFIG="$2"
      shift 2
      ;;
    -F|--nodaemonize)
      shift
      ;;
    *)
      shift
      ;;
  esac
done
exec python3 - "$CONFIG" <<'PY'
import glob
import os
import signal
import socket
import sys
import time

config = sys.argv[1]
base = os.path.dirname(config)
sockets = []
running = True

def stop(signum, frame):
    global running
    running = False

signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)

for pool in sorted(glob.glob(os.path.join(base, "pools", "*.conf"))):
    listen = None
    with open(pool, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("listen ="):
                listen = line.split("=", 1)[1].strip()
                break
    if not listen:
        continue
    host, port = listen.rsplit(":", 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, int(port)))
    sock.listen(16)
    sockets.append(sock)

while running:
    time.sleep(0.05)

for sock in sockets:
    sock.close()
PY
`
}

func waitForTCPState(t *testing.T, address string, wantOpen bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if wantOpen {
			if err == nil {
				_ = conn.Close()
				return
			}
		} else if err != nil {
			return
		} else {
			_ = conn.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}
	if wantOpen {
		t.Fatalf("timed out waiting for %s to open", address)
	}
	t.Fatalf("timed out waiting for %s to close", address)
}
