#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MOCK_CLAUDE_PORT="${MOCK_CLAUDE_PORT:-18095}"
MOCK_CLAUDE_LOG="$(mktemp)"
MOCK_CLAUDE_PID=""

cleanup() {
  if [[ -n "${MOCK_CLAUDE_PID}" ]]; then
    kill "${MOCK_CLAUDE_PID}" >/dev/null 2>&1 || true
    wait "${MOCK_CLAUDE_PID}" >/dev/null 2>&1 || true
  fi
  rm -f "${MOCK_CLAUDE_LOG}"
}
trap cleanup EXIT

python3 - "${MOCK_CLAUDE_PORT}" "${MOCK_CLAUDE_LOG}" <<'PY' &
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port = int(sys.argv[1])
log_path = sys.argv[2]

proposal = {
    "proposal": {
        "id": "fp-claude-mock-001",
        "title": "Scoped false-positive tuning suggestion",
        "summary": "Mocked Claude provider response for bridge test.",
        "reason": "Local mock response for fp_tuner_provider_claude.sh",
        "confidence": 0.89,
        "target_path": "tukuyomi.conf",
        "rule_line": "SecRule REQUEST_HEADERS:Host \"@rx ^search\\.example\\.com(:443)?$\" \"id:190888,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\"",
    }
}


class Handler(BaseHTTPRequestHandler):
    def _write(self, status, obj):
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/healthz":
            self._write(200, {"ok": True})
            return
        self._write(404, {"ok": False})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        entry = {
            "path": self.path,
            "headers": dict(self.headers),
            "body": json.loads(body) if body else {},
        }
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry))
            f.write("\n")

        if self.path == "/v1/messages":
            self._write(
                200,
                {
                    "id": "msg_test",
                    "type": "message",
                    "role": "assistant",
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(proposal),
                        }
                    ],
                },
            )
            return

        self._write(404, {"error": "not found"})

    def log_message(self, _fmt, *_args):
        return


HTTPServer(("127.0.0.1", port), Handler).serve_forever()
PY
MOCK_CLAUDE_PID="$!"

for _ in $(seq 1 30); do
  code="$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${MOCK_CLAUDE_PORT}/healthz" || true)"
  if [[ "${code}" == "200" ]]; then
    break
  fi
  sleep 1
done
if [[ "${code:-}" != "200" ]]; then
  echo "[fp-tuner-claude] mock server failed to start" >&2
  exit 1
fi

FP_TUNER_CLAUDE_API_KEY="dummy" \
FP_TUNER_CLAUDE_MODEL="claude-sonnet-4-6" \
FP_TUNER_CLAUDE_BASE_URL="http://127.0.0.1:${MOCK_CLAUDE_PORT}" \
FP_TUNER_CLAUDE_API_VERSION="2023-06-01" \
BRIDGE_COMMAND="${ROOT_DIR}/scripts/fp_tuner_provider_claude.sh" \
FP_TUNER_BRIDGE_AUTO_DOWN="${FP_TUNER_BRIDGE_AUTO_DOWN:-1}" \
SIMULATE="${SIMULATE:-1}" \
HOST_CORAZA_PORT="${HOST_CORAZA_PORT:-19090}" \
"${ROOT_DIR}/scripts/test_fp_tuner_bridge_command.sh"

if [[ ! -s "${MOCK_CLAUDE_LOG}" ]]; then
  echo "[fp-tuner-claude] mock Claude endpoint did not receive requests" >&2
  exit 1
fi

last_request="$(tail -n 1 "${MOCK_CLAUDE_LOG}")"
if ! printf '%s\n' "${last_request}" | jq -e '(.headers["anthropic-version"] // .headers["Anthropic-Version"] // "") == "2023-06-01"' >/dev/null; then
  echo "[fp-tuner-claude] anthropic-version header was not set as expected" >&2
  printf '%s\n' "${last_request}" >&2
  exit 1
fi

if ! printf '%s\n' "${last_request}" | jq -e '.body.model == "claude-sonnet-4-6"' >/dev/null; then
  echo "[fp-tuner-claude] request model mismatch" >&2
  printf '%s\n' "${last_request}" >&2
  exit 1
fi

echo "[fp-tuner-claude] completed"
