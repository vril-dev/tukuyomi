#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MOCK_OPENAI_PORT="${MOCK_OPENAI_PORT:-18094}"
MOCK_OPENAI_LOG="$(mktemp)"
MOCK_OPENAI_PID=""

cleanup() {
  if [[ -n "${MOCK_OPENAI_PID}" ]]; then
    kill "${MOCK_OPENAI_PID}" >/dev/null 2>&1 || true
    wait "${MOCK_OPENAI_PID}" >/dev/null 2>&1 || true
  fi
  rm -f "${MOCK_OPENAI_LOG}"
}
trap cleanup EXIT

python3 - "${MOCK_OPENAI_PORT}" "${MOCK_OPENAI_LOG}" <<'PY' &
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port = int(sys.argv[1])
log_path = sys.argv[2]

proposal = {
    "proposal": {
        "id": "fp-openai-mock-001",
        "title": "Scoped false-positive tuning suggestion",
        "summary": "Mocked OpenAI provider response for bridge test.",
        "reason": "Local mock response for fp_tuner_provider_openai.sh",
        "confidence": 0.87,
        "target_path": "rules/tukuyomi.conf",
        "rule_line": "SecRule REQUEST_URI \"@beginsWith /search\" \"id:190654,phase:1,pass,nolog,ctl:ruleRemoveTargetById=100004;ARGS:q,msg:'tukuyomi fp_tuner scoped exclusion'\"",
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
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(body)
            f.write("\n")

        if self.path == "/v1/responses":
            self._write(200, {"output_text": json.dumps(proposal)})
            return
        if self.path == "/v1/chat/completions":
            self._write(200, {"choices": [{"message": {"content": json.dumps(proposal)}}]})
            return
        self._write(404, {"error": "not found"})

    def log_message(self, _fmt, *_args):
        return


HTTPServer(("127.0.0.1", port), Handler).serve_forever()
PY
MOCK_OPENAI_PID="$!"

for i in $(seq 1 30); do
  code="$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${MOCK_OPENAI_PORT}/healthz" || true)"
  if [[ "${code}" == "200" ]]; then
    break
  fi
  sleep 1
done
if [[ "${code:-}" != "200" ]]; then
  echo "[fp-tuner-openai] mock server failed to start" >&2
  exit 1
fi

FP_TUNER_OPENAI_API_KEY="dummy" \
FP_TUNER_OPENAI_MODEL="gpt-test" \
FP_TUNER_OPENAI_BASE_URL="http://127.0.0.1:${MOCK_OPENAI_PORT}/v1" \
FP_TUNER_OPENAI_API_TYPE="responses" \
BRIDGE_COMMAND="${ROOT_DIR}/scripts/fp_tuner_provider_openai.sh" \
FP_TUNER_BRIDGE_AUTO_DOWN="${FP_TUNER_BRIDGE_AUTO_DOWN:-1}" \
SIMULATE="${SIMULATE:-1}" \
HOST_CORAZA_PORT="${HOST_CORAZA_PORT:-19090}" \
"${ROOT_DIR}/scripts/test_fp_tuner_bridge_command.sh"

if [[ ! -s "${MOCK_OPENAI_LOG}" ]]; then
  echo "[fp-tuner-openai] mock OpenAI endpoint did not receive requests" >&2
  exit 1
fi

echo "[fp-tuner-openai] completed"
