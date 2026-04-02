#!/usr/bin/env bash
set -euo pipefail

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "required command not found: $1" >&2
    exit 1
  fi
}

extract_json_object() {
  python3 -c '
import json
import re
import sys

raw = sys.stdin.read().strip()
if not raw:
    print("empty model output", file=sys.stderr)
    sys.exit(1)

raw = re.sub(r"^```(?:json)?\\s*", "", raw, flags=re.IGNORECASE)
raw = re.sub(r"\\s*```$", "", raw)
raw = raw.strip()

def emit(obj):
    if isinstance(obj, dict) and isinstance(obj.get("proposal"), dict):
        obj = obj["proposal"]
    if not isinstance(obj, dict):
        raise ValueError("model output must decode to JSON object")
    print(json.dumps(obj, ensure_ascii=False))

try:
    emit(json.loads(raw))
    sys.exit(0)
except Exception:
    pass

first = raw.find("{")
last = raw.rfind("}")
if first == -1 or last == -1 or first >= last:
    print("model output does not contain JSON object", file=sys.stderr)
    sys.exit(1)

candidate = raw[first:last + 1]
try:
    emit(json.loads(candidate))
except Exception as exc:
    print(f"failed to parse model JSON: {exc}", file=sys.stderr)
    sys.exit(1)
'
}

require_cmd curl
require_cmd jq
require_cmd python3

payload="$(cat)"
if [[ -z "${payload}" ]]; then
  echo "stdin payload is empty" >&2
  exit 1
fi

api_key="${FP_TUNER_CLAUDE_API_KEY:-${ANTHROPIC_API_KEY:-}}"
if [[ -z "${api_key}" ]]; then
  echo "FP_TUNER_CLAUDE_API_KEY (or ANTHROPIC_API_KEY) is required" >&2
  exit 1
fi

request_model="$(jq -r '.model // empty' <<<"${payload}")"
model="${FP_TUNER_CLAUDE_MODEL:-${ANTHROPIC_MODEL:-${request_model:-claude-sonnet-4-6}}}"

base_url="${FP_TUNER_CLAUDE_BASE_URL:-${ANTHROPIC_BASE_URL:-https://api.anthropic.com}}"
base_url="${base_url%/}"
endpoint="${FP_TUNER_CLAUDE_ENDPOINT:-${base_url}/v1/messages}"

api_version="${FP_TUNER_CLAUDE_API_VERSION:-2023-06-01}"
beta_header="${FP_TUNER_CLAUDE_BETA:-}"

timeout_sec="${FP_TUNER_CLAUDE_TIMEOUT_SEC:-30}"
if ! [[ "${timeout_sec}" =~ ^[0-9]+$ ]] || [[ "${timeout_sec}" -le 0 ]]; then
  echo "FP_TUNER_CLAUDE_TIMEOUT_SEC must be a positive integer" >&2
  exit 1
fi

max_tokens="${FP_TUNER_CLAUDE_MAX_TOKENS:-700}"
if ! [[ "${max_tokens}" =~ ^[0-9]+$ ]] || [[ "${max_tokens}" -le 0 ]]; then
  echo "FP_TUNER_CLAUDE_MAX_TOKENS must be a positive integer" >&2
  exit 1
fi

system_prompt="You are a WAF false-positive tuning assistant. Return exactly one JSON object for a safe scoped exclusion rule. The output JSON must include id, title, summary, reason, confidence (0-1), target_path, rule_line. Do not include markdown or extra text. Follow constraints in the request strictly."
user_prompt="fp_tuner_provider_request_json:\n${payload}"

req_json="$(jq -n \
  --arg model "${model}" \
  --arg system "${system_prompt}" \
  --arg user "${user_prompt}" \
  --argjson max_tokens "${max_tokens}" \
  '{
    model: $model,
    max_tokens: $max_tokens,
    system: $system,
    messages: [
      {
        role: "user",
        content: [
          {
            type: "text",
            text: $user
          }
        ]
      }
    ],
    temperature: 0
  }')"

curl_args=(
  -fsS
  -m "${timeout_sec}"
  -H "x-api-key: ${api_key}"
  -H "anthropic-version: ${api_version}"
  -H "content-type: application/json"
)
if [[ -n "${beta_header}" ]]; then
  curl_args+=( -H "anthropic-beta: ${beta_header}" )
fi

resp="$(curl "${curl_args[@]}" -X POST "${endpoint}" --data "${req_json}")"

if jq -e '.proposal? | type == "object"' >/dev/null 2>&1 <<<"${resp}"; then
  jq -c '.proposal' <<<"${resp}"
  exit 0
fi

text="$(jq -r '
  if (.content? | type) == "array" then
    [.content[]? | select(.type == "text") | .text // empty] | join("\n")
  elif (.content? | type) == "string" then
    .content
  elif (.completion? | type) == "string" then
    .completion
  else
    ""
  end
' <<<"${resp}")"

if [[ -z "${text}" ]]; then
  echo "failed to extract Claude output text" >&2
  echo "raw_response=${resp}" >&2
  exit 1
fi

printf '%s' "${text}" | extract_json_object
