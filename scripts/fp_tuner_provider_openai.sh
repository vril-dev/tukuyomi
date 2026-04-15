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

# strip common markdown fences
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

api_key="${FP_TUNER_OPENAI_API_KEY:-${OPENAI_API_KEY:-}}"
if [[ -z "${api_key}" ]]; then
  echo "FP_TUNER_OPENAI_API_KEY (or OPENAI_API_KEY) is required" >&2
  exit 1
fi

api_type="${FP_TUNER_OPENAI_API_TYPE:-responses}"
base_url="${FP_TUNER_OPENAI_BASE_URL:-${OPENAI_BASE_URL:-https://api.openai.com/v1}}"
base_url="${base_url%/}"

request_model="$(jq -r '.model // empty' <<<"${payload}")"
model="${FP_TUNER_OPENAI_MODEL:-${OPENAI_MODEL:-${request_model}}}"
if [[ -z "${model}" ]]; then
  echo "FP_TUNER_OPENAI_MODEL (or OPENAI_MODEL, or request.model) is required" >&2
  exit 1
fi

timeout_sec="${FP_TUNER_OPENAI_TIMEOUT_SEC:-30}"
if ! [[ "${timeout_sec}" =~ ^[0-9]+$ ]] || [[ "${timeout_sec}" -le 0 ]]; then
  echo "FP_TUNER_OPENAI_TIMEOUT_SEC must be a positive integer" >&2
  exit 1
fi

system_prompt="You are a Coraza WAF false-positive tuning assistant. Return exactly one JSON object. If a safe host-scoped exclusion is justified, return proposal JSON with id, title, summary, reason, confidence (0-1), target_path, rule_line. If evidence is insufficient or the event looks like a real attack, return no_proposal JSON with decision=no_proposal, reason, confidence. Do not include markdown or extra text. Follow constraints in the request strictly."
user_prompt="fp_tuner_provider_request_json:\n${payload}"

case "${api_type}" in
  responses)
    endpoint="${FP_TUNER_OPENAI_ENDPOINT:-${base_url}/responses}"
    req_json="$(jq -n \
      --arg model "${model}" \
      --arg system "${system_prompt}" \
      --arg user "${user_prompt}" \
      '{
        model: $model,
        input: [
          {role: "system", content: $system},
          {role: "user", content: $user}
        ],
        temperature: 0
      }')"
    ;;
  chat)
    endpoint="${FP_TUNER_OPENAI_ENDPOINT:-${base_url}/chat/completions}"
    req_json="$(jq -n \
      --arg model "${model}" \
      --arg system "${system_prompt}" \
      --arg user "${user_prompt}" \
      '{
        model: $model,
        messages: [
          {role: "system", content: $system},
          {role: "user", content: $user}
        ],
        temperature: 0,
        response_format: {type: "json_object"}
      }')"
    ;;
  *)
    echo "unsupported FP_TUNER_OPENAI_API_TYPE: ${api_type} (use responses|chat)" >&2
    exit 1
    ;;
esac

resp="$(curl -fsS -m "${timeout_sec}" \
  -H "Authorization: Bearer ${api_key}" \
  -H "Content-Type: application/json" \
  -X POST "${endpoint}" \
  --data "${req_json}")"

if jq -e '.proposal? | type == "object"' >/dev/null 2>&1 <<<"${resp}"; then
  jq -c '.proposal' <<<"${resp}"
  exit 0
fi
if jq -e '.output_parsed? | type == "object"' >/dev/null 2>&1 <<<"${resp}"; then
  jq -c '.output_parsed' <<<"${resp}"
  exit 0
fi

text="$(jq -r '
  if (.output_text? | type) == "string" and (.output_text | length) > 0 then
    .output_text
  elif (.choices?[0].message?.content? | type) == "string" then
    .choices[0].message.content
  elif (.choices?[0].message?.content? | type) == "array" then
    (.choices[0].message.content | map(.text // .) | join(""))
  elif (.output? | type) == "array" then
    ([.output[]?.content[]? | .text? // .value? // empty] | join(""))
  else
    ""
  end
' <<<"${resp}")"

if [[ -z "${text}" ]]; then
  echo "failed to extract model text output" >&2
  echo "raw_response=${resp}" >&2
  exit 1
fi

printf '%s' "${text}" | extract_json_object
