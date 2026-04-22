#!/usr/bin/env python3
import hashlib
import json
import os
import re
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict

DEFAULT_RULE_ID = 100004
DEFAULT_VARIABLE = "ARGS:q"
DEFAULT_CONFIDENCE = 0.82
MAX_BODY_BYTES = 2 * 1024 * 1024
VAR_RE = re.compile(r"^[A-Za-z0-9_.:!]+$")

CFG: Dict[str, Any] = {
    "mode": "fixture",
    "fixture_file": "",
    "command": "",
    "command_timeout_sec": 20,
    "request_log": "",
}


def parse_int(value: Any, default: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return n if n > 0 else default


def normalize_path(value: Any) -> str:
    if not isinstance(value, str):
        return "/"
    path = value.strip()
    if not path or not path.startswith("/"):
        return "/"
    if "\n" in path or "\r" in path or '"' in path:
        return "/"
    return path


def normalize_host(value: Any) -> str:
    if not isinstance(value, str):
        return "localhost"
    host = value.strip().lower()
    if not host or "://" in host or "/" in host or any(ch in host for ch in "\r\n\t "):
        return "localhost"
    return host


def normalize_scheme(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    scheme = value.strip().lower()
    if scheme in ("http", "https"):
        return scheme
    return ""


def split_host_port(host: str) -> tuple[str, str]:
    if not host:
        return "", ""
    if host.startswith("["):
        end = host.find("]")
        if end >= 0:
            suffix = host[end + 1 :]
            if suffix.startswith(":") and suffix[1:].isdigit():
                return host[: end + 1], suffix[1:]
            return host, ""
    if host.count(":") == 1:
        left, right = host.rsplit(":", 1)
        if right.isdigit():
            return left, right
    return host, ""


def normalize_variable(value: Any) -> str:
    if not isinstance(value, str):
        return DEFAULT_VARIABLE
    v = value.strip()
    if not v or not VAR_RE.match(v):
        return DEFAULT_VARIABLE
    return v


def normalize_confidence(value: Any) -> float:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return DEFAULT_CONFIDENCE
    if n <= 0:
        return DEFAULT_CONFIDENCE
    if 1 < n <= 100:
        n = n / 100.0
    if n > 1:
        n = 1.0
    return round(n, 4)


def build_host_match(host: str, scheme: str) -> tuple[str, str]:
    host_only, port = split_host_port(host)
    if not scheme:
        if port == "80":
            scheme = "http"
        elif port == "443":
            scheme = "https"
    if scheme == "http" and port in ("", "80") and host_only:
        return "rx", "^" + re.escape(host_only) + "(:80)?$"
    if scheme == "https" and port in ("", "443") and host_only:
        return "rx", "^" + re.escape(host_only) + "(:443)?$"
    return "streq", host


def build_rule_line(host: str, scheme: str, path: str, rule_id: int, variable: str) -> str:
    operator, operand = build_host_match(host, scheme)
    digest = hashlib.sha1(f"{rule_id}|{operator}|{operand}|{path}|{variable}".encode("utf-8")).hexdigest()
    generated_id = 190000 + (int(digest[:6], 16) % 9000)
    return (
        f'SecRule REQUEST_HEADERS:Host "@{operator} {operand}" '
        f'"id:{generated_id},phase:1,pass,nolog,chain,msg:\'tukuyomi fp_tuner scoped exclusion\'"\n'
        f'SecRule REQUEST_URI "@beginsWith {path}" '
        f'"ctl:ruleRemoveTargetById={rule_id};{variable}"'
    )


def decode_proposal_payload(raw: str) -> Dict[str, Any]:
    obj = json.loads(raw)
    if isinstance(obj, dict):
        if isinstance(obj.get("proposal"), dict):
            return dict(obj["proposal"])
        return dict(obj)
    raise ValueError("provider output must be a JSON object")


def fill_proposal_defaults(proposal: Dict[str, Any], req_obj: Dict[str, Any]) -> Dict[str, Any]:
    req_input = req_obj.get("input")
    if not isinstance(req_input, dict):
        req_input = {}

    scheme = normalize_scheme(req_input.get("scheme"))
    host = normalize_host(req_input.get("host"))
    path = normalize_path(req_input.get("path"))
    rule_id = parse_int(req_input.get("rule_id"), DEFAULT_RULE_ID)
    variable = normalize_variable(req_input.get("matched_variable"))

    target_path = str(req_obj.get("target_path") or proposal.get("target_path") or "rules/tukuyomi.conf").strip()
    if not target_path:
        target_path = "rules/tukuyomi.conf"

    out = dict(proposal)
    if not str(out.get("id", "")).strip():
        out["id"] = f"fp-bridge-{int(time.time())}"
    if not str(out.get("title", "")).strip():
        out["title"] = "Scoped false-positive tuning suggestion"
    if not str(out.get("summary", "")).strip():
        out["summary"] = f"Exclude {variable} from rule {rule_id} under host {host} and path prefix {path}."
    if not str(out.get("reason", "")).strip():
        out["reason"] = "Generated by fp-tuner provider bridge"
    out["confidence"] = normalize_confidence(out.get("confidence"))
    if not str(out.get("target_path", "")).strip():
        out["target_path"] = target_path
    if not str(out.get("rule_line", "")).strip():
        out["rule_line"] = build_rule_line(host, scheme, path, rule_id, variable)

    return out


def append_request_log(raw: str) -> None:
    path = str(CFG.get("request_log") or "").strip()
    if not path:
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(raw)
        f.write("\n")


def build_proposal_from_fixture(req_obj: Dict[str, Any]) -> Dict[str, Any]:
    fixture_path = str(CFG.get("fixture_file") or "").strip()
    fixture_proposal: Dict[str, Any] = {}
    if fixture_path:
        raw = Path(fixture_path).read_text(encoding="utf-8")
        fixture_proposal = decode_proposal_payload(raw)
    return fill_proposal_defaults(fixture_proposal, req_obj)


def build_proposal_from_command(req_raw: str, req_obj: Dict[str, Any]) -> Dict[str, Any]:
    command = str(CFG.get("command") or "").strip()
    if not command:
        raise ValueError("FP_TUNER_BRIDGE_COMMAND is empty")

    timeout_sec = parse_int(CFG.get("command_timeout_sec"), 20)
    proc = subprocess.run(
        command,
        input=req_raw,
        capture_output=True,
        text=True,
        shell=True,
        timeout=timeout_sec,
        check=False,
    )
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise RuntimeError(f"command failed: exit={proc.returncode} stderr={stderr}")

    out = (proc.stdout or "").strip()
    if not out:
        raise RuntimeError("command output is empty")

    proposal = decode_proposal_payload(out)
    return fill_proposal_defaults(proposal, req_obj)


def resolve_proposal(req_raw: str, req_obj: Dict[str, Any]) -> Dict[str, Any]:
    mode = str(CFG.get("mode") or "fixture").strip().lower()
    if mode == "fixture":
        return build_proposal_from_fixture(req_obj)
    if mode == "command":
        return build_proposal_from_command(req_raw, req_obj)
    raise ValueError(f"unsupported FP_TUNER_BRIDGE_MODE: {mode}")


class Handler(BaseHTTPRequestHandler):
    server_version = "fp-tuner-provider-bridge/1.0"

    def _send_json(self, code: int, payload: Dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path in ("/", "/healthz"):
            self._send_json(200, {"ok": True, "mode": CFG.get("mode", "fixture")})
            return
        self._send_json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:
        if self.path not in ("/", "/propose"):
            self._send_json(404, {"ok": False, "error": "not found"})
            return

        length = parse_int(self.headers.get("Content-Length"), 0)
        if length <= 0:
            self._send_json(400, {"ok": False, "error": "empty body"})
            return
        if length > MAX_BODY_BYTES:
            self._send_json(413, {"ok": False, "error": "payload too large"})
            return

        raw_bytes = self.rfile.read(length)
        req_raw = raw_bytes.decode("utf-8", errors="replace")

        try:
            req_obj = json.loads(req_raw)
            if not isinstance(req_obj, dict):
                raise ValueError("request body must be JSON object")
        except Exception as exc:
            self._send_json(400, {"ok": False, "error": f"invalid json: {exc}"})
            return

        try:
            append_request_log(req_raw)
            proposal = resolve_proposal(req_raw, req_obj)
        except Exception as exc:
            self._send_json(502, {"ok": False, "error": str(exc)})
            return

        self._send_json(200, {"proposal": proposal})

    def log_message(self, _fmt: str, *_args: Any) -> None:
        return


def main() -> int:
    host = os.getenv("FP_TUNER_BRIDGE_HOST", "127.0.0.1").strip() or "127.0.0.1"
    port = parse_int(os.getenv("FP_TUNER_BRIDGE_PORT"), 18091)

    CFG["mode"] = os.getenv("FP_TUNER_BRIDGE_MODE", "fixture").strip() or "fixture"
    CFG["fixture_file"] = os.getenv("FP_TUNER_BRIDGE_FIXTURE_FILE", "").strip()
    CFG["command"] = os.getenv("FP_TUNER_BRIDGE_COMMAND", "").strip()
    CFG["command_timeout_sec"] = parse_int(os.getenv("FP_TUNER_BRIDGE_COMMAND_TIMEOUT_SEC"), 20)
    CFG["request_log"] = os.getenv("FP_TUNER_BRIDGE_REQUEST_LOG", "").strip()

    server = ThreadingHTTPServer((host, port), Handler)
    print(
        json.dumps(
            {
                "event": "fp_tuner_provider_bridge_start",
                "host": host,
                "port": port,
                "mode": CFG["mode"],
                "fixture_file": CFG["fixture_file"],
                "request_log": CFG["request_log"],
            }
        ),
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
