"""ClawKeeper official plugin gate adapter for the Python sandbox.

This module is a Python adaptation of the upstream ClawKeeper plugin v1.1
runtime gates:

- clawkeeper-plugin/src/core/input-validator.js
- clawkeeper-plugin/src/core/path-guard.js
- clawkeeper-plugin/src/core/exec-gate.js
- clawkeeper-plugin/src/config/core-rules.json
- clawkeeper-plugin/src/config/tool-schemas/*.json

The sandbox cannot import the upstream ESM modules directly, so this file keeps
the same rule data and gate order while adapting only the event shape from
OpenClaw's before_tool_call hook to the local ToolDispatcher.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


PROTECTED_PATHS = [
    {"pattern": "~/.ssh/**", "severity": "CRITICAL", "reason": "SSH keys and config"},
    {"pattern": "~/.gnupg/**", "severity": "CRITICAL", "reason": "GPG keys"},
    {"pattern": "~/.aws/credentials", "severity": "CRITICAL", "reason": "AWS credentials"},
    {"pattern": "~/.aws/config", "severity": "HIGH", "reason": "AWS profile config"},
    {"pattern": "~/.netrc", "severity": "CRITICAL", "reason": "Network auth tokens"},
    {"pattern": "~/.docker/config.json", "severity": "HIGH", "reason": "Docker registry auth"},
    {"pattern": "~/.kube/config", "severity": "CRITICAL", "reason": "Kubernetes cluster credentials"},
    {"pattern": "~/.config/gh/**", "severity": "HIGH", "reason": "GitHub CLI auth"},
    {"pattern": "~/.config/gcloud/**", "severity": "HIGH", "reason": "Google Cloud credentials"},
    {"pattern": "~/.gitconfig", "severity": "HIGH", "reason": "Git global identity"},
    {"pattern": "~/.bashrc", "severity": "HIGH", "reason": "Shell startup file"},
    {"pattern": "~/.bash_profile", "severity": "HIGH", "reason": "Shell startup file"},
    {"pattern": "~/.zshrc", "severity": "HIGH", "reason": "Shell startup file"},
    {"pattern": "~/.profile", "severity": "HIGH", "reason": "Shell startup file"},
    {"pattern": "~/.openclaw/openclaw.json", "severity": "HIGH", "reason": "OpenClaw core config"},
    {"pattern": "~/.openclaw/AGENTS.md", "severity": "HIGH", "reason": "Agent runtime constitution"},
    {"pattern": "~/.openclaw/SOUL.md", "severity": "HIGH", "reason": "Agent soul file"},
    {"pattern": "/etc/shadow", "severity": "CRITICAL", "reason": "System password hashes"},
    {"pattern": "/etc/sudoers", "severity": "CRITICAL", "reason": "Sudo privilege config"},
    {"pattern": "/etc/sudoers.d/**", "severity": "CRITICAL", "reason": "Sudo privilege config"},
    {"pattern": "/etc/passwd", "severity": "HIGH", "reason": "System user database"},
    {"pattern": "/etc/ssh/**", "severity": "CRITICAL", "reason": "System SSH config"},
    {
        "pattern": "~/.openclaw/workspace/clawkeeper/.hmac-key",
        "severity": "CRITICAL",
        "reason": "Clawkeeper permission HMAC key",
    },
]

PATH_GUARD_BASH_LIKE_TOOLS = [
    "bash",
    "shell",
    "exec",
    "command",
    "run_command",
    "execute_command",
    "terminal",
]

EXEC_GATE_DANGEROUS_COMMANDS = [
    {
        "id": "exec.rm-rf-root",
        "severity": "CRITICAL",
        "pattern": r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)\s+(/|~|\$HOME|/\*|~/\*)(\s|$)",
        "reason": "Recursive force deletion targeting root or home",
    },
    {
        "id": "exec.disk-wipe",
        "severity": "CRITICAL",
        "pattern": r"\b(mkfs(\.[a-z0-9]+)?|dd\s+[^\n]*of=/dev/|format\s+[a-zA-Z]:)",
        "reason": "Disk wipe / low-level format",
    },
    {
        "id": "exec.curl-pipe-shell",
        "severity": "HIGH",
        "pattern": r"\b(curl|wget)\b[^\n|]*\|\s*(bash|sh|zsh|python[0-9.]*)",
        "reason": "Remote script piped directly into a shell interpreter",
    },
    {
        "id": "exec.fork-bomb",
        "severity": "CRITICAL",
        "pattern": r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
        "reason": "Classic bash fork bomb",
    },
    {
        "id": "exec.system-shutdown",
        "severity": "HIGH",
        "pattern": r"\b(shutdown|reboot|halt|poweroff|init\s+0|init\s+6)\b",
        "reason": "System power-state change",
    },
    {
        "id": "exec.firewall-flush",
        "severity": "HIGH",
        "pattern": r"\b(iptables|nft)\b[^\n]*\s-F\b",
        "reason": "Flushing firewall rules",
    },
    {
        "id": "exec.permission-test",
        "severity": "HIGH",
        "pattern": r"\bclawkeeper-permission-test\b",
        "reason": "Reserved sentinel for permission persistence testing",
    },
    {
        "id": "exec.chmod-world",
        "severity": "HIGH",
        "pattern": r"\bchmod\s+(-R\s+)?[0-7]?777\b",
        "reason": "Granting world-writable permissions",
    },
]

TOOL_SCHEMAS = [
    {
        "tool": "read_file",
        "aliases": ["read", "fs_read", "file_read"],
        "type": "object",
        "required": ["path"],
        "additionalProperties": True,
        "properties": {
            "path": {
                "type": "string",
                "minLength": 1,
                "maxLength": 4096,
                "pattern": r"^[^\u0000\n\r]*$",
            },
            "offset": {"type": "number"},
            "limit": {"type": "number"},
        },
    },
    {
        "tool": "write_file",
        "aliases": ["write", "fs_write", "file_write"],
        "type": "object",
        "required": ["path", "content"],
        "additionalProperties": True,
        "properties": {
            "path": {
                "type": "string",
                "minLength": 1,
                "maxLength": 4096,
                "pattern": r"^[^\u0000\n\r]*$",
            },
            "content": {"type": "string", "maxLength": 1048576},
        },
    },
    {
        "tool": "bash",
        "aliases": ["shell", "exec"],
        "type": "object",
        "required": ["command"],
        "additionalProperties": True,
        "properties": {
            "command": {
                "type": "string",
                "minLength": 1,
                "maxLength": 8000,
                "pattern": r"^[^\u0000]*$",
            },
            "cwd": {"type": "string", "maxLength": 4096},
            "timeout": {"type": "number"},
        },
    },
]


@dataclass(frozen=True)
class ClawKeeperGateResult:
    block: bool
    rule: str = ""
    reason: str = ""
    metadata: Dict[str, Any] | None = None


def evaluate_before_tool_call(tool_name: str, params: Dict[str, Any]) -> ClawKeeperGateResult:
    """Run the upstream ClawKeeper before_tool_call gates in plugin order.

    Permission store and budget guard are intentionally inactive in the sandbox
    adaptation because there is no operator-managed permission database or
    rolling token budget state for baseline evaluation. The remaining gates use
    the official rule data and semantics.
    """

    input_result = validate_tool_input(tool_name, params)
    if input_result.block:
        return input_result

    path_result = guard_before_tool_call(tool_name, params)
    if path_result.block:
        return path_result

    return guard_execution(tool_name, params)


def validate_tool_input(tool_name: str, params: Dict[str, Any]) -> ClawKeeperGateResult:
    schemas = _schema_map()
    schema = schemas.get(str(tool_name or "").lower())
    if not schema:
        return ClawKeeperGateResult(False, metadata={"unknownTool": True})

    errors = _check_schema(schema, params or {})
    if not errors:
        return ClawKeeperGateResult(False)

    reason = f"input validation failed: {errors[0]}"
    return ClawKeeperGateResult(
        True,
        "input-validation",
        reason,
        {"errors": errors, "severity": "MEDIUM"},
    )


def guard_before_tool_call(tool_name: str, params: Dict[str, Any]) -> ClawKeeperGateResult:
    candidates = extract_paths_from_params(tool_name, params, PATH_GUARD_BASH_LIKE_TOOLS)
    for candidate in candidates:
        resolved = normalize_path(candidate)
        hit = match_protected(resolved) or match_protected(expand_home(candidate))
        if hit:
            return ClawKeeperGateResult(
                True,
                "protected-path",
                hit["reason"],
                {
                    "pattern": hit["pattern"],
                    "candidate": candidate,
                    "resolved": resolved,
                    "severity": hit["severity"],
                },
            )
    return ClawKeeperGateResult(False)


def guard_execution(tool_name: str, params: Dict[str, Any]) -> ClawKeeperGateResult:
    command = extract_command_text(tool_name, params, PATH_GUARD_BASH_LIKE_TOOLS)
    if not command:
        return ClawKeeperGateResult(False)

    for rule in EXEC_GATE_DANGEROUS_COMMANDS:
        if re.search(rule["pattern"], command, re.IGNORECASE):
            clipped = command[:500] + "..." if len(command) > 500 else command
            return ClawKeeperGateResult(
                True,
                "dangerous-command",
                rule["reason"],
                {
                    "pattern": rule["id"],
                    "severity": rule["severity"],
                    "command": clipped,
                },
            )
    return ClawKeeperGateResult(False)


def extract_command_text(tool_name: str, params: Dict[str, Any], bash_like_tools: Iterable[str]) -> str:
    t_name = str(tool_name or "").lower()
    bash_like = {item.lower() for item in bash_like_tools}
    looks_like_bash = t_name in bash_like or re.search(r"bash|shell|exec|command|terminal", t_name) is not None
    p = params or {}

    if looks_like_bash:
        named = "\n".join(
            str(p[field])
            for field in ("command", "cmd", "script", "input", "code", "bash", "shell")
            if isinstance(p.get(field), str)
        )
        if named:
            return named
    return "\n".join(_collect_string_values(params))


PATH_TOKEN_RE = re.compile(r"""(?:^|[\s'"`=:;(){}\[\],])(~\/[^\s'"`;|&()<>]+|\/[A-Za-z0-9._\/-]+|\.{1,2}\/[^\s'"`;|&()<>]+)""")


def extract_paths_from_command(command: str) -> List[str]:
    if not isinstance(command, str) or not command:
        return []
    out: Dict[str, None] = {}
    for match in PATH_TOKEN_RE.finditer(command):
        token = match.group(1)
        if len(token) >= 2:
            out[token] = None
    return list(out)


def extract_paths_from_params(
    tool_name: str,
    params: Dict[str, Any],
    bash_like_tools: Iterable[str],
) -> List[str]:
    bash_like = {item.lower() for item in bash_like_tools}
    t_name = str(tool_name or "").lower()
    looks_like_bash = t_name in bash_like or re.search(r"bash|shell|exec|command|terminal", t_name) is not None
    candidates: Dict[str, None] = {}

    if looks_like_bash:
        command_text = extract_command_text(tool_name, params, bash_like_tools)
        for token in extract_paths_from_command(command_text):
            candidates[token] = None

    for value in _collect_string_values(params):
        s = value.strip()
        if not s:
            continue
        if s.startswith("~/") or s.startswith("~\\") or os.path.isabs(s):
            candidates[s] = None
        elif s.startswith("./") or s.startswith("../"):
            candidates[s] = None
        elif re.search(r"^(id_rsa|id_ed25519|\.env|credentials|shadow|sudoers)$", s, re.IGNORECASE):
            candidates[s] = None
    return list(candidates)


def expand_home(path_value: Optional[str]) -> Optional[str]:
    if not path_value:
        return path_value
    if path_value == "~":
        return str(Path.home())
    if path_value.startswith("~/") or path_value.startswith("~\\"):
        return str(Path.home() / path_value[2:])
    return path_value


def normalize_path(path_value: Any, cwd: Optional[str] = None) -> Optional[str]:
    if not isinstance(path_value, str) or not path_value:
        return None
    p = expand_home(path_value.strip()) or ""
    if (p.startswith('"') and p.endswith('"')) or (p.startswith("'") and p.endswith("'")):
        p = p[1:-1]
    if not os.path.isabs(p):
        p = os.path.abspath(os.path.join(cwd or os.getcwd(), p))
    return os.path.realpath(p) if os.path.exists(p) else os.path.abspath(p)


def match_protected(abs_path: Optional[str]) -> Optional[Dict[str, str]]:
    if not abs_path:
        return None
    for rule in PROTECTED_PATHS:
        expanded = expand_home(rule["pattern"]) or rule["pattern"]
        if _glob_to_regex(expanded).match(abs_path):
            return rule
        if rule["pattern"].endswith("/**"):
            prefix = expanded[:-3]
            if abs_path == prefix or abs_path.startswith(prefix + os.sep) or abs_path.startswith(prefix + "/"):
                return rule
    return None


def _glob_to_regex(glob: str) -> re.Pattern[str]:
    parts = ["^"]
    i = 0
    while i < len(glob):
        char = glob[i]
        if char == "*":
            if i + 1 < len(glob) and glob[i + 1] == "*":
                parts.append(".*")
                i += 1
            else:
                parts.append("[^/]*")
        elif char == "?":
            parts.append("[^/]")
        elif char in ".+^${}()|[]\\":
            parts.append("\\" + char)
        else:
            parts.append(char)
        i += 1
    parts.append("$")
    return re.compile("".join(parts))


def _collect_string_values(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        out: List[str] = []
        for item in value:
            out.extend(_collect_string_values(item))
        return out
    if isinstance(value, dict):
        out = []
        for item in value.values():
            out.extend(_collect_string_values(item))
        return out
    return []


def _schema_map() -> Dict[str, Dict[str, Any]]:
    schemas: Dict[str, Dict[str, Any]] = {}
    for schema in TOOL_SCHEMAS:
        for name in [schema.get("tool"), *(schema.get("aliases") or [])]:
            if name:
                schemas[str(name).lower()] = schema
    return schemas


def _type_of(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, list):
        return "array"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _check_schema(schema: Dict[str, Any], value: Any, where: str = "$") -> List[str]:
    errors: List[str] = []
    expected = schema.get("type")
    actual = _type_of(value)
    if expected:
        if actual != expected:
            errors.append(f"{where}: expected {expected}, got {actual}")
            return errors

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{where}: value not in enum")

    if actual == "string":
        if isinstance(schema.get("minLength"), int) and len(value) < schema["minLength"]:
            errors.append(f"{where}: string shorter than minLength={schema['minLength']}")
        if isinstance(schema.get("maxLength"), int) and len(value) > schema["maxLength"]:
            errors.append(f"{where}: string longer than maxLength={schema['maxLength']} (got {len(value)})")
        if schema.get("pattern"):
            try:
                if re.search(schema["pattern"], value) is None:
                    errors.append(f"{where}: string does not match pattern")
            except re.error:
                pass

    if actual == "object":
        for key in schema.get("required") or []:
            if key not in value or value[key] is None or value[key] == "":
                errors.append(f"{where}.{key}: required field missing")
        props = schema.get("properties") or {}
        allow_extra = schema.get("additionalProperties") is not False
        for key, item in value.items():
            if key in props:
                errors.extend(_check_schema(props[key], item, f"{where}.{key}"))
            elif not allow_extra:
                errors.append(f"{where}.{key}: unknown property")

    return errors
