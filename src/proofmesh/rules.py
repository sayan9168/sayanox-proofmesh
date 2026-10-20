"""Built-in and configurable detection rules with redaction."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RuleMatch:
    """A single rule match (never stores the raw secret value)."""

    rule_id: str
    severity: str
    path: str
    line: int | None
    column: int | None
    message: str
    remediation: str
    matched_preview: str


_BUILTIN_SECRET_RULES: list[dict[str, Any]] = [
    {
        "id": "secret.aws_access_key",
        "name": "AWS Access Key ID",
        "pattern": r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])",
        "severity": "high",
        "remediation": "Rotate the AWS access key immediately and remove it from source control.",
    },
    {
        "id": "secret.generic_api_key",
        "name": "Generic API key assignment",
        "pattern": r"(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]",
        "severity": "high",
        "remediation": "Move secrets to environment variables or a secret manager; rotate the exposed value.",
    },
    {
        "id": "secret.private_key_header",
        "name": "Private key header",
        "pattern": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "severity": "critical",
        "remediation": "Remove private keys from the repository and rotate any associated credentials.",
    },
    {
        "id": "secret.github_token",
        "name": "GitHub token-like string",
        "pattern": r"(?<![A-Za-z0-9])(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})(?![A-Za-z0-9])",
        "severity": "critical",
        "remediation": "Revoke the GitHub token and store tokens outside the repository.",
    },
    {
        "id": "secret.slack_token",
        "name": "Slack token-like string",
        "pattern": r"xox[baprs]-[0-9A-Za-z\-]{10,}",
        "severity": "high",
        "remediation": "Revoke the Slack token via the Slack admin console.",
    },
    {
        "id": "secret.jwt",
        "name": "JWT-like token",
        "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "severity": "medium",
        "remediation": "Avoid embedding long-lived JWTs in source; prefer short-lived tokens from a secure store.",
    },
]

_BUILTIN_RISKY_RULES: list[dict[str, Any]] = [
    {
        "id": "risky.eval",
        "name": "Use of eval()",
        "pattern": r"(?<![A-Za-z0-9_])eval\s*\(",
        "severity": "high",
        "remediation": "Avoid eval on untrusted input; use safer alternatives (ast.literal_eval, parsers).",
    },
    {
        "id": "risky.exec",
        "name": "Use of exec()",
        "pattern": r"(?<![A-Za-z0-9_])exec\s*\(",
        "severity": "high",
        "remediation": "Avoid exec on untrusted input.",
    },
    {
        "id": "risky.shell_true",
        "name": "subprocess with shell=True",
        "pattern": r"subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True",
        "severity": "high",
        "remediation": "Prefer shell=False and pass arguments as a list to avoid command injection.",
    },
    {
        "id": "risky.pickle",
        "name": "pickle load of untrusted data",
        "pattern": r"pickle\.(?:load|loads)\s*\(",
        "severity": "medium",
        "remediation": "Do not unpickle untrusted data; use safer serialization formats.",
    },
    {
        "id": "risky.hardcoded_password",
        "name": "Hardcoded password assignment",
        "pattern": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
        "severity": "high",
        "remediation": "Remove hardcoded passwords; use environment variables or a secret manager.",
    },
]


def _compile_rules(rules: list[dict[str, Any]]) -> list[tuple[dict[str, Any], re.Pattern[str]]]:
    compiled: list[tuple[dict[str, Any], re.Pattern[str]]] = []
    for rule in rules:
        try:
            pat = re.compile(rule["pattern"])
            compiled.append((rule, pat))
        except re.error:
            continue
    return compiled


_COMPILED_SECRETS = _compile_rules(_BUILTIN_SECRET_RULES)
_COMPILED_RISKY = _compile_rules(_BUILTIN_RISKY_RULES)


def redact(value: str, keep: int = 4) -> str:
    """Redact a matched secret value for safe display."""
    if len(value) <= keep * 2:
        return "***REDACTED***"
    return f"{value[:keep]}…{value[-keep:]} [REDACTED]"


def scan_text(
    text: str,
    path: str,
    *,
    include_secrets: bool = True,
    include_risky: bool = True,
    extra_secret_rules: list[dict[str, Any]] | None = None,
    extra_risky_rules: list[dict[str, Any]] | None = None,
) -> list[RuleMatch]:
    """Scan text for secret and risky patterns. Never returns raw secret values."""
    matches: list[RuleMatch] = []
    lines = text.splitlines()

    secret_rules = list(_COMPILED_SECRETS)
    if extra_secret_rules:
        secret_rules.extend(_compile_rules(extra_secret_rules))
    risky_rules = list(_COMPILED_RISKY)
    if extra_risky_rules:
        risky_rules.extend(_compile_rules(extra_risky_rules))

    rule_sets: list[tuple[bool, list[tuple[dict[str, Any], re.Pattern[str]]]]] = []
    if include_secrets:
        rule_sets.append((True, secret_rules))
    if include_risky:
        rule_sets.append((False, risky_rules))

    for line_no, line in enumerate(lines, start=1):
        for is_secret, rules in rule_sets:
            for rule, pattern in rules:
                for m in pattern.finditer(line):
                    raw = m.group(0)
                    preview = redact(raw) if is_secret else (raw[:80] + ("…" if len(raw) > 80 else ""))
                    matches.append(
                        RuleMatch(
                            rule_id=rule["id"],
                            severity=rule.get("severity", "medium"),
                            path=path,
                            line=line_no,
                            column=m.start() + 1,
                            message=rule.get("name", rule["id"]),
                            remediation=rule.get("remediation", ""),
                            matched_preview=preview,
                        )
                    )
    return matches


def list_builtin_rules() -> dict[str, list[dict[str, Any]]]:
    """Return built-in rules (patterns included for transparency; values never logged)."""
    return {
        "secrets": [
            {k: v for k, v in r.items() if k != "pattern"} | {"pattern": r["pattern"]}
            for r in _BUILTIN_SECRET_RULES
        ],
        "risky_code": [
            {k: v for k, v in r.items() if k != "pattern"} | {"pattern": r["pattern"]}
            for r in _BUILTIN_RISKY_RULES
        ],
    }
