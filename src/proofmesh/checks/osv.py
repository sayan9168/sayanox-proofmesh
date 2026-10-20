"""OSV vulnerability lookup check (free public API, best-effort)."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from proofmesh.checks.base import CheckResult, CheckStatus, Finding, now_iso
from proofmesh.gitdiff import RepositoryState


OSV_QUERY_URL = "https://api.osv.dev/v1/query"
USER_AGENT = "sayanox-proofmesh/0.1.0 (local-first; +https://github.com/sayan9168/sayanox-proofmesh)"


def _parse_requirements(path: Path) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return pairs
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if "==" in line:
            name, ver = line.split("==", 1)
            name = name.strip()
            ver = ver.strip().split(";")[0].strip()
            if name and ver:
                pairs.append((name, ver))
    return pairs


def _parse_package_json(path: Path) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return out
    for section in ("dependencies", "devDependencies"):
        for name, ver in (data.get(section) or {}).items():
            ver_s = str(ver).lstrip("^~>=<")
            if ver_s and not ver_s.startswith("http"):
                out.append((name, ver_s, "npm"))
    return out


def query_osv(package: str, version: str, ecosystem: str, timeout: float = 15.0) -> list[dict[str, Any]]:
    payload = {
        "package": {"name": package, "ecosystem": ecosystem},
        "version": version,
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OSV_QUERY_URL,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return []
    return list(data.get("vulns") or [])


class OSVCheck:
    """Best-effort vulnerability lookup via the public OSV API. Opt-in / network required."""

    check_id = "osv"

    def __init__(
        self,
        *,
        enabled: bool = True,
        max_packages: int = 40,
        timeout_per_query: float = 12.0,
        offline: bool = False,
    ) -> None:
        self.enabled = enabled
        self.max_packages = max_packages
        self.timeout_per_query = timeout_per_query
        self.offline = offline

    def run(self, state: RepositoryState) -> CheckResult:
        started = now_iso()
        t0 = time.perf_counter()
        limitations = [
            "Uses public OSV API (https://osv.dev); requires network.",
            "Only exact == versions from requirements.txt and simple package.json entries.",
            "Not a complete SCA product; false negatives are expected.",
            "Query count is bounded to limit runtime and API load.",
        ]

        if self.offline or not self.enabled:
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.SKIPPED,
                started_at=started,
                finished_at=now_iso(),
                duration_ms=(time.perf_counter() - t0) * 1000,
                message="OSV check skipped (offline or disabled).",
                limitations=limitations,
            )

        packages: list[tuple[str, str, str, str]] = []
        root = state.root
        req = root / "requirements.txt"
        if req.is_file():
            for name, ver in _parse_requirements(req):
                packages.append((name, ver, "PyPI", "requirements.txt"))
        pkg_json = root / "package.json"
        if pkg_json.is_file():
            for name, ver, eco in _parse_package_json(pkg_json):
                packages.append((name, ver, eco, "package.json"))

        packages = packages[: self.max_packages]
        if not packages:
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.SKIPPED,
                started_at=started,
                finished_at=now_iso(),
                duration_ms=(time.perf_counter() - t0) * 1000,
                message="No pinned dependencies found for OSV query.",
                limitations=limitations,
            )

        findings: list[Finding] = []
        queried = 0
        errors = 0
        for name, ver, eco, source in packages:
            queried += 1
            try:
                vulns = query_osv(name, ver, eco, timeout=self.timeout_per_query)
            except Exception:  # noqa: BLE001
                errors += 1
                continue
            for v in vulns:
                vid = v.get("id") or "unknown"
                summary = (v.get("summary") or v.get("details") or "")[:200]
                severity = "medium"
                db = v.get("database_specific") or {}
                sev = db.get("severity") or db.get("severity_level")
                if isinstance(sev, str):
                    severity = sev.lower()
                findings.append(
                    Finding(
                        rule_id=f"osv.{vid}",
                        severity=severity if severity in ("critical", "high", "medium", "low") else "medium",
                        path=source,
                        message=f"{name}@{ver}: {vid} — {summary}",
                        remediation="Upgrade to a non-affected version; see https://osv.dev/vulnerability/" + str(vid),
                        extra={"package": name, "version": ver, "ecosystem": eco, "osv_id": vid},
                    )
                )

        status = CheckStatus.FAILED if findings else CheckStatus.PASSED
        msg = f"Queried {queried} package(s); {len(findings)} vulnerability finding(s); {errors} query error(s)."
        return CheckResult(
            check_id=self.check_id,
            status=status,
            findings=findings,
            started_at=started,
            finished_at=now_iso(),
            duration_ms=(time.perf_counter() - t0) * 1000,
            tool_version="osv.dev-api",
            exit_code=1 if findings else 0,
            message=msg,
            limitations=limitations,
            metadata={"packages_queried": queried, "query_errors": errors},
        )
