"""Verification orchestrator — runs configured checks and collects results."""

from __future__ import annotations

import time
from typing import Callable

from proofmesh.checks.base import CheckResult, CheckStatus, now_iso
from proofmesh.checks.inventory import DependencyInventoryCheck, FileInventoryCheck
from proofmesh.checks.risky import RiskyCodeCheck
from proofmesh.checks.secrets import SecretsCheck
from proofmesh.config import ProofMeshConfig
from proofmesh.gitdiff import RepositoryState, inspect_repository


CheckRunner = Callable[[RepositoryState], CheckResult]


DEFAULT_CHECKS: dict[str, CheckRunner] = {
    "file_inventory": lambda s: FileInventoryCheck().run(s),
    "secrets": lambda s: SecretsCheck().run(s),
    "risky_code": lambda s: RiskyCodeCheck().run(s),
    "dependency_inventory": lambda s: DependencyInventoryCheck().run(s),
}


class Orchestrator:
    """Execute a set of checks against a repository state."""

    def __init__(self, config: ProofMeshConfig | None = None) -> None:
        self.config = config
        self._runners = dict(DEFAULT_CHECKS)

    def register(self, check_id: str, runner: CheckRunner) -> None:
        self._runners[check_id] = runner

    def run(
        self,
        state: RepositoryState | None = None,
        *,
        path=None,
        only: list[str] | None = None,
    ) -> tuple[RepositoryState, list[CheckResult]]:
        if state is None:
            state = inspect_repository(path)

        selected = only or list(self._runners.keys())
        results: list[CheckResult] = []

        for check_id in selected:
            cfg = None
            if self.config and check_id in self.config.checks:
                cfg = self.config.checks[check_id]
                if not cfg.enabled:
                    results.append(
                        CheckResult(
                            check_id=check_id,
                            status=CheckStatus.SKIPPED,
                            started_at=now_iso(),
                            finished_at=now_iso(),
                            message="Disabled in configuration",
                        )
                    )
                    continue

            runner = self._runners.get(check_id)
            if runner is None:
                results.append(
                    CheckResult(
                        check_id=check_id,
                        status=CheckStatus.ERRORED,
                        started_at=now_iso(),
                        finished_at=now_iso(),
                        message=f"Unknown check: {check_id}",
                        exit_code=2,
                    )
                )
                continue

            timeout = cfg.timeout_seconds if cfg else 60.0
            t0 = time.perf_counter()
            try:
                result = runner(state)
                elapsed = time.perf_counter() - t0
                if elapsed > timeout:
                    result.status = CheckStatus.ERRORED
                    result.message = f"Check exceeded timeout ({timeout}s)"
                    result.exit_code = 124
                results.append(result)
            except Exception as exc:  # noqa: BLE001
                results.append(
                    CheckResult(
                        check_id=check_id,
                        status=CheckStatus.ERRORED,
                        started_at=now_iso(),
                        finished_at=now_iso(),
                        duration_ms=(time.perf_counter() - t0) * 1000,
                        message=f"Check raised exception: {type(exc).__name__}: {exc}",
                        exit_code=2,
                    )
                )

        return state, results
