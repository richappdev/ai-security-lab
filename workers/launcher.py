"""Disposable worker launchers with a deny-by-default execution boundary."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class WorkerLaunchRequest:
    run_id: str
    image: str
    capability: str
    command: list[str] = field(default_factory=list)
    cpu_limit: str = "1.0"
    memory_limit: str = "512m"
    timeout_seconds: int = 600
    network: str = "none"


@dataclass
class WorkerLaunchResult:
    container_id: str | None
    command: list[str]
    started: bool


class WorkerLauncher(Protocol):
    def launch(self, request: WorkerLaunchRequest, *, dry_run: bool = False) -> WorkerLaunchResult:
        ...

    def terminate(self, container_id: str, *, timeout_seconds: int = 10) -> None:
        ...


class DockerWorkerLauncher:
    """Launch one non-root, read-only, resource-bounded container per run."""

    def build_command(self, request: WorkerLaunchRequest) -> list[str]:
        if request.network != "none" and not request.network.startswith("aisec-run-"):
            raise ValueError("worker network must be none or a reviewed per-run network")
        return [
            "docker",
            "run",
            "--detach",
            "--rm",
            "--read-only",
            "--user",
            "65532:65532",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--network",
            request.network,
            "--cpus",
            request.cpu_limit,
            "--memory",
            request.memory_limit,
            "--pids-limit",
            "128",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            "--label",
            f"aisec.run_id={request.run_id}",
            "--env",
            f"RUN_ID={request.run_id}",
            "--env",
            f"RUN_CAPABILITY={request.capability}",
            request.image,
            *request.command,
        ]

    def launch(self, request: WorkerLaunchRequest, *, dry_run: bool = False) -> WorkerLaunchResult:
        command = self.build_command(request)
        if dry_run:
            # Do not expose the capability in diagnostics.
            sanitized = [
                "[REDACTED]" if item == f"RUN_CAPABILITY={request.capability}" else item
                for item in command
            ]
            return WorkerLaunchResult(container_id=None, command=sanitized, started=False)
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        return WorkerLaunchResult(
            container_id=completed.stdout.strip(),
            command=["docker", "run", "[REDACTED]"],
            started=True,
        )

    def terminate(self, container_id: str, *, timeout_seconds: int = 10) -> None:
        if not container_id or any(character.isspace() for character in container_id):
            raise ValueError("invalid container id")
        subprocess.run(
            ["docker", "stop", "--time", str(timeout_seconds), container_id],
            capture_output=True,
            text=True,
            timeout=timeout_seconds + 10,
            check=True,
        )
