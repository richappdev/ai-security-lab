"""Load and query tools/manifest.yml at runtime."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ManifestError(ValueError):
    """Raised when the tool manifest is missing or invalid."""


@dataclass(frozen=True)
class ToolManifestEntry:
    name: str
    category: str
    risk: str
    entrypoint: str
    allowed_targets_file: str
    requires_network: bool
    timeout_seconds: int
    audit_required: bool
    description: str

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> ToolManifestEntry:
        required = (
            "name",
            "category",
            "risk",
            "entrypoint",
            "allowed_targets_file",
            "requires_network",
            "timeout_seconds",
            "audit_required",
            "description",
        )
        missing = [key for key in required if key not in raw]
        if missing:
            raise ManifestError(f"tool entry missing fields: {', '.join(missing)}")

        timeout = raw["timeout_seconds"]
        if not isinstance(timeout, int) or timeout < 1:
            raise ManifestError(f"timeout_seconds must be a positive integer for tool {raw.get('name')}")

        return cls(
            name=str(raw["name"]),
            category=str(raw["category"]),
            risk=str(raw["risk"]),
            entrypoint=str(raw["entrypoint"]),
            allowed_targets_file=str(raw["allowed_targets_file"]),
            requires_network=bool(raw["requires_network"]),
            timeout_seconds=timeout,
            audit_required=bool(raw["audit_required"]),
            description=str(raw["description"]),
        )


def _parse_scalar(value: str) -> Any:
    normalized = value.strip()
    if normalized.lower() == "true":
        return True
    if normalized.lower() == "false":
        return False
    try:
        return int(normalized)
    except ValueError:
        return normalized


def _parse_manifest_yaml(text: str) -> dict[str, Any]:
    version: Any = None
    tools: list[dict[str, Any]] = []
    current_tool: dict[str, Any] | None = None
    in_tools = False

    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue

        indent = len(raw_line) - len(raw_line.lstrip(" "))
        stripped = raw_line.strip()

        if indent == 0:
            if stripped.startswith("version:"):
                version = _parse_scalar(stripped.split(":", 1)[1])
                in_tools = False
                current_tool = None
            elif stripped == "tools:" or stripped.startswith("tools:"):
                in_tools = True
                current_tool = None
            else:
                raise ManifestError(f"unexpected top-level key in manifest: {stripped}")
            continue

        if not in_tools:
            raise ManifestError(f"manifest line is outside tools section: {raw_line}")

        if stripped.startswith("- "):
            current_tool = {}
            tools.append(current_tool)
            rest = stripped[2:].strip()
            if ":" not in rest:
                raise ManifestError(f"invalid tool list item: {raw_line}")
            key, value = rest.split(":", 1)
            current_tool[key.strip()] = _parse_scalar(value)
            continue

        if current_tool is None:
            raise ManifestError(f"tool field appears before a list item: {raw_line}")
        if ":" not in stripped:
            raise ManifestError(f"invalid tool field: {raw_line}")

        key, value = stripped.split(":", 1)
        current_tool[key.strip()] = _parse_scalar(value)

    if version is None:
        raise ManifestError("manifest version is missing")
    if not tools:
        raise ManifestError("manifest tools list is empty")

    return {"version": version, "tools": tools}


def default_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_tool_manifest(
    repo_root: str | Path | None = None,
    manifest_file: str | Path = "tools/manifest.yml",
) -> list[ToolManifestEntry]:
    root = Path(repo_root).resolve() if repo_root is not None else default_repo_root()
    manifest_path = root / manifest_file
    if not manifest_path.exists():
        raise ManifestError(f"tool manifest is missing: {manifest_path}")

    raw = _parse_manifest_yaml(manifest_path.read_text(encoding="utf-8"))
    entries = [ToolManifestEntry.from_mapping(item) for item in raw["tools"]]
    names = [entry.name for entry in entries]
    if len(names) != len(set(names)):
        raise ManifestError("tool manifest contains duplicate tool names")
    return entries


def get_tool_by_name(
    name: str,
    repo_root: str | Path | None = None,
    manifest_file: str | Path = "tools/manifest.yml",
) -> ToolManifestEntry:
    for entry in load_tool_manifest(repo_root=repo_root, manifest_file=manifest_file):
        if entry.name == name:
            return entry
    raise ManifestError(f"unknown tool in manifest: {name}")


def tool_map(
    repo_root: str | Path | None = None,
    manifest_file: str | Path = "tools/manifest.yml",
) -> dict[str, ToolManifestEntry]:
    return {
        entry.name: entry
        for entry in load_tool_manifest(repo_root=repo_root, manifest_file=manifest_file)
    }
