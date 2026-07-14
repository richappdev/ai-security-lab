"""Service helpers that connect API requests to guarded tools."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable
from urllib.request import urlopen
from uuid import uuid4

from reports.writer import write_markdown_report
from tools.active.auth_page_metadata_check import lab_auth_page_metadata_check
from tools.active.http_methods_check import lab_http_methods_check
from tools.active.route_exists_check import lab_route_exists_check
from tools.active.security_header_delta_check import lab_security_header_delta_check
from tools.active.xss_lab_check import lab_xss_reflection_check
from tools.passive.cookies import inspect_cookies
from tools.passive.forms import discover_forms
from tools.passive.headers import inspect_headers


DEFAULT_OPERATOR = "local-user"
DEFAULT_TIMEOUT_SECONDS = 10


def default_repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def new_run_id() -> str:
    return f"run-{uuid4()}"


def run_passive_header_scan(
    target: str,
    operator: str = DEFAULT_OPERATOR,
    run_id: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    repo_root: str | Path | None = None,
    opener: Callable[..., Any] = urlopen,
    generate_report: bool = False,
) -> dict[str, Any]:
    actual_run_id = run_id or new_run_id()
    actual_repo_root = repo_root or default_repo_root()
    result = inspect_headers(
        target=target,
        operator=operator or DEFAULT_OPERATOR,
        run_id=actual_run_id,
        timeout_seconds=timeout_seconds,
        repo_root=actual_repo_root,
        opener=opener,
    )
    if generate_report:
        result["report"] = write_markdown_report(
            result,
            operator=operator or DEFAULT_OPERATOR,
            run_id=actual_run_id,
            repo_root=actual_repo_root,
        )
    return result


def run_passive_cookie_scan(
    target: str,
    operator: str = DEFAULT_OPERATOR,
    run_id: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    repo_root: str | Path | None = None,
    opener: Callable[..., Any] = urlopen,
    generate_report: bool = False,
) -> dict[str, Any]:
    actual_run_id = run_id or new_run_id()
    actual_repo_root = repo_root or default_repo_root()
    result = inspect_cookies(
        target=target,
        operator=operator or DEFAULT_OPERATOR,
        run_id=actual_run_id,
        timeout_seconds=timeout_seconds,
        repo_root=actual_repo_root,
        opener=opener,
    )
    if generate_report:
        result["report"] = write_markdown_report(
            result,
            operator=operator or DEFAULT_OPERATOR,
            run_id=actual_run_id,
            repo_root=actual_repo_root,
        )
    return result


def run_passive_form_scan(
    target: str,
    operator: str = DEFAULT_OPERATOR,
    run_id: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    repo_root: str | Path | None = None,
    opener: Callable[..., Any] = urlopen,
    generate_report: bool = False,
) -> dict[str, Any]:
    actual_run_id = run_id or new_run_id()
    actual_repo_root = repo_root or default_repo_root()
    result = discover_forms(
        target=target,
        operator=operator or DEFAULT_OPERATOR,
        run_id=actual_run_id,
        timeout_seconds=timeout_seconds,
        repo_root=actual_repo_root,
        opener=opener,
    )
    if generate_report:
        result["report"] = write_markdown_report(
            result,
            operator=operator or DEFAULT_OPERATOR,
            run_id=actual_run_id,
            repo_root=actual_repo_root,
        )
    return result


def run_active_xss_reflection_scan(
    target: str,
    operator: str = DEFAULT_OPERATOR,
    run_id: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    rate_limit_per_minute: int | None = None,
    repo_root: str | Path | None = None,
    opener: Callable[..., Any] = urlopen,
    generate_report: bool = False,
) -> dict[str, Any]:
    actual_run_id = run_id or new_run_id()
    actual_repo_root = repo_root or default_repo_root()
    result = lab_xss_reflection_check(
        target=target,
        operator=operator or DEFAULT_OPERATOR,
        run_id=actual_run_id,
        timeout_seconds=timeout_seconds,
        rate_limit_per_minute=rate_limit_per_minute,
        repo_root=actual_repo_root,
        opener=opener,
    )
    if generate_report:
        result["report"] = write_markdown_report(
            result,
            operator=operator or DEFAULT_OPERATOR,
            run_id=actual_run_id,
            repo_root=actual_repo_root,
        )
    return result


def run_active_http_methods_scan(
    target: str,
    operator: str = DEFAULT_OPERATOR,
    run_id: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    rate_limit_per_minute: int | None = None,
    repo_root: str | Path | None = None,
    opener: Callable[..., Any] = urlopen,
    generate_report: bool = False,
) -> dict[str, Any]:
    actual_run_id = run_id or new_run_id()
    actual_repo_root = repo_root or default_repo_root()
    result = lab_http_methods_check(
        target=target,
        operator=operator or DEFAULT_OPERATOR,
        run_id=actual_run_id,
        timeout_seconds=timeout_seconds,
        rate_limit_per_minute=rate_limit_per_minute,
        repo_root=actual_repo_root,
        opener=opener,
    )
    if generate_report:
        result["report"] = write_markdown_report(
            result,
            operator=operator or DEFAULT_OPERATOR,
            run_id=actual_run_id,
            repo_root=actual_repo_root,
        )
    return result


def run_active_route_exists_scan(
    target: str,
    route_path: str,
    operator: str = DEFAULT_OPERATOR,
    run_id: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    rate_limit_per_minute: int | None = None,
    repo_root: str | Path | None = None,
    opener: Callable[..., Any] = urlopen,
    generate_report: bool = False,
) -> dict[str, Any]:
    actual_run_id = run_id or new_run_id()
    actual_repo_root = repo_root or default_repo_root()
    result = lab_route_exists_check(
        target=target,
        route_path=route_path,
        operator=operator or DEFAULT_OPERATOR,
        run_id=actual_run_id,
        timeout_seconds=timeout_seconds,
        rate_limit_per_minute=rate_limit_per_minute,
        repo_root=actual_repo_root,
        opener=opener,
    )
    if generate_report:
        result["report"] = write_markdown_report(
            result,
            operator=operator or DEFAULT_OPERATOR,
            run_id=actual_run_id,
            repo_root=actual_repo_root,
        )
    return result


def run_active_security_header_delta_scan(
    target: str,
    route_path: str,
    operator: str = DEFAULT_OPERATOR,
    run_id: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    rate_limit_per_minute: int | None = None,
    repo_root: str | Path | None = None,
    opener: Callable[..., Any] = urlopen,
    generate_report: bool = False,
) -> dict[str, Any]:
    actual_run_id = run_id or new_run_id()
    actual_repo_root = repo_root or default_repo_root()
    result = lab_security_header_delta_check(
        target=target,
        route_path=route_path,
        operator=operator or DEFAULT_OPERATOR,
        run_id=actual_run_id,
        timeout_seconds=timeout_seconds,
        rate_limit_per_minute=rate_limit_per_minute,
        repo_root=actual_repo_root,
        opener=opener,
    )
    if generate_report:
        result["report"] = write_markdown_report(
            result,
            operator=operator or DEFAULT_OPERATOR,
            run_id=actual_run_id,
            repo_root=actual_repo_root,
        )
    return result


def run_active_auth_page_metadata_scan(
    target: str,
    route_path: str,
    operator: str = DEFAULT_OPERATOR,
    run_id: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    rate_limit_per_minute: int | None = None,
    repo_root: str | Path | None = None,
    opener: Callable[..., Any] = urlopen,
    generate_report: bool = False,
) -> dict[str, Any]:
    actual_run_id = run_id or new_run_id()
    actual_repo_root = repo_root or default_repo_root()
    result = lab_auth_page_metadata_check(
        target=target,
        route_path=route_path,
        operator=operator or DEFAULT_OPERATOR,
        run_id=actual_run_id,
        timeout_seconds=timeout_seconds,
        rate_limit_per_minute=rate_limit_per_minute,
        repo_root=actual_repo_root,
        opener=opener,
    )
    if generate_report:
        result["report"] = write_markdown_report(
            result,
            operator=operator or DEFAULT_OPERATOR,
            run_id=actual_run_id,
            repo_root=actual_repo_root,
        )
    return result
