"""FastAPI entrypoint for the local security app."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.api.jobs import JobNotFoundError, job_registry
from app.api.service import (
    DEFAULT_OPERATOR,
    DEFAULT_TIMEOUT_SECONDS,
    default_repo_root,
    run_active_auth_page_metadata_scan,
    run_active_http_methods_scan,
    run_active_route_exists_scan,
    run_active_security_header_delta_scan,
    run_active_xss_reflection_scan,
    run_passive_cookie_scan,
    run_passive_form_scan,
    run_passive_header_scan,
    start_active_bulk_route_exists_scan,
)


def configured_repo_root() -> Path:
    return Path(os.environ.get("APP_REPO_ROOT", default_repo_root())).resolve()


class HeaderScanRequest(BaseModel):
    target: str = Field(..., examples=["http://juice-shop.local:3000"])
    operator: str = Field(DEFAULT_OPERATOR, min_length=1)
    run_id: str | None = None
    timeout_seconds: int = Field(DEFAULT_TIMEOUT_SECONDS, ge=1, le=30)
    generate_report: bool = False


class CookieScanRequest(BaseModel):
    target: str = Field(..., examples=["http://juice-shop.local:3000"])
    operator: str = Field(DEFAULT_OPERATOR, min_length=1)
    run_id: str | None = None
    timeout_seconds: int = Field(DEFAULT_TIMEOUT_SECONDS, ge=1, le=30)
    generate_report: bool = False


class FormScanRequest(BaseModel):
    target: str = Field(..., examples=["http://juice-shop.local:3000"])
    operator: str = Field(DEFAULT_OPERATOR, min_length=1)
    run_id: str | None = None
    timeout_seconds: int = Field(DEFAULT_TIMEOUT_SECONDS, ge=1, le=30)
    generate_report: bool = False


class ActiveXssReflectionRequest(BaseModel):
    target: str = Field(..., examples=["http://juice-shop.local:3000"])
    operator: str = Field(DEFAULT_OPERATOR, min_length=1)
    run_id: str | None = None
    timeout_seconds: int = Field(DEFAULT_TIMEOUT_SECONDS, ge=1, le=30)
    rate_limit_per_minute: int | None = Field(default=None, ge=1, le=30)
    generate_report: bool = False


class ActiveHttpMethodsRequest(BaseModel):
    target: str = Field(..., examples=["http://juice-shop.local:3000"])
    operator: str = Field(DEFAULT_OPERATOR, min_length=1)
    run_id: str | None = None
    timeout_seconds: int = Field(DEFAULT_TIMEOUT_SECONDS, ge=1, le=30)
    rate_limit_per_minute: int | None = Field(default=None, ge=1, le=30)
    generate_report: bool = False


class ActiveRouteExistsRequest(BaseModel):
    target: str = Field(..., examples=["http://juice-shop.local:3000"])
    route_path: str = Field(..., examples=["/login"], min_length=1)
    operator: str = Field(DEFAULT_OPERATOR, min_length=1)
    run_id: str | None = None
    timeout_seconds: int = Field(DEFAULT_TIMEOUT_SECONDS, ge=1, le=30)
    rate_limit_per_minute: int | None = Field(default=None, ge=1, le=30)
    generate_report: bool = False


class ActiveSecurityHeaderDeltaRequest(BaseModel):
    target: str = Field(..., examples=["http://juice-shop.local:3000"])
    route_path: str = Field(..., examples=["/login"], min_length=1)
    operator: str = Field(DEFAULT_OPERATOR, min_length=1)
    run_id: str | None = None
    timeout_seconds: int = Field(DEFAULT_TIMEOUT_SECONDS, ge=1, le=30)
    rate_limit_per_minute: int | None = Field(default=None, ge=1, le=30)
    generate_report: bool = False


class ActiveAuthPageMetadataRequest(BaseModel):
    target: str = Field(..., examples=["http://juice-shop.local:3000"])
    route_path: str = Field(..., examples=["/login"], min_length=1)
    operator: str = Field(DEFAULT_OPERATOR, min_length=1)
    run_id: str | None = None
    timeout_seconds: int = Field(DEFAULT_TIMEOUT_SECONDS, ge=1, le=30)
    rate_limit_per_minute: int | None = Field(default=None, ge=1, le=30)
    generate_report: bool = False


class ActiveBulkRouteExistsRequest(BaseModel):
    target: str = Field(..., examples=["http://juice-shop.local:3000"])
    operator: str = Field(DEFAULT_OPERATOR, min_length=1)
    run_id: str | None = None
    timeout_seconds: int = Field(DEFAULT_TIMEOUT_SECONDS, ge=1, le=30)
    rate_limit_per_minute: int | None = Field(default=None, ge=1, le=30)
    generate_report: bool = False


class HealthResponse(BaseModel):
    status: str
    service: str


class JobResponse(BaseModel):
    job_id: str
    tool: str
    target: str
    operator: str
    status: str
    created_at: str
    started_at: str | None = None
    ended_at: str | None = None
    result: dict[str, Any] | None = None
    error: str | None = None


app = FastAPI(
    title="AI Security Lab API",
    version="0.1.0",
    description="Local-only API for guarded security lab tools.",
)

app.mount("/ui", StaticFiles(directory=configured_repo_root() / "app" / "ui", html=True), name="ui")


@app.get("/", include_in_schema=False)
def dashboard() -> RedirectResponse:
    return RedirectResponse(url="/ui/")


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", service="security-app")


@app.get("/jobs/{job_id}", response_model=JobResponse)
def get_job(job_id: str) -> dict[str, Any]:
    try:
        return job_registry.snapshot(job_id)
    except JobNotFoundError as exc:
        raise HTTPException(status_code=404, detail="job not found") from exc


@app.post("/jobs/{job_id}/cancel", response_model=JobResponse)
def cancel_job(job_id: str) -> dict[str, Any]:
    try:
        return job_registry.cancel_job(job_id)
    except JobNotFoundError as exc:
        raise HTTPException(status_code=404, detail="job not found") from exc


@app.post("/scan/passive/headers")
def scan_passive_headers(request: HeaderScanRequest) -> dict[str, Any]:
    return run_passive_header_scan(
        target=request.target,
        operator=request.operator,
        run_id=request.run_id,
        timeout_seconds=request.timeout_seconds,
        repo_root=configured_repo_root(),
        generate_report=request.generate_report,
    )


@app.post("/scan/passive/cookies")
def scan_passive_cookies(request: CookieScanRequest) -> dict[str, Any]:
    return run_passive_cookie_scan(
        target=request.target,
        operator=request.operator,
        run_id=request.run_id,
        timeout_seconds=request.timeout_seconds,
        repo_root=configured_repo_root(),
        generate_report=request.generate_report,
    )


@app.post("/scan/passive/forms")
def scan_passive_forms(request: FormScanRequest) -> dict[str, Any]:
    return run_passive_form_scan(
        target=request.target,
        operator=request.operator,
        run_id=request.run_id,
        timeout_seconds=request.timeout_seconds,
        repo_root=configured_repo_root(),
        generate_report=request.generate_report,
    )


@app.post("/scan/active/xss-reflection")
def scan_active_xss_reflection(request: ActiveXssReflectionRequest) -> dict[str, Any]:
    return run_active_xss_reflection_scan(
        target=request.target,
        operator=request.operator,
        run_id=request.run_id,
        timeout_seconds=request.timeout_seconds,
        rate_limit_per_minute=request.rate_limit_per_minute,
        repo_root=configured_repo_root(),
        generate_report=request.generate_report,
    )


@app.post("/scan/active/http-methods")
def scan_active_http_methods(request: ActiveHttpMethodsRequest) -> dict[str, Any]:
    return run_active_http_methods_scan(
        target=request.target,
        operator=request.operator,
        run_id=request.run_id,
        timeout_seconds=request.timeout_seconds,
        rate_limit_per_minute=request.rate_limit_per_minute,
        repo_root=configured_repo_root(),
        generate_report=request.generate_report,
    )


@app.post("/scan/active/route-exists")
def scan_active_route_exists(request: ActiveRouteExistsRequest) -> dict[str, Any]:
    return run_active_route_exists_scan(
        target=request.target,
        route_path=request.route_path,
        operator=request.operator,
        run_id=request.run_id,
        timeout_seconds=request.timeout_seconds,
        rate_limit_per_minute=request.rate_limit_per_minute,
        repo_root=configured_repo_root(),
        generate_report=request.generate_report,
    )


@app.post("/scan/active/security-header-delta")
def scan_active_security_header_delta(request: ActiveSecurityHeaderDeltaRequest) -> dict[str, Any]:
    return run_active_security_header_delta_scan(
        target=request.target,
        route_path=request.route_path,
        operator=request.operator,
        run_id=request.run_id,
        timeout_seconds=request.timeout_seconds,
        rate_limit_per_minute=request.rate_limit_per_minute,
        repo_root=configured_repo_root(),
        generate_report=request.generate_report,
    )


@app.post("/scan/active/auth-page-metadata")
def scan_active_auth_page_metadata(request: ActiveAuthPageMetadataRequest) -> dict[str, Any]:
    return run_active_auth_page_metadata_scan(
        target=request.target,
        route_path=request.route_path,
        operator=request.operator,
        run_id=request.run_id,
        timeout_seconds=request.timeout_seconds,
        rate_limit_per_minute=request.rate_limit_per_minute,
        repo_root=configured_repo_root(),
        generate_report=request.generate_report,
    )


@app.post("/scan/active/bulk-route-exists", response_model=JobResponse)
def scan_active_bulk_route_exists(request: ActiveBulkRouteExistsRequest) -> dict[str, Any]:
    return start_active_bulk_route_exists_scan(
        target=request.target,
        operator=request.operator,
        run_id=request.run_id,
        timeout_seconds=request.timeout_seconds,
        rate_limit_per_minute=request.rate_limit_per_minute,
        repo_root=configured_repo_root(),
        generate_report=request.generate_report,
        start_thread=True,
    )
