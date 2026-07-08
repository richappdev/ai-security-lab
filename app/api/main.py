"""FastAPI entrypoint for the local security app."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from app.api.service import (
    DEFAULT_OPERATOR,
    DEFAULT_TIMEOUT_SECONDS,
    default_repo_root,
    run_active_http_methods_scan,
    run_active_xss_reflection_scan,
    run_passive_header_scan,
)


def configured_repo_root() -> Path:
    return Path(os.environ.get("APP_REPO_ROOT", default_repo_root())).resolve()


class HeaderScanRequest(BaseModel):
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


class HealthResponse(BaseModel):
    status: str
    service: str


app = FastAPI(
    title="AI Security Lab API",
    version="0.1.0",
    description="Local-only API for guarded security lab tools.",
)


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", service="security-app")


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
