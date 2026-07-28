"""Correlation IDs, structured request metrics, and beta readiness checks."""

from __future__ import annotations

import json
import logging
import os
import time
from collections import Counter
from contextvars import ContextVar
from typing import Any
from uuid import uuid4

from fastapi import Request

correlation_id: ContextVar[str | None] = ContextVar("correlation_id", default=None)
REQUESTS = Counter()
DOMAIN_METRICS = Counter()
LATENCY_MS: list[float] = []
LOGGER = logging.getLogger("aisec.requests")


async def request_observability_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Correlation-ID") or str(uuid4())
    token = correlation_id.set(request_id)
    started = time.perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        response.headers["X-Correlation-ID"] = request_id
        return response
    finally:
        latency = (time.perf_counter() - started) * 1000
        REQUESTS[(request.method, request.url.path, status_code)] += 1
        LATENCY_MS.append(latency)
        if len(LATENCY_MS) > 10000:
            del LATENCY_MS[:5000]
        LOGGER.info(
            json.dumps(
                {
                    "event": "http.request",
                    "correlation_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": status_code,
                    "latency_ms": round(latency, 2),
                }
            )
        )
        correlation_id.reset(token)


def metrics_snapshot() -> dict[str, Any]:
    ordered = sorted(LATENCY_MS)
    p95 = ordered[int(len(ordered) * 0.95)] if ordered else 0
    return {
        "requests": [
            {"method": key[0], "path": key[1], "status": key[2], "count": count}
            for key, count in REQUESTS.items()
        ],
        "latency_ms": {
            "count": len(ordered),
            "p95": round(p95, 2),
            "max": round(max(ordered), 2) if ordered else 0,
        },
        "domain": dict(DOMAIN_METRICS),
    }


def record_metric(name: str, value: int = 1) -> None:
    DOMAIN_METRICS[name] += value


def validate_beta_configuration() -> None:
    environment = os.environ.get("DEPLOYMENT_ENV", "local").lower()
    if environment not in {"beta", "production"}:
        return
    missing = []
    if os.environ.get("ALLOW_DEV_AUTH", "false").lower() in {"1", "true", "yes", "on"}:
        missing.append("ALLOW_DEV_AUTH must be false")
    if os.environ.get("ALLOW_LEGACY_SYNC_RUNS", "true").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        missing.append("ALLOW_LEGACY_SYNC_RUNS must be false")
    for name in (
        "DATABASE_URL",
        "OIDC_ISSUER",
        "OIDC_AUDIENCE",
        "TEMPORAL_ADDRESS",
        "MINIO_ENDPOINT",
        "MINIO_BUCKET",
        "MINIO_ACCESS_KEY",
        "MINIO_SECRET_KEY",
        "EVIDENCE_ED25519_PRIVATE_KEY",
        "EVIDENCE_SIGNING_KEY_ID",
        "CAPABILITY_ED25519_PRIVATE_KEY",
        "CAPABILITY_SIGNING_KEY_ID",
        "INTEGRATION_ENCRYPTION_KEY",
        "OPERATIONS_TOKEN",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
    ):
        if not os.environ.get(name):
            missing.append(name)
    if not os.environ.get("DATABASE_URL", "").startswith("postgresql"):
        missing.append("DATABASE_URL must use PostgreSQL")
    if os.environ.get("TEMPORAL_TLS", "false").lower() not in {"1", "true", "yes", "on"}:
        missing.append("TEMPORAL_TLS must be true")
    if not (
        os.environ.get("TEMPORAL_API_KEY")
        or (
            os.environ.get("TEMPORAL_CLIENT_CERT")
            and os.environ.get("TEMPORAL_CLIENT_KEY")
        )
    ):
        missing.append("Temporal Cloud authentication is required")
    if os.environ.get("EVIDENCE_ED25519_PRIVATE_KEY") == os.environ.get(
        "CAPABILITY_ED25519_PRIVATE_KEY"
    ):
        missing.append("evidence and capability signing keys must be distinct")
    if missing:
        raise RuntimeError("unsafe beta configuration: " + ", ".join(missing))
