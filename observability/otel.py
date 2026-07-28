"""OpenTelemetry bootstrap (Private Beta)."""

from __future__ import annotations

import os
from typing import Any


def configure_telemetry(service_name: str = "ai-security-lab") -> dict[str, Any]:
    """Configure OTel when OTEL_EXPORTER_OTLP_ENDPOINT is set; otherwise no-op."""
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return {"enabled": False, "service_name": service_name}
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        trace.set_tracer_provider(provider)
        try:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

            # Instrumentation binds to the app from its own bootstrap when available.
            FastAPIInstrumentor.instrument()
        except ImportError:
            pass
        return {"enabled": True, "service_name": service_name, "endpoint": endpoint}
    except ImportError:
        return {"enabled": False, "service_name": service_name, "reason": "opentelemetry not installed"}
