"""Shared Temporal Cloud client configuration."""

from __future__ import annotations

import base64
import os
from typing import Any, Mapping


def _secret_bytes(value: str | None) -> bytes | None:
    if not value:
        return None
    expanded = value.replace("\\n", "\n")
    if "-----BEGIN" in expanded:
        return expanded.encode("utf-8")
    try:
        return base64.b64decode(expanded, validate=True)
    except ValueError:
        return expanded.encode("utf-8")


def temporal_connection_settings(
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    env = os.environ if environment is None else environment
    address = env.get("TEMPORAL_ADDRESS") or env.get("TEMPORAL_HOST")
    if not address:
        raise RuntimeError("TEMPORAL_ADDRESS is required")
    tls_enabled = env.get("TEMPORAL_TLS", "true").lower() in {"1", "true", "yes", "on"}
    client_cert = _secret_bytes(env.get("TEMPORAL_CLIENT_CERT"))
    client_key = _secret_bytes(env.get("TEMPORAL_CLIENT_KEY"))
    root_ca = _secret_bytes(env.get("TEMPORAL_SERVER_ROOT_CA"))
    if bool(client_cert) != bool(client_key):
        raise RuntimeError("TEMPORAL_CLIENT_CERT and TEMPORAL_CLIENT_KEY must be configured together")
    tls: Any = tls_enabled
    if client_cert and client_key:
        from temporalio.service import TLSConfig

        tls = TLSConfig(
            server_root_ca_cert=root_ca,
            domain=env.get("TEMPORAL_TLS_DOMAIN") or None,
            client_cert=client_cert,
            client_private_key=client_key,
        )
    return {
        "target_host": address,
        "namespace": env.get("TEMPORAL_NAMESPACE", "default"),
        "api_key": env.get("TEMPORAL_API_KEY") or None,
        "tls": tls,
    }


async def connect_temporal(environment: Mapping[str, str] | None = None):
    from temporalio.client import Client

    return await Client.connect(**temporal_connection_settings(environment))
