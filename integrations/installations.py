"""Encrypted organization-scoped CI integration installations."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.fernet import Fernet
from sqlalchemy.orm import Session

from persistence import IntegrationInstallation, new_id
from persistence.repositories import (
    AuthorizationError,
    Principal,
    audit_authz,
    get_project,
    require_role,
)


def _fernet() -> Fernet:
    configured = os.environ.get("INTEGRATION_ENCRYPTION_KEY")
    if configured:
        return Fernet(configured.encode("ascii"))
    local_seed = os.environ.get("EVIDENCE_SIGNING_KEY", "local-dev-evidence-key").encode()
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(local_seed).digest()))


def create_installation(
    session: Session,
    principal: Principal,
    *,
    provider: str,
    config: dict[str, Any],
    project_id: str | None = None,
) -> IntegrationInstallation:
    require_role(principal, admin=True)
    if provider not in {"github", "gitlab"}:
        raise ValueError("provider must be github or gitlab")
    required = (
        {"owner", "repo", "token"} if provider == "github" else {"project_id", "token"}
    )
    missing = sorted(key for key in required if not config.get(key))
    if missing:
        raise ValueError("missing integration settings: " + ", ".join(missing))
    if project_id:
        get_project(session, principal, project_id)
    encrypted = _fernet().encrypt(
        json.dumps(config, sort_keys=True).encode("utf-8")
    ).decode("ascii")
    row = IntegrationInstallation(
        id=new_id(),
        organization_id=principal.organization_id,
        project_id=project_id,
        provider=provider,
        encrypted_config=encrypted,
    )
    session.add(row)
    audit_authz(
        session,
        principal=principal,
        action="integration.install",
        resource_type="integration_installation",
        resource_id=row.id,
        allowed=True,
        detail={"provider": provider, "project_id": project_id},
    )
    return row


def installation_config(
    session: Session,
    principal: Principal,
    installation_id: str,
) -> tuple[IntegrationInstallation, dict[str, Any]]:
    row = session.get(IntegrationInstallation, installation_id)
    if row is None or row.organization_id != principal.organization_id:
        raise AuthorizationError("integration installation not found in organization")
    decrypted = _fernet().decrypt(row.encrypted_config.encode("ascii"))
    return row, json.loads(decrypted)
