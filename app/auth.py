"""OIDC / local principal resolution for the control plane."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import Depends, Header, HTTPException, Request
from jose import JWTError, jwt
from jose.backends import RSAKey
from sqlalchemy.orm import Session

from persistence import SessionLocal, init_db, is_postgres, make_engine
from sqlalchemy import text
from persistence.repositories import AuthorizationError, Principal, resolve_principal


@dataclass
class AuthContext:
    user_sub: str
    claims: dict[str, Any]
    auth_mode: str = "dev"


_jwks_cache: dict[str, Any] | None = None
_oidc_metadata_cache: dict[str, Any] | None = None
_engine = None


def get_engine():
    global _engine
    if _engine is None:
        _engine = make_engine()
        if os.environ.get("DEPLOYMENT_ENV", "local").lower() in {"beta", "production"}:
            # Hosted environments are migrated explicitly with Alembic; silently
            # creating an unprotected schema would bypass migration-managed RLS.
            SessionLocal.configure(bind=_engine)
        else:
            init_db(_engine)
    return _engine


def reset_engine_for_tests(engine) -> None:
    global _engine
    global _jwks_cache
    global _oidc_metadata_cache
    _engine = engine
    _jwks_cache = None
    _oidc_metadata_cache = None
    init_db(engine)


def _organization_from_path(request: Request) -> str | None:
    parts = [part for part in request.url.path.split("/") if part]
    try:
        marker = parts.index("organizations")
        return parts[marker + 1]
    except (ValueError, IndexError):
        return None


def get_db(request: Request) -> Session:
    get_engine()
    session = SessionLocal()
    try:
        organization_id = _organization_from_path(request)
        if organization_id and is_postgres(str(session.get_bind().url)):
            session.execute(
                text("SELECT set_config('app.organization_id', :oid, true)"),
                {"oid": organization_id},
            )
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def oidc_enabled() -> bool:
    return bool(os.environ.get("OIDC_ISSUER"))


def allow_dev_auth() -> bool:
    """X-User-Sub / opaque bearer allowed only when explicitly enabled (default on for local/tests)."""
    raw = os.environ.get("ALLOW_DEV_AUTH", "true").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def auth_config() -> dict[str, Any]:
    issuer = os.environ.get("OIDC_ISSUER", "").rstrip("/")
    return {
        "oidc_enabled": oidc_enabled(),
        "allow_dev_auth": allow_dev_auth(),
        "issuer": issuer or None,
        "audience": os.environ.get("OIDC_AUDIENCE") or None,
        "discovery_url": f"{issuer}/.well-known/openid-configuration" if issuer else None,
        "jwks_url": os.environ.get("OIDC_JWKS_URL"),
        "token_url": os.environ.get("OIDC_TOKEN_URL"),
        "auth_url": os.environ.get("OIDC_AUTH_URL"),
        "client_id": os.environ.get("OIDC_CLIENT_ID", "aisec-ui"),
    }


def _load_oidc_metadata() -> dict[str, Any]:
    global _oidc_metadata_cache
    if _oidc_metadata_cache is not None:
        return _oidc_metadata_cache
    issuer = os.environ["OIDC_ISSUER"].rstrip("/")
    response = httpx.get(f"{issuer}/.well-known/openid-configuration", timeout=10.0)
    response.raise_for_status()
    metadata = response.json()
    if metadata.get("issuer", "").rstrip("/") != issuer:
        raise HTTPException(status_code=401, detail="OIDC discovery issuer mismatch")
    _oidc_metadata_cache = metadata
    return metadata


def _load_jwks() -> dict[str, Any]:
    global _jwks_cache
    if _jwks_cache is not None:
        return _jwks_cache
    issuer = os.environ["OIDC_ISSUER"].rstrip("/")
    jwks_url = os.environ.get("OIDC_JWKS_URL")
    if not jwks_url:
        jwks_url = str(_load_oidc_metadata()["jwks_uri"])
    response = httpx.get(jwks_url, timeout=10.0)
    response.raise_for_status()
    _jwks_cache = response.json()
    return _jwks_cache


def _rsa_key_for_token(token: str):
    jwks = _load_jwks()
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    allowed_algorithms = {
        value.strip()
        for value in os.environ.get("OIDC_ALLOWED_ALGORITHMS", "RS256").split(",")
        if value.strip()
    }
    if header.get("alg") not in allowed_algorithms:
        raise KeyError("token signing algorithm is not allowed")
    for key_data in jwks.get("keys", []):
        if kid is None or key_data.get("kid") == kid:
            return RSAKey(key_data, algorithm=header.get("alg", "RS256"))
    raise KeyError(f"jwks key not found for kid={kid}")


def decode_bearer_token(token: str) -> AuthContext:
    if not oidc_enabled():
        if not allow_dev_auth():
            raise HTTPException(status_code=401, detail="OIDC required; set OIDC_ISSUER")
        return AuthContext(user_sub=token, claims={"sub": token}, auth_mode="dev")
    try:
        key = _rsa_key_for_token(token)
        claims = jwt.decode(
            token,
            key,
            algorithms=[jwt.get_unverified_header(token).get("alg", "RS256")],
            audience=os.environ.get("OIDC_AUDIENCE"),
            issuer=os.environ.get("OIDC_ISSUER"),
            options={"verify_aud": bool(os.environ.get("OIDC_AUDIENCE"))},
        )
        return AuthContext(user_sub=str(claims["sub"]), claims=claims, auth_mode="oidc")
    except (JWTError, StopIteration, KeyError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=401, detail=f"invalid token: {exc}") from exc


def get_auth_context(
    authorization: str | None = Header(default=None),
    x_user_sub: str | None = Header(default=None, alias="X-User-Sub"),
) -> AuthContext:
    """Resolve caller identity.

    Partner/prod: Bearer JWT from Keycloak / managed OIDC when OIDC_ISSUER is set.
    Local/tests: `X-User-Sub` or opaque Bearer only when ALLOW_DEV_AUTH=true.
    """
    if authorization and authorization.lower().startswith("bearer "):
        return decode_bearer_token(authorization.split(" ", 1)[1].strip())
    if x_user_sub:
        if oidc_enabled() and not allow_dev_auth():
            raise HTTPException(
                status_code=401,
                detail="dev header auth disabled; use OIDC Bearer token",
            )
        if not allow_dev_auth() and not oidc_enabled():
            raise HTTPException(status_code=401, detail="dev auth disabled")
        return AuthContext(user_sub=x_user_sub, claims={"sub": x_user_sub}, auth_mode="dev")
    raise HTTPException(status_code=401, detail="missing credentials")


def get_principal(
    organization_id: str,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> Principal:
    try:
        return resolve_principal(db, auth.user_sub, organization_id)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
