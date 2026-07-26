"""OIDC / local principal resolution for the control plane."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import Depends, Header, HTTPException
from jose import JWTError, jwt
from jose.backends import RSAKey
from sqlalchemy.orm import Session

from persistence import SessionLocal, init_db, make_engine
from persistence.repositories import AuthorizationError, Principal, resolve_principal


@dataclass
class AuthContext:
    user_sub: str
    claims: dict[str, Any]
    auth_mode: str = "dev"


_jwks_cache: dict[str, Any] | None = None
_engine = None


def get_engine():
    global _engine
    if _engine is None:
        _engine = make_engine()
        init_db(_engine)
    return _engine


def reset_engine_for_tests(engine) -> None:
    global _engine
    global _jwks_cache
    _engine = engine
    _jwks_cache = None
    init_db(engine)


def get_db() -> Session:
    get_engine()
    session = SessionLocal()
    try:
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
        "jwks_url": os.environ.get("OIDC_JWKS_URL")
        or (f"{issuer}/protocol/openid-connect/certs" if issuer else None),
        "token_url": f"{issuer}/protocol/openid-connect/token" if issuer else None,
        "auth_url": f"{issuer}/protocol/openid-connect/auth" if issuer else None,
        "client_id": os.environ.get("OIDC_CLIENT_ID", "aisec-ui"),
    }


def _load_jwks() -> dict[str, Any]:
    global _jwks_cache
    if _jwks_cache is not None:
        return _jwks_cache
    issuer = os.environ["OIDC_ISSUER"].rstrip("/")
    jwks_url = os.environ.get("OIDC_JWKS_URL", f"{issuer}/protocol/openid-connect/certs")
    response = httpx.get(jwks_url, timeout=10.0)
    response.raise_for_status()
    _jwks_cache = response.json()
    return _jwks_cache


def _rsa_key_for_token(token: str):
    jwks = _load_jwks()
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
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
