"""OIDC / local principal resolution for the control plane."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import Depends, Header, HTTPException
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from persistence import SessionLocal, init_db, make_engine
from persistence.repositories import AuthorizationError, Principal, resolve_principal


@dataclass
class AuthContext:
    user_sub: str
    claims: dict[str, Any]


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
    _engine = engine
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


def decode_bearer_token(token: str) -> AuthContext:
    if not oidc_enabled():
        # Local/dev: treat opaque token as user_sub when OIDC is not configured.
        return AuthContext(user_sub=token, claims={"sub": token})
    try:
        jwks = _load_jwks()
        header = jwt.get_unverified_header(token)
        key = next(k for k in jwks["keys"] if k["kid"] == header.get("kid"))
        claims = jwt.decode(
            token,
            key,
            algorithms=[header.get("alg", "RS256")],
            audience=os.environ.get("OIDC_AUDIENCE"),
            issuer=os.environ.get("OIDC_ISSUER"),
            options={"verify_aud": bool(os.environ.get("OIDC_AUDIENCE"))},
        )
        return AuthContext(user_sub=str(claims["sub"]), claims=claims)
    except (JWTError, StopIteration, KeyError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=401, detail=f"invalid token: {exc}") from exc


def get_auth_context(
    authorization: str | None = Header(default=None),
    x_user_sub: str | None = Header(default=None, alias="X-User-Sub"),
) -> AuthContext:
    """Resolve caller identity.

    Production: Bearer JWT from Keycloak / managed OIDC.
    Local/tests: `X-User-Sub` or `Authorization: Bearer <user_sub>`.
    """
    if authorization and authorization.lower().startswith("bearer "):
        return decode_bearer_token(authorization.split(" ", 1)[1].strip())
    if x_user_sub:
        return AuthContext(user_sub=x_user_sub, claims={"sub": x_user_sub})
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
