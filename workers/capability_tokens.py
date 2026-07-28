"""Compact Ed25519-signed run capability tokens."""

from __future__ import annotations

import hashlib
import json
import os
from base64 import b64decode, urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class CapabilityTokenError(PermissionError):
    pass


def _b64url(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    return urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _private_key() -> Ed25519PrivateKey:
    encoded = os.environ.get("CAPABILITY_ED25519_PRIVATE_KEY")
    if encoded:
        return Ed25519PrivateKey.from_private_bytes(b64decode(encoded))
    evidence_key = os.environ.get("EVIDENCE_ED25519_PRIVATE_KEY")
    if evidence_key:
        return Ed25519PrivateKey.from_private_bytes(b64decode(evidence_key))
    seed = hashlib.sha256(
        os.environ.get("EVIDENCE_SIGNING_KEY", "local-dev-evidence-key").encode()
        + b":capability"
    ).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def issue_capability_token(claims: dict[str, Any]) -> str:
    header = {
        "alg": "EdDSA",
        "typ": "AISec-Capability",
        "kid": os.environ.get("CAPABILITY_SIGNING_KEY_ID", "cap-local"),
    }
    encoded_header = _b64url(
        json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    )
    encoded_claims = _b64url(
        json.dumps(claims, sort_keys=True, separators=(",", ":"), default=str).encode()
    )
    signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
    signature = _private_key().sign(signing_input)
    return f"{encoded_header}.{encoded_claims}.{_b64url(signature)}"


def verify_capability_token(token: str) -> dict[str, Any]:
    try:
        encoded_header, encoded_claims, encoded_signature = token.split(".")
        header = json.loads(_decode(encoded_header))
        if header.get("alg") != "EdDSA" or header.get("typ") != "AISec-Capability":
            raise CapabilityTokenError("unsupported capability token")
        signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
        _private_key().public_key().verify(_decode(encoded_signature), signing_input)
        claims = json.loads(_decode(encoded_claims))
        if int(claims["exp"]) <= int(datetime.now(timezone.utc).timestamp()):
            raise TimeoutError("capability expired")
        return claims
    except TimeoutError:
        raise
    except (ValueError, KeyError, json.JSONDecodeError, InvalidSignature) as exc:
        raise CapabilityTokenError("invalid capability signature or claims") from exc
