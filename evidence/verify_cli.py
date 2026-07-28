"""Offline evidence-bundle verifier."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from evidence import canonical_json, sha256_bytes, verify_signature


def verify_bundle(bundle: dict) -> dict[str, bool]:
    manifest = bundle.get("manifest") or {}
    public_key = (manifest.get("signing") or {}).get("public_key")
    unsigned_manifest = {**manifest, "signature": None}
    unsigned_bundle = {key: value for key, value in bundle.items() if key != "signature"}
    hashes = manifest.get("content_hashes") or {}
    return {
        "manifest_signature": verify_signature(
            unsigned_manifest,
            manifest.get("signature"),
            public_key=public_key,
        ),
        "bundle_signature": verify_signature(
            unsigned_bundle,
            bundle.get("signature"),
            public_key=public_key,
        ),
        "events_hash": hashes.get("events")
        == sha256_bytes(canonical_json(bundle.get("events") or [])),
        "findings_hash": hashes.get("findings")
        == sha256_bytes(canonical_json(bundle.get("findings") or [])),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    result = verify_bundle(json.loads(args.bundle.read_text(encoding="utf-8")))
    print(json.dumps(result, sort_keys=True))
    if not all(result.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
