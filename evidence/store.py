"""MinIO / S3-compatible evidence object storage (Private Beta)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


class EvidenceStore:
    """Stores evidence blobs. Local fallback uses filesystem; MinIO when configured."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or Path(os.environ.get("EVIDENCE_LOCAL_ROOT", "tmp/evidence"))
        self.endpoint = os.environ.get("MINIO_ENDPOINT")
        self.bucket = os.environ.get("MINIO_BUCKET", "evidence")
        self.access_key = os.environ.get("MINIO_ACCESS_KEY", "minioadmin")
        self.secret_key = os.environ.get("MINIO_SECRET_KEY", "minioadmin")

    def put_json(
        self,
        *,
        organization_id: str,
        project_id: str,
        run_id: str,
        name: str,
        payload: Any,
    ) -> str:
        key = f"{organization_id}/{project_id}/{run_id}/{name}"
        body = json.dumps(payload, indent=2, sort_keys=True, default=str).encode("utf-8")
        if self.endpoint:
            return self._put_minio(key, body)
        return self._put_local(key, body)

    def _put_local(self, key: str, body: bytes) -> str:
        path = self.root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        return f"file://{path.resolve().as_posix()}"

    def _put_minio(self, key: str, body: bytes) -> str:
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("boto3 required for MinIO evidence store") from exc
        client = boto3.client(
            "s3",
            endpoint_url=self.endpoint,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
        )
        client.put_object(Bucket=self.bucket, Key=key, Body=body, ContentType="application/json")
        return f"s3://{self.bucket}/{key}"
