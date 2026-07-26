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
        self.region = os.environ.get("MINIO_REGION", "us-east-1")

    def ensure_bucket(self) -> None:
        if not self.endpoint:
            self.root.mkdir(parents=True, exist_ok=True)
            return
        client = self._client()
        try:
            client.head_bucket(Bucket=self.bucket)
        except Exception:  # noqa: BLE001
            client.create_bucket(Bucket=self.bucket)

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
            self.ensure_bucket()
            return self._put_minio(key, body)
        return self._put_local(key, body)

    def get_json(
        self,
        *,
        organization_id: str,
        project_id: str,
        run_id: str,
        name: str,
    ) -> Any:
        key = f"{organization_id}/{project_id}/{run_id}/{name}"
        if self.endpoint:
            client = self._client()
            obj = client.get_object(Bucket=self.bucket, Key=key)
            return json.loads(obj["Body"].read().decode("utf-8"))
        path = self.root / key
        return json.loads(path.read_text(encoding="utf-8"))

    def _client(self):
        import boto3
        from botocore.client import Config

        return boto3.client(
            "s3",
            endpoint_url=self.endpoint,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            region_name=self.region,
            config=Config(signature_version="s3v4"),
        )

    def _put_local(self, key: str, body: bytes) -> str:
        path = self.root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        return f"file://{path.resolve().as_posix()}"

    def _put_minio(self, key: str, body: bytes) -> str:
        client = self._client()
        client.put_object(Bucket=self.bucket, Key=key, Body=body, ContentType="application/json")
        return f"s3://{self.bucket}/{key}"
