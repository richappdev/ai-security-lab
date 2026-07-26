"""Server-Sent Events for run timeline (Private Beta)."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from sse_starlette.sse import EventSourceResponse

from app.auth import AuthContext, get_auth_context, get_db
from persistence import Run, RunEvent
from persistence.repositories import AuthorizationError, get_run, resolve_principal

router = APIRouter(prefix="/v1", tags=["sse"])


@router.get("/organizations/{organization_id}/runs/{run_id}/events/stream")
async def stream_run_events(
    organization_id: str,
    run_id: str,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> EventSourceResponse:
    try:
        principal = resolve_principal(db, auth.user_sub, organization_id)
        get_run(db, principal, run_id)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    async def event_generator():
        last_seq = 0
        # Snapshot existing events then poll briefly for updates.
        for _ in range(30):
            rows = list(
                db.scalars(
                    select(RunEvent)
                    .where(
                        RunEvent.run_id == run_id,
                        RunEvent.organization_id == organization_id,
                        RunEvent.seq > last_seq,
                    )
                    .order_by(RunEvent.seq)
                )
            )
            for row in rows:
                last_seq = row.seq
                payload: dict[str, Any] = {
                    "seq": row.seq,
                    "type": row.event_type,
                    "payload": row.payload,
                }
                yield {"event": "run.event", "data": json.dumps(payload)}
            run = db.get(Run, run_id)
            if run and run.status in {"completed", "failed", "cancelled"}:
                yield {
                    "event": "run.completed",
                    "data": json.dumps({"status": run.status, "gate_result": run.gate_result}),
                }
                break
            await asyncio.sleep(0.2)

    return EventSourceResponse(event_generator())
