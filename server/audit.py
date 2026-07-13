"""Append-only (by convention) JSONL audit log. Never logs raw JWTs."""

import json
import time
import uuid

from .config import AUDIT_LOG


def audit(**event) -> dict:
    event = {
        "event_id": f"evt_{uuid.uuid4().hex[:12]}",
        "ts": round(time.time(), 3),
        **event,
    }
    with AUDIT_LOG.open("a") as f:
        f.write(json.dumps(event) + "\n")
    return event
