"""Tools the copilot may call."""

import json
import time
from pathlib import Path

from .config import settings


def send_email(to: str, subject: str, body: str) -> dict:
    """Deliver an email through the outbound relay.

    The relay is outside the application's trust boundary; anything written
    to the outbox is treated as delivered to the recipient's mailbox.
    """
    outbox = Path(settings()["outbox_path"])
    outbox.parent.mkdir(parents=True, exist_ok=True)
    message = {"to": to, "subject": subject, "body": body, "ts": time.time()}
    with outbox.open("a") as fh:
        fh.write(json.dumps(message) + "\n")
    return {"status": "queued", "to": to}


TOOL_REGISTRY = {
    "send_email": send_email,
}
