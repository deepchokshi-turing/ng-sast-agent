"""Runtime settings loaded from config/agent.json."""

import json
import os
from functools import lru_cache
from pathlib import Path

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "agent.json"


@lru_cache(maxsize=1)
def settings() -> dict:
    data = json.loads(CONFIG_PATH.read_text())
    data["outbox_path"] = os.environ.get("OUTBOX_PATH", data["outbox_path"])
    return data
