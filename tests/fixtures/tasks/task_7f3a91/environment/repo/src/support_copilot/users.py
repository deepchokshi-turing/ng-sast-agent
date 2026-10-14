"""Authenticated support-portal users."""

import json
from dataclasses import dataclass
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures"


@dataclass(frozen=True)
class User:
    user_id: str
    tenant_id: str
    display_name: str
    verified_email: str


def load_user(user_id: str) -> User:
    raw = json.loads((FIXTURE_DIR / "users.json").read_text())
    for entry in raw["users"]:
        if entry["user_id"] == user_id:
            return User(**entry)
    raise KeyError(user_id)
