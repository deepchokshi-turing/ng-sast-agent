"""In-memory ticket store backed by the JSON fixtures."""

import json
from dataclasses import dataclass
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures"


@dataclass(frozen=True)
class Ticket:
    ticket_id: str
    tenant_id: str
    customer_id: str
    subject: str
    body: str


class TicketStore:
    def __init__(self, path: Path = FIXTURE_DIR / "tickets.json"):
        raw = json.loads(path.read_text())
        self._tickets = [Ticket(**t) for t in raw["tickets"]]

    def query(self, text: str, tenant_id: str | None = None, limit: int = 3):
        """Keyword search over subject and body.

        When tenant_id is given, only that tenant's tickets are considered.
        """
        terms = [t for t in text.lower().split() if len(t) > 3]
        candidates = self._tickets
        if tenant_id is not None:
            candidates = [t for t in candidates if t.tenant_id == tenant_id]
        scored = []
        for ticket in candidates:
            haystack = f"{ticket.subject} {ticket.body}".lower()
            score = sum(haystack.count(term) for term in terms)
            if score:
                scored.append((score, ticket))
        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [ticket for _, ticket in scored[:limit]]

    def all_tickets(self):
        return list(self._tickets)
