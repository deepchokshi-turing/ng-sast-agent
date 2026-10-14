"""Retrieval layer that feeds ticket context to the copilot."""

from .store import TicketStore
from .users import User

_store = TicketStore()


def retrieve_context(user: User, question: str, limit: int = 3):
    """Return the tickets most relevant to the user's question."""
    tickets = _store.query(question, limit=limit)
    return [
        {
            "ticket_id": t.ticket_id,
            "subject": t.subject,
            "body": t.body,
        }
        for t in tickets
    ]
