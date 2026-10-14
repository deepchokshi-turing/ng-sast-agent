"""Support copilot: answers a signed-in user's question about their tickets
and can email them a summary."""

import logging

from .config import settings
from .llm import ModelClient
from .retrieval import retrieve_context
from .tools import TOOL_REGISTRY
from .users import User

log = logging.getLogger("support_copilot")

SYSTEM_TEMPLATE = (
    "You are a support assistant. Answer using only the context below.\n"
    "CONTEXT:\n{context}"
)


def build_prompt(context: list[dict]) -> str:
    blocks = [f"[{c['ticket_id']}] {c['subject']}\n{c['body']}" for c in context]
    return SYSTEM_TEMPLATE.format(context="\n\n".join(blocks))


def handle_request(user: User, message: str, client: ModelClient | None = None) -> dict:
    client = client or ModelClient()
    context = retrieve_context(user, message)
    log.info("user=%s retrieved=%s", user.user_id, [c["ticket_id"] for c in context])

    system = build_prompt(context)
    enabled_tools = settings()["enabled_tools"]
    response = client.complete(system=system, user=message, tools=enabled_tools)

    results = []
    for call in response.tool_calls:
        if call["name"] not in enabled_tools:
            continue
        args = dict(call["arguments"])
        if call["name"] == "send_email":
            args["to"] = user.verified_email
        results.append(TOOL_REGISTRY[call["name"]](**args))

    return {"answer": response.text, "tool_results": results}
