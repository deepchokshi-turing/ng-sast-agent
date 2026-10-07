"""Model client.

In production this wraps the hosted chat-completions endpoint. For local
runs and tests the deterministic stub below is used: it answers by quoting
the context it was given and requests the email tool when asked to.
"""

import os
from dataclasses import dataclass, field


@dataclass
class ModelResponse:
    text: str
    tool_calls: list = field(default_factory=list)


class ModelClient:
    def __init__(self, mode: str | None = None):
        self.mode = mode or os.environ.get("LLM_MODE", "stub")

    def complete(self, system: str, user: str, tools: list[str]) -> ModelResponse:
        if self.mode != "stub":
            raise RuntimeError("hosted mode is not available in this build")
        context = system.split("CONTEXT:\n", 1)[-1]
        summary = "Summary of related tickets:\n" + context.strip()
        calls = []
        if "email" in user.lower() and "send_email" in tools:
            calls.append({"name": "send_email", "arguments": {"subject": "Your ticket summary", "body": summary}})
        return ModelResponse(text=summary, tool_calls=calls)
