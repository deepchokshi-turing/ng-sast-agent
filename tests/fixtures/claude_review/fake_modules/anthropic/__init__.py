"""A stand-in for the anthropic SDK, for the claude_review driver tests. No network.

Only what the driver and the upstream filter use: ``Anthropic(api_key=...,
max_retries=...)``, ``client.messages.create(...)`` returning an object with
``content[].text`` and ``usage``, and the error classes the driver classifies.

Behaviour comes from the JSON file named by FAKE_ANTHROPIC_CONFIG:

- ``auth_error``: every call raises AuthenticationError.
- ``connection_error``: every call raises APIConnectionError.
- ``unavailable_models``: calls naming these models raise NotFoundError.
- ``fail_ping_calls``: 1-based numbers of the ping calls (max_tokens 1) that
  raise a 500 APIStatusError.
- ``finding_error``: every finding analysis raises a 500 APIStatusError.
- ``exclude_categories``: a finding whose JSON names one of these categories
  gets ``keep_finding: false``; any other gets ``keep_finding: true``.
- ``finding_reply_text``: the raw reply text for every finding analysis.

Every call is appended to the file named by FAKE_ANTHROPIC_LOG as one JSON
line: the model, max_tokens, whether a system prompt was given, the api_key the
client was made with, and the categories in the prompt.
"""

import json
import os
import re

__version__ = "0.79.0-fake"


class APIError(Exception):
    pass


class APIStatusError(APIError):
    def __init__(self, message, status_code=500):
        APIError.__init__(self, message)
        self.status_code = status_code


class AuthenticationError(APIStatusError):
    pass


class PermissionDeniedError(APIStatusError):
    pass


class NotFoundError(APIStatusError):
    pass


class APIConnectionError(APIError):
    pass


def _config():
    path = os.environ.get("FAKE_ANTHROPIC_CONFIG")
    if not path:
        return {}
    with open(path) as f:
        return json.load(f)


def _log(entry):
    path = os.environ.get("FAKE_ANTHROPIC_LOG")
    if path:
        with open(path, "a") as f:
            f.write(json.dumps(entry) + "\n")


class _Block(object):
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _Usage(object):
    def __init__(self, input_tokens, output_tokens):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cache_creation_input_tokens = 0
        self.cache_read_input_tokens = 0


class _Response(object):
    def __init__(self, text, model):
        self.content = [_Block(text)]
        self.usage = _Usage(100, 10)
        self.model = model


_STATE = {"pings": 0}


class _Messages(object):
    def __init__(self, client):
        self._client = client

    def create(self, model=None, max_tokens=None, messages=None, system=None, timeout=None, **kwargs):
        config = _config()
        prompt = "".join(m.get("content", "") for m in (messages or []) if isinstance(m.get("content"), str))
        categories = re.findall(r'"category": "([^"]*)"', prompt)
        ping = max_tokens == 1
        _log({"model": model, "max_tokens": max_tokens, "system": bool(system), "api_key": self._client.api_key,
              "categories": categories, "ping": ping, "timeout": timeout})
        if config.get("auth_error"):
            raise AuthenticationError("Error code: 401 - invalid x-api-key", 401)
        if config.get("connection_error"):
            raise APIConnectionError("Connection error.")
        if model in (config.get("unavailable_models") or []):
            raise NotFoundError("Error code: 404 - model: {}".format(model), 404)
        if ping:
            _STATE["pings"] += 1
            if _STATE["pings"] in (config.get("fail_ping_calls") or []):
                raise APIStatusError("Error code: 500 - internal error", 500)
            return _Response("pong", model)
        if config.get("finding_error"):
            raise APIStatusError("Error code: 500 - overloaded", 500)
        if config.get("finding_reply_text") is not None:
            return _Response(config["finding_reply_text"], model)
        keep = not any(c in (config.get("exclude_categories") or []) for c in categories)
        reply = {"original_severity": "HIGH", "confidence_score": 8 if keep else 2, "keep_finding": keep,
                 "exclusion_reason": None if keep else "fake: excluded category",
                 "justification": "fake analysis"}
        return _Response(json.dumps(reply), model)


class Anthropic(object):
    def __init__(self, api_key=None, max_retries=2, **kwargs):
        self.api_key = api_key
        self.max_retries = max_retries
        self.messages = _Messages(self)
