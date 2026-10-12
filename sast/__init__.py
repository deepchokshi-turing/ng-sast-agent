"""Security scanners as Harbor agents.

Semgrep, CodeQL and SonarQube are static analysis with no LLM. The Claude Code
security review agent (``sast.claude_review``) calls an Anthropic model, but
only inside the task sandbox, where its own venv holds ``anthropic``. On the
host it is plain Python like the rest.

Every module under ``sast`` imports only the standard library and ``harbor``:
the eval platform puts this repository on Harbor's PYTHONPATH and installs
nothing, so a third-party import here would break loading on the worker.
"""

__version__ = "0.5.0"
