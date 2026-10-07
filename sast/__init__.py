"""Static-analysis scanners (no LLM) as Harbor agents.

Every module under ``sast`` imports only the standard library and ``harbor``:
the eval platform puts this repository on Harbor's PYTHONPATH and installs
nothing, so a third-party import here would break loading on the worker.
"""

__version__ = "0.3.0"
