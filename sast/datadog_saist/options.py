"""``--ak`` settings for the datadog-saist agent.

Every option can also come from the host's environment, as
``DATADOG_SAIST_<OPTION>`` (for example ``DATADOG_SAIST_MODEL``). An ``--ak``
value wins over the environment. The credential is not an option: it is read
from the host variable of the model's provider (``OPENAI_API_KEY``,
``ANTHROPIC_API_KEY`` or ``GOOGLE_API_KEY``), so it never sits in a job config.

Unknown keys are accepted and recorded instead of rejected, as for the other
agents.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from harbor.agents.options import AgentOptions, Env
from pydantic import ConfigDict, Field, field_validator, model_validator

from . import pins


def _env(option: str) -> Env:
    name = f"DATADOG_SAIST_{option.upper()}"
    return Env(name, fallback=name)


def cli_model(value: Any) -> Any:
    """A model as the binary names it: its own name, an API id (gpt-5.2) or <provider>/<API id>."""
    if not isinstance(value, str):
        return value
    value = value.strip()
    if not value:
        return None
    if value in pins.MODELS:
        return value
    bare = value.split("/", 1)[1] if "/" in value else value
    if bare in pins.MODELS:
        return bare
    if bare in pins.API_TO_CLI:
        return pins.API_TO_CLI[bare]
    raise ValueError(f"datadog-saist {pins.VERSION} does not support the model {value!r}; it supports "
                     + ", ".join(pins.MODELS))


class DatadogSaistOptions(AgentOptions):
    model_config = ConfigDict(extra="allow", coerce_numbers_to_str=True)

    model: Annotated[str | None, _env("model")] = Field(
        default=None,
        description=f"Detection model (--detection-model), a name the binary knows ({', '.join(pins.MODELS)}) or "
        f"its API id (gpt-5.2). Default: Harbor's -m when it names one of these, else {pins.DEFAULT_MODEL}.",
    )
    validation_model: Annotated[str | None, _env("validation_model")] = Field(
        default=None, description="Validation model (--validation-model). Default: the detection model.",
    )
    mode: Annotated[Literal["stock", "scoped"], _env("mode")] = Field(
        default="stock",
        description="stock: datadog-saist's own rules and prompts. scoped is accepted (the benchmark's AI agents "
        "default to it) but datadog-saist takes no extra instructions: its rules come from Datadog's endpoint or "
        "the binary, and its answer schema is fixed. A scoped run therefore runs exactly as stock and records "
        "mode_effective=stock and the contract it could not pass on.",
    )
    rules: Annotated[Literal["api", "embedded"], _env("rules")] = Field(
        default="api",
        description="api: the tool's default, the rules from Datadog's public endpoint at run time (not "
        "pinnable; a digest is recorded). embedded: --local-prompts, the 12 rules compiled into the binary "
        "(cmdi, sqli, xpathi, xss for Go, Java, Python), none of them an LLM rule.",
    )
    request_timeout_sec: Annotated[int, _env("request_timeout_sec")] = Field(
        default=120, ge=10, le=900,
        description="--request-timeout-sec, the limit per model call. The tool's default is 30 s, which reasoning "
        "models exceed on its 8k-token prompts.",
    )
    file_concurrency: Annotated[int, _env("file_concurrency")] = Field(
        default=20, ge=1, le=64, description="--file-concurrency (the tool's default, 20).")
    skip_indexing: Annotated[bool, _env("skip_indexing")] = Field(
        default=False, description="--skip-indexing: no cross-file context (the tool's default is to index).")
    timeout_sec: Annotated[int | None, _env("timeout_sec")] = Field(
        default=None, ge=120,
        description="Wall-clock limit for the whole scan. Default: the task's agent timeout minus 120 s.",
    )
    scan_budget_sec: int | None = Field(default=None, ge=120, description="Same as timeout_sec.")
    scan_roots: list[str] | None = Field(
        default=None, description="Paths inside /app/repo to scan (comma-separated). Default: the task's "
        "metadata.scanner_roots.")
    exclude: list[str] | None = Field(
        default=None, description="Paths to skip (comma-separated). Default: the task's metadata.excluded_paths.")

    @field_validator("scan_roots", "exclude", mode="before")
    @classmethod
    def _split(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @field_validator("model", "validation_model", mode="before")
    @classmethod
    def _model(cls, value: Any) -> Any:
        return cli_model(value)

    @model_validator(mode="after")
    def _one_provider(self) -> "DatadogSaistOptions":
        if self.model and self.validation_model and \
                pins.MODELS[self.model][0] != pins.MODELS[self.validation_model][0]:
            raise ValueError("model and validation_model must use the same provider (one key is passed)")
        return self
