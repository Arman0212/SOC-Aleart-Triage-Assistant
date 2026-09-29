"""LLM clients behind a small interface, so tests never need a model."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Protocol

from pydantic_settings import BaseSettings, SettingsConfigDict

from nullpunkt.core.config import BriefingConfig


class LLMError(Exception):
    """The model could not produce an answer. ``kind`` is "timeout", "unreachable" or "error"."""

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(f"{kind}: {detail}")
        self.kind = kind


class LLMClient(Protocol):
    model: str

    def generate(self, system: str, user: str, schema: dict) -> str:
        """Return the model's reply: a JSON string that should match ``schema``."""
        ...


class OllamaSettings(BaseSettings):
    """OLLAMA_MODEL / OLLAMA_HOST from the environment or .env override pipeline.yaml."""

    model_config = SettingsConfigDict(env_prefix="OLLAMA_", env_file=".env", extra="ignore")

    model: str | None = None
    host: str | None = None


class OllamaClient:
    """Structured output (``format`` = JSON schema), temperature 0 and a fixed seed."""

    def __init__(self, config: BriefingConfig, settings: OllamaSettings | None = None) -> None:
        import ollama  # imported lazily so nothing but this client needs the package loaded

        env = settings or OllamaSettings()
        self.model = env.model or config.model
        self.host = env.host or config.host
        self.options = {
            "temperature": config.temperature,
            "seed": config.seed,
            "num_ctx": config.num_ctx,
        }
        self._client = ollama.Client(host=self.host, timeout=config.timeout_seconds)
        self._ollama = ollama

    def generate(self, system: str, user: str, schema: dict) -> str:
        try:
            response = self._client.chat(
                model=self.model,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                format=schema,
                options=self.options,
            )
        except self._ollama.ResponseError as exc:
            raise LLMError("error", str(exc)) from exc
        except ConnectionError as exc:  # ollama raises this when the server is not running
            raise LLMError("unreachable", str(exc)) from exc
        except Exception as exc:
            # The ollama package surfaces its HTTP library's timeout (httpx.TimeoutException);
            # match it by name so we need not import a transitive dependency.
            if any(cls.__name__ == "TimeoutException" for cls in type(exc).__mro__):
                raise LLMError("timeout", str(exc) or "request timed out") from exc
            if any(cls.__name__ in ("ConnectError", "NetworkError") for cls in type(exc).__mro__):
                raise LLMError("unreachable", str(exc)) from exc
            raise
        return response["message"]["content"]


@dataclass
class FakeClient:
    """Replays scripted replies (strings) or raises scripted LLMErrors, in order. A callable
    receives (system, user) and returns the reply. Records every call for assertions."""

    replies: Iterable[str | LLMError | Callable[[str, str], str]]
    model: str = "fake"
    calls: list[tuple[str, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._replies = iter(self.replies)

    def generate(self, system: str, user: str, schema: dict) -> str:
        self.calls.append((system, user))
        try:
            reply = next(self._replies)
        except StopIteration:
            raise AssertionError("FakeClient ran out of scripted replies") from None
        if isinstance(reply, LLMError):
            raise reply
        if callable(reply):
            return reply(system, user)
        return reply
