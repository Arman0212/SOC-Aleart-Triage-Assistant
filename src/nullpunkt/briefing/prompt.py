"""Versioned prompts (src/nullpunkt/briefing/prompts/brief_<version>.md)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import cache
from importlib.resources import files

# Identifiers used only in the prompt's fictional worked example. A brief that contains any of
# them copied the example instead of describing the incident, and is rejected.
EXAMPLE_TOKENS = frozenset(
    {"EXAMPLE-SRV9", "EXAMPLE-WS7", "sam.fictional", "198.18.7.7", "INC-9999"}
)
DATA_OPEN, DATA_CLOSE = "<incident_data>", "</incident_data>"


@dataclass(frozen=True)
class Prompt:
    version: str
    text: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()


@cache
def load_prompt(version: str) -> Prompt:
    path = files("nullpunkt.briefing").joinpath(f"prompts/brief_{version}.md")
    if not path.is_file():
        raise ValueError(f"no prompt for version {version!r}")
    return Prompt(version, path.read_text(encoding="utf-8"))


def render_data(data: dict) -> str:
    """The incident JSON inside its data block. '<' is escaped so nothing in the data (an alert
    message, for example) can close the block early."""
    body = json.dumps(data, ensure_ascii=False, indent=1).replace("<", "\\u003c")
    return f"{DATA_OPEN}\n{body}\n{DATA_CLOSE}"


def user_message(data: dict, errors: list[str] | None = None) -> str:
    text = f"{render_data(data)}\nWrite the shift brief for {data['incident_id']} as JSON."
    if errors:
        problems = "\n".join(f"- {e}" for e in errors)
        text += (
            "\n\nYour previous answer was rejected for these reasons. Fix every one of them and "
            f"answer again, using only facts from the data block:\n{problems}"
        )
    return text
