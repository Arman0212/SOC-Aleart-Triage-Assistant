"""Briefs on the seed-42 demo batch, with a fake model (no Ollama needed), plus one optional
test against the real model (``-m ollama``; skipped when Ollama is not reachable)."""

import json
import urllib.request
from pathlib import Path

import pytest
import yaml

from nullpunkt.briefing.llm import FakeClient, LLMError, OllamaClient
from nullpunkt.briefing.validation import validate
from nullpunkt.core.config import BriefingConfig, PipelineConfig
from nullpunkt.core.schema import BriefSource
from nullpunkt.generator.batch import generate, write_batch
from nullpunkt.generator.config import GeneratorConfig
from nullpunkt.pipeline import main, run

REPO = Path(__file__).parents[2]


@pytest.fixture(scope="module")
def batch_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("brief") / "batch-042"
    write_batch(generate(GeneratorConfig(seed=42)), out)
    return out


def config(tmp_path, **briefing) -> PipelineConfig:
    settings = {"cache_dir": str(tmp_path / "cache"), **briefing}
    return PipelineConfig(briefing=BriefingConfig(**settings))


def test_site_timezone_matches_generator_config():
    generator = yaml.safe_load((REPO / "configs" / "generator.yaml").read_text())
    assert PipelineConfig().site.timezone == generator["company_timezone"]


def test_template_briefs_for_the_top_10_when_the_model_is_down(batch_dir, tmp_path):
    client = FakeClient([LLMError("unreachable", "connection refused")])
    result = run(batch_dir, config(tmp_path), briefs=True, client=client)
    assert result.briefing is not None
    assert list(result.briefing.outcomes) == [r.incident.incident_id for r in result.ranked[:10]]
    assert result.briefing.paths() == {"fallback": 10}
    assert len(client.calls) == 1  # no waiting on a dead model ten times
    for r in result.ranked[:10]:
        brief = r.incident.brief
        assert brief is not None and brief.generated_by is BriefSource.TEMPLATE and brief.validated
        ctx = result.brief_contexts[r.incident.incident_id]
        assert validate(brief.model_dump_json(include=_DRAFT_FIELDS), ctx).ok
    assert all(r.incident.brief is None for r in result.ranked[10:])


_DRAFT_FIELDS = {
    "summary",
    "affected_assets",
    "techniques",
    "timeline",
    "next_action",
    "confidence",
}


def test_scn05_brief_context_leads_with_the_exfiltration(batch_dir, tmp_path):
    result = run(
        batch_dir, config(tmp_path), briefs=True, client=FakeClient([LLMError("unreachable", "x")])
    )
    ctx = next(c for c in result.brief_contexts.values() if len(c.incident.alert_ids) == 64)
    data = ctx.data
    assert data["headline"]["asset_at_risk"] == "FS02"
    assert data["routine_activity"][0].startswith("46 × Failed login, ")
    assert data["routine_activity"][0].endswith(" IST, routine")
    assert data["evidence_timeline"][0]["rule"] == "Login from new source host"
    brief = result.briefing.outcomes[ctx.incident_id].brief
    assert "file_server FS02" in brief.summary.splitlines()[0]


def test_llm_briefs_are_cached_between_runs(batch_dir, tmp_path):
    def answer(system, user):
        data = json.loads(user.split("<incident_data>\n")[1].split("\n</incident_data>")[0])
        hosts = [a["host"] for a in data["assets_at_risk"]] or [data["headline"]["asset_at_risk"]]
        return json.dumps(
            {
                "summary": f"{hosts[0]} is likely compromised.\nSee the evidence timeline.",
                "affected_assets": hosts[:1],
                "techniques": [t["id"] for t in data["techniques"]][:1],
                "timeline": [f"{data['window']} - activity on {hosts[0]}"],
                "next_action": data["playbook_most_urgent_first"][0]["action"],
                "confidence": "high",
            }
        )

    cfg = config(tmp_path)
    first = run(batch_dir, cfg, briefs=True, client=FakeClient([answer] * 10))
    assert first.briefing.paths() == {"first-pass": 10}
    second_client = FakeClient([])
    second = run(batch_dir, cfg, briefs=True, client=second_client)
    assert second.briefing.paths() == {"cached": 10} and second_client.calls == []
    assert [r.incident.brief for r in second.ranked[:10]] == [
        r.incident.brief for r in first.ranked[:10]
    ]
    assert len(list(Path(cfg.briefing.cache_dir).glob("*.json"))) == 10


def test_top_n_is_configurable(batch_dir, tmp_path):
    down = FakeClient([LLMError("unreachable", "x")])
    result = run(batch_dir, config(tmp_path, top_n=3), briefs=True, client=down)
    assert len(result.briefing.outcomes) == 3


def test_cli_prints_briefs(batch_dir, tmp_path, capsys, monkeypatch):
    # No server on this port: the CLI's Ollama client is unreachable, so briefs are templates.
    cfg = tmp_path / "pipeline.yaml"
    cfg.write_text(
        f"briefing:\n  host: http://127.0.0.1:9\n  top_n: 2\n  cache_dir: {tmp_path / 'cache'}\n"
    )
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.chdir(tmp_path)  # no .env here
    assert main(["--batch", str(batch_dir), "--config", str(cfg), "--briefs"]) == 0
    out = capsys.readouterr().out
    assert "Briefs (phi4-mini, prompt v1): fallback 2" in out
    assert "--- 1. [P1] INC-0055 (template, fallback" in out


# --- optional: the real model ------------------------------------------------------------------


def _ollama_ready(cfg: BriefingConfig) -> bool:
    try:
        with urllib.request.urlopen(f"{cfg.host}/api/tags", timeout=2) as response:
            models = [m["name"] for m in json.load(response)["models"]]
    except OSError:
        return False
    return any(m.split(":")[0] == cfg.model for m in models)


@pytest.mark.ollama
def test_real_model_briefs_scn01(batch_dir, tmp_path):
    cfg = config(tmp_path, top_n=1, cache_dir=None)
    if not _ollama_ready(cfg.briefing):
        pytest.skip("Ollama with the configured model is not reachable")
    result = run(batch_dir, cfg, briefs=True, client=OllamaClient(cfg.briefing))
    outcome = result.briefing.outcomes["INC-0055"]
    assert outcome.brief.validated
    if not outcome.fallback_used:
        assert "FINDB01" in outcome.brief.affected_assets
