"""Streamlit helpers shared by the pages in app/: the cached repository, the sidebar (analyst,
batch, study session), and small rendering pieces. The app only talks to the database."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import streamlit as st

from nullpunkt.app.views import STATUS_LABEL, TIER_COLOURS, TIER_MEANING
from nullpunkt.core.config import PipelineConfig, load_pipeline_config
from nullpunkt.storage.repository import (
    BatchInfo,
    DecisionError,
    SessionRecord,
    SQLiteRepository,
    resolve_db_path,
)

CONFIG_PATH = Path("configs/pipeline.yaml")

CSS = """
<style>
.block-container { padding-top: 1.2rem; max-width: 1400px; }
.np-tier { display: inline-block; min-width: 2.4rem; text-align: center; padding: .05rem .5rem;
           border-radius: .35rem; font-weight: 700; color: #0b1220; }
.np-badge { display: inline-block; padding: .05rem .5rem; border-radius: .35rem;
            border: 1px solid #334155; margin-right: .35rem; font-size: .85rem; }
.np-verdict { font-size: 1.25rem; line-height: 1.5; border-left: 4px solid #3b82f6;
              padding: .4rem .9rem; background: #131c2e; border-radius: .3rem; }
.np-muted { color: #94a3b8; }
</style>
"""


@st.cache_resource(show_spinner=False)
def _repository(db_path: str) -> SQLiteRepository:
    return SQLiteRepository(db_path)


def config() -> PipelineConfig:
    return load_pipeline_config(CONFIG_PATH) if CONFIG_PATH.is_file() else PipelineConfig()


def repository() -> SQLiteRepository:
    return _repository(resolve_db_path(config().storage))


@dataclass(frozen=True)
class Context:
    repo: SQLiteRepository
    batch: BatchInfo | None
    analyst: str
    session: SessionRecord | None  # the analyst's running study session for this batch

    @property
    def session_id(self) -> str | None:
        return self.session.session_id if self.session else None


def sidebar() -> Context:
    repo = repository()
    st.markdown(CSS, unsafe_allow_html=True)
    with st.sidebar:
        st.markdown("### NULLPUNKT")
        # Streamlit drops widget state when switching pages, so the chosen values are kept in
        # plain session keys and fed back as the widgets' defaults.
        analyst = st.text_input(
            "Analyst",
            value=st.session_state.get("analyst_name", ""),
            key="analyst",
            placeholder="your name",
        ).strip()
        st.session_state["analyst_name"] = analyst
        batches = repo.batches()
        batch = None
        if batches:
            ids = [b.batch_id for b in batches]
            kept = st.session_state.get("batch_name")
            chosen = st.selectbox(
                "Shift", ids, index=ids.index(kept) if kept in ids else 0, key="batch_id"
            )
            st.session_state["batch_name"] = chosen
            batch = next(b for b in batches if b.batch_id == chosen)
        session = _session_controls(repo, analyst, batch)
        st.caption("No login: the analyst name is self-declared.")
    return Context(repo, batch, analyst, session)


def _session_controls(
    repo: SQLiteRepository, analyst: str, batch: BatchInfo | None
) -> SessionRecord | None:
    if not analyst or batch is None:
        return None
    st.divider()
    st.markdown("**Study session**")
    running = repo.running_session(analyst)
    if running is not None and running.batch_id != batch.batch_id:
        st.warning(f"Session {running.session_id} is running on {running.batch_id}.")
        return None
    if running is None:
        if st.button("Start session", key="session_start", width="stretch"):
            try:
                running = repo.start_session(analyst, batch.batch_id)
            except DecisionError as exc:
                st.error(str(exc))
            st.rerun()
        st.caption("Decisions outside a session are not counted in study metrics.")
        return None
    st.success(f"{running.session_id} running")
    if st.button("End session", key="session_end", width="stretch"):
        repo.end_session(running.session_id)
        st.rerun()
    return running


def tier_badge(tier: str) -> str:
    return (
        f"<span class='np-tier' style='background:{TIER_COLOURS[tier]}' "
        f"title='{TIER_MEANING[tier]}'>{tier}</span>"
    )


def badge(text: str) -> str:
    return f"<span class='np-badge'>{text}</span>"


def status_label(status: str) -> str:
    return STATUS_LABEL.get(status, status)


def require_batch(ctx: Context) -> BatchInfo:
    if ctx.batch is None:
        st.info(
            "No prepared shift in the database yet. Run "
            "`nullpunkt-prepare-shift --batch data/generated/batch-001` first."
        )
        st.stop()
    return ctx.batch
