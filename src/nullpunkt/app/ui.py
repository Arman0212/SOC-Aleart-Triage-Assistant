"""Streamlit helpers shared by the pages in app/: the cached repository, the sidebar (analyst,
batch, study session), and small rendering pieces. The app only talks to the database."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import streamlit as st

from nullpunkt.app import theme
from nullpunkt.app.gate import sign_in_page, sign_out_button, signed_in
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


@st.cache_resource(show_spinner=False)
def _repository(db_path: str) -> SQLiteRepository:
    return SQLiteRepository(db_path)


def config() -> PipelineConfig:
    """configs/pipeline.yaml, or the defaults when it is missing."""
    return load_pipeline_config(CONFIG_PATH) if CONFIG_PATH.is_file() else PipelineConfig()


def repository() -> SQLiteRepository:
    """The app's shared repository for the configured database."""
    return _repository(resolve_db_path(config().storage))


@dataclass(frozen=True)
class Context:
    """What a page needs: the repository, the chosen shift, the analyst and the running study
    session."""

    repo: SQLiteRepository
    batch: BatchInfo | None
    analyst: str  # the participant code while a study session runs
    session: SessionRecord | None  # the session started in this browser, while it runs

    @property
    def session_id(self) -> str | None:
        return self.session.session_id if self.session else None

    @property
    def arm(self) -> str | None:
        return self.session.arm if self.session else None


ACTIVE = "active_session_id"
PAGES = {
    "queue": ("pages/queue.py", "Queue", "📋"),
    "incident": ("pages/incident.py", "Incident", "🔎"),
    "handover": ("pages/handover.py", "Handover", "📝"),
    "baseline": ("pages/baseline.py", "Alert list", "📄"),
}


def active_session(repo: SQLiteRepository | None = None) -> SessionRecord | None:
    """The study session started in this browser, if it is still running. A session whose time
    box ran out is ended by the repository on this read."""
    session_id = st.session_state.get(ACTIVE)
    if not session_id:
        return None
    repo = repo or repository()
    try:
        session = repo.session(session_id)
    except KeyError:
        st.session_state.pop(ACTIVE, None)
        return None
    if not session.running:
        st.session_state.pop(ACTIVE, None)
        reason = "time box reached" if session.end_reason == "timed_out" else "ended"
        st.session_state["session_notice"] = f"Session {session.session_id} over: {reason}."
        return None
    return session


def navigation_pages() -> list:
    """While a study session runs, participants only reach their arm's pages: the baseline arm
    sees only the raw alert list; the tool arm sees only the Nullpunkt pages."""
    arm = (active_session() or _NoSession).arm
    names = {
        "baseline": ["baseline"],
        "tool": ["queue", "incident", "handover"],
    }.get(arm, ["queue", "incident", "handover", "baseline"])
    return [
        st.Page(path, title=title, icon=icon, default=(n == names[0]), url_path=n)
        for n in names
        for path, title, icon in [PAGES[n]]
    ]


class _NoSession:
    arm = None


def sidebar() -> Context:
    """Render the sidebar (analyst, shift, study session) and return the page context."""
    if not signed_in():
        # A page reached without streamlit_app.py's navigation (Streamlit serves app/pages/ by URL
        # until st.navigation first runs) still shows only the sign-in page.
        sign_in_page()
        st.stop()
    repo = repository()
    st.markdown(theme.CSS, unsafe_allow_html=True)
    session = active_session(repo)
    with st.sidebar:
        st.markdown(theme.MARK, unsafe_allow_html=True)
        if session is not None:
            batch = repo.batch(session.batch_id)
            analyst = session.analyst
            _running_panel(repo, session)
        else:
            if notice := st.session_state.pop("session_notice", None):
                st.warning(notice)
            analyst = st.session_state.get("analyst_name", "")  # the account's username
            st.markdown(f"Signed in as **{analyst}**")
            # Streamlit drops widget state when switching pages, so the chosen shift is kept in a
            # plain session key and fed back as the widget's default.
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
                _start_form(repo, [b.batch_id for b in batches], chosen)
            sign_out_button()
    return Context(repo, batch, analyst, session)


def _start_form(repo: SQLiteRepository, batch_ids: list[str], current: str) -> None:
    with st.expander("Start a study session", expanded=False):
        code = st.text_input("Participant code", key="s_participant", placeholder="P1").strip()
        arm = st.radio("Arm", ["baseline", "tool"], key="s_arm", horizontal=True)
        batch_id = st.selectbox("Batch", batch_ids, index=batch_ids.index(current), key="s_batch")
        purpose = st.selectbox("Purpose", ["study", "practice", "dry-run"], key="s_purpose")
        minutes = st.number_input(
            "Time box (minutes)",
            min_value=1.0,
            max_value=120.0,
            value=float(config().study.time_box_minutes),
            step=1.0,
            key="s_minutes",
        )
        st.caption(f"Check before starting: {code or '—'} · {arm} · {batch_id} · {purpose}")
        if st.button("Start session", key="session_start", type="primary", width="stretch"):
            try:
                session = repo.start_session(
                    code,
                    batch_id,
                    arm=arm,
                    purpose=purpose,
                    time_box_seconds=int(round(minutes * 60)),
                )
            except DecisionError as exc:
                st.error(str(exc))
                return
            st.session_state[ACTIVE] = session.session_id
            st.session_state["batch_name"] = batch_id
            st.rerun()


def _running_panel(repo: SQLiteRepository, session: SessionRecord) -> None:
    st.markdown(
        f"**{session.analyst}** · {session.arm} arm · {session.batch_id}"
        + ("" if session.purpose == "study" else f" · {session.purpose}")
    )
    _countdown(session.session_id)
    if st.button("End session", key="session_end", width="stretch"):
        repo.end_session(session.session_id)
        st.rerun()


@st.fragment(run_every=1)
def _countdown(session_id: str) -> None:
    repo = repository()
    session = repo.session(session_id)  # ends it at the deadline if the time box ran out
    if not session.running:
        st.rerun(scope="app")
    remaining = int(session.remaining_seconds(repo.now()) or 0)
    minutes, seconds = divmod(remaining, 60)
    st.markdown(f"## ⏱ {minutes:02d}:{seconds:02d}")
    st.caption("time left in this session")


def tier_badge(tier: str) -> str:
    """HTML badge for a tier: its colour, with its meaning as the tooltip."""
    return (
        f"<span class='np-tier' style='background:{TIER_COLOURS[tier]}' "
        f"title='{TIER_MEANING[tier]}'>{tier}</span>"
    )


def badge(text: str) -> str:
    """HTML for a neutral badge."""
    return f"<span class='np-badge'>{text}</span>"


def status_label(status: str) -> str:
    """Display label for an incident status."""
    return STATUS_LABEL.get(status, status)


def require_batch(ctx: Context) -> BatchInfo:
    """The context's shift; without one, explain how to prepare it and stop the page."""
    if ctx.batch is None:
        st.info(
            "No prepared shift in the database yet. Run "
            "`nullpunkt-prepare-shift --batch data/generated/batch-001` first."
        )
        st.stop()
    return ctx.batch
