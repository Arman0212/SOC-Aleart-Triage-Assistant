"""Queue: incidents by rank, tier first."""

import pandas as pd
import streamlit as st

from nullpunkt.app.metrics import format_duration, shift_stats
from nullpunkt.app.ui import require_batch, sidebar, status_label
from nullpunkt.app.views import TIER_COLOURS, risk_bar_fraction, tactic_chain

ctx = sidebar()
batch = require_batch(ctx)
repo = ctx.repo

stats = shift_stats(repo, batch.batch_id, ctx.session_id)
st.markdown(f"## Shift {batch.batch_id}")
cols = st.columns(5)
cols[0].metric("Alerts in shift", f"{stats.alerts:,}")
cols[1].metric("Incidents", stats.incidents)
cols[2].metric("Reduction", f"{stats.reduction_ratio:.0f}×")
cols[3].metric("Decided", f"{stats.decided} / {stats.incidents}")
cols[4].metric("MTTT (first decisions)", format_duration(stats.mttt_seconds))

f1, f2 = st.columns(2)
tiers = f1.multiselect(
    "Tier", ["P1", "P2", "P3", "P4"], default=["P1", "P2", "P3", "P4"], key="f_tier"
)
statuses = f2.multiselect(
    "Status",
    ["open", "approved", "dismissed", "escalated"],
    default=["open", "approved", "dismissed", "escalated"],
    format_func=status_label,
    key="f_status",
)

rows = repo.queue(batch.batch_id, tiers=tiers, statuses=statuses, scope=ctx.session_id)
top = max((r.risk for r in repo.queue(batch.batch_id)[:1]), default=0.0)

if not rows:
    st.info("No incidents match these filters.")
    st.stop()

o1, o2 = st.columns([4, 1])
choice = o1.selectbox(
    "Open incident",
    [r.incident_id for r in rows],
    format_func=lambda iid: next(
        f"#{r.rank} [{r.tier}] {r.incident_id} · {r.asset or '—'} · risk {r.risk:.1f}"
        for r in rows
        if r.incident_id == iid
    ),
    key="open_choice",
)
if o2.button("Open", key="open_incident", type="primary", width="stretch"):
    st.session_state["incident_id"] = choice
    st.switch_page("pages/incident.py")

frame = pd.DataFrame(
    {
        "Tier": [r.tier for r in rows],
        "Rank": [r.rank for r in rows],
        "Risk vs top": [risk_bar_fraction(r.risk, top) for r in rows],
        "Risk": [r.risk for r in rows],
        "Asset at risk": [f"{r.asset or '—'} · crit {r.criticality}" for r in rows],
        "ATT&CK tactics": [tactic_chain(r.tactics) for r in rows],
        "Alerts": [r.alert_count for r in rows],
        "Status": [status_label(r.status) for r in rows],
        "Incident": [r.incident_id for r in rows],
    }
)
styled = frame.style.map(
    lambda t: f"background-color: {TIER_COLOURS[t]}; color: #0b1220; font-weight: 700",
    subset=["Tier"],
)
event = st.dataframe(
    styled,
    hide_index=True,
    width="stretch",
    height=min(38 + 35 * len(rows), 720),
    on_select="rerun",
    selection_mode="single-row",
    key="queue_table",
    column_config={
        "Risk vs top": st.column_config.ProgressColumn(
            "Risk vs top", min_value=0.0, max_value=1.0, format=" "
        ),
        "Risk": st.column_config.NumberColumn("Risk", format="%.1f"),
        "ATT&CK tactics": st.column_config.TextColumn(
            "ATT&CK tactics", help="IA initial access, EX execution, ST stealth, CA credential "
            "access, DS discovery, LM lateral movement, CO collection, C2 command and control, "
            "EF exfiltration, IM impact"
        ),
    },
)  # fmt: skip
selected = event.selection.rows if event and event.selection else []
if selected:
    st.session_state["incident_id"] = rows[selected[0]].incident_id
    st.switch_page("pages/incident.py")
