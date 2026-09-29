"""Baseline arm: the raw alert list a SIEM shows today.

Deliberately shows nothing the pipeline derives: no incidents, grouping, scores, tiers, ATT&CK
or briefs. Only the stored raw alerts, sorted by severity then time.
"""

import pandas as pd
import streamlit as st

from nullpunkt.app.baseline import alert_table, filter_alerts
from nullpunkt.app.ui import require_batch, sidebar
from nullpunkt.app.views import local_time, zone_name
from nullpunkt.storage.repository import DecisionError

ctx = sidebar()
batch = require_batch(ctx)
repo = ctx.repo
tz = batch.timezone


@st.cache_data(show_spinner=False)
def _rows(db_path: str, batch_id: str, tz: str) -> list[dict]:
    return alert_table(repo.raw_alerts(batch_id), tz)


rows = _rows(repo.path, batch.batch_id, tz)
zone = zone_name(batch.first_alert_at, tz)
st.markdown(f"## Alerts · {batch.batch_id}")

c1, c2, c3 = st.columns([3, 2, 2])
query = c1.text_input("Search (rule, message, host, user, IP)", key="b_search")
severities = c2.multiselect(
    "Severity", ["critical", "high", "medium", "low"], key="b_severity", placeholder="all"
)
sources = c3.multiselect(
    "Source", sorted({r["Source"] for r in rows}), key="b_source", placeholder="all"
)
c4, c5 = st.columns(2)
host = c4.text_input("Host contains", key="b_host")
user = c5.text_input("User contains", key="b_user")

shown = filter_alerts(rows, query, severities, sources, host, user)
st.caption(f"{len(rows):,} alerts · {len(shown):,} shown · times in {zone}")

frame = pd.DataFrame(shown, columns=list(rows[0]) if rows else None)
event = st.dataframe(
    frame,
    hide_index=True,
    width="stretch",
    height=520,
    on_select="rerun",
    selection_mode="single-row",
    key="alert_table",
)
selected = event.selection.rows if event and event.selection else []
if selected:
    st.session_state["flag_alert_id"] = shown[selected[0]]["Alert"]

st.markdown("#### Flag an alert as suspicious")
if ctx.arm != "baseline":
    st.info("Flags are recorded only during a baseline study session.")
else:
    f1, f2, f3 = st.columns([2, 4, 1])
    alert_id = f1.text_input("Alert ID", key="flag_alert_id").strip()
    note = f2.text_input("Short note (optional)", key="flag_note")
    if f3.button("Flag", key="flag_submit", type="primary", width="stretch"):
        try:
            flag = repo.flag_alert(ctx.session_id, alert_id, note)
        except DecisionError as exc:
            st.session_state["flag_error"] = str(exc)
        else:
            st.session_state["flag_done"] = f"Flagged {flag.alert_id}"
        st.rerun()
    if err := st.session_state.pop("flag_error", None):
        st.error(err)
    if done := st.session_state.pop("flag_done", None):
        st.toast(done)

    flags = repo.flags(ctx.session_id)
    st.markdown(f"#### My flags ({len(flags)})")
    for flag in reversed(flags):
        note_text = f" · {flag.note}" if flag.note else ""
        st.markdown(
            f"- {local_time(flag.flagged_at, tz, '%H:%M:%S')} · `{flag.alert_id}`{note_text}"
        )
