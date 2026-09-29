"""Incident: verdict first, then decide, then the evidence behind it."""

import pandas as pd
import streamlit as st

from nullpunkt.app.metrics import format_duration
from nullpunkt.app.ui import badge, require_batch, sidebar, status_label, tier_badge
from nullpunkt.app.views import (
    brief_as_text,
    evidence_rows,
    local_time,
    routine_lines,
    tactic_name,
    techniques_in_kill_chain_order,
    zone_name,
)
from nullpunkt.core.schema import DecisionAction
from nullpunkt.correlation.result import Link
from nullpunkt.storage.repository import DecisionError

ctx = sidebar()
batch = require_batch(ctx)
repo = ctx.repo
tz = batch.timezone

incident_id = st.session_state.get("incident_id") or st.query_params.get("incident")
if not incident_id:
    st.info("Pick an incident in the queue.")
    if st.button("← Queue", key="back_empty"):
        st.switch_page("pages/queue.py")
    st.stop()
st.query_params["incident"] = incident_id

try:
    view = repo.incident(batch.batch_id, incident_id, scope=ctx.session_id)
except KeyError:
    st.error(f"{incident_id} is not in shift {batch.batch_id}.")
    st.stop()

inc, score, record = view.incident, view.incident.score, view.brief

# Start triage (idempotent across reruns, refreshes and tabs; never for decided incidents).
opened_at = None
if ctx.analyst:
    opened_at = repo.open_incident(batch.batch_id, incident_id, ctx.analyst, ctx.session_id)

head, back = st.columns([6, 1])
head.markdown(
    f"### {tier_badge(view.tier)} {incident_id} · risk {score.risk_score:.1f} · "
    f"#{view.rank} · status: {status_label(view.status)}",
    unsafe_allow_html=True,
)
if back.button("← Queue", key="back", width="stretch"):
    st.switch_page("pages/queue.py")

# --- verdict -------------------------------------------------------------------------------
if record is not None:
    brief = record.brief
    st.markdown(
        "<div class='np-verdict'>" + "<br>".join(brief.summary.splitlines()) + "</div>",
        unsafe_allow_html=True,
    )
    source = "LLM · " + record.meta["model"] if brief.generated_by.value == "llm" else "Template"
    badges = [
        badge(source),
        badge("validated ✓" if brief.validated else "not validated"),
        badge(f"confidence: {brief.confidence.value}"),
    ]
    if record.meta["fallback_reason"]:
        badges.append(badge(f"fallback: {record.meta['fallback_reason']}"))
    st.markdown("".join(badges), unsafe_allow_html=True)
else:
    brief = None
    st.markdown(f"<div class='np-verdict'>{score.explanation}</div>", unsafe_allow_html=True)
    st.caption("No brief for this incident (only the top incidents are briefed).")

# --- decide --------------------------------------------------------------------------------
st.markdown("#### Decision")
latest = view.latest_decision
if not ctx.analyst:
    st.warning("Enter your analyst name in the sidebar to triage (the timer starts on open).")
elif latest is not None and opened_at is None:
    st.success(
        f"{latest.action.value.upper()} by {latest.analyst} at "
        f"{local_time(latest.decided_at, tz)} {zone_name(latest.decided_at, tz)}"
        + (f" · {latest.notes}" if latest.notes else "")
    )
    if st.button("Change decision", key="redecide"):
        repo.reopen_for_redecision(batch.batch_id, incident_id, ctx.analyst, ctx.session_id)
        st.rerun()
else:
    elapsed = (repo.now() - opened_at).total_seconds() if opened_at else 0
    st.caption(
        f"Triage started {local_time(opened_at, tz)} ({format_duration(elapsed)} ago)"
        + (f" · session {ctx.session_id}" if ctx.session_id else " · no study session")
    )

    def decide(action: DecisionAction, **kw) -> None:
        try:
            repo.record_decision(
                batch.batch_id, incident_id, ctx.analyst, action, session_id=ctx.session_id, **kw
            )
        except DecisionError as exc:
            st.session_state["decision_error"] = str(exc)
        else:
            st.session_state.pop("decision_error", None)
            st.session_state["decision_done"] = f"{action.value} saved for {incident_id}"
        st.rerun()

    a, e, d, x = st.tabs(["✅ Approve", "✏️ Edit & approve", "🚫 Dismiss as FP", "⬆️ Escalate"])
    with a:
        if st.button("Approve brief", key="approve", type="primary"):
            decide(DecisionAction.APPROVE)
    with e:
        text = st.text_area(
            "Brief text", value=brief_as_text(brief) if brief else "", height=260, key="edit_text"
        )
        if st.button("Save edit and approve", key="edit_submit"):
            decide(DecisionAction.EDIT, edited_brief=text)
    with d:
        reason = st.text_input("Reason (required)", key="dismiss_reason")
        if st.button("Dismiss as false positive", key="dismiss_submit"):
            decide(DecisionAction.DISMISS, notes=reason)
    with x:
        note = st.text_area("Escalation note (required)", key="escalate_note", height=100)
        if st.button("Escalate", key="escalate_submit"):
            decide(DecisionAction.ESCALATE, notes=note)
if err := st.session_state.pop("decision_error", None):
    st.error(err)
if done := st.session_state.pop("decision_done", None):
    st.toast(done)

# --- score and grouping ----------------------------------------------------------------------
left, right = st.columns(2)
with left:
    st.markdown("#### Score")
    s1, s2, s3, s4 = st.columns(4)
    s1.metric("Severity × criticality", f"{score.severity_weight} × {score.asset_criticality}")
    s2.metric("Stage multiplier", f"{score.stage_multiplier:g}")
    s3.metric("Noise penalty", f"{score.noise_penalty:.2f}")
    s4.metric("Risk", f"{score.risk_score:.1f}")
    st.caption(score.explanation)
with right:
    st.markdown("#### Why these alerts are grouped")
    if view.links:
        for link in view.links[:12]:
            st.markdown(
                f"- `{link['alert_id']}` + `{link['linked_to']}`: {Link(**link).describe()}"
            )
        if len(view.links) > 12:
            with st.expander(f"{len(view.links) - 12} more links"):
                for link in view.links[12:]:
                    st.markdown(f"- `{link['alert_id']}`: {Link(**link).describe()}")
    else:
        st.caption("Single alert.")

# --- evidence ------------------------------------------------------------------------------
evidence_ids = set(view.detail["evidence"]) or {a.alert_id for a in view.alerts}
zone = zone_name(inc.first_seen, tz)
st.markdown(f"#### Evidence timeline ({zone})")
for row in evidence_rows(view.alerts, evidence_ids, tz):
    when = row["start"] if row["start"] == row["end"] else f"{row['start']}–{row['end']}"
    count = f"{row['count']} × " if row["count"] > 1 else ""
    who = f" · {row['user']}" if row["user"] else ""
    st.markdown(f"- **{when}** {count}{row['rule']} · `{row['host']}`{who} · {row['severity']}")
for line in routine_lines(view.alerts, evidence_ids, tz):
    st.caption(f"Routine: {line}")

st.markdown("#### ATT&CK techniques (kill-chain order)")
for t in techniques_in_kill_chain_order(inc.techniques):
    st.markdown(f"- **{tactic_name(t.tactic)}**: `{t.technique_id}` {t.name}")

if brief is not None:
    st.markdown("#### Brief")
    st.markdown(f"**Affected assets:** {', '.join(brief.affected_assets)}")
    st.markdown("**Timeline:**\n" + "\n".join(f"- {entry}" for entry in brief.timeline))
    st.markdown(f"**Next action:** {brief.next_action}")

with st.expander(f"Raw alerts ({len(view.alerts)})"):
    st.dataframe(
        pd.DataFrame([a.model_dump(mode="json") for a in view.alerts]),
        hide_index=True,
        width="stretch",
    )
