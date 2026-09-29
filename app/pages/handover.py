"""Handover: shift stats and the approved, edited and escalated incidents for the next shift."""

import streamlit as st

from nullpunkt.app.report import build_handover, to_html, to_markdown
from nullpunkt.app.ui import require_batch, sidebar

ctx = sidebar()
batch = require_batch(ctx)

st.markdown(f"## Handover · {batch.batch_id}")
handover = build_handover(ctx.repo, batch.batch_id, ctx.session_id)
markdown = to_markdown(handover)

c1, c2 = st.columns(2)
c1.download_button(
    "Download Markdown",
    markdown,
    file_name=f"handover-{batch.batch_id}.md",
    mime="text/markdown",
    key="dl_md",
    width="stretch",
)
c2.download_button(
    "Download HTML (print to PDF)",
    to_html(handover),
    file_name=f"handover-{batch.batch_id}.html",
    mime="text/html",
    key="dl_html",
    width="stretch",
)
st.caption("For a PDF, open the HTML file and use the browser's Print → Save as PDF.")
st.divider()
st.markdown(markdown)
