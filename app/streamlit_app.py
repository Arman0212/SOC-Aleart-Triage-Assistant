"""Nullpunkt analyst app: streamlit run app/streamlit_app.py

Reads and writes only the shift database (see nullpunkt-prepare-shift)."""

import streamlit as st

st.set_page_config(page_title="Nullpunkt", page_icon="🛡️", layout="wide")

pages = st.navigation(
    [
        st.Page("pages/queue.py", title="Queue", icon="📋", default=True),
        st.Page("pages/incident.py", title="Incident", icon="🔎", url_path="incident"),
        st.Page("pages/handover.py", title="Handover", icon="📝", url_path="handover"),
    ]
)
pages.run()
