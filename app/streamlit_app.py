"""Nullpunkt analyst app: streamlit run app/streamlit_app.py

Reads and writes only the shift database (see nullpunkt-prepare-shift). While a study session
runs, only that arm's pages are reachable (docs/study_protocol.md)."""

import streamlit as st

from nullpunkt.app.ui import navigation_pages

st.set_page_config(page_title="Nullpunkt", page_icon="🛡️", layout="wide")
st.navigation(navigation_pages()).run()
