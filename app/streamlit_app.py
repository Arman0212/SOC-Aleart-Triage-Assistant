"""Nullpunkt analyst app: streamlit run app/streamlit_app.py

Reads and writes only the shift database (see nullpunkt-prepare-shift). While a study session
runs, only that arm's pages are reachable (docs/study_protocol.md). If DEMO_PASSCODE is set, a
passcode prompt is the only page until it is entered (docs/deployment.md)."""

import streamlit as st

from nullpunkt.app.gate import passcode_page, unlocked
from nullpunkt.app.ui import navigation_pages

st.set_page_config(page_title="Nullpunkt", page_icon="🛡️", layout="wide")
if unlocked():
    st.navigation(navigation_pages()).run()
else:
    # Only the prompt is registered, so no other page can be reached by URL while locked.
    st.navigation([st.Page(passcode_page, title="Passcode")], position="hidden").run()
