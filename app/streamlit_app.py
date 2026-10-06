"""Nullpunkt analyst app: streamlit run app/streamlit_app.py

Reads and writes only the shift database (see nullpunkt-prepare-shift). While a study session
runs, only that arm's pages are reachable (docs/study_protocol.md). The sign-in page (analyst name,
plus DEMO_PASSCODE if set) is the only page until the browser session signs in."""

import streamlit as st

from nullpunkt.app.gate import sign_in_page, signed_in
from nullpunkt.app.ui import navigation_pages

st.set_page_config(page_title="Nullpunkt", page_icon="🛡️", layout="wide")
if signed_in():
    st.navigation(navigation_pages()).run()
else:
    # Only the sign-in page is registered, so no other page can be reached by URL before sign-in.
    st.navigation([st.Page(sign_in_page, title="Sign in")], position="hidden").run()
