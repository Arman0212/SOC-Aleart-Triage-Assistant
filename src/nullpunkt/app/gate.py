"""Optional passcode for a deployed demo.

If ``DEMO_PASSCODE`` is set in the environment, the app shows only a passcode prompt until the
right passcode is entered in that browser session. If it is unset, the app is unchanged. This keeps
casual visitors out of a public demo URL; it is not per-user authentication, and the analyst name
is still self-declared.
"""

from __future__ import annotations

import hmac
import os

import streamlit as st

PASSCODE_ENV = "DEMO_PASSCODE"
UNLOCKED = "demo_unlocked"


def required_passcode() -> str | None:
    """The passcode the app asks for, or None when the gate is off."""
    return os.environ.get(PASSCODE_ENV) or None


def unlocked() -> bool:
    """True when the gate is off or this browser session entered the right passcode."""
    return required_passcode() is None or bool(st.session_state.get(UNLOCKED))


def passcode_page() -> None:
    """The only page while the app is locked."""
    st.markdown("## Nullpunkt")
    st.caption("This demo is protected by a passcode.")
    with st.form("passcode_form"):
        entered = st.text_input("Passcode", type="password", key="passcode")
        submitted = st.form_submit_button("Enter")
    expected = required_passcode()
    if submitted and expected is not None:
        if hmac.compare_digest(entered.encode("utf-8"), expected.encode("utf-8")):
            st.session_state[UNLOCKED] = True
            st.rerun()
        st.error("Wrong passcode.")
