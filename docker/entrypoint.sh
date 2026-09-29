#!/bin/sh
# Container start: restore the pristine demo database to local disk, then serve the app.
# Every start is a fresh demo, so restarting the container (or Container App revision) resets it.
set -eu
nullpunkt-demo-reset
exec streamlit run app/streamlit_app.py "$@"
