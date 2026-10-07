"""Smoke test run inside the built image by CI (.github/workflows/docker.yml).

    docker run --rm -v "$PWD/docker/smoke_test.py:/tmp/smoke_test.py:ro" --entrypoint sh IMAGE \
        -c "nullpunkt-demo-reset && python /tmp/smoke_test.py"

Renders the app headlessly on the restored demo database, so the trimmed environment (pandas,
pyarrow, Streamlit) is exercised end to end: signing in with an account, the queue, the top
incident and the handover page. It makes no decisions (opening INC-0055 records an opening and the
handover page audits a report export), and the container's copy is replaced at every start anyway.
The account goes into a throwaway accounts database, so no email is needed.
"""

import os
import sys
import tempfile
from pathlib import Path
from zoneinfo import ZoneInfo

from streamlit.testing.v1 import AppTest

from nullpunkt.storage.accounts import AccountStore

ZoneInfo("Asia/Kolkata")  # the demo shift's time zone must resolve inside the image

# Read by AccountStore here and by the app's sign-in page below.
os.environ["ACCOUNTS_DB_PATH"] = str(Path(tempfile.mkdtemp()) / "accounts.db")
with AccountStore() as store:
    store.add_confirmed("smoke", "smoke@example.com", "smoke-test-password")

# AppTest resolves relative paths against this file, so anchor at the working directory (/app).
at = AppTest.from_file(str(Path.cwd() / "app" / "streamlit_app.py"), default_timeout=60)
at.run()
assert not at.exception, at.exception
assert len(at.dataframe) == 0, "the app must open on the sign-in page"
at.text_input(key="login_id").input("smoke")
at.text_input(key="login_password").input("smoke-test-password")
at.button(key="login_submit").click().run()
assert not at.exception, at.exception
queue = at.dataframe[0].value
assert len(queue) == 65, len(queue)
assert queue["Incident"].iloc[0] == "INC-0055", queue["Incident"].iloc[0]

at.session_state["incident_id"] = "INC-0055"
at.switch_page("pages/incident.py").run()
assert not at.exception, at.exception
page = " ".join(m.value for m in at.markdown)
assert "np-verdict" in page and "INC-0055" in page

at.switch_page("pages/handover.py").run()
assert not at.exception, at.exception

print("smoke test passed: account sign-in, queue (65 incidents), INC-0055 and handover render")
sys.exit(0)
