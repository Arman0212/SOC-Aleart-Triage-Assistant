"""Sign-in page: the app always opens on it.

The analyst enters a name, which goes on every decision made in that browser session. If
``DEMO_PASSCODE`` is set (in the environment or ``.env``), the page also asks for that shared
password, which keeps casual visitors out of a public demo URL. Neither is per-user
authentication: the name is self-declared and there are no accounts.

The shift is chosen in the sidebar afterwards, which opens on the first shift.
``sign_out_button`` forgets the analyst and returns to the sign-in page.
"""

from __future__ import annotations

import hmac
import json

import streamlit as st
import streamlit.components.v1 as components
from pydantic_settings import BaseSettings, SettingsConfigDict

from nullpunkt.app import theme
from nullpunkt.app.views import TIER_COLOURS

PASSCODE_ENV = "DEMO_PASSCODE"
SIGNED_IN = "signed_in"


class GateSettings(BaseSettings):
    """The shared sign-in password: ``DEMO_PASSCODE`` from the environment (Azure sets it from a
    Container Apps secret) or from ``.env``. The environment wins; an empty value means none."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    demo_passcode: str | None = None


def required_passcode() -> str | None:
    """The shared password the sign-in page asks for, or None when it asks only for a name."""
    return GateSettings().demo_passcode or None


def signed_in() -> bool:
    """True once this browser session has signed in."""
    return bool(st.session_state.get(SIGNED_IN))


# Sign-in page only, on top of theme.CSS (fonts, colours, the ring logo).
CSS = """
<style>
[data-testid="stHeader"], [data-testid="stSidebar"], [data-testid="stSidebarCollapsedControl"] {
  display: none; }
.block-container { max-width: 1240px; padding-top: 3rem; }
.np-live { font-family: var(--np-mono); font-size: .72rem; letter-spacing: .08em;
  text-transform: uppercase; color: var(--np-muted); display: flex; align-items: center;
  gap: .5rem; }
.np-live i { width: 8px; height: 8px; border-radius: 50%; background: #e5484d;
  box-shadow: 0 0 0 4px rgba(229,72,77,.2); }
.np-title { font-family: var(--np-display); font-size: 1.85rem; font-weight: 700;
  letter-spacing: -.03em; margin: .5rem 0 .2rem; color: var(--np-text); line-height: 1.15; }
.np-sub { color: var(--np-muted); font-size: .92rem; margin: 0 0 .4rem; }
[data-testid="stForm"] { background: var(--np-panel); border: 1px solid var(--np-line);
  border-radius: 24px; padding: 1.8rem 1.7rem 1.2rem; backdrop-filter: blur(10px); }
[data-testid="stForm"] [data-testid="stTextInputRootElement"] { border-radius: 999px;
  background: var(--np-bg); border: 1px solid var(--np-line); min-height: 3rem;
  padding-left: .6rem; }
[data-testid="stForm"] [data-testid="stTextInputRootElement"]:focus-within {
  border-color: var(--np-accent); }
[data-testid="stFormSubmitButton"] button { height: 3.2rem; border: 0; margin-top: .4rem;
  border-radius: 999px; font-weight: 700; color: #0b1220; background: var(--np-grad); }
[data-testid="stFormSubmitButton"] button:hover { filter: brightness(1.08); color: #0b1220; }
[data-testid="stFormSubmitButton"] button p { font-size: 1rem; font-weight: 700; }
</style>
"""

# The left panel: scattered alerts drifting into a few tier-coloured incidents. It runs in its
# own iframe, so it carries its own fonts and styles. __STATS__ is replaced with the shift counts.
HERO = """
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Schibsted+Grotesk:wght@500;800&family=JetBrains+Mono:wght@500&display=swap">
<style>
  html, body { margin: 0; height: 100%; background: transparent; color: #e6edf3;
    font-family: "Schibsted Grotesk", "Helvetica Neue", Arial, sans-serif; overflow: hidden; }
  .hero { position: relative; height: 100%; padding: 8px 8px 12px; box-sizing: border-box;
    display: flex; flex-direction: column; gap: 16px; }
  canvas { position: absolute; inset: 0; width: 100%; height: 100%; }
  .hero > *:not(canvas) { position: relative; }
  h1 { margin: 54px 0 0; font-size: clamp(36px, 6vw, 58px); line-height: 1; letter-spacing: -.04em;
    font-weight: 800; max-width: 11ch; }
  p { margin: 0; color: #8a97ad; max-width: 40ch; font-size: 16px; line-height: 1.5; }
  .stats { margin-top: auto; display: flex; gap: 28px; flex-wrap: wrap; }
  .stats div { display: grid; }
  .stats b { font-size: 26px; letter-spacing: -.02em; font-variant-numeric: tabular-nums; }
  .stats span { font: 500 11px "JetBrains Mono", monospace; color: #8a97ad; letter-spacing: .1em;
    text-transform: uppercase; }
</style>
<div class="hero">
  <canvas id="c"></canvas>
  <h1>Bring the noise down to zero.</h1>
  <p>Every dot is an alert from tonight's shift. Nullpunkt folds them into the few incidents
     worth a human decision.</p>
  <div class="stats" id="stats"></div>
</div>
<script>
const S = __STATS__;
document.getElementById("stats").innerHTML = S.items
  .map(([v, l]) => `<div><b>${v}</b><span>${l}</span></div>`).join("");
const cv = document.getElementById("c"), ctx = cv.getContext("2d");
const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
const cols = S.colours;
let W, H, dots, sinks;
function size() {
  const r = cv.getBoundingClientRect(), d = devicePixelRatio || 1;
  W = r.width; H = r.height; cv.width = W * d; cv.height = H * d;
  ctx.setTransform(d, 0, 0, d, 0, 0);
  sinks = [[.80,.22,0],[.90,.38,0],[.74,.50,1],[.92,.58,1],[.82,.70,2],[.66,.32,2],[.94,.20,3]]
    .map(([x, y, t]) => ({x: x * W, y: y * H, t}));
  dots = Array.from({length: 320}, () => seed({}));
}
function seed(d) {
  d.x = Math.random() * W * .55; d.y = Math.random() * H;
  d.s = sinks[Math.floor(Math.random() * sinks.length)];
  d.v = .006 + Math.random() * .012; d.a = 0; d.r = 1 + Math.random() * 1.4; return d;
}
function frame() {
  ctx.clearRect(0, 0, W, H);
  for (const d of dots) {
    d.x += (d.s.x - d.x) * d.v; d.y += (d.s.y - d.y) * d.v; d.a = Math.min(1, d.a + .02);
    const near = Math.hypot(d.s.x - d.x, d.s.y - d.y);
    ctx.globalAlpha = d.a * Math.min(1, near / 40) * .8;
    ctx.fillStyle = near < 120 ? cols[d.s.t] : "#8a97ad";
    ctx.beginPath(); ctx.arc(d.x, d.y, d.r, 0, 6.283); ctx.fill();
    if (near < 3) seed(d);
  }
  ctx.globalAlpha = 1;
  for (const s of sinks) {
    ctx.fillStyle = cols[s.t]; ctx.beginPath(); ctx.arc(s.x, s.y, 7, 0, 6.283); ctx.fill();
    ctx.strokeStyle = cols[s.t]; ctx.globalAlpha = .25;
    ctx.beginPath(); ctx.arc(s.x, s.y, 16, 0, 6.283); ctx.stroke(); ctx.globalAlpha = 1;
  }
  if (!reduce) requestAnimationFrame(frame);
}
size();
if (reduce) for (let i = 0; i < 60; i++) for (const d of dots) {
  d.x += (d.s.x - d.x) * d.v; d.y += (d.s.y - d.y) * d.v; d.a = 1; }
frame();
addEventListener("resize", () => { size(); if (reduce) frame(); });
</script>
"""


def _hero(stats: list[tuple[str, str]]) -> str:
    colours = [TIER_COLOURS[t] for t in ("P1", "P2", "P3", "P4")]
    return HERO.replace("__STATS__", json.dumps({"items": stats, "colours": colours}))


def sign_out_button() -> None:
    """A sidebar button that forgets the analyst and returns to the sign-in page."""
    if st.button("Sign out", key="sign_out", icon=":material/logout:", width="stretch"):
        for key in (SIGNED_IN, "analyst_name", "passcode", "gate_analyst"):
            st.session_state.pop(key, None)
        st.rerun()


def sign_in_page() -> None:
    """The only page until this browser session signs in."""
    # Imported here because ui imports this module for the sign-out button.
    from nullpunkt.app.ui import repository

    st.markdown(theme.CSS + CSS, unsafe_allow_html=True)
    repo = repository()
    batches = repo.batches()
    # The shift the sidebar will open on: the one kept from before sign-out, else the first.
    kept = st.session_state.get("batch_name")
    shown = next((b for b in batches if b.batch_id == kept), batches[0] if batches else None)
    expected = required_passcode()

    hero, form = st.columns([1.15, 0.85], gap="large")
    with form:
        with st.form("sign_in_form"):
            live = f"Shift {shown.batch_id} is live" if shown else "Nullpunkt analyst console"
            st.markdown(
                theme.MARK + f'<div class="np-live" style="margin-top:1.1rem"><i></i>{live}</div>'
                '<p class="np-title">Sign in to triage</p>'
                '<p class="np-sub">Your name goes on every decision you make.</p>',
                unsafe_allow_html=True,
            )
            name = st.text_input(
                "Analyst name",
                value=st.session_state.get("analyst_name", ""),
                key="gate_analyst",
                placeholder="your name",
            )
            entered = ""
            if expected is not None:
                entered = st.text_input("Password", type="password", key="passcode")
            submitted = st.form_submit_button("Start shift", width="stretch")
            st.caption(
                "The password comes from your shift lead."
                if expected is not None
                else "No accounts: your name is self-declared."
            )
        if submitted:
            if expected is not None and not hmac.compare_digest(
                entered.encode("utf-8"), expected.encode("utf-8")
            ):
                st.error("Wrong password. Check it with your shift lead and try again.")
            elif not name.strip():
                st.error("Enter your name to start the shift.")
            else:
                st.session_state[SIGNED_IN] = True
                st.session_state["analyst_name"] = name.strip()
                st.rerun()

    with hero:
        stats = []
        if shown is not None:
            p1 = len(repo.queue(shown.batch_id, tiers=["P1"]))
            stats = [
                (f"{shown.alert_count:,}", "alerts in"),
                (f"{shown.incident_count:,}", "incidents"),
                (f"{p1}", "P1 waiting"),
            ]
        components.html(_hero(stats), height=560)
