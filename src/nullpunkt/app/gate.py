"""Sign-in page: the app always opens on it.

Each analyst has an account (``storage.accounts``): a username, an email address and a password.
The page has five screens, kept in ``st.session_state[MODE]``:

- **login**: username or email, and password. The username goes on every decision.
- **register**: username, email, password twice, and the team password if ``DEMO_PASSCODE`` is
  set (in the environment or ``.env``), so strangers who find a public URL can't sign up.
- **confirm**: the 6-digit code emailed at registration (``app.mail``); confirming signs in.
- **forgot** and **reset**: a code emailed to the account's address, then a new password. These
  screens say the same thing whether or not an account matches.

The shift is chosen in the sidebar afterwards, which opens on the first shift.
``sign_out_button`` forgets the analyst and returns to the sign-in page.
"""

from __future__ import annotations

import hmac
import json
from collections import Counter

import streamlit as st
import streamlit.components.v1 as components
from pydantic_settings import BaseSettings, SettingsConfigDict

from nullpunkt.app import theme
from nullpunkt.app.mail import NOT_SET_UP, MailError, mail_configured, send_code
from nullpunkt.app.views import TIER_COLOURS
from nullpunkt.storage.accounts import (
    MIN_PASSWORD,
    Account,
    AccountError,
    AccountStore,
    NotVerified,
    mask_email,
)

PASSCODE_ENV = "DEMO_PASSCODE"
SIGNED_IN = "signed_in"
MODE = "gate_mode"  # login, register, confirm, forgot or reset
PENDING = "gate_pending"  # the account the confirm or reset screen is for
NOTICE = "gate_notice"  # (kind, text) shown once on the next screen
# Widget keys holding what was typed on the sign-in page; cleared on sign-in and sign-out.
TYPED = (
    "login_id",
    "login_password",
    "reg_username",
    "reg_email",
    "reg_password",
    "reg_repeat",
    "reg_team",
    "confirm_code",
    "forgot_id",
    "reset_code",
    "reset_password",
    "reset_repeat",
)
SAME_EITHER_WAY = "If an account matches, we've emailed it a code. It expires in 10 minutes."


class GateSettings(BaseSettings):
    """The team password: ``DEMO_PASSCODE`` from the environment (Azure sets it from a Container
    Apps secret) or from ``.env``. The environment wins; an empty value means none."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    demo_passcode: str | None = None


def required_passcode() -> str | None:
    """The team password that registration asks for, or None when anyone can register."""
    return GateSettings().demo_passcode or None


def signed_in() -> bool:
    """True once this browser session has signed in."""
    return bool(st.session_state.get(SIGNED_IN))


# Sign-in page only, on top of theme.CSS (fonts, colours, the ring logo). Its classes start with
# np-cv- ("cover") so they never collide with the app pages' styles.
CSS = """
<style>
[data-testid="stHeader"], [data-testid="stSidebar"], [data-testid="stSidebarCollapsedControl"] {
  display: none; }
[data-testid="stAppViewContainer"] {
  background:
    radial-gradient(900px 520px at 6% -4%, rgba(59,130,246,.18), transparent 62%),
    radial-gradient(760px 460px at 104% 104%, rgba(229,72,77,.13), transparent 60%),
    linear-gradient(rgba(255,255,255,.022) 1px, transparent 1px) 0 0 / 48px 48px,
    linear-gradient(90deg, rgba(255,255,255,.022) 1px, transparent 1px) 0 0 / 48px 48px,
    #0b1220; }
.block-container { max-width: 1320px; min-height: 100vh; display: flex; flex-direction: column;
  justify-content: center; padding-top: 1.5rem; padding-bottom: 1.5rem; }
.st-key-np_cover_panel { min-height: 640px; justify-content: center; gap: .6rem;
  background: rgba(19,28,46,.72); border: 1px solid var(--np-line); border-radius: 28px;
  padding: 2.2rem 2rem 1.4rem; backdrop-filter: blur(14px);
  box-shadow: 0 30px 80px rgba(0,0,0,.35), inset 0 1px 0 rgba(255,255,255,.04); }
.st-key-np_cover_panel [data-testid="stForm"] { background: transparent; border: 0; padding: 0; }
.st-key-np_cover_panel [data-testid="stTextInputRootElement"] { border-radius: 999px;
  background: var(--np-bg); border: 1px solid var(--np-line); min-height: 3rem;
  padding-left: .6rem; }
.st-key-np_cover_panel [data-testid="stTextInputRootElement"]:focus-within {
  border-color: var(--np-accent); box-shadow: 0 0 0 4px rgba(59,130,246,.15); }
[data-testid="stFormSubmitButton"] button { height: 3.2rem; border: 0; margin-top: .4rem;
  border-radius: 999px; font-weight: 700; color: #0b1220; background: var(--np-grad);
  box-shadow: 0 10px 30px rgba(229,72,77,.25); }
[data-testid="stFormSubmitButton"] button:hover { filter: brightness(1.08); color: #0b1220; }
[data-testid="stFormSubmitButton"] button p { font-size: 1rem; font-weight: 700; }
.np-cv-mobile { display: none; margin-bottom: 1.2rem; }
.np-cv-live { display: inline-flex; align-items: center; gap: .55rem; font: 500 .68rem
  var(--np-mono); letter-spacing: .1em; text-transform: uppercase; color: var(--np-muted);
  border: 1px solid var(--np-line); border-radius: 999px; padding: .32rem .75rem;
  background: rgba(11,18,32,.6); }
.np-cv-live i { width: 7px; height: 7px; border-radius: 50%; background: #e5484d;
  animation: np-cv-pulse 1.8s ease-out infinite; }
@keyframes np-cv-pulse { 0% { box-shadow: 0 0 0 0 rgba(229,72,77,.55); }
  100% { box-shadow: 0 0 0 9px rgba(229,72,77,0); } }
.st-key-np_cover_panel p.np-cv-title { font-family: var(--np-display); font-size: 2.05rem;
  font-weight: 700; letter-spacing: -.035em; line-height: 1.08; color: var(--np-text);
  margin: 1.1rem 0 .35rem; }
.st-key-np_cover_panel p.np-cv-sub { color: var(--np-muted); font-size: .95rem;
  margin: 0 0 .6rem; }
.st-key-np_cover_links { border-top: 1px solid var(--np-line); padding-top: .5rem; }
.st-key-np_cover_links [data-testid="stBaseButton-tertiary"] { color: #e6edf3; }
.st-key-np_cover_links [data-testid="stBaseButton-tertiary"] p { font-weight: 600; }
.st-key-np_cover_links [data-testid="stBaseButton-tertiary"]:hover { color: #f5a524; }
.st-key-np_cover_links [data-testid="stColumn"]:last-child:not(:first-child)
  [data-testid="stVerticalBlock"] { align-items: flex-end; }
@media (max-width: 640px) {
  .st-key-np_cover_hero { display: none; }
  .np-cv-mobile { display: block; }
  .st-key-np_cover_panel { min-height: 0; padding: 1.6rem 1.2rem 1rem; } }
</style>
"""

HERO_HEIGHT = 640

# The left panel, in its own iframe (so it carries its own fonts and styles): the headline, then
# the shift as a funnel. A cloud of grey alerts streams into one dot per incident, coloured by
# tier; the P1 dots feed a ranked list. Only counts reach this page, never incident IDs or asset
# names: it is shown before sign-in. __DATA__ is replaced with them.
HERO = """
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Schibsted+Grotesk:wght@500;700;800&family=JetBrains+Mono:wght@500&display=swap">
<style>
  :root { --text: #e6edf3; --muted: #8a97ad; --line: #22304a;
    --mono: "JetBrains Mono", ui-monospace, monospace;
    --display: "Schibsted Grotesk", "Helvetica Neue", Arial, sans-serif; }
  html, body { margin: 0; height: 100%; background: transparent; color: var(--text);
    font-family: var(--display); overflow: hidden; }
  .cv { height: 100%; box-sizing: border-box; padding: 4px 6px 2px 2px; display: flex;
    flex-direction: column; }
  header { display: flex; align-items: center; justify-content: space-between; }
  .mark { display: flex; align-items: center; gap: 10px; font-weight: 800; font-size: 21px;
    letter-spacing: -.02em; }
  .ring { width: 24px; height: 24px; border-radius: 50%; position: relative;
    background: conic-gradient(from 210deg, #e5484d, #f5a524, #22d3ee, #3b82f6, #e5484d); }
  .ring::after { content: ""; position: absolute; inset: 4px; border-radius: 50%;
    background: #0d1526; }
  .tag { font: 500 11px var(--mono); letter-spacing: .14em; text-transform: uppercase;
    color: var(--muted); }
  h1 { margin: 30px 0 0; font-size: clamp(34px, 5vw, 58px); line-height: 1.02;
    letter-spacing: -.045em; font-weight: 800; }
  h1 em { font-style: normal; color: transparent; -webkit-background-clip: text;
    background-clip: text; background-image: linear-gradient(100deg, #e5484d, #f5a524); }
  .lede { margin: 14px 0 0; max-width: 54ch; color: var(--muted); font-size: 15.5px;
    line-height: 1.55; }
  .stage { position: relative; flex: 1; min-height: 150px; margin-top: 10px; }
  canvas { position: absolute; inset: 0; width: 100%; height: 100%; }
  .counts { display: grid; grid-template-columns: 36% 34% 30%; padding-top: 12px;
    border-top: 1px solid var(--line); }
  .counts div { display: grid; gap: 2px; }
  .counts b { font-size: 30px; font-weight: 800; letter-spacing: -.03em;
    font-variant-numeric: tabular-nums; }
  .counts span { font: 500 11px var(--mono); letter-spacing: .1em; text-transform: uppercase;
    color: var(--muted); }
  .counts .p1 b { color: #e5484d; }
  .pills { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
  .pills span { font: 500 12px var(--mono); color: #c9d4e3; border: 1px solid var(--line);
    border-radius: 999px; padding: 6px 12px; background: rgba(19,28,46,.6); }
  .pills i { display: inline-block; width: 6px; height: 6px; border-radius: 50%;
    margin-right: 8px; vertical-align: 1px; }
</style>
<div class="cv">
  <header><div class="mark"><span class="ring"></span>Nullpunkt</div>
    <div class="tag">SOC alert triage</div></header>
  <h1 id="headline"></h1>
  <p class="lede">Nullpunkt groups the shift's alerts into incidents, ranks them by risk to the
    business and drafts a brief for each. You start with what matters, and you make every call.</p>
  <div class="stage"><canvas id="c"></canvas></div>
  <div class="counts" id="counts"></div>
  <div class="pills">
    <span><i style="background:#3b82f6"></i>Correlate</span>
    <span><i style="background:#f5a524"></i>Rank by business risk</span>
    <span><i style="background:#e5484d"></i>Briefs by Phi</span>
    <span><i style="background:#6b7280"></i>The analyst decides</span>
  </div>
</div>
<script>
const D = __DATA__;
const WORDS = ["No", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten",
  "Eleven", "Twelve"];
const fmt = n => n.toLocaleString("en-US");
document.getElementById("headline").innerHTML = D.alerts
  ? `${fmt(D.alerts)} alerts.<br>One analyst.<br><em>${D.p1 <= 12 ? WORDS[D.p1] : fmt(D.p1)} that `
    + `matter${D.p1 === 1 ? "s" : ""}.</em>`
  : "Every alert.<br>One analyst.<br><em>The few that matter.</em>";
document.getElementById("counts").innerHTML =
  `<div><b>${fmt(D.alerts)}</b><span>alerts in</span></div>`
  + `<div><b>${fmt(D.incidents)}</b><span>incidents</span></div>`
  + `<div class="p1"><b>${D.p1}</b><span>P1 &middot; act now</span></div>`;

const cv = document.getElementById("c"), ctx = cv.getContext("2d");
const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
const [P1, , , ] = D.colours, GREY = "#8a97ad";
const rnd = (a, b) => a + Math.random() * (b - a);
const rgba = (hex, a) => { const n = parseInt(hex.slice(1), 16);
  return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${a})`; };
const quad = (a, b, c, t) => (1 - t) * (1 - t) * a + 2 * (1 - t) * t * b + t * t * c;
const cubic = (a, b, c, d, t) => { const u = 1 - t;
  return u * u * u * a + 3 * u * u * t * b + 3 * u * t * t * c + t * t * t * d; };
let W, H, X0, cloud, nodes, firsts, rows, flow, sparks, clock = 0, nextSpark = 0, turn = 0;

function layout() {
  const r = cv.getBoundingClientRect(), dpr = devicePixelRatio || 1;
  W = r.width; H = r.height; cv.width = W * dpr; cv.height = H * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  X0 = .72 * W;
  // Unsorted alerts: a few dense clumps (bursts of one rule) over a thin even spread.
  const clumps = Array.from({length: 7}, () => [rnd(.04, .25) * W, rnd(.15, .85) * H]);
  const gauss = () => (Math.random() + Math.random() + Math.random() - 1.5) / 1.5;
  cloud = Array.from({length: 420}, (_, i) => {
    const [cx, cy] = clumps[i % clumps.length], loose = i % 3 === 0;
    return {x: loose ? rnd(.01, .28) * W : cx + gauss() * .05 * W,
      y: loose ? rnd(.06, .94) * H : cy + gauss() * .12 * H, r: rnd(.7, 1.7), p: rnd(0, 6.28)};
  });
  const tiers = [];
  ["P1", "P2", "P3", "P4"].forEach((t, i) => {
    for (let k = 0; k < (D.tiers[t] || 0); k++) tiers.push(i); });
  if (!tiers.length) for (let k = 0; k < 24; k++) tiers.push(Math.min(3, Math.floor(k / 4)));
  for (let i = tiers.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1));
    [tiers[i], tiers[j]] = [tiers[j], tiers[i]]; }
  const cols = Math.ceil(Math.sqrt(tiers.length * .55)), lines = Math.ceil(tiers.length / cols);
  nodes = tiers.map((t, i) => ({
    x: (.37 + .25 * ((i % cols) + .5) / cols) * W + rnd(-5, 5),
    y: (.08 + .84 * (Math.floor(i / cols) + .5) / lines) * H + rnd(-4, 4),
    t, r: [5.5, 4.2, 3.4, 2.6][t], pulse: 0}));
  const shown = Math.min(D.p1 || 0, 5);
  const gap = Math.min(34, H / (shown + 1));
  rows = Array.from({length: shown}, (_, i) => ({y: H / 2 + (i - (shown - 1) / 2) * gap,
    w: D.p1_risk[i] ?? Math.max(.4, 1 - i * .15), glow: reduce ? .5 : 0}));
  firsts = nodes.filter(n => n.t === 0).slice(0, shown);
  // With reduced motion the same stream is drawn once, frozen mid-flight.
  flow = Array.from({length: 150}, () => spawn({}, true));
  sparks = [];
}
function spawn(p, anywhere) {
  const from = cloud[Math.floor(Math.random() * cloud.length)];
  p.to = nodes[Math.floor(Math.random() * nodes.length)];
  p.x0 = from.x; p.y0 = from.y;
  p.cx = (from.x + p.to.x) / 2 + rnd(-20, 20); p.cy = (from.y + p.to.y) / 2 + rnd(-40, 40);
  p.t = anywhere ? Math.random() : 0; p.v = rnd(.0035, .008); p.r = rnd(.9, 1.6);
  return p;
}
function guide(i, t) {
  const n = firsts[i], row = rows[i], mid = (n.x + X0) / 2;
  return [cubic(n.x, mid, mid, X0 - 8, t), cubic(n.y, n.y, row.y, row.y, t)];
}
function dot(x, y, r, fill) { ctx.fillStyle = fill; ctx.beginPath(); ctx.arc(x, y, r, 0, 6.283);
  ctx.fill(); }
function draw(dt) {
  clock += dt;
  ctx.clearRect(0, 0, W, H);
  ctx.setLineDash([3, 5]); ctx.lineWidth = 1; ctx.strokeStyle = rgba(P1, .3);
  firsts.forEach((n, i) => { ctx.beginPath(); ctx.moveTo(n.x, n.y);
    for (let s = 1; s <= 24; s++) ctx.lineTo(...guide(i, s / 24)); ctx.stroke(); });
  ctx.setLineDash([]);
  for (const c of cloud) dot(c.x + (reduce ? 0 : Math.sin(clock / 900 + c.p) * .8), c.y, c.r,
    rgba(GREY, .5));
  for (const p of flow) {
    if (!reduce) p.t += p.v * dt / 16;
    if (p.t >= 1) { p.to.pulse = 1; spawn(p, false); continue; }
    const x = quad(p.x0, p.cx, p.to.x, p.t), y = quad(p.y0, p.cy, p.to.y, p.t);
    dot(x, y, p.r, rgba(p.t > .55 ? D.colours[p.to.t] : GREY, .2 + .65 * p.t));
  }
  for (const n of nodes) {
    if (n.pulse > 0) { ctx.strokeStyle = rgba(D.colours[n.t], n.pulse * .5); ctx.lineWidth = 1;
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r + (1 - n.pulse) * 12, 0, 6.283); ctx.stroke();
      n.pulse = Math.max(0, n.pulse - dt / 650); }
    dot(n.x, n.y, n.r, D.colours[n.t]);
  }
  if (!reduce && firsts.length && clock > nextSpark) {
    sparks.push({i: turn++ % firsts.length, t: 0}); nextSpark = clock + 750;
  }
  sparks = sparks.filter(s => { s.t += dt / 900;
    if (s.t >= 1) { rows[s.i].glow = 1; return false; }
    const [x, y] = guide(s.i, s.t); dot(x, y, 2.6, rgba(P1, .95)); return true; });
  const left = X0 + 26, track = W - 8 - left;
  ctx.font = "500 11px 'JetBrains Mono', monospace"; ctx.textBaseline = "middle";
  rows.forEach((row, i) => {
    ctx.fillStyle = rgba("#ffffff", .05); ctx.beginPath();
    ctx.roundRect(left, row.y - 9, track, 18, 9); ctx.fill();
    ctx.fillStyle = rgba(P1, .35 + .55 * row.glow); ctx.beginPath();
    ctx.roundRect(left, row.y - 9, Math.max(18, track * row.w), 18, 9); ctx.fill();
    ctx.fillStyle = rgba("#e6edf3", .75); ctx.fillText(`#${i + 1}`, X0, row.y);
    ctx.fillStyle = "#0b1220"; ctx.fillText("P1", left + 8, row.y);
    if (!reduce) row.glow = Math.max(0, row.glow - dt / 1400);
  });
}
let before = performance.now();
function loop(now) { draw(Math.min(48, now - before)); before = now; requestAnimationFrame(loop); }
layout();
if (reduce) draw(16); else requestAnimationFrame(loop);
addEventListener("resize", () => { layout(); if (reduce) draw(16); });
</script>
"""


def _hero(data: dict) -> str:
    return HERO.replace("__DATA__", json.dumps(data))


def sign_out_button() -> None:
    """A sidebar button that forgets the analyst and returns to the sign-in page."""
    if st.button("Sign out", key="sign_out", icon=":material/logout:", width="stretch"):
        for key in (SIGNED_IN, "analyst_name", MODE, PENDING, NOTICE, *TYPED):
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
    live = f"Shift {shown.batch_id} is live" if shown else "Analyst console"

    # Counts only: this page is public, so no incident IDs or asset names.
    rows = repo.queue(shown.batch_id) if shown else []
    top = max((r.risk for r in rows), default=0.0) or 1.0
    data = {
        "alerts": shown.alert_count if shown else 0,
        "incidents": shown.incident_count if shown else 0,
        "p1": sum(r.tier == "P1" for r in rows),
        "tiers": dict(Counter(r.tier for r in rows)),
        "p1_risk": [round(r.risk / top, 3) for r in rows if r.tier == "P1"][:5],
        "colours": [TIER_COLOURS[t] for t in ("P1", "P2", "P3", "P4")],
    }

    hero, panel = st.columns([1.3, 0.9], gap="large", vertical_alignment="center")
    with hero, st.container(key="np_cover_hero"):
        components.html(_hero(data), height=HERO_HEIGHT)
    with panel, st.container(key="np_cover_panel"):
        screen = SCREENS.get(st.session_state.get(MODE, "login"), _login)
        screen(live)


# --- the screens ---------------------------------------------------------------------------------


def _accounts() -> AccountStore:
    """A short-lived store per action, so sessions on different threads never share a
    connection."""
    return AccountStore()


def _header(live: str, title: str, sub: str) -> None:
    st.markdown(
        f'<div class="np-cv-mobile">{theme.MARK}</div>'
        f'<div class="np-cv-live"><i></i>{live}</div>'
        f'<p class="np-cv-title">{title}</p><p class="np-cv-sub">{sub}</p>',
        unsafe_allow_html=True,
    )
    if notice := st.session_state.pop(NOTICE, None):
        kind, text = notice
        getattr(st, kind)(text)


def _links(count: int) -> list:
    """Columns for the links under a screen's form, in their own divided row. With two, the second
    link is right-aligned (see CSS)."""
    return st.container(key="np_cover_links").columns(count)


def _go(mode: str, pending: str | None = None, notice: tuple[str, str] | None = None) -> None:
    st.session_state[MODE] = mode
    if pending is not None:
        st.session_state[PENDING] = pending
    if notice is not None:
        st.session_state[NOTICE] = notice
    st.rerun()


def _sign_in(username: str) -> None:
    for key in (MODE, PENDING, NOTICE, *TYPED):
        st.session_state.pop(key, None)
    st.session_state[SIGNED_IN] = True
    st.session_state["analyst_name"] = username
    st.rerun()


def _email(account: Account, code: str, purpose: str) -> bool:
    """Email the code; on failure show why and return False."""
    try:
        send_code(account.email, account.username, code, purpose)
    except MailError as exc:
        st.error(str(exc))
        return False
    return True


def _login(live: str) -> None:
    with st.form("login_form"):
        _header(live, "Sign in to triage", "Your username goes on every decision you make.")
        identifier = st.text_input("Username or email", key="login_id")
        password = st.text_input("Password", type="password", key="login_password")
        submitted = st.form_submit_button("Start shift", key="login_submit", width="stretch")
    if submitted:
        try:
            with _accounts() as store:
                account = store.authenticate(identifier, password)
        except NotVerified:
            # The password was right, so send a fresh code (unless one was just sent).
            with _accounts() as store:
                pending = store.account(identifier)
                try:
                    code = store.issue_code(pending.username, "verify")
                except AccountError:
                    code = None
            if code is None or _email(pending, code, "verify"):
                where = mask_email(pending.email)
                notice = ("info", f"Confirm your email first: enter the code sent to {where}.")
                _go("confirm", pending.username, notice)
        except AccountError as exc:
            st.error(str(exc))
        else:
            _sign_in(account.username)
    left, right = _links(2)
    if left.button("Create an account", key="to_register", type="tertiary"):
        _go("register")
    if right.button("Forgot password?", key="to_forgot", type="tertiary"):
        _go("forgot")


def _register(live: str) -> None:
    team = required_passcode()
    with st.form("register_form"):
        _header(live, "Create an account", "We'll email you a code to confirm your address.")
        username = st.text_input(
            "Username",
            key="reg_username",
            help="3 to 32 characters: letters, digits, dots, dashes or underscores.",
        )
        email = st.text_input("Email", key="reg_email", placeholder="you@gmail.com")
        password = st.text_input(
            "Password",
            type="password",
            key="reg_password",
            help=f"At least {MIN_PASSWORD} characters.",
        )
        repeat = st.text_input("Repeat password", type="password", key="reg_repeat")
        invite = ""
        if team is not None:
            invite = st.text_input(
                "Team password", type="password", key="reg_team", help="From your shift lead."
            )
        submitted = st.form_submit_button("Create account", key="register_submit", width="stretch")
    if submitted:
        if team is not None and not hmac.compare_digest(
            invite.encode("utf-8"), team.encode("utf-8")
        ):
            st.error("Wrong team password. Ask your shift lead for it.")
        elif password != repeat:
            st.error("The two passwords differ.")
        elif not mail_configured():
            st.error(NOT_SET_UP)
        else:
            try:
                with _accounts() as store:
                    account = store.register(username, email, password)
                    code = store.issue_code(account.username, "verify")
            except AccountError as exc:
                st.error(str(exc))
            else:
                if _email(account, code, "verify"):
                    where = mask_email(account.email)
                    notice = ("success", f"Account created. We sent a 6-digit code to {where}.")
                else:
                    notice = (
                        "warning",
                        "Account created, but the email failed: ask for a new code.",
                    )
                _go("confirm", account.username, notice)
    if _links(1)[0].button("I already have an account", key="register_back", type="tertiary"):
        _go("login")


def _confirm(live: str) -> None:
    username = st.session_state.get(PENDING)
    if not username:
        _go("login")
    with st.form("confirm_form"):
        _header(live, "Confirm your email", "Enter the 6-digit code from the email we sent you.")
        code = st.text_input("Code", key="confirm_code", max_chars=6, placeholder="123456")
        submitted = st.form_submit_button(
            "Confirm and start", key="confirm_submit", width="stretch"
        )
    if submitted:
        try:
            with _accounts() as store:
                account = store.confirm_email(username, code)
        except AccountError as exc:
            st.error(str(exc))
        else:
            _sign_in(account.username)
    left, right = _links(2)
    if left.button("Send a new code", key="confirm_resend", type="tertiary"):
        try:
            with _accounts() as store:
                account = store.account(username)
                code = store.issue_code(username, "verify")
        except AccountError as exc:
            st.error(str(exc))
        else:
            if _email(account, code, "verify"):
                st.success(f"New code sent to {mask_email(account.email)}.")
    if right.button("Back to sign in", key="confirm_back", type="tertiary"):
        _go("login")


def _forgot(live: str) -> None:
    with st.form("forgot_form"):
        _header(live, "Reset your password", "We'll email a code to the address on your account.")
        identifier = st.text_input("Username or email", key="forgot_id")
        submitted = st.form_submit_button("Email me a code", key="forgot_submit", width="stretch")
    if submitted:
        if not identifier.strip():
            st.error("Enter your username or email address.")
        elif not mail_configured():
            st.error(NOT_SET_UP)
        elif _request_reset(identifier):
            _go("reset", identifier.strip(), ("info", SAME_EITHER_WAY))
    if _links(1)[0].button("Back to sign in", key="forgot_back", type="tertiary"):
        _go("login")


def _request_reset(identifier: str) -> bool:
    """Email a reset code if a confirmed account matches. True unless sending failed; the screen
    says the same either way."""
    with _accounts() as store:
        sent = store.request_reset(identifier)
    return sent is None or _email(sent[0], sent[1], "reset")


def _reset(live: str) -> None:
    identifier = st.session_state.get(PENDING)
    if not identifier:
        _go("login")
    with st.form("reset_form"):
        _header(live, "Choose a new password", "Enter the code from the email and a new password.")
        code = st.text_input("Code", key="reset_code", max_chars=6, placeholder="123456")
        password = st.text_input(
            "New password",
            type="password",
            key="reset_password",
            help=f"At least {MIN_PASSWORD} characters.",
        )
        repeat = st.text_input("Repeat new password", type="password", key="reset_repeat")
        submitted = st.form_submit_button("Set new password", key="reset_submit", width="stretch")
    if submitted:
        if password != repeat:
            st.error("The two passwords differ.")
        else:
            try:
                with _accounts() as store:
                    store.reset_password(identifier, code, password)
            except AccountError as exc:
                st.error(str(exc))
            else:
                _go("login", notice=("success", "Password changed. Sign in with the new one."))
    left, right = _links(2)
    if left.button("Send a new code", key="reset_resend", type="tertiary"):
        if _request_reset(identifier):
            st.info(SAME_EITHER_WAY)
    if right.button("Back to sign in", key="reset_back", type="tertiary"):
        _go("login")


SCREENS = {
    "login": _login,
    "register": _register,
    "confirm": _confirm,
    "forgot": _forgot,
    "reset": _reset,
}
