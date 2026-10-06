"""The app's look, shared by the sign-in page and every other page.

Headings in Schibsted Grotesk, labels and IDs in JetBrains Mono, rounded inputs, buttons and
cards, and the red-to-amber gradient on primary buttons only. Tier colours stay in
``views.TIER_COLOURS`` and are always shown with their label. Without network the fonts fall back
to the theme's sans serif, so the offline demo still works.
"""

from __future__ import annotations

# The ring logo and wordmark, used on the sign-in page and at the top of the sidebar.
MARK = '<div class="np-mark"><span class="np-ring"></span>Nullpunkt</div>'

# One <style> block with no blank lines: st.markdown would end the HTML block at a blank line.
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Schibsted+Grotesk:wght@500;700;800&family=JetBrains+Mono:wght@500&display=swap');
:root { --np-bg: #0b1220; --np-panel: rgba(19,28,46,.82); --np-line: #22304a;
  --np-muted: #8a97ad; --np-text: #e6edf3; --np-accent: #3b82f6;
  --np-grad: linear-gradient(100deg, #e5484d 0%, #f5a524 100%);
  --np-display: "Schibsted Grotesk", "Source Sans Pro", sans-serif;
  --np-mono: "JetBrains Mono", ui-monospace, monospace; }
[data-testid="stAppViewContainer"] {
  background: radial-gradient(1200px 520px at 12% 110%, rgba(59,130,246,.14), transparent 60%),
              var(--np-bg); }
[data-testid="stHeader"] { background: transparent; }
[data-testid="stSidebar"] { border-right: 1px solid var(--np-line); }
.block-container { padding-top: 1.2rem; max-width: 1400px; }
h1, h2, h3, h4 { font-family: var(--np-display) !important; font-weight: 700 !important;
  letter-spacing: -.02em; }
.np-mark { display: flex; align-items: center; gap: .6rem; font-weight: 800; font-size: 1.35rem;
  letter-spacing: -.02em; font-family: var(--np-display); color: var(--np-text); }
.np-ring { width: 24px; height: 24px; border-radius: 50%; flex: none; position: relative;
  background: conic-gradient(from 210deg, #e5484d, #f5a524, #22d3ee, #3b82f6, #e5484d); }
.np-ring::after { content: ""; position: absolute; inset: 4px; border-radius: 50%;
  background: #131c2e; }
[data-testid="stSidebarNavLink"] { border-radius: 999px; }
[data-testid="stMetric"] { background: var(--np-panel); border: 1px solid var(--np-line);
  border-radius: 18px; padding: .75rem .85rem; container-type: inline-size; }
[data-testid="stMetricLabel"] [data-testid="stMarkdownContainer"] { white-space: normal;
  overflow: visible; }
[data-testid="stMetricLabel"] p { font-family: var(--np-mono); font-size: .68rem !important;
  letter-spacing: .04em; line-height: 1.25; white-space: normal; min-height: 2.5em;
  text-transform: uppercase; color: var(--np-muted); }
[data-testid="stMetricValue"] { font-family: var(--np-display); font-weight: 700;
  letter-spacing: -.02em; font-variant-numeric: tabular-nums;
  font-size: clamp(1.3rem, 25cqi, 2.25rem); }
[data-testid="stTextInputRootElement"], [data-testid="stNumberInputContainer"],
[data-testid="stSelectbox"] > div > div, [data-testid="stMultiSelect"] > div > div {
  border-radius: 1.4rem !important; border-color: var(--np-line); }
[data-testid="stTextAreaRootElement"] { border-radius: 16px !important;
  border-color: var(--np-line); }
[data-testid^="stBaseButton-"] { border-radius: 999px; }
[data-testid="stBaseButton-secondary"] { background: var(--np-panel);
  border-color: var(--np-line); }
[data-testid="stBaseButton-primary"] { background: var(--np-grad); border: 0; color: #0b1220; }
[data-testid="stBaseButton-primary"]:hover { filter: brightness(1.08); color: #0b1220; }
[data-testid="stBaseButton-primary"] p { font-weight: 700; }
[data-testid="stDataFrame"] { border-radius: 18px; overflow: hidden; }
[data-testid="stExpander"] details { border-radius: 16px; border-color: var(--np-line);
  background: var(--np-panel); }
[data-testid="stAlertContainer"] { border-radius: 16px; }
hr { border-color: var(--np-line) !important; }
[data-testid="stMarkdownContainer"] code { font-family: var(--np-mono); font-size: .8em;
  color: #93c5fd; background: rgba(59,130,246,.12); border-radius: 6px; padding: .1rem .35rem; }
.np-tier { display: inline-block; min-width: 2.4rem; text-align: center; padding: .05rem .6rem;
  border-radius: 999px; font-weight: 700; color: #0b1220; }
.np-badge { display: inline-block; padding: .1rem .65rem; border-radius: 999px;
  border: 1px solid var(--np-line); background: var(--np-panel); margin-right: .35rem;
  font: 500 .72rem var(--np-mono); letter-spacing: .04em; color: var(--np-muted); }
.np-verdict { font-size: 1.25rem; line-height: 1.5; padding: .9rem 1.2rem; border-radius: 18px;
  background: var(--np-panel); border: 1px solid var(--np-line);
  box-shadow: inset 4px 0 0 var(--np-accent); }
.np-muted { color: #94a3b8; }
</style>
"""
