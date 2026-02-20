from __future__ import annotations

import streamlit as st


def inject_theme(theme: str = "dark") -> None:
    is_dark = theme == "dark"

    bg = "#070b11" if is_dark else "#f7fafc"
    panel = "#111827" if is_dark else "#ffffff"
    panel_2 = "#0f172a" if is_dark else "#eef2f7"
    text = "#e6edf3" if is_dark else "#101828"
    muted = "#9aa4b2" if is_dark else "#475467"
    line = "#233044" if is_dark else "#d0d5dd"
    accent = "#20c997" if is_dark else "#0f766e"
    danger = "#f85149" if is_dark else "#b42318"
    warn = "#f59f00" if is_dark else "#b54708"

    st.markdown(
        f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
:root {{
  --bg:{bg}; --panel:{panel}; --panel-2:{panel_2}; --text:{text}; --muted:{muted};
  --line:{line}; --accent:{accent}; --danger:{danger}; --warn:{warn};
}}
html, body, [class*="css"] {{
  font-family: "IBM Plex Sans", "Segoe UI", sans-serif !important;
  background: var(--bg) !important;
  color: var(--text) !important;
}}
.stApp {{ background: radial-gradient(1200px 600px at 20% -10%, #12324a44, transparent), var(--bg) !important; }}
.block-container {{ max-width: 1260px; padding-top: 1.2rem; padding-bottom: 4rem; }}
h1,h2,h3 {{ font-family: "Space Grotesk", "IBM Plex Sans", sans-serif !important; letter-spacing: -0.02em; color: var(--text) !important; }}
small, .muted {{ color: var(--muted) !important; }}
.rf-card {{
  background: linear-gradient(165deg, var(--panel), var(--panel-2));
  border: 1px solid var(--line); border-radius: 14px; padding: 1rem 1.1rem;
  animation: slideIn .35s cubic-bezier(.2,.8,.2,1);
}}
.rf-kpi {{
  border: 1px solid var(--line); border-radius: 12px; padding: .8rem;
  background: color-mix(in srgb, var(--panel) 78%, black 22%);
}}
.rf-pill {{
  display:inline-block; border:1px solid var(--line); border-radius:999px;
  padding: .2rem .55rem; color: var(--muted); font-size: .74rem;
}}
div[data-testid="stMetric"] {{ background: var(--panel); border:1px solid var(--line); padding:.55rem .75rem; border-radius:10px; }}
div[data-testid="stMetric"] label, div[data-testid="stMetric"] [data-testid="stMetricLabel"] {{ color: var(--muted) !important; }}
.stTabs [data-baseweb="tab-list"] {{ gap: .5rem; }}
.stTabs [data-baseweb="tab"] {{
  background: var(--panel); border:1px solid var(--line); border-radius:10px;
  color: var(--text); padding: .4rem .7rem;
}}
.stTabs [aria-selected="true"] {{ border-color: var(--accent) !important; color: var(--accent) !important; }}
.stButton > button {{
  border-radius: 10px; border:1px solid var(--line); background: var(--panel); color: var(--text);
  transition: all .2s ease;
}}
.stButton > button:hover {{ transform: translateY(-1px); border-color: var(--accent); }}
.stTextArea textarea, .stTextInput input, .stSelectbox [data-baseweb="select"] > div {{
  background: var(--panel) !important; color: var(--text) !important; border-color: var(--line) !important;
}}
hr {{ border-color: var(--line); }}
@keyframes slideIn {{ from {{ opacity:0; transform:translateY(6px); }} to {{ opacity:1; transform:translateY(0); }} }}
</style>
""",
        unsafe_allow_html=True,
    )


def top_nav(config_name: str, pages: list[str], active_page: str) -> str:
    cols = st.columns([2.2, 5.2, 1.8])
    with cols[0]:
        st.markdown(f"### {config_name}")
    with cols[1]:
        selected = st.radio(
            "Navigation",
            pages,
            index=pages.index(active_page),
            horizontal=True,
            label_visibility="collapsed",
        )
    with cols[2]:
        toggle = st.toggle("Light Mode", value=(st.session_state.get("theme", "dark") == "light"))
        st.session_state["theme"] = "light" if toggle else "dark"
    return selected


def section_card(title: str, body: str) -> None:
    st.markdown(f"<div class='rf-card'><h3>{title}</h3><p class='muted'>{body}</p></div>", unsafe_allow_html=True)
