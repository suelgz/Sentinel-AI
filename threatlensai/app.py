from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from database import delete_analysis, get_all_analyses, get_analysis_detail, save_analysis, save_uploaded_file
from gemini_client import GeminiAPIError, analyze_code, analyze_logs, generate_executive_summary
from i18n import APP_NAME, translate_text
from log_parser import get_log_stats, parse_log_file
from report_generator import build_text_report
from risk_scoring import compute_risk_score, get_score_breakdown, get_severity_color
from rule_detector import get_flagged_content_for_gemini, run_rule_detection, summarize_rule_findings
from threat_knowledge import (
    build_attack_timeline,
    format_mitre_attack,
    generate_top_recommendations,
    merge_rule_and_gemini_findings,
)


SAMPLE_DATA_DIR = Path(__file__).parent / "sample_data"
ANALYSIS_MODES = ["Local Scan Only", "Local + Gemini Explanation", "Full Gemini Report"]
INPUT_TYPES = ["Apache Log", "PHP Code", "Flask Code", "Custom Code"]
LANGUAGES = {"English": "en"}


st.set_page_config(
    page_title=APP_NAME,
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================================
# SESSION STATE INITIALIZATION - MUST BE FIRST
# ============================================================================
def init_session_state() -> None:
    """Initialize all session state variables early."""
    defaults = {
        "language": "en",
        "analysis_mode": ANALYSIS_MODES[1],
        "input_type": INPUT_TYPES[0],
        "demo_mode": True,
        "input_text": "",
        "input_name": "manual-input",
        "api_key": get_secret_api_key(),
        "result": None,
        "last_upload_name": "",
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def get_secret_api_key() -> str:
    """Retrieve Gemini API key from secrets."""
    try:
        return st.secrets.get("GEMINI_API_KEY", "")
    except Exception:
        return ""


# Initialize session state BEFORE any other code
init_session_state()


st.markdown(
    """
<style>
  :root {
    --tl-bg: #07111f;
    --tl-panel: #0d1829;
    --tl-panel-soft: #111d31;
    --tl-border: #223247;
    --tl-text: #e6edf7;
    --tl-muted: #9aa8bd;
    --tl-cyan: #25d7f2;
    --tl-green: #27d98d;
    --tl-amber: #f6b73c;
    --tl-orange: #ff7a45;
    --tl-red: #ff4d5f;
  }
  .block-container { padding-top: 1.4rem; max-width: 1280px; }
  .tl-hero {
    border: 1px solid var(--tl-border);
    background: linear-gradient(135deg, rgba(37,215,242,.12), rgba(39,217,141,.06));
    border-radius: 8px;
    padding: 22px 24px;
    margin-bottom: 18px;
  }
  .tl-title {
    color: var(--tl-text);
    font-size: 2.2rem;
    line-height: 1.1;
    font-weight: 800;
    margin: 0 0 6px 0;
  }
  .tl-subtitle {
    color: var(--tl-cyan);
    font-size: 1.05rem;
    font-weight: 650;
    margin-bottom: 8px;
  }
  .tl-muted { color: var(--tl-muted); }
  .tl-card {
    border: 1px solid var(--tl-border);
    background: var(--tl-panel);
    border-radius: 8px;
    padding: 16px;
    min-height: 108px;
  }
  .tl-card-label {
    color: var(--tl-muted);
    text-transform: uppercase;
    font-size: .72rem;
    letter-spacing: .08em;
    margin-bottom: 7px;
  }
  .tl-card-value {
    color: var(--tl-text);
    font-size: 1.55rem;
    font-weight: 800;
  }
  .tl-card-note {
    color: var(--tl-muted);
    font-size: .82rem;
    margin-top: 4px;
  }
  .tl-finding {
    border: 1px solid var(--tl-border);
    border-left-width: 5px;
    background: var(--tl-panel-soft);
    border-radius: 8px;
    padding: 14px 16px;
    margin: 12px 0;
  }
  .tl-badge {
    border-radius: 999px;
    padding: 4px 10px;
    font-weight: 700;
    font-size: .76rem;
    display: inline-block;
  }
  .tl-evidence {
    background: #07101c;
    border: 1px solid var(--tl-border);
    border-radius: 6px;
    padding: 10px;
    color: #b7f6ff;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
    font-size: .84rem;
  }
  section[data-testid="stSidebar"] {
    border-right: 1px solid var(--tl-border);
  }
  div[data-testid="stMetric"] {
    border: 1px solid var(--tl-border);
    border-radius: 8px;
    padding: 12px;
  }
  .stButton > button, .stDownloadButton > button {
    border-radius: 6px;
    min-height: 42px;
    font-weight: 700;
  }
  @media (max-width: 780px) {
    .tl-title { font-size: 1.65rem; }
    .tl-card { min-height: auto; }
  }
</style>
""",
    unsafe_allow_html=True,
)


def t(key: str, **kwargs: Any) -> str:
    """Translate key using current language."""
    return translate_text(key, st.session_state.get("language", "en"), **kwargs)


def read_sample(sample_name: str) -> tuple[str, str]:
    """Read sample data file or build inline demo."""
    samples = {
        "Apache Log": ("demo_apache_attack.txt", "demo-apache-attack.txt"),
        "PHP Code": ("vulnerable_login.php", "vulnerable_login.php"),
        "Flask Code": ("vulnerable_flask.py", "vulnerable_flask.py"),
    }
    filename, display_name = samples.get(sample_name, samples["Apache Log"])
    path = SAMPLE_DATA_DIR / filename
    if path.exists():
        return path.read_text(encoding="utf-8", errors="replace"), display_name
    return build_inline_demo(sample_name), f"demo-{sample_name.lower().replace(' ', '-')}.txt"


def build_inline_demo(sample_name: str) -> str:
    """Build inline demo content when sample files aren't available."""
    if sample_name == "PHP Code":
        return """<?php
$username = $_POST['username'];
$password = $_POST['password'];
$api_key = "AIzaSyDemoKeyForTrainingOnly1234567890";
$sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";
echo $_GET['next'];
?>"""
    if sample_name in {"Flask Code", "Custom Code"}:
        return """from flask import Flask, request
import os, hashlib

app = Flask(__name__)
app.secret_key = "hardcoded-secret-value"

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    return os.popen("ping -c 1 " + host).read()

def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()
"""
    return """203.0.113.10 - - [04/Jun/2026:12:00:01 +0000] "GET /login.php?id=1%20OR%201=1-- HTTP/1.1" 500 532 "-" "sqlmap/1.7"
203.0.113.20 - - [04/Jun/2026:12:00:05 +0000] "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 421 "-" "Mozilla/5.0"
203.0.113.30 - - [04/Jun/2026:12:00:10 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 403 118 "-" "curl/8.0"
198.51.100.44 - - [04/Jun/2026:12:01:01 +0000] "POST /login HTTP/1.1" 401 88 "-" "Mozilla/5.0"
198.51.100.44 - - [04/Jun/2026:12:01:03 +0000] "POST /login HTTP/1.1" 401 88 "-" "Mozilla/5.0"
198.51.100.44 - - [04/Jun/2026:12:01:05 +0000] "POST /login HTTP/1.1" 401 88 "-" "Mozilla/5.0"
198.51.100.44 - - [04/Jun/2026:12:01:07 +0000] "POST /login HTTP/1.1" 401 88 "-" "Mozilla/5.0"
198.51.100.44 - - [04/Jun/2026:12:01:09 +0000] "POST /login HTTP/1.1" 401 88 "-" "Mozilla/5.0"
203.0.113.50 - - [04/Jun/2026:12:02:00 +0000] "GET /.env HTTP/1.1" 404 42 "-" "python-requests/2.31"
"""


def decode_upload(uploaded_file: Any) -> str:
    """Decode uploaded file to string."""
    try:
        return uploaded_file.getvalue().decode("utf-8")
    except UnicodeDecodeError:
        return uploaded_file.getvalue().decode("latin-1", errors="replace")


def status_text(api_key: str, result: Any) -> tuple[str, str]:
    """Determine Gemini status text and alert level."""
    if not api_key:
        return "API Key: Not Set", "warning"
    if result and result.get("gemini_used"):
        return "API Key: Ready", "success"
    return "API Key: Ready (not used)", "info"


def render_metric_card(label: str, value: str, note: str) -> None:
    """Render a metric card."""
    st.markdown(
        f"""
<div class="tl-card">
  <div class="tl-card-label">{html.escape(label)}</div>
  <div class="tl-card-value">{html.escape(value)}</div>
  <div class="tl-card-note">{html.escape(note)}</div>
</div>
""",
        unsafe_allow_html=True,
    )


# Placeholder functions - replace with actual implementations from your modules
def run_threatlens_analysis(*args, **kwargs) -> dict:
    """Run ThreatLens analysis."""
    # TODO: Implement actual analysis logic
    return {"findings": [], "risk_score": 0, "severity": "Clean"}


def build_json_export(*args, **kwargs) -> str:
    """Build JSON export."""
    return json.dumps({})


def render_results_tabs(*args, **kwargs) -> None:
    """Render results tabs."""
    st.write("Results would be rendered here")


# ============================================================================
# SIDEBAR CONTROLS
# ============================================================================
with st.sidebar:
    st.markdown("## 🛡️ ThreatLens AI")
    
    selected_language = st.selectbox(
        "Language",
        index=0 if st.session_state["language"] == "en" else 1,
    )
    st.session_state["language"] = LANGUAGES[selected_language]

    st.markdown("### 🔑 Gemini API")
    st.session_state["api_key"] = st.text_input(
        t("gemini_api_key") if "gemini_api_key" in dir() else "Gemini API Key",
        value=st.session_state.get("api_key", ""),
        type="password",
        placeholder="AIza...",
        help=t("api_key_help") if "api_key_help" in dir() else "Enter your Gemini API key",
    )
    status, level = status_text(st.session_state["api_key"], st.session_state.get("result"))
    getattr(st, level)(status)

    st.markdown("### ⚙️ Analysis")
    st.session_state["analysis_mode"] = st.selectbox(
        t("analysis_mode") if "analysis_mode" in dir() else "Analysis Mode",
        ANALYSIS_MODES,
        index=ANALYSIS_MODES.index(st.session_state.get("analysis_mode", ANALYSIS_MODES[1])),
    )
    st.session_state["input_type"] = st.selectbox(
        t("input_type") if "input_type" in dir() else "Input Type",
        INPUT_TYPES,
        index=INPUT_TYPES.index(st.session_state.get("input_type", INPUT_TYPES[0])),
    )
   


# ============================================================================
# HEADER & METRICS
# ============================================================================
st.markdown(
    f"""
<div class="tl-hero">
  <div class="tl-title">🛡️ ThreatLens AI</div>
  <div class="tl-subtitle">Gemini-Powered Cybersecurity Risk Analyzer</div>
  <div class="tl-muted">{t("hero_description") if "hero_description" in dir() else "Detect threats in logs and code"}</div>
</div>
""",
    unsafe_allow_html=True,
)

result = st.session_state.get("result")
status, _ = status_text(st.session_state.get("api_key", ""), result)
total_findings = len(result.get("findings", [])) if result else 0
high_findings = (
    sum(1 for item in result.get("findings", []) if item.get("severity") in {"Critical", "High"})
    if result
    else 0
)

card1, card2, card3, card4, card5 = st.columns(5)
with card1:
    render_metric_card("Overall Risk Score", f"{result.get('risk_score', 0) if result else 0}/100", result.get("severity", "Clean") if result else "Clean")
with card2:
    render_metric_card("Total Findings", str(total_findings), t("local_and_ai") if "local_and_ai" in dir() else "local + AI")
with card3:
    render_metric_card("High/Critical", str(high_findings), t("priority_items") if "priority_items" in dir() else "priority items")
with card4:
    render_metric_card("Gemini Status", status.split(":")[0], t("optional_enrichment") if "optional_enrichment" in dir() else "optional enrichment")
with card5:
    render_metric_card("Analysis Mode", st.session_state["analysis_mode"], st.session_state["input_type"])


# ============================================================================
# INPUT SECTION - WITH PROPER CALLBACK HANDLING
# ============================================================================
st.markdown(f"## 🛡️ {t('threat_detection') if 'threat_detection' in dir() else 'Threat Detection'}")

top_left, top_right = st.columns([2, 1])

with top_right:
    st.markdown(f"### 🧪 {t('demo_mode') if 'demo_mode' in dir() else 'Demo Mode'}")
    if st.button("🧪 Load Demo Data", use_container_width=True):
        demo_text, demo_name = read_sample(st.session_state["input_type"])
        st.session_state["input_text"] = demo_text
        st.session_state["input_name"] = demo_name
        st.rerun()
    st.caption(t("demo_help") if "demo_help" in dir() else "Load sample data for testing")

with top_left:
    uploaded_file = st.file_uploader(
        t("upload_optional") if "upload_optional" in dir() else "Upload a file (optional)",
        type=["txt", "log", "py", "php", "js", "json", "conf"]
    )
    if uploaded_file and uploaded_file.name != st.session_state.get("last_upload_name"):
        st.session_state["input_text"] = decode_upload(uploaded_file)
        st.session_state["input_name"] = uploaded_file.name
        st.session_state["last_upload_name"] = uploaded_file.name
        st.rerun()

    st.text_input(
        t("input_name") if "input_name" in dir() else "Input Name",
        key="input_name"
    )
    st.text_area(
        t("input_text") if "input_text" in dir() else "Input Text",
        key="input_text",
        height=260,
        placeholder=t("input_placeholder") if "input_placeholder" in dir() else "Paste logs or code here...",
    )


# ============================================================================
# ACTION BUTTONS - CALLBACK APPROACH
# ============================================================================
def clear_analysis():
    """Callback to clear analysis."""
    st.session_state["input_text"] = ""
    st.session_state["result"] = None


run_col, clear_col = st.columns([2, 1])

with run_col:
    run_clicked = st.button("🚀 Run ThreatLens Analysis", type="primary", use_container_width=True)

with clear_col:
    st.button(
        t("clear") if "clear" in dir() else "Clear",
        on_click=clear_analysis,
        use_container_width=True
    )


# ============================================================================
# ANALYSIS EXECUTION
# ============================================================================
if run_clicked:
    try:
        with st.spinner(t("analysis_running") if "analysis_running" in dir() else "Running analysis..."):
            st.session_state["result"] = run_threatlens_analysis(
                st.session_state["input_text"],
                st.session_state["input_type"],
                st.session_state["input_name"] or "manual-input",
                st.session_state["analysis_mode"],
                st.session_state["language"],
                st.session_state.get("api_key", ""),
            )
        st.success(t("analysis_complete") if "analysis_complete" in dir() else "Analysis complete!")
        st.rerun()
    except ValueError as exc:
        st.warning(str(exc))
    except Exception as exc:
        st.error(
            t("analysis_failed", error=str(exc))
            if "analysis_failed" in dir()
            else f"Analysis failed: {str(exc)}"
        )


# ============================================================================
# RESULTS DISPLAY
# ============================================================================
if st.session_state.get("result"):
    render_results_tabs(st.session_state["result"], st.session_state.get("api_key", ""))
else:
    st.info(t("empty_state") if "empty_state" in dir() else "Run an analysis to see results")
