from __future__ import annotations

import html
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

APP_NAME = "ThreatLens AI"

APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

try:
    from database import delete_analysis, get_all_analyses, get_analysis_detail, save_analysis, save_uploaded_file
    from gemini_client import GeminiAPIError, analyze_code, analyze_logs, generate_executive_summary
    from input_detector import detect_input
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
except ModuleNotFoundError:
    from threatlensai.database import (
        delete_analysis,
        get_all_analyses,
        get_analysis_detail,
        save_analysis,
        save_uploaded_file,
    )
    from threatlensai.gemini_client import GeminiAPIError, analyze_code, analyze_logs, generate_executive_summary
    from threatlensai.input_detector import detect_input
    from threatlensai.log_parser import get_log_stats, parse_log_file
    from threatlensai.report_generator import build_text_report
    from threatlensai.risk_scoring import compute_risk_score, get_score_breakdown, get_severity_color
    from threatlensai.rule_detector import get_flagged_content_for_gemini, run_rule_detection, summarize_rule_findings
    from threatlensai.threat_knowledge import (
        build_attack_timeline,
        format_mitre_attack,
        generate_top_recommendations,
        merge_rule_and_gemini_findings,
    )


SAMPLE_DATA_DIR = Path(__file__).parent / "sample_data"
ANALYSIS_MODES = ["Local Scan Only", "Local + Gemini Explanation", "Full Gemini Report"]
DEMO_SAMPLES = {
    "apache": ("Apache Log Demo", "demo_apache_attack.txt", "demo-apache-attack.txt"),
    "php": ("PHP Demo", "vulnerable_login.php", "vulnerable_login.php"),
    "flask": ("Flask Demo", "vulnerable_flask.py", "vulnerable_flask.py"),
}


st.set_page_config(
    page_title=APP_NAME,
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


st.markdown(
    """
<style>
  :root {
    --tl-bg: #08111f;
    --tl-panel: #0c1728;
    --tl-panel-2: #0f1b2d;
    --tl-panel-3: #101d31;
    --tl-border: #213148;
    --tl-border-soft: #17253a;
    --tl-text: #edf5ff;
    --tl-muted: #94a3b8;
    --tl-soft: #cbd5e1;
    --tl-cyan: #22d3ee;
    --tl-blue: #3b82f6;
    --tl-green: #22c55e;
    --tl-amber: #f59e0b;
    --tl-red: #fb7185;
    --tl-purple: #a855f7;
    --tl-shadow: 0 18px 45px rgba(0, 0, 0, .28);
  }

  html, body, [data-testid="stAppViewContainer"], [data-testid="stApp"] {
    background: var(--tl-bg) !important;
    color: var(--tl-text);
    font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  }

  [data-testid="stHeader"], [data-testid="stToolbar"], footer { display: none !important; }
  .block-container {
    max-width: 1480px;
    padding: 30px 30px 48px 30px;
  }

  section[data-testid="stSidebar"] {
    width: 304px !important;
    background: #07101d !important;
    border-right: 1px solid var(--tl-border-soft);
    box-shadow: 12px 0 40px rgba(0,0,0,.18);
  }
  section[data-testid="stSidebar"] > div { padding: 24px 20px; }
  section[data-testid="stSidebar"] label,
  section[data-testid="stSidebar"] .stMarkdown p { color: var(--tl-soft) !important; }

  h1, h2, h3, p { letter-spacing: 0; }
  h1, h2, h3 { color: var(--tl-text) !important; }

  .tl-sidebar-logo {
    display: flex;
    align-items: center;
    gap: 13px;
    margin-bottom: 28px;
    padding-bottom: 22px;
    border-bottom: 1px solid var(--tl-border-soft);
  }
  .tl-logo-mark {
    width: 46px;
    height: 46px;
    border-radius: 14px;
    border: 1px solid rgba(34, 211, 238, .5);
    background: #0b2033;
    display: grid;
    place-items: center;
    color: var(--tl-cyan);
    font-weight: 900;
    font-size: 1.35rem;
  }
  .tl-logo-title { font-size: 1.12rem; font-weight: 850; color: var(--tl-text); line-height: 1.1; }
  .tl-logo-subtitle { color: var(--tl-cyan); font-size: .78rem; font-weight: 700; margin-top: 4px; }

  .tl-sidebar-section {
    border: 1px solid var(--tl-border);
    background: var(--tl-panel);
    border-radius: 16px;
    padding: 16px;
    margin-bottom: 16px;
    box-shadow: var(--tl-shadow);
  }
  .tl-sidebar-heading {
    color: var(--tl-text);
    font-weight: 800;
    font-size: .95rem;
    margin-bottom: 12px;
  }
  .tl-status-badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 100%;
    min-height: 36px;
    border-radius: 12px;
    font-weight: 800;
    font-size: .82rem;
    margin-top: 10px;
    border: 1px solid transparent;
  }
  .tl-status-ok { color: #86efac; background: rgba(34, 197, 94, .12); border-color: rgba(34, 197, 94, .25); }
  .tl-status-missing { color: #fbbf24; background: rgba(245, 158, 11, .12); border-color: rgba(245, 158, 11, .25); }

  .tl-hero {
    margin-bottom: 24px;
  }
  .tl-title {
    color: var(--tl-text);
    font-size: clamp(2rem, 3vw, 3.1rem);
    line-height: 1.04;
    font-weight: 900;
    margin: 0 0 10px 0;
  }
  .tl-subtitle {
    color: var(--tl-cyan);
    font-size: 1.15rem;
    font-weight: 800;
    margin-bottom: 10px;
  }
  .tl-muted { color: var(--tl-muted); font-size: .95rem; line-height: 1.6; }

  .tl-card, .tl-panel, .tl-demo-card, .tl-privacy-card, .tl-detected-card, .tl-finding {
    border: 1px solid var(--tl-border);
    background: var(--tl-panel);
    border-radius: 16px;
    box-shadow: var(--tl-shadow);
  }
  .tl-card {
    min-height: 142px;
    padding: 18px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
  }
  .tl-card-label {
    color: var(--tl-muted);
    text-transform: uppercase;
    font-size: .72rem;
    font-weight: 800;
    letter-spacing: .08em;
    margin-bottom: 9px;
  }
  .tl-card-value {
    color: var(--tl-text);
    font-size: clamp(1.35rem, 2vw, 1.85rem);
    font-weight: 900;
    line-height: 1.1;
  }
  .tl-card-note {
    color: var(--tl-muted);
    font-size: .84rem;
    margin-top: 8px;
    min-height: 20px;
  }

  .tl-section-title { font-size: 1.45rem; font-weight: 900; color: var(--tl-text); margin: 0; }
  .tl-section-note { color: var(--tl-muted); margin: 7px 0 20px 0; font-size: .94rem; }
  .tl-panel { padding: 24px; margin-top: 18px; }
  .tl-panel-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; margin-bottom: 18px; }

  .tl-upload-shell {
    border: 1px dashed #2b425c;
    background: #091525;
    border-radius: 16px;
    padding: 18px;
    margin-bottom: 16px;
  }
  .tl-detected-card {
    min-height: auto;
    padding: 16px 18px;
    margin: 0 0 18px 0;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }
  .tl-detected-card .tl-card-label { margin: 0 0 6px 0; text-align: left; }
  .tl-detected-value { color: var(--tl-text); font-size: 1.2rem; font-weight: 900; }
  .tl-detected-note { color: var(--tl-muted); font-size: .84rem; }

  .tl-demo-card {
    padding: 18px;
    min-height: 82px;
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    gap: 14px;
  }
  .tl-demo-icon {
    width: 44px;
    height: 44px;
    border-radius: 13px;
    display: grid;
    place-items: center;
    background: #10243a;
    color: var(--tl-cyan);
    font-weight: 900;
  }
  .tl-demo-title { color: var(--tl-text); font-size: .98rem; font-weight: 850; }
  .tl-demo-note { color: var(--tl-muted); font-size: .82rem; margin-top: 3px; }
  .tl-privacy-card { padding: 16px; color: #7dd3fc; font-size: .9rem; line-height: 1.55; background: #0a1a2d; }

  .tl-results-shell { margin-top: 26px; }
  .tl-results-heading { font-size: 1.65rem; font-weight: 900; margin-bottom: 6px; color: var(--tl-text); }
  .tl-results-subtitle { color: var(--tl-muted); margin-bottom: 18px; }
  .tl-finding {
    border-left-width: 5px;
    background: var(--tl-panel-2);
    padding: 16px 18px;
    margin: 14px 0;
  }
  .tl-badge {
    border-radius: 999px;
    padding: 5px 11px;
    font-weight: 850;
    font-size: .75rem;
    display: inline-block;
  }
  .tl-evidence {
    background: #07101c;
    border: 1px solid var(--tl-border);
    border-radius: 14px;
    padding: 14px;
    color: #b7f6ff;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
    font-size: .86rem;
  }

  div[data-testid="column"] { min-width: 0; }
  .stTextInput input, .stTextArea textarea, .stSelectbox [data-baseweb="select"] > div {
    background: #081525 !important;
    border: 1px solid var(--tl-border) !important;
    border-radius: 13px !important;
    color: var(--tl-text) !important;
    box-shadow: none !important;
  }
  .stTextArea textarea {
    min-height: 260px !important;
    font-family: ui-monospace, SFMono-Regular, Consolas, monospace !important;
    font-size: .95rem !important;
  }
  .stFileUploader section {
    background: transparent !important;
    border: 0 !important;
    padding: 0 !important;
  }
  .stFileUploader [data-testid="stFileUploaderDropzone"] {
    background: #081525 !important;
    border: 1px dashed #2b425c !important;
    border-radius: 16px !important;
    padding: 22px !important;
  }
  .stFileUploader button, .stButton > button, .stDownloadButton > button {
    border-radius: 13px !important;
    min-height: 46px;
    font-weight: 850 !important;
    border: 1px solid var(--tl-border) !important;
    background: #0b1728 !important;
    color: var(--tl-text) !important;
    box-shadow: none !important;
  }
  .stButton > button[kind="primary"] {
    border: 0 !important;
    background: linear-gradient(135deg, var(--tl-cyan), #6366f1) !important;
    color: #ffffff !important;
  }
  .stButton > button:hover, .stDownloadButton > button:hover, .stFileUploader button:hover {
    border-color: rgba(34, 211, 238, .6) !important;
    color: #ffffff !important;
    transform: translateY(-1px);
  }

  div[data-testid="stMetric"] {
    border: 1px solid var(--tl-border);
    border-radius: 16px;
    padding: 16px;
    background: var(--tl-panel);
  }
  .stTabs [data-baseweb="tab-list"] {
    gap: 10px;
    border-bottom: 1px solid var(--tl-border-soft);
    margin-bottom: 18px;
  }
  .stTabs [data-baseweb="tab"] {
    border-radius: 12px 12px 0 0;
    color: var(--tl-muted);
    font-weight: 800;
  }
  .stTabs [aria-selected="true"] {
    color: var(--tl-cyan) !important;
    background: rgba(34, 211, 238, .08) !important;
  }

  @media (max-width: 980px) {
    .block-container { padding: 22px 16px 36px 16px; }
    .tl-card { min-height: 118px; }
    .tl-panel { padding: 18px; }
  }
</style>
""",
    unsafe_allow_html=True,
)



def get_secret_api_key() -> str:
    try:
        return st.secrets.get("GEMINI_API_KEY", "").strip()
    except Exception:
        return ""


def init_state() -> None:
    defaults = {
        "analysis_mode": ANALYSIS_MODES[1],
        "demo_mode": True,
        "input_text": "",
        "input_name": "manual-input",
        "api_key": get_secret_api_key(),
        "result": None,
        "last_upload_name": "",
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


def clear_analysis_input() -> None:
    st.session_state["input_text"] = ""
    st.session_state["input_name"] = "manual-input"
    st.session_state["result"] = None
    st.session_state["last_upload_name"] = ""


def read_sample(sample_key: str) -> tuple[str, str]:
    _, filename, display_name = DEMO_SAMPLES.get(sample_key, DEMO_SAMPLES["apache"])
    path = SAMPLE_DATA_DIR / filename
    if path.exists():
        return path.read_text(encoding="utf-8", errors="replace"), display_name
    return build_inline_demo(sample_key), display_name


def build_inline_demo(sample_key: str) -> str:
    if sample_key == "php":
        return """<?php
$username = $_POST['username'];
$password = $_POST['password'];
$api_key = "AIzaSyDemoKeyForTrainingOnly1234567890";
$sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";
echo $_GET['next'];
?>"""
    if sample_key == "flask":
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
    try:
        return uploaded_file.getvalue().decode("utf-8")
    except UnicodeDecodeError:
        return uploaded_file.getvalue().decode("latin-1", errors="replace")
    except Exception as exc:
        st.error(f"Could not read uploaded file: {exc}")
        return ""


def status_text(api_key: str, result: dict[str, Any] | None = None) -> tuple[str, str]:
    if result and result.get("gemini_error"):
        return "Gemini error: showing local fallback results", "warning"
    if (api_key or "").strip():
        return "Gemini key set: enrichment available", "success"
    return "Gemini key missing: local analysis only", "warning"

def severity_style(severity: str) -> tuple[str, str]:
    color = get_severity_color(severity)
    return color, f"background:{color}22;color:{color};border:1px solid {color}66"


def score_explanation(score: int, severity: str, findings: list[dict[str, Any]]) -> str:
    if score == 0:
        return "No local indicators were detected, so the score remains clean. Continue validating with real context."
    high_count = sum(1 for item in findings if item.get("severity") in {"Critical", "High"})
    if severity in {"Critical", "High"}:
        return f"The score is elevated because {high_count} high or critical finding(s) affect sensitive attack paths."
    if severity == "Medium":
        return "The score is medium because one or more findings need validation and remediation planning."
    return "The score is low because the detected patterns have limited severity or confidence."


def local_summary(severity: str, score: int, findings: list[dict[str, Any]]) -> dict[str, Any]:
    recommendations = generate_top_recommendations(findings, limit=3)
    if findings:
        paragraph = f"Local rule analysis detected {len(findings)} finding(s). Overall risk is {score}/100 with a {severity} severity label."
    else:
        paragraph = "Local rule analysis did not detect clear threat indicators."
    return {
        "overall_status": severity,
        "summary_paragraph": paragraph,
        "top_priority_action": recommendations[0] if recommendations else "Continue reviewing logs and code before release.",
        "estimated_business_risk": "Business risk depends on whether the suspicious activity reached real assets.",
        "positive_notes": "Analysis completed without requiring a Gemini API key.",
        "recommended_next_steps": recommendations or ["Validate the input", "Keep monitoring", "Run Gemini enrichment when available"],
    }


def run_threatlens_analysis(
    content: str,
    input_name: str,
    mode: str,
    api_key: str,
) -> dict[str, Any]:
    content = (content or "").strip()
    api_key = (api_key or "").strip()
    if not content:
        raise ValueError("Add input text, upload a file, or load demo data before running analysis.")

    detected_input = detect_input(content)
    is_log = detected_input.analysis_kind == "log"
    if is_log:
        parsed_df, log_format = parse_log_file(content)
        source_type = ""
    else:
        parsed_df = pd.DataFrame()
        log_format = "code"
        source_type = detected_input.source_type

    rule_findings = run_rule_detection(parsed_df, content)
    pre_labels = summarize_rule_findings(rule_findings)
    flagged_content = get_flagged_content_for_gemini(rule_findings) or content[:5000]
    gemini_findings: list[dict[str, Any]] = []
    executive_summary: dict[str, Any] = {}
    gemini_used = False
    gemini_error = ""

    should_use_gemini = mode != "Local Scan Only" and bool(api_key)
    should_send_to_gemini = should_use_gemini and (rule_findings or mode == "Full Gemini Report")

    if should_send_to_gemini:
        try:
            if is_log:
                gemini_findings = analyze_logs(flagged_content, pre_labels, api_key)
            else:
                gemini_findings = analyze_code(flagged_content, source_type, pre_labels, api_key)
            gemini_used = True
        except GeminiAPIError as exc:
            gemini_error = str(exc)

    findings = merge_rule_and_gemini_findings(gemini_findings, rule_findings)
    risk_score, severity = compute_risk_score(findings, rule_findings)
    top_recommendations = generate_top_recommendations(findings)
    attack_timeline = build_attack_timeline(parsed_df, rule_findings) if is_log else []

    if should_send_to_gemini and gemini_used and mode == "Full Gemini Report":
        executive_summary = generate_executive_summary(
            findings, risk_score, severity, api_key
        )
    else:
        executive_summary = local_summary(severity, risk_score, findings)

    analysis_type = "log" if is_log else "code"
    analysis_id = save_analysis(
        analysis_type,
        input_name,
        content[:1000],
        risk_score,
        severity,
        findings,
        executive_summary=executive_summary,
        top_recommendations=top_recommendations,
        attack_timeline=attack_timeline,
    )
    save_uploaded_file(
        analysis_id,
        input_name,
        len(content.encode("utf-8")),
        analysis_type,
        line_count=len(content.splitlines()),
        flagged_count=sum(len(item.get("matched_lines", [])) for item in rule_findings),
    )

    return {
        "analysis_id": analysis_id,
        "analysis_type": analysis_type,
        "analysis_mode": mode,
        "detected_input": detected_input.as_dict(),
        "input_name": input_name,
        "log_format": log_format,
        "line_count": len(content.splitlines()),
        "log_stats": get_log_stats(parsed_df) if is_log else {},
        "risk_score": risk_score,
        "severity": severity,
        "findings": findings,
        "rule_findings": rule_findings,
        "executive_summary": executive_summary,
        "top_recommendations": top_recommendations,
        "attack_timeline": attack_timeline,
        "gemini_used": gemini_used,
        "gemini_error": gemini_error,
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }


def build_json_export(result: dict[str, Any]) -> str:
    payload = {
        "project_name": APP_NAME,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "analysis_mode": result.get("analysis_mode"),
        "gemini_used": result.get("gemini_used", False),
        "overall_risk_score": result.get("risk_score", 0),
        "severity": result.get("severity", "Clean"),
        "findings": result.get("findings", []),
        "rule_findings": result.get("rule_findings", []),
        "owasp_mapping": sorted({item.get("owasp_category", "N/A") for item in result.get("findings", [])}),
        "mitre_mapping": sorted({
            format_mitre_attack(item.get("mitre_attack"))
            for item in result.get("findings", [])
            if item.get("mitre_attack")
        }),
        "remediation_checklist": result.get("top_recommendations", []),
        "ethical_notice": "ThreatLens AI is for defensive security review, education, and authorized analysis only. It must not be used for exploitation, live attacks, unauthorized scanning, phishing, malware generation, credential theft, or any activity against systems you do not own or have permission to assess.",
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_metric_card(label: str, value: str, note: str = "") -> None:
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


def get_detected_input_display(content: str, result: dict[str, Any] | None = None) -> dict[str, Any]:
    if result and result.get("detected_input"):
        return dict(result["detected_input"])
    if (content or "").strip():
        return detect_input(content).as_dict()
    return detect_input("").as_dict()


def render_detected_input_card(detected: dict[str, Any], compact: bool = False) -> None:
    label = str(detected.get("label") or "Generic Source Code")
    icon = str(detected.get("icon") or "\U0001f4c4")
    note = "Automatically classified" if label != "Generic Source Code" else "Low-confidence inputs use the generic code analyzer"
    extra_style = "margin-bottom:0" if compact else ""
    st.markdown(
        f"""
<div class="tl-detected-card" style="{extra_style}">
  <div>
    <div class="tl-card-label">Detected Input</div>
    <div class="tl-detected-value">{html.escape(icon)} {html.escape(label)}</div>
  </div>
  <div class="tl-detected-note">{html.escape(note)}</div>
</div>
""",
        unsafe_allow_html=True,
    )


def render_panel_open(title: str, note: str = "") -> None:
    note_html = f'<div class="tl-section-note">{html.escape(note)}</div>' if note else ""
    st.markdown(
        f"""
<div class="tl-panel">
  <div class="tl-section-title">{html.escape(title)}</div>
  {note_html}
""",
        unsafe_allow_html=True,
    )


def render_panel_close() -> None:
    st.markdown("</div>", unsafe_allow_html=True)


def render_finding(finding: dict[str, Any], index: int) -> None:
    severity = finding.get("severity", "Unknown")
    color, badge_style = severity_style(severity)
    confidence = int(float(finding.get("confidence", 0) or 0) * 100)
    rule_confidence = int(float(finding.get("rule_confidence", 0) or 0) * 100)
    mitre = finding.get("mitre_attack_summary") or format_mitre_attack(finding.get("mitre_attack"))
    evidence = html.escape(str(finding.get("evidence", "N/A")))
    threat = html.escape(str(finding.get("threat_type", "Unknown")))

    st.markdown(
        f"""
<div class="tl-finding" style="border-left-color:{color}">
  <div style="display:flex;gap:10px;justify-content:space-between;align-items:flex-start;flex-wrap:wrap">
    <div style="font-weight:800;font-size:1rem">#{index} {threat}</div>
    <span class="tl-badge" style="{badge_style}">{html.escape(severity)}</span>
  </div>
  <div class="tl-muted" style="margin-top:6px">
    Confidence: {confidence}% AI / {rule_confidence}% Rule - Source: {html.escape(str(finding.get("analysis_source", "Rule Engine")))}
  </div>
  <div class="tl-muted" style="margin-top:6px">
    OWASP: {html.escape(str(finding.get("owasp_category", "N/A")))}<br>
    MITRE ATT&CK: {html.escape(str(mitre))}
  </div>
</div>
""",
        unsafe_allow_html=True,
    )

    with st.expander(f"Evidence & Remediation #{index}", expanded=index == 1):
        st.markdown(f'<div class="tl-evidence">{evidence}</div>', unsafe_allow_html=True)
        left, right = st.columns(2)
        with left:
            st.markdown("**Technical Explanation**")
            st.write(finding.get("explanation", "N/A"))
            st.markdown("**Business Impact**")
            st.warning(finding.get("business_impact", "N/A"))
        with right:
            st.markdown("**Immediate Fix**")
            st.success(finding.get("immediate_fix", "N/A"))
            st.markdown("**Long-Term Fix**")
            st.info(finding.get("long_term_fix", "N/A"))
            st.caption(f"False Positive Note: {finding.get('false_positive_note', 'N/A')}")


def render_results_tabs(result: dict[str, Any], api_key: str) -> None:
    findings = result.get("findings", [])
    rule_findings = result.get("rule_findings", [])
    risk_score = int(result.get("risk_score", 0))
    severity = result.get("severity", "Clean")
    summary = result.get("executive_summary", {})
    top_recommendations = result.get("top_recommendations", [])
    breakdown = get_score_breakdown(findings, rule_findings)

    st.markdown(
        """
<div class="tl-results-shell">
  <div class="tl-results-heading">Analysis Results</div>
  <div class="tl-results-subtitle">Review the security assessment, mapped findings, history, and exports.</div>
</div>
""",
        unsafe_allow_html=True,
    )
    render_detected_input_card(result.get("detected_input") or {})

    tab_overview, tab_findings, tab_summary, tab_mapping, tab_history, tab_export = st.tabs(
        [
            "Overview",
            "Findings",
            "Executive Summary",
            "OWASP / MITRE",
            "History",
            "Export",
        ]
    )

    with tab_overview:
        left, right = st.columns([1, 2])
        with left:
            st.markdown("### Risk Score")
            st.progress(min(risk_score, 100) / 100)
            st.markdown(
                f"<div style='font-size:3rem;font-weight:900;color:{get_severity_color(severity)}'>{risk_score}/100</div>",
                unsafe_allow_html=True,
            )
            st.markdown(f"**{severity}**")
        with right:
            st.markdown("### Executive Summary")
            st.write(summary.get("summary_paragraph", "Executive summary is not available."))
            st.markdown("**Why this score?**")
            st.info(score_explanation(risk_score, severity, findings))
            st.markdown("**Top risk factors**")
            if top_recommendations:
                for item in top_recommendations[:5]:
                    st.markdown(f"- {item}")
            else:
                st.success("No prioritized remediation items are available.")

        st.markdown("### Analysis Details")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Rule Signals", len(rule_findings))
        c2.metric("Flagged Lines", breakdown.get("flagged_lines_count", 0))
        c3.metric("Avg Confidence", f"{int(breakdown.get('avg_gemini_confidence', 0) * 100)}%")
        c4.metric("Analysis ID", str(result.get("analysis_id", "-")))

    with tab_findings:
        if not findings:
            st.success("No threats detected by the current local rules.")
        else:
            for index, finding in enumerate(findings, 1):
                render_finding(finding, index)

    with tab_summary:
        status, level = status_text(api_key, result)
        getattr(st, level)(status)
        st.markdown("### Executive Summary")
        st.write(summary.get("summary_paragraph", "Executive summary is not available."))
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Top Priority Action**")
            st.warning(summary.get("top_priority_action", "N/A"))
            st.markdown("**Business Risk**")
            st.write(summary.get("estimated_business_risk", "N/A"))
        with col2:
            st.markdown("**Attack Narrative**")
            if result.get("attack_timeline"):
                first = result["attack_timeline"][0]
                last = result["attack_timeline"][-1]
                st.write(
                    f"The visible chain starts with {first.get('threat_type', 'unknown')} and later includes {last.get('threat_type', 'unknown')}. Treat this as a triage narrative, not proof of compromise."
                )
            elif findings:
                st.write(
                    f"ThreatLens identified {len(findings)} finding(s). Review the evidence, confirm true positives, and prioritize fixes by severity."
                )
            else:
                st.write("No clear attack chain is visible in this input.")
            st.markdown("**Recommended Next Steps**")
            for step in summary.get("recommended_next_steps", []):
                st.markdown(f"- {step}")

    with tab_mapping:
        if not findings:
            st.info("No mapping is available because no findings were detected.")
        else:
            rows = []
            for item in findings:
                rows.append(
                    {
                        "Threat Type": item.get("threat_type", "Unknown"),
                        "Severity": item.get("severity", "Unknown"),
                        "OWASP": item.get("owasp_category", "N/A"),
                        "MITRE ATT&CK": item.get("mitre_attack_summary")
                        or format_mitre_attack(item.get("mitre_attack")),
                    }
                )
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        if result.get("attack_timeline"):
            st.markdown("### Attack Timeline")
            st.dataframe(pd.DataFrame(result["attack_timeline"]), use_container_width=True, hide_index=True)

    with tab_export:
        text_report = build_text_report(
            result.get("analysis_type", ""),
            result.get("input_name", ""),
            risk_score,
            severity,
            findings,
            summary,
            rule_findings=rule_findings,
            attack_timeline=result.get("attack_timeline", []),
            top_recommendations=top_recommendations,
            analysis_mode=result.get("analysis_mode", ""),
            gemini_used=result.get("gemini_used", False),
        )
        json_report = build_json_export(result)
        st.text_area("Report Preview", text_report, height=300)
        col_txt, col_json = st.columns(2)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        col_txt.download_button(
            "Download TXT Report",
            data=text_report,
            file_name=f"threatlens_ai_report_{timestamp}.txt",
            mime="text/plain",
            use_container_width=True,
        )
        col_json.download_button(
            "Download JSON Report",
            data=json_report,
            file_name=f"threatlens_ai_report_{timestamp}.json",
            mime="application/json",
            use_container_width=True,
        )

    with tab_history:
        render_history()


def render_history() -> None:
    analyses = get_all_analyses(25)
    if not analyses:
        st.info("No saved analyses yet.")
        return
    for item in analyses:
        label = (
            f"{item.get('created_at', '')[:16].replace('T', ' ')} - "
            f"{item.get('input_filename', 'input')} - "
            f"{item.get('severity_label', 'Clean')} - {item.get('overall_risk_score', 0)}/100"
        )
        with st.expander(label):
            detail = get_analysis_detail(item["id"])
            st.caption(f"Findings: {len(detail.get('findings', []))}")
            for finding in detail.get("findings", [])[:5]:
                st.markdown(f"- **{finding.get('threat_type', 'Unknown')}** - {finding.get('severity', 'Unknown')}")
            col1, col2 = st.columns([1, 1])
            with col1:
                if st.button("Load", key=f"load_{item['id']}"):
                    st.session_state.result = {
                        "analysis_id": item["id"],
                        "analysis_type": item.get("analysis_type", ""),
                        "analysis_mode": "History",
                        "input_name": item.get("input_filename", ""),
                        "detected_input": detect_input(str(item.get("input_preview", ""))).as_dict(),
                        "risk_score": item.get("overall_risk_score", 0),
                        "severity": item.get("severity_label", "Clean"),
                        "findings": detail.get("findings", []),
                        "rule_findings": [],
                        "executive_summary": _safe_json(item.get("executive_summary"), {}),
                        "top_recommendations": detail.get("analysis", {}).get("top_recommendations", []),
                        "attack_timeline": detail.get("analysis", {}).get("attack_timeline", []),
                        "gemini_used": False,
                        "gemini_error": "",
                    }
                    st.rerun()
            with col2:
                if st.button("Delete", key=f"delete_{item['id']}"):
                    delete_analysis(item["id"])
                    st.rerun()


def _safe_json(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value or "")
    except Exception:
        return default



init_state()

with st.sidebar:
    st.markdown(
        """
<div class="tl-sidebar-logo">
  <div class="tl-logo-mark">TL</div>
  <div>
    <div class="tl-logo-title">ThreatLens AI</div>
    <div class="tl-logo-subtitle">Security Analyzer</div>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown('<div class="tl-sidebar-section"><div class="tl-sidebar-heading">Gemini API</div>', unsafe_allow_html=True)
    st.session_state["api_key"] = st.text_input(
        "API key",
        value=st.session_state.get("api_key", ""),
        type="password",
        placeholder="AIza...",
        help="Paste a Gemini API key for this session.",
    )
    status_label = "Connected" if st.session_state.get("api_key", "").strip() else "Missing"
    status_class = "tl-status-ok" if status_label == "Connected" else "tl-status-missing"
    st.markdown(f'<div class="tl-status-badge {status_class}">{status_label}</div></div>', unsafe_allow_html=True)

    st.markdown('<div class="tl-sidebar-section"><div class="tl-sidebar-heading">Analysis</div>', unsafe_allow_html=True)
    st.session_state["analysis_mode"] = st.selectbox(
        "Analysis Mode",
        ANALYSIS_MODES,
        index=ANALYSIS_MODES.index(st.session_state.get("analysis_mode", ANALYSIS_MODES[1])),
    )
    st.session_state["demo_mode"] = st.toggle("Demo Mode", value=st.session_state.get("demo_mode", True))
    st.markdown('</div>', unsafe_allow_html=True)


st.markdown(
    """
<div class="tl-hero">
  <div class="tl-title">ThreatLens AI</div>
  <div class="tl-subtitle">AI-Powered Cybersecurity Risk Analyzer</div>
  <div class="tl-muted">Analyze logs and source code with local threat detection, optional Gemini explanations, risk scoring, and export-ready security reports.</div>
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
detected_display = get_detected_input_display(st.session_state.get("input_text", ""), result)

card1, card2, card3, card4, card5 = st.columns(5, gap="medium")
with card1:
    render_metric_card("Overall Risk Score", f"{result.get('risk_score', 0) if result else 0}/100", result.get("severity", "Clean") if result else "Clean")
with card2:
    render_metric_card("Total Findings", str(total_findings), "Detected issues")
with card3:
    render_metric_card("High/Critical Findings", str(high_findings), "Priority review")
with card4:
    render_metric_card("Gemini Status", status.split(":")[0], "AI enrichment")
with card5:
    render_metric_card("Analysis Mode", st.session_state["analysis_mode"], "Auto input detection")

left, right = st.columns([1.62, 1], gap="large")
with left:
    render_panel_open(
        "Threat Detection",
        "Upload a file or paste logs/source code. ThreatLens AI will automatically detect the input type before analysis.",
    )
    st.markdown('<div class="tl-upload-shell">', unsafe_allow_html=True)
    uploaded_file = st.file_uploader("Upload log/code file", type=["txt", "log", "py", "php", "js", "json", "conf"])
    st.markdown('</div>', unsafe_allow_html=True)
    if uploaded_file and uploaded_file.name != st.session_state.get("last_upload_name"):
        st.session_state["input_text"] = decode_upload(uploaded_file)
        st.session_state["input_name"] = uploaded_file.name
        st.session_state["last_upload_name"] = uploaded_file.name
        st.rerun()

    st.text_input("Input Name", key="input_name", placeholder="server-log.txt, app.py")
    st.text_area(
        "Code Editor",
        key="input_text",
        height=300,
        placeholder="Paste logs or source code here... ThreatLens AI will automatically detect the input type.",
    )
    if st.session_state.get("input_text", "").strip():
        render_detected_input_card(detected_display, compact=True)

    run_col, clear_col = st.columns([2, 1], gap="medium")
    with run_col:
        run_clicked = st.button("Run ThreatLens Analysis", type="primary", use_container_width=True)
    with clear_col:
        st.button("Clear", use_container_width=True, on_click=clear_analysis_input)
    render_panel_close()

with right:
    render_panel_open("Demo Data", "Load a sample to test the analyzer.")
    demo_meta = {
        "apache": ("Apache Demo", "Realistic web server logs", "LOG"),
        "php": ("PHP Demo", "Vulnerable PHP source sample", "PHP"),
        "flask": ("Flask Demo", "Vulnerable Python / Flask code", "PY"),
    }
    for sample_key, (title, note, badge) in demo_meta.items():
        st.markdown(
            f"""
<div class="tl-demo-card">
  <div class="tl-demo-icon">{html.escape(badge)}</div>
  <div>
    <div class="tl-demo-title">{html.escape(title)}</div>
    <div class="tl-demo-note">{html.escape(note)}</div>
  </div>
</div>
""",
            unsafe_allow_html=True,
        )
        if st.button(f"Load {title}", key=f"demo_{sample_key}", use_container_width=True):
            demo_text, demo_name = read_sample(sample_key)
            st.session_state["input_text"] = demo_text
            st.session_state["input_name"] = demo_name
            st.rerun()
    st.markdown(
        """
<div class="tl-privacy-card">
  <strong>Private by default.</strong><br>
  Processing starts only when you run an analysis. Gemini is used only when you provide a key and choose an AI-enabled mode.
</div>
""",
        unsafe_allow_html=True,
    )
    render_panel_close()

if 'run_clicked' in locals() and run_clicked:
    try:
        with st.spinner("Running threat analysis..."):
            st.session_state["result"] = run_threatlens_analysis(
                st.session_state["input_text"],
                st.session_state["input_name"] or "manual-input",
                st.session_state["analysis_mode"],
                st.session_state.get("api_key", ""),
            )
        st.success("Analysis complete.")
        st.rerun()
    except ValueError as exc:
        st.warning(str(exc))
    except Exception as exc:
        st.error(f"Analysis failed: {exc}")

if st.session_state.get("result"):
    render_results_tabs(st.session_state["result"], st.session_state.get("api_key", ""))
