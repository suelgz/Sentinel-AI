from __future__ import annotations

import sys
from pathlib import Path

# Fix import path resolution precedence for Streamlit execution
sys.path.insert(0, str(Path(__file__).parent.absolute()))

import html
import json
import os
import re
import time
from datetime import datetime
from typing import Any

import pandas as pd
import streamlit as st

from database import delete_analysis, get_all_analyses, get_analysis_detail, save_analysis, save_uploaded_file
from gemini_client import GeminiAPIError, analyze_code, analyze_logs, generate_executive_summary
APP_NAME = "ThreatLens AI"
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
st.set_page_config(
    page_title=APP_NAME,
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


st.markdown(
    """
<style>
  /* Remove Streamlit's fixed top chrome so it cannot cover the app.
     This also recovers vertical space for the action buttons. */
  header[data-testid="stHeader"] {
    display: none !important;
  }
  div[data-testid="stToolbar"] {
    display: none !important;
  }
  div[data-testid="stDecoration"] {
    display: none !important;
  }
  #MainMenu {
    visibility: hidden !important;
  }
  footer {
    visibility: hidden !important;
  }

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
  .block-container { padding-top: 0.75rem !important; padding-bottom: 1.25rem; max-width: 1280px; }
  .tl-hero {
    border: 1px solid var(--tl-border);
    background: linear-gradient(135deg, rgba(37,215,242,.12), rgba(39,217,141,.06));
    border-radius: 8px;
    padding: 14px 20px;
    margin: 0 0 12px 0;
    overflow: visible;
  }
  .tl-title {
    color: var(--tl-text);
    font-size: 1.9rem;
    line-height: 1.1;
    font-weight: 800;
    margin: 0 0 4px 0;
  }
  .tl-subtitle {
    color: var(--tl-cyan);
    font-size: 1.05rem;
    font-weight: 650;
    margin-bottom: 5px;
  }
  .tl-muted { color: var(--tl-muted); }
  .tl-sidebar-details {
    border: 1px solid var(--tl-border);
    background: var(--tl-panel);
    border-radius: 8px;
    padding: 12px;
    margin: 14px 0 16px 0;
  }
  .tl-sidebar-title {
    color: var(--tl-text);
    font-weight: 800;
    font-size: .96rem;
    margin-bottom: 10px;
  }
  .tl-sidebar-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 8px;
  }
  .tl-sidebar-mini {
    border: 1px solid rgba(34,50,71,.82);
    background: rgba(7,17,31,.48);
    border-radius: 7px;
    padding: 9px 10px;
  }
  .tl-sidebar-label {
    color: var(--tl-muted);
    font-size: .68rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .06em;
    margin-bottom: 3px;
  }
  .tl-sidebar-value {
    color: var(--tl-text);
    font-size: .94rem;
    font-weight: 760;
    line-height: 1.2;
    overflow-wrap: anywhere;
  }
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
  .tl-action-card {
    border: 1px solid var(--tl-border);
    background: var(--tl-panel);
    border-radius: 8px;
    padding: 18px;
    min-height: 100%;
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
  .tl-page-kicker {
    color: var(--tl-muted);
    text-transform: uppercase;
    font-size: .72rem;
    letter-spacing: .08em;
    font-weight: 700;
    margin-bottom: 4px;
  }
  .tl-section-spacer { margin-top: 18px; }

  /* Home page only: move the hero and Analysis heading slightly lower */
  .tl-home-top-space {
    height: 4px;
  }
  .tl-history-top-space {
    height: 28px;
  }
  .tl-sidebar-gap {
    height: 30px;
  }

  /* Compact Home layout so action buttons stay above the fold */
  div[data-testid="stVerticalBlock"] > div:has(.tl-hero) {
    gap: 0.65rem;
  }
  div[data-testid="stTextArea"] textarea {
    min-height: 125px !important;
  }

  section[data-testid="stSidebar"] {
    border-right: 1px solid var(--tl-border);
  }
  div[data-testid="stFileUploaderDropzone"] {
    min-height: 46px;
    padding: 5px 10px;
  }
  div[data-testid="stFileUploaderDropzone"] button {
    min-height: 32px;
  }
  div[data-testid="stFileUploaderDropzone"] small {
    display: none;
  }
  div[data-testid="stMetric"] {
    border: 1px solid var(--tl-border);
    border-radius: 8px;
    padding: 12px;
  }
  .stButton > button, .stDownloadButton > button {
    border-radius: 6px;
    min-height: 40px;
    font-weight: 700;
  }
  @media (max-width: 780px) {
    .block-container { padding-top: 0.75rem !important; }
    .tl-title { font-size: 1.65rem; }
    .tl-card { min-height: auto; }
  }
</style>
""",
    unsafe_allow_html=True,
)


TEXT = {
    "hero_description": "ThreatLens AI combines local regex/rule-based detection with optional Gemini explanations, summaries, remediation advice, and OWASP/MITRE context for defensive security review.",
    "gemini_api_key": "Gemini API Key",
    "api_key_help": "The key is never stored by the app.",
    "analysis_mode": "Analysis Mode",
    "input_type": "Input Type",
    "sidebar_note": "Gemini enriches local findings; local scan still works without a key.",
    "threat_detection": "Threat Detection",
    "demo_mode": "Demo Mode",
    "demo_help": "Loads intentionally vulnerable sample logs or code so the app can be demonstrated without uploading a file.",
    "upload_optional": "Upload log/code file (optional)",
    "input_name": "Input name",
    "input_text": "Log or code input",
    "input_placeholder": "Paste Apache logs, PHP code, Flask code, or another snippet here...",
    "clear": "Clear",
    "analysis_failed": "Analysis failed: {error}",
    "invalid_file": "Could not read uploaded file: {error}",
    "empty_input": "Add input text, upload a file, or load demo data before running analysis.",
    "overview": "Overview",
    "findings": "Findings",
    "owasp_mitre_mapping": "OWASP / MITRE",
    "gemini_ai_explanation": "AI Explanation",
    "report": "Report",
    "executive_summary": "Executive Summary",
    "score_reason": "Risk Factors",
    "score_clean": "No local indicators were detected, so the score remains clean. Continue validating with real context.",
    "score_low": "The score is low because the detected patterns have limited severity or confidence.",
    "score_medium": "The score is medium because one or more findings need validation and remediation planning.",
    "score_high": "The score is elevated because {count} high or critical finding(s) affect sensitive attack paths.",
    "rule_signals": "Rule Signals",
    "flagged_lines": "Flagged Lines",
    "avg_confidence": "Avg Confidence",
    "analysis_id": "Analysis ID",
    "no_recommendations": "No prioritized remediation items are available.",
    "no_threats_detected": "No threats detected by the current local rules.",
    "evidence_and_remediation": "Evidence & Remediation",
    "technical_explanation": "Technical Explanation",
    "business_impact": "Business Impact",
    "immediate_fix": "Immediate Fix",
    "long_term_fix": "Long-Term Fix",
    "false_positive_note": "False Positive Note",
    "top_priority_action": "Top Priority Action",
    "business_risk": "Business Risk",
    "attack_narrative": "Attack Narrative",
    "timeline_narrative": "The visible chain starts with {first} and later includes {last}. Treat this as a triage narrative, not proof of compromise.",
    "findings_narrative": "ThreatLens identified {count} finding(s). Review the evidence, confirm true positives, and prioritize fixes by severity.",
    "clean_narrative": "No clear attack chain is visible in this input.",
    "recommended_next_steps": "Recommended Next Steps",
    "mapping_empty": "No mapping is available because no findings were detected.",
    "attack_timeline": "Attack Timeline",
    "report_preview": "Report Preview",
    "history_empty": "No saved analyses yet.",
    "load_history": "Load",
    "delete": "Delete",
    "threat_type": "Threat Type",
    "summary_not_available": "Executive summary is not available.",
    "ethical_notice_body": "ThreatLens AI is for defensive security review, education, and authorized analysis only. It must not be used for exploitation, live attacks, unauthorized scanning, phishing, malware generation, credential theft, or any activity against systems you do not own or have permission to assess.",
}


def t(key: str, **kwargs: Any) -> str:
    text = TEXT.get(key, key)
    return text.format(**kwargs) if kwargs else text


def get_secret_api_key() -> str:
    env_key = os.environ.get("GEMINI_API_KEY", "")
    if env_key:
        return env_key
    try:
        return st.secrets.get("GEMINI_API_KEY", "")
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
        "current_page": "Home",
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


def read_sample(sample_name: str) -> tuple[str, str]:
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
    try:
        return uploaded_file.getvalue().decode("utf-8")
    except UnicodeDecodeError:
        return uploaded_file.getvalue().decode("latin-1", errors="replace")
    except Exception as exc:
        st.error(t("invalid_file", error=str(exc)))
        return ""


def status_text(api_key: str, result: dict[str, Any] | None = None) -> tuple[str, str]:
    if result and result.get("gemini_error"):
        return "❌ Gemini error: fallback to local results", "error"
    if api_key:
        return "✅ Gemini connected", "success"
    return "⚠️ Gemini key missing: local analysis only", "warning"


def severity_style(severity: str) -> tuple[str, str]:
    color = get_severity_color(severity)
    return color, f"background:{color}22;color:{color};border:1px solid {color}66"


def score_explanation(score: int, severity: str, findings: list[dict[str, Any]]) -> str:
    if score == 0:
        return t("score_clean")
    high_count = sum(1 for item in findings if item.get("severity") in {"Critical", "High"})
    if severity in {"Critical", "High"}:
        return t("score_high", count=high_count)
    if severity == "Medium":
        return t("score_medium")
    return t("score_low")


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


def detect_input_type(content: str, input_name: str = "") -> str:
    """Detect logs, PHP, Flask/Python, or generic source code.

    Unknown or unsupported source code safely falls back to Custom Code.
    """
    text = (content or "").strip()
    lowered = text.lower()
    suffix = Path(input_name or "").suffix.lower()

    # Strong filename signals.
    if suffix == ".php":
        return "PHP Code"

    if suffix == ".py":
        if re.search(r"\bfrom\s+flask\b|\bimport\s+flask\b|Flask\s*\(|@app\.route", text):
            return "Flask Code"
        return "Custom Code"

    if suffix in {
        ".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".h", ".cpp", ".cc",
        ".cxx", ".hpp", ".cs", ".go", ".rb", ".rs", ".swift", ".kt", ".kts",
        ".scala", ".sh", ".bash", ".ps1", ".sql", ".html", ".css", ".vue",
    }:
        return "Custom Code"

    if suffix in {".log"}:
        return "Apache Log"

    # Apache/common access-log pattern.
    apache_pattern = re.compile(
        r'(?m)^\s*(?:\d{1,3}\.){3}\d{1,3}\s+\S+\s+\S+\s+\[[^\]]+\]\s+'
        r'"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+(?:\s+HTTP/\d(?:\.\d)?)?"\s+\d{3}\b'
    )
    if apache_pattern.search(text):
        return "Apache Log"

    # PHP markers.
    if (
        "<?php" in lowered
        or re.search(r"\$_(?:get|post|request|cookie|server|files)\b", lowered)
        or re.search(r"\bmysqli?_(?:query|connect)\s*\(", lowered)
    ):
        return "PHP Code"

    # Flask markers.
    if re.search(r"\bfrom\s+flask\b|\bimport\s+flask\b|Flask\s*\(|@app\.route", text):
        return "Flask Code"

    # Anything else is treated as generic source code.
    return "Custom Code"


def detect_code_language(content: str, input_name: str = "") -> str:
    """Infer a useful language label for Gemini and reports."""
    text = (content or "").strip()
    lowered = text.lower()
    suffix = Path(input_name or "").suffix.lower()

    extension_map = {
        ".py": "python",
        ".php": "php",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".c": "c",
        ".h": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".hpp": "cpp",
        ".cs": "csharp",
        ".go": "go",
        ".rb": "ruby",
        ".rs": "rust",
        ".swift": "swift",
        ".kt": "kotlin",
        ".kts": "kotlin",
        ".scala": "scala",
        ".sh": "shell",
        ".bash": "shell",
        ".ps1": "powershell",
        ".sql": "sql",
        ".html": "html",
        ".css": "css",
        ".vue": "vue",
    }
    if suffix in extension_map:
        return extension_map[suffix]

    language_patterns = [
        ("php", r"<\?php|\$_(?:get|post|request|cookie|server|files)\b"),
        ("python", r"^\s*(?:from|import)\s+[A-Za-z_]|^\s*(?:def|class)\s+[A-Za-z_]\w*\s*[:(]"),
        ("javascript", r"\b(?:const|let|var|function)\s+[A-Za-z_$]|\brequire\s*\(|=>"),
        ("typescript", r"\binterface\s+\w+|\btype\s+\w+\s*=|:\s*(?:string|number|boolean)\b"),
        ("java", r"\bpublic\s+(?:static\s+)?(?:class|interface|enum)\b|\bSystem\.out\.println\s*\("),
        ("csharp", r"\busing\s+System\b|\bnamespace\s+\w+|\bConsole\.WriteLine\s*\("),
        ("cpp", r"#include\s*[<\"](?:iostream|vector|string|map)|\bstd::"),
        ("c", r"#include\s*[<\"](?:stdio\.h|stdlib\.h|string\.h)|\bprintf\s*\("),
        ("go", r"^\s*package\s+\w+|\bfunc\s+\w+\s*\("),
        ("ruby", r"^\s*(?:require|class|module|def)\s+|\bputs\s+"),
        ("rust", r"\bfn\s+main\s*\(|\blet\s+mut\b|\bprintln!\s*\("),
        ("kotlin", r"\bfun\s+main\s*\(|\bval\s+\w+|\bvar\s+\w+"),
        ("swift", r"\bimport\s+Foundation\b|\bfunc\s+\w+\s*\(|\blet\s+\w+\s*="),
        ("shell", r"^#!\/(?:usr\/bin\/env\s+)?(?:bash|sh)\b|\b(?:echo|grep|awk|sed)\b"),
        ("powershell", r"\bWrite-Host\b|\bGet-[A-Z]\w+|\$\w+\s*="),
        ("sql", r"\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER)\b.+\b(?:FROM|INTO|TABLE|SET)\b"),
        ("html", r"<!doctype\s+html>|<html\b|<body\b|<div\b"),
        ("css", r"(?m)^\s*[.#]?[A-Za-z][\w\s.#>:,\-\[\]=\"']*\s*\{[^}]*:[^}]*\}"),
    ]

    for language, pattern in language_patterns:
        if re.search(pattern, text, re.IGNORECASE | re.MULTILINE | re.DOTALL):
            return language

    return "generic"



def run_threatlens_analysis(
    content: str,
    input_name: str,
    mode: str,
    api_key: str,
) -> dict[str, Any]:
    content = (content or "").strip()
    if not content:
        raise ValueError(t("empty_input"))

    detected_input_type = detect_input_type(content, input_name)
    is_log = detected_input_type == "Apache Log"

    if is_log:
        parsed_df, log_format = parse_log_file(content)
        code_language = ""
    else:
        parsed_df = pd.DataFrame()
        log_format = "code"
        code_language = detect_code_language(content, input_name)

    rule_findings = run_rule_detection(parsed_df, content)

    # User-Agent rules are meaningful for access logs, not source-code input.
    if not is_log:
        rule_findings = [
            finding
            for finding in rule_findings
            if finding.get("threat_type") != "Suspicious User-Agent"
        ]

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
                gemini_findings = analyze_code(flagged_content, code_language, pre_labels, api_key)
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
        "input_type": detected_input_type,
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
        "ethical_notice": t("ethical_notice_body"),
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


def render_detected_input_card(result: dict[str, Any]) -> None:
    input_type = str(result.get("input_type") or result.get("analysis_type") or "Unknown Input")
    input_name = str(result.get("input_name") or "manual-input")
    line_count = int(result.get("line_count") or 0)
    log_format = str(result.get("log_format") or "auto")
    note = f"{html.escape(input_name)} - {line_count} line(s) - {html.escape(log_format)}"
    st.markdown(
        f"""
<div class="tl-card" style="min-height:auto;margin-bottom:14px">
  <div class="tl-card-label">Input Reviewed</div>
  <div class="tl-card-value">{html.escape(input_type)}</div>
  <div class="tl-card-note">{note}</div>
</div>
""",
        unsafe_allow_html=True,
    )


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
    Confidence: {confidence}% AI / {rule_confidence}% Rule · Source: {html.escape(str(finding.get("analysis_source", "Rule Engine")))}
  </div>
  <div class="tl-muted" style="margin-top:6px">
    OWASP: {html.escape(str(finding.get("owasp_category", "N/A")))}<br>
    MITRE ATT&CK: {html.escape(str(mitre))}
  </div>
</div>
""",
        unsafe_allow_html=True,
    )

    with st.expander(f"📌 {t('evidence_and_remediation')} #{index}", expanded=index == 1):
        st.markdown(f'<div class="tl-evidence">{evidence}</div>', unsafe_allow_html=True)
        left, right = st.columns(2)
        with left:
            st.markdown(f"**{t('technical_explanation')}**")
            st.write(finding.get("explanation", "N/A"))
            st.markdown(f"**{t('business_impact')}**")
            st.warning(finding.get("business_impact", "N/A"))
        with right:
            st.markdown(f"**{t('immediate_fix')}**")
            st.success(finding.get("immediate_fix", "N/A"))
            st.markdown(f"**{t('long_term_fix')}**")
            st.info(finding.get("long_term_fix", "N/A"))
            st.caption(f"{t('false_positive_note')}: {finding.get('false_positive_note', 'N/A')}")


def render_result_metrics(result: dict[str, Any]) -> None:
    findings = result.get("findings", [])
    rule_findings = result.get("rule_findings", [])
    high_findings = sum(1 for item in findings if item.get("severity") in {"Critical", "High"})
    breakdown = get_score_breakdown(findings, rule_findings)

    card1, card2, card3, card4, card5 = st.columns(5)
    with card1:
        render_metric_card("Overall Risk Score", f"{result.get('risk_score', 0)}/100", result.get("severity", "Clean"))
    with card2:
        render_metric_card("Total Findings", str(len(findings)), "Confirmed signals")
    with card3:
        render_metric_card("High/Critical", str(high_findings), "Priority review")
    with card4:
        render_metric_card("Rule Signals", str(len(rule_findings)), "Local detection")
    with card5:
        render_metric_card("Flagged Lines", str(breakdown.get("flagged_lines_count", 0)), "Evidence matches")


def render_sidebar_analysis_details(result: dict[str, Any]) -> None:
    findings = result.get("findings", [])
    rule_findings = result.get("rule_findings", [])
    breakdown = get_score_breakdown(findings, rule_findings)
    input_type = str(result.get("input_type", result.get("analysis_type", "-"))).title()
    details = [
        (t("input_type"), input_type),
        (t("avg_confidence"), f"{int(breakdown.get('avg_gemini_confidence', 0) * 100)}%"),
        ("Gemini Used", "Yes" if result.get("gemini_used") else "No"),
        (t("analysis_id"), str(result.get("analysis_id", "-"))),
    ]
    card_fragments = []
    for label, value in details:
        safe_label = html.escape(str(label))
        safe_value = html.escape(str(value))
        card_fragments.append(
            f'<div class="tl-sidebar-mini">'
            f'<div class="tl-sidebar-label">{safe_label}</div>'
            f'<div class="tl-sidebar-value">{safe_value}</div>'
            f'</div>'
        )
    cards_html = "".join(card_fragments)
    sidebar_html = (
        '<div class="tl-sidebar-details">'
        '<div class="tl-sidebar-title">Analysis Details</div>'
        f'<div class="tl-sidebar-grid">{cards_html}</div>'
        '</div>'
    )
    st.markdown(sidebar_html, unsafe_allow_html=True)


def render_results_page(result: dict[str, Any], api_key: str) -> None:
    findings = result.get("findings", [])
    rule_findings = result.get("rule_findings", [])
    risk_score = int(result.get("risk_score", 0))
    severity = result.get("severity", "Clean")
    summary = result.get("executive_summary", {})
    top_recommendations = result.get("top_recommendations", [])
    st.markdown('<div class="tl-page-kicker">Analysis Results</div>', unsafe_allow_html=True)
    st.markdown("# Results")
    render_result_metrics(result)
    st.markdown('<div class="tl-section-spacer"></div>', unsafe_allow_html=True)
    render_detected_input_card(result)

    tab_overview, tab_findings, tab_mapping, tab_ai, tab_report = st.tabs(
        [
            t("overview"),
            t("findings"),
            t("owasp_mitre_mapping"),
            t("gemini_ai_explanation"),
            t("report"),
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
            st.markdown(f"### {t('executive_summary')}")
            st.write(summary.get("summary_paragraph", t("summary_not_available")))
            st.markdown(f"**{t('score_reason')}**")
            st.info(score_explanation(risk_score, severity, findings))
            if top_recommendations:
                for item in top_recommendations[:5]:
                    st.markdown(f"- {item}")
            else:
                st.success(t("no_recommendations"))

    with tab_findings:
        if not findings:
            st.success(t("no_threats_detected"))
        else:
            for index, finding in enumerate(findings, 1):
                render_finding(finding, index)

    with tab_mapping:
        if not findings:
            st.info(t("mapping_empty"))
        else:
            rows = []
            for item in findings:
                rows.append(
                    {
                        t("threat_type"): item.get("threat_type", "Unknown"),
                        "Severity": item.get("severity", "Unknown"),
                        "OWASP": item.get("owasp_category", "N/A"),
                        "MITRE ATT&CK": item.get("mitre_attack_summary")
                        or format_mitre_attack(item.get("mitre_attack")),
                    }
                )
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        if result.get("attack_timeline"):
            st.markdown(f"### {t('attack_timeline')}")
            st.dataframe(pd.DataFrame(result["attack_timeline"]), use_container_width=True, hide_index=True)

    with tab_ai:
        status, level = status_text(api_key, result)
        getattr(st, level)(status)
        st.markdown("### Gemini Explanation")
        st.write(summary.get("summary_paragraph", t("summary_not_available")))
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**{t('top_priority_action')}**")
            st.warning(summary.get("top_priority_action", "N/A"))
            st.markdown(f"**{t('business_risk')}**")
            st.write(summary.get("estimated_business_risk", "N/A"))
        with col2:
            st.markdown(f"**{t('attack_narrative')}**")
            if result.get("attack_timeline"):
                first = result["attack_timeline"][0]
                last = result["attack_timeline"][-1]
                st.write(
                    t(
                        "timeline_narrative",
                        first=first.get("threat_type", "unknown"),
                        last=last.get("threat_type", "unknown"),
                    )
                )
            elif findings:
                st.write(t("findings_narrative", count=len(findings)))
            else:
                st.write(t("clean_narrative"))
            st.markdown(f"**{t('recommended_next_steps')}**")
            for step in summary.get("recommended_next_steps", []):
                st.markdown(f"- {step}")

    with tab_report:
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
        st.markdown("### Report")
        st.text_area(t("report_preview"), text_report, height=300)
        st.markdown("### Export Options")
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


def render_history() -> None:
    analyses = get_all_analyses(25)
    if not analyses:
        st.info(t("history_empty"))
        return
    for item in analyses:
        label = (
            f"{item.get('created_at', '')[:16].replace('T', ' ')} · "
            f"{item.get('input_filename', 'input')} · "
            f"{item.get('severity_label', 'Clean')} · {item.get('overall_risk_score', 0)}/100"
        )
        with st.expander(label):
            detail = get_analysis_detail(item["id"])
            st.caption(f"{t('findings')}: {len(detail.get('findings', []))}")
            for finding in detail.get("findings", [])[:5]:
                st.markdown(f"- **{finding.get('threat_type', 'Unknown')}** · {finding.get('severity', 'Unknown')}")
            col1, col2 = st.columns([1, 1])
            with col1:
                if st.button(t("load_history"), key=f"load_{item['id']}"):
                    st.session_state["result"] = {
                        "analysis_id": item["id"],
                        "analysis_type": item.get("analysis_type", ""),
                        "analysis_mode": "History",
                        "input_name": item.get("input_filename", ""),
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
                    st.session_state["current_page"] = "Results"
                    st.rerun()
            with col2:
                if st.button(t("delete"), key=f"delete_{item['id']}"):
                    delete_analysis(item["id"])
                    st.session_state["current_page"] = "History"
                    st.rerun()


def _safe_json(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value or "")
    except Exception:
        return default


def clear_analysis_input() -> None:
    st.session_state["input_text"] = ""
    st.session_state["input_name"] = "manual-input"
    st.session_state["last_upload_name"] = ""
    st.session_state["uploaded_file"] = None
    st.session_state["result"] = None
    st.session_state["current_page"] = "Home"


def load_demo_data() -> None:
    demo_text, demo_name = read_sample("Apache Log")
    st.session_state["demo_mode"] = True
    st.session_state["input_text"] = demo_text
    st.session_state["input_name"] = demo_name


def handle_uploaded_file() -> None:
    """Load an uploaded file into session state before input widgets render."""
    uploaded_file = st.session_state.get("uploaded_file")
    if uploaded_file is None:
        return

    if uploaded_file.name == st.session_state.get("last_upload_name"):
        return

    st.session_state["input_text"] = decode_upload(uploaded_file)
    st.session_state["input_name"] = uploaded_file.name
    st.session_state["last_upload_name"] = uploaded_file.name
    st.session_state["result"] = None


def render_sidebar() -> None:
    with st.sidebar:
        st.markdown("## ThreatLens AI")
        st.caption("Defensive analysis workspace")

        nav_home, nav_results, nav_history = st.columns(3)
        with nav_home:
            if st.button("Home", use_container_width=True):
                st.session_state["current_page"] = "Home"
                st.rerun()
        results_disabled = not bool(st.session_state.get("result"))
        with nav_results:
            if st.button("Results", use_container_width=True, disabled=results_disabled):
                st.session_state["current_page"] = "Results"
                st.rerun()
        with nav_history:
            if st.button("History", use_container_width=True):
                st.session_state["current_page"] = "History"
                st.rerun()

        result = st.session_state.get("result")
        if result:
            render_sidebar_analysis_details(result)

        st.markdown('<div class="tl-sidebar-gap"></div>', unsafe_allow_html=True)
        st.markdown("### Gemini API")
        st.session_state["api_key"] = st.text_input(
            t("gemini_api_key"),
            value=st.session_state.get("api_key", ""),
            type="password",
            placeholder="AIza...",
            help=t("api_key_help"),
        )
        status, level = status_text(st.session_state["api_key"], st.session_state.get("result"))
        getattr(st, level)(status)



def render_home_page() -> None:
    st.markdown(
        '<div class="tl-home-top-space"></div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
<div class="tl-hero">
  <div class="tl-title">ThreatLens AI</div>
  <div class="tl-subtitle">Gemini-Powered Cybersecurity Risk Analyzer</div>
  <div class="tl-muted">{t("hero_description")}</div>
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown(f"## {t('threat_detection')}")

    mode_col, name_col = st.columns([1, 2])
    with mode_col:
        st.session_state["analysis_mode"] = st.selectbox(
            t("analysis_mode"),
            ANALYSIS_MODES,
            index=ANALYSIS_MODES.index(
                st.session_state.get("analysis_mode", ANALYSIS_MODES[1])
            ),
        )
    with name_col:
        st.text_input(t("input_name"), key="input_name")

    st.caption(t("sidebar_note"))

    st.file_uploader(
        t("upload_optional"),
        type=[
            "txt", "log", "py", "php", "js", "jsx", "ts", "tsx", "json", "conf",
            "java", "c", "h", "cpp", "cc", "cxx", "hpp", "cs", "go", "rb", "rs",
            "swift", "kt", "kts", "scala", "sh", "bash", "ps1", "sql", "html",
            "css", "vue",
        ],
        key="uploaded_file",
        on_change=handle_uploaded_file,
    )

    st.text_area(
        t("input_text"),
        key="input_text",
        height=125,
        placeholder=t("input_placeholder"),
    )

    run_col, demo_col, clear_col = st.columns([2, 1, 1])
    with run_col:
        run_clicked = st.button("Run ThreatLens Analysis", type="primary", use_container_width=True)
    with demo_col:
        st.button("Load Demo Data", use_container_width=True, on_click=load_demo_data)
    with clear_col:
        st.button(t("clear"), use_container_width=True, on_click=clear_analysis_input)

    if run_clicked:
        run_analysis_flow()
    elif not st.session_state.get("input_text"):
        st.info("Load demo data, upload a file, or paste input to start a new analysis.")


def run_analysis_flow() -> None:
    try:
        loading_box = st.container()
        with loading_box:
            st.markdown("### Preparing analysis")
            progress = st.progress(0)
            status_line = st.empty()
            steps = [
                ("Parsing input...", 15),
                ("Running local rules...", 35),
                ("Calculating risk score...", 55),
                ("Generating report...", 75),
                ("Preparing AI explanation...", 90),
            ]
            for label, value in steps[:2]:
                status_line.info(label)
                progress.progress(value)
                time.sleep(0.12)

            st.session_state["result"] = run_threatlens_analysis(
                st.session_state["input_text"],
                st.session_state["input_name"] or "manual-input",
                st.session_state["analysis_mode"],
                st.session_state.get("api_key", ""),
            )

            for label, value in steps[2:]:
                status_line.info(label)
                progress.progress(value)
                time.sleep(0.12)
            status_line.success("Analysis complete. Opening results...")
            progress.progress(100)
            time.sleep(0.15)

        st.session_state["current_page"] = "Results"
        st.rerun()
    except ValueError as exc:
        st.warning(str(exc))
    except Exception as exc:
        st.error(t("analysis_failed", error=str(exc)))


def render_history_page() -> None:
    st.markdown(
        '<div class="tl-history-top-space"></div>',
        unsafe_allow_html=True,
    )
    st.markdown('<div class="tl-page-kicker">Saved Analyses</div>', unsafe_allow_html=True)
    st.markdown("# History")
    render_history()


def render_current_page() -> None:
    page = st.session_state.get("current_page", "Home")
    if page == "Results":
        result = st.session_state.get("result")
        if result:
            render_results_page(result, st.session_state.get("api_key", ""))
            return
        st.session_state["current_page"] = "Home"
    if page == "History":
        render_history_page()
        return
    render_home_page()


init_state()
render_sidebar()
render_current_page()
