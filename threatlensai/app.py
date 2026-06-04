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
LANGUAGES = {"English": "en", "Turkish": "tr"}


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
    return translate_text(key, st.session_state.get("language", "en"), **kwargs)


def get_secret_api_key() -> str:
    try:
        return st.secrets.get("GEMINI_API_KEY", "")
    except Exception:
        return ""


def init_state() -> None:
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


def local_summary(severity: str, score: int, findings: list[dict[str, Any]], language: str) -> dict[str, Any]:
    recommendations = generate_top_recommendations(findings, limit=3)
    if language == "tr":
        if findings:
            paragraph = f"Yerel kural analizi {len(findings)} bulgu tespit etti. Genel risk skoru {score}/100 ve seviye {severity} olarak hesaplandı."
        else:
            paragraph = "Yerel kural analizi belirgin bir tehdit işareti bulmadı."
        return {
            "overall_status": severity,
            "summary_paragraph": paragraph,
            "top_priority_action": recommendations[0] if recommendations else "Log ve kodu düzenli olarak gözden geçirin.",
            "estimated_business_risk": "Risk, bulguların gerçek sistemlere ulaşıp ulaşmadığına göre değişir.",
            "positive_notes": "Analiz Gemini API anahtarı olmadan yerel kurallarla tamamlandı.",
            "recommended_next_steps": recommendations or ["Bulguları doğrulayın", "Gerekli düzeltmeleri uygulayın", "Tekrar analiz çalıştırın"],
        }
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
    input_type: str,
    input_name: str,
    mode: str,
    language: str,
    api_key: str,
) -> dict[str, Any]:
    content = (content or "").strip()
    if not content:
        raise ValueError(t("empty_input"))

    is_log = input_type == "Apache Log"
    if is_log:
        parsed_df, log_format = parse_log_file(content)
        code_language = ""
    else:
        parsed_df = pd.DataFrame()
        log_format = "code"
        code_language = "php" if input_type == "PHP Code" else "python"

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
                gemini_findings = analyze_logs(flagged_content, pre_labels, api_key, language=language)
            else:
                gemini_findings = analyze_code(flagged_content, code_language, pre_labels, api_key, language=language)
            gemini_used = True
        except GeminiAPIError as exc:
            gemini_error = str(exc)

    findings = merge_rule_and_gemini_findings(gemini_findings, rule_findings)
    risk_score, severity = compute_risk_score(findings, rule_findings)
    top_recommendations = generate_top_recommendations(findings)
    attack_timeline = build_attack_timeline(parsed_df, rule_findings) if is_log else []

    if should_send_to_gemini and gemini_used and mode == "Full Gemini Report":
        executive_summary = generate_executive_summary(
            findings, risk_score, severity, api_key, language=language
        )
    else:
        executive_summary = local_summary(severity, risk_score, findings, language)

    analysis_type = "log" if is_log else "code"
    analysis_id = save_analysis(
        analysis_type,
        input_name,
        content[:1000],
        risk_score,
        severity,
        findings,
        executive_summary=executive_summary,
        language=language,
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
        "input_type": input_type,
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


def build_json_export(result: dict[str, Any], language: str) -> str:
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
        "ethical_notice": translate_text("ethical_notice_body", language),
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


def render_results_tabs(result: dict[str, Any], api_key: str) -> None:
    findings = result.get("findings", [])
    rule_findings = result.get("rule_findings", [])
    risk_score = int(result.get("risk_score", 0))
    severity = result.get("severity", "Clean")
    summary = result.get("executive_summary", {})
    top_recommendations = result.get("top_recommendations", [])
    breakdown = get_score_breakdown(findings, rule_findings)

    tab_overview, tab_findings, tab_ai, tab_mapping, tab_report, tab_history = st.tabs(
        [
            f"📊 {t('overview')}",
            f"🚨 {t('findings')}",
            f"🧠 {t('gemini_ai_explanation')}",
            f"🧭 {t('owasp_mitre_mapping')}",
            f"🧾 {t('report')}",
            f"🕘 {t('history')}",
        ]
    )

    with tab_overview:
        left, right = st.columns([1, 2])
        with left:
            st.markdown("### 📊 Risk Score")
            st.progress(min(risk_score, 100) / 100)
            st.markdown(
                f"<div style='font-size:3rem;font-weight:900;color:{get_severity_color(severity)}'>{risk_score}/100</div>",
                unsafe_allow_html=True,
            )
            st.markdown(f"**{severity}**")
        with right:
            st.markdown(f"### ✨ {t('executive_summary')}")
            st.write(summary.get("summary_paragraph", t("summary_not_available")))
            st.markdown(f"**{t('score_reason')}**")
            st.info(score_explanation(risk_score, severity, findings))
            st.markdown(f"**{t('top_risk_factors')}**")
            if top_recommendations:
                for item in top_recommendations[:5]:
                    st.markdown(f"- {item}")
            else:
                st.success(t("no_recommendations"))

        st.markdown("### 🧪 Analysis Details")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric(t("rule_signals"), len(rule_findings))
        c2.metric(t("flagged_lines"), breakdown.get("flagged_lines_count", 0))
        c3.metric(t("avg_confidence"), f"{int(breakdown.get('avg_gemini_confidence', 0) * 100)}%")
        c4.metric(t("analysis_id"), str(result.get("analysis_id", "-")))

    with tab_findings:
        if not findings:
            st.success(t("no_threats_detected"))
        else:
            for index, finding in enumerate(findings, 1):
                render_finding(finding, index)

    with tab_ai:
        status, level = status_text(api_key, result)
        getattr(st, level)(status)
        st.markdown(f"### ✨ {t('executive_summary')}")
        st.write(summary.get("summary_paragraph", t("summary_not_available")))
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**{t('top_priority_action')}**")
            st.warning(summary.get("top_priority_action", "N/A"))
            st.markdown(f"**{t('business_risk')}**")
            st.write(summary.get("estimated_business_risk", "N/A"))
        with col2:
            st.markdown(f"**🧬 {t('attack_narrative')}**")
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
            st.markdown(f"### 🧬 {t('attack_timeline')}")
            st.dataframe(pd.DataFrame(result["attack_timeline"]), use_container_width=True, hide_index=True)

    with tab_report:
        text_report = build_text_report(
            result.get("analysis_type", ""),
            result.get("input_name", ""),
            risk_score,
            severity,
            findings,
            summary,
            language=st.session_state["language"],
            rule_findings=rule_findings,
            attack_timeline=result.get("attack_timeline", []),
            top_recommendations=top_recommendations,
            analysis_mode=result.get("analysis_mode", ""),
            gemini_used=result.get("gemini_used", False),
        )
        json_report = build_json_export(result, st.session_state["language"])
        st.text_area(t("report_preview"), text_report, height=300)
        col_txt, col_json = st.columns(2)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        col_txt.download_button(
            "🧾 Download TXT Report",
            data=text_report,
            file_name=f"threatlens_ai_report_{timestamp}.txt",
            mime="text/plain",
            use_container_width=True,
        )
        col_json.download_button(
            "🧾 Download JSON Report",
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
                    st.session_state.result = {
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
                    st.rerun()
            with col2:
                if st.button(t("delete"), key=f"delete_{item['id']}"):
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
    st.markdown("## 🛡️ ThreatLens AI")
    selected_language = st.selectbox(
        "Language / Dil",
        list(LANGUAGES.keys()),
        index=0 if st.session_state["language"] == "en" else 1,
    )
    st.session_state["language"] = LANGUAGES[selected_language]

    st.markdown("### 🔑 Gemini API")
    st.session_state["api_key"] = st.text_input(
        t("gemini_api_key"),
        value=st.session_state.get("api_key", ""),
        type="password",
        placeholder="AIza...",
        help=t("api_key_help"),
    )
    status, level = status_text(st.session_state["api_key"], st.session_state.get("result"))
    getattr(st, level)(status)

    st.markdown("### ⚙️ Analysis")
    st.session_state["analysis_mode"] = st.selectbox(
        t("analysis_mode"),
        ANALYSIS_MODES,
        index=ANALYSIS_MODES.index(st.session_state.get("analysis_mode", ANALYSIS_MODES[1])),
    )
    st.session_state["input_type"] = st.selectbox(
        t("input_type"),
        INPUT_TYPES,
        index=INPUT_TYPES.index(st.session_state.get("input_type", INPUT_TYPES[0])),
    )
    st.session_state["demo_mode"] = st.toggle("🧪 Demo Mode", value=st.session_state.get("demo_mode", True))
    st.caption(t("sidebar_note"))


st.markdown(
    f"""
<div class="tl-hero">
  <div class="tl-title">🛡️ ThreatLens AI</div>
  <div class="tl-subtitle">Gemini-Powered Cybersecurity Risk Analyzer</div>
  <div class="tl-muted">{t("hero_description")}</div>
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
    render_metric_card("Total Findings", str(total_findings), t("local_and_ai"))
with card3:
    render_metric_card("High/Critical", str(high_findings), t("priority_items"))
with card4:
    render_metric_card("Gemini Status", status.split(":")[0], t("optional_enrichment"))
with card5:
    render_metric_card("Analysis Mode", st.session_state["analysis_mode"], st.session_state["input_type"])


st.markdown(f"## 🛡️ {t('threat_detection')}")
top_left, top_right = st.columns([2, 1])
with top_right:
    st.markdown(f"### 🧪 {t('demo_mode')}")
    if st.button("🧪 Load Demo Data", use_container_width=True):
        demo_text, demo_name = read_sample(st.session_state["input_type"])
        st.session_state["input_text"] = demo_text
        st.session_state["input_name"] = demo_name
        st.rerun()
    st.caption(t("demo_help"))

with top_left:
    uploaded_file = st.file_uploader(t("upload_optional"), type=["txt", "log", "py", "php", "js", "json", "conf"])
    if uploaded_file and uploaded_file.name != st.session_state.get("last_upload_name"):
        st.session_state["input_text"] = decode_upload(uploaded_file)
        st.session_state["input_name"] = uploaded_file.name
        st.session_state["last_upload_name"] = uploaded_file.name
        st.rerun()

    st.text_input(t("input_name"), key="input_name")
    st.text_area(
        t("input_text"),
        key="input_text",
        height=260,
        placeholder=t("input_placeholder"),
    )

run_col, clear_col = st.columns([2, 1])
with run_col:
    run_clicked = st.button("🚀 Run ThreatLens Analysis", type="primary", use_container_width=True)
with clear_col:
    if st.button(t("clear"), use_container_width=True):
        st.session_state["input_text"] = ""
        st.session_state["result"] = None
        st.rerun()

if run_clicked:
    try:
        with st.spinner(t("analysis_running")):
            st.session_state["result"] = run_threatlens_analysis(
                st.session_state["input_text"],
                st.session_state["input_type"],
                st.session_state["input_name"] or "manual-input",
                st.session_state["analysis_mode"],
                st.session_state["language"],
                st.session_state.get("api_key", ""),
            )
        st.success(t("analysis_complete"))
        st.rerun()
    except ValueError as exc:
        st.warning(str(exc))
    except Exception as exc:
        st.error(t("analysis_failed", error=str(exc)))


if st.session_state.get("result"):
    render_results_tabs(st.session_state["result"], st.session_state.get("api_key", ""))
else:
    st.info(t("empty_state"))
