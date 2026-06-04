from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any

from i18n import APP_NAME, translate_text
from threat_knowledge import format_mitre_attack, generate_top_recommendations


EXPORTS_DIR = Path(
    os.environ.get(
        "THREATLENSAI_EXPORTS_DIR",
        Path(os.environ.get("LOCALAPPDATA", Path(__file__).parent / "runtime_data")) / "ThreatLensAI" / "exports",
    )
)

SEVERITY_MARKERS = {
    "Critical": "[CRITICAL]",
    "High": "[HIGH]",
    "Medium": "[MEDIUM]",
    "Low": "[LOW]",
    "Informational": "[INFO]",
    "Clean": "[CLEAN]",
}

OWASP_LINKS = {
    "A01:2021": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "A02:2021": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    "A03:2021": "https://owasp.org/Top10/A03_2021-Injection/",
    "A04:2021": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    "A05:2021": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    "A06:2021": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    "A07:2021": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    "A08:2021": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    "A09:2021": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    "A10:2021": "https://owasp.org/Top10/A10_2021-Server_Side_Request_Forgery/",
}


def _rt(language: str, key: str, **kwargs: Any) -> str:
    return translate_text(key, language, **kwargs)


def build_text_report(
    analysis_type: str,
    input_name: str,
    risk_score: int,
    severity_label: str,
    findings: list[dict[str, Any]],
    executive_summary: dict | None = None,
    language: str = "en",
    rule_findings: list[dict[str, Any]] | None = None,
    attack_timeline: list[dict[str, Any]] | None = None,
    top_recommendations: list[str] | None = None,
    analysis_mode: str = "",
    gemini_used: bool = False,
) -> str:
    lines: list[str] = []
    sep = "=" * 78
    thin = "-" * 78
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    marker = SEVERITY_MARKERS.get(severity_label, "[WARN]")
    findings = findings or []
    rule_findings = rule_findings or []
    top_recommendations = top_recommendations or generate_top_recommendations(findings)

    lines.append(sep)
    lines.append(_rt(language, "report_title"))
    lines.append(sep)
    lines.append(f"{_rt(language, 'generated'):<14}: {now}")
    lines.append(f"{_rt(language, 'analysis_type_label'):<14}: {analysis_type.upper()}")
    if analysis_mode:
        lines.append(f"{_rt(language, 'analysis_mode'):<14}: {analysis_mode}")
    lines.append(f"{_rt(language, 'gemini_used'):<14}: {_rt(language, 'yes') if gemini_used else _rt(language, 'no')}")
    lines.append(f"{_rt(language, 'source_label'):<14}: {input_name}")
    lines.append(f"{_rt(language, 'risk_score_label'):<14}: {risk_score}/100")
    lines.append(f"{_rt(language, 'severity'):<14}: {marker} {severity_label}")
    lines.append(f"{_rt(language, 'findings'):<14}: {len(findings)}")
    lines.append(f"{_rt(language, 'rule_signals'):<14}: {len(rule_findings)}")
    lines.append(sep)
    lines.append("")

    _append_executive_summary(lines, executive_summary or {}, severity_label, language)
    _append_top_recommendations(lines, top_recommendations, language)
    _append_attack_timeline(lines, attack_timeline or [], language)
    _append_rule_pre_scan(lines, rule_findings, language)
    _append_detailed_findings(lines, findings, language)
    _append_remediation_checklist(lines, top_recommendations, language)
    _append_references(lines, findings, rule_findings, language)

    lines.append(sep)
    lines.append(_rt(language, "disclaimer").upper())
    lines.append(thin)
    for wrapped in _wrap(_rt(language, "disclaimer_body", app=APP_NAME), 74):
        lines.append(wrapped)
    lines.append(sep)

    return "\n".join(lines)


def save_text_report(content: str, prefix: str = "report") -> Path:
    filename = f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = EXPORTS_DIR / filename
    path.write_text(content, encoding="utf-8")
    return path


def _append_executive_summary(
    lines: list[str],
    executive_summary: dict,
    severity_label: str,
    language: str,
) -> None:
    lines.append(_rt(language, "tab_summary").upper())
    lines.append("-" * 78)
    if not executive_summary:
        lines.append(f"{_rt(language, 'overall_status')}: {severity_label}")
        lines.append(_rt(language, "summary_not_available"))
        lines.append("")
        return

    lines.append(f"{_rt(language, 'status')}: {executive_summary.get('overall_status', severity_label)}")
    lines.append("")
    for wrapped in _wrap(executive_summary.get("summary_paragraph", ""), 74):
        lines.append(wrapped)
    lines.append("")
    lines.append(f"{_rt(language, 'top_priority_action')}: {executive_summary.get('top_priority_action', '')}")
    lines.append("")
    lines.append(f"{_rt(language, 'business_risk')}:")
    for wrapped in _wrap(executive_summary.get("estimated_business_risk", ""), 74):
        lines.append(f"  {wrapped}")
    lines.append("")

    steps = executive_summary.get("recommended_next_steps", [])
    if steps:
        lines.append(f"{_rt(language, 'prioritized_next_steps')}:")
        for idx, step in enumerate(steps, 1):
            lines.append(f"  {idx}. {step}")
    lines.append("")


def _append_top_recommendations(lines: list[str], recommendations: list[str], language: str) -> None:
    lines.append(_rt(language, "top_3_recommendations").upper())
    lines.append("-" * 78)
    if not recommendations:
        lines.append(_rt(language, "no_recommendations"))
    else:
        for idx, recommendation in enumerate(recommendations, 1):
            lines.append(f"{idx}. {recommendation}")
    lines.append("")


def _append_attack_timeline(
    lines: list[str],
    attack_timeline: list[dict[str, Any]],
    language: str,
) -> None:
    if not attack_timeline:
        return
    lines.append(_rt(language, "attack_timeline").upper())
    lines.append("-" * 78)
    for item in attack_timeline[:25]:
        lines.append(
            f"- {item.get('timestamp', 'unknown time')} | "
            f"{item.get('source_ip', 'unknown ip')} | "
            f"{item.get('threat_type', 'Unknown')} | "
            f"{item.get('method', '')} {item.get('path', '')} | "
            f"status={item.get('status', '')}"
        )
    lines.append("")


def _append_rule_pre_scan(lines: list[str], rule_findings: list[dict[str, Any]], language: str) -> None:
    if not rule_findings:
        return
    lines.append(_rt(language, "rule_pre_scan_signals").upper())
    lines.append("-" * 78)
    for finding in rule_findings:
        confidence = int(float(finding.get("rule_confidence", finding.get("confidence", 0)) or 0) * 100)
        lines.append(
            f"- {finding.get('threat_type', 'Unknown')}: "
            f"{confidence}% {_rt(language, 'confidence_label')}, {_rt(language, 'pattern_score')} {finding.get('pattern_score', 0)}, "
            f"{finding.get('owasp_category', 'N/A')}, MITRE {finding.get('mitre_attack_summary', 'N/A')}"
        )
        indicators = finding.get("indicator_hits", [])
        if indicators:
            lines.append(f"  {_rt(language, 'indicators')}: {', '.join(indicators[:5])}")
    lines.append("")


def _append_detailed_findings(lines: list[str], findings: list[dict[str, Any]], language: str) -> None:
    lines.append(_rt(language, "detailed_findings").upper())
    lines.append("-" * 78)

    if not findings:
        lines.append(_rt(language, "no_threats_detected"))
        lines.append("")
        return

    for idx, finding in enumerate(findings, 1):
        severity = finding.get("severity", "Unknown")
        marker = SEVERITY_MARKERS.get(severity, "[WARN]")
        confidence = int(float(finding.get("confidence", 0) or 0) * 100)
        rule_conf = int(float(finding.get("rule_confidence", 0) or 0) * 100)

        lines.append(f"[{_rt(language, 'finding_label')} #{idx}] {marker} {finding.get('threat_type', 'Unknown')}")
        lines.append(f"  {_rt(language, 'source_label'):<11}: {finding.get('analysis_source', 'Gemini AI')}")
        lines.append(f"  {_rt(language, 'severity'):<11}: {severity}")
        lines.append(f"  {_rt(language, 'confidence_label'):<11}: {confidence}% AI / {rule_conf}% {_rt(language, 'rule_confidence_short')}")
        lines.append(f"  OWASP      : {finding.get('owasp_category', 'N/A')}")
        lines.append(f"  MITRE ATT&CK: {finding.get('mitre_attack_summary') or format_mitre_attack(finding.get('mitre_attack'))}")
        lines.append("")

        _append_wrapped_block(lines, _rt(language, "evidence"), finding.get("evidence", "N/A"))
        _append_wrapped_block(lines, _rt(language, "explanation"), finding.get("explanation", ""))
        _append_wrapped_block(lines, _rt(language, "business_impact"), finding.get("business_impact", ""))
        _append_wrapped_block(lines, _rt(language, "immediate_fix"), finding.get("immediate_fix", ""))
        _append_wrapped_block(lines, _rt(language, "long_term_fix"), finding.get("long_term_fix", ""))
        _append_wrapped_block(lines, _rt(language, "recommended_fix"), finding.get("recommended_fix", ""))

        false_positive = finding.get("false_positive_note")
        if false_positive:
            _append_wrapped_block(lines, _rt(language, "false_positive_note"), false_positive)
        lines.append("-" * 78)


def _append_remediation_checklist(lines: list[str], recommendations: list[str], language: str) -> None:
    lines.append(_rt(language, "remediation_checklist").upper())
    lines.append("-" * 78)
    if not recommendations:
        lines.append(_rt(language, "no_recommendations"))
    else:
        for item in recommendations:
            lines.append(f"[ ] {item}")
    lines.append("")


def _append_references(
    lines: list[str],
    findings: list[dict[str, Any]],
    rule_findings: list[dict[str, Any]],
    language: str,
) -> None:
    combined = (findings or []) + (rule_findings or [])
    if not combined:
        return

    lines.append(_rt(language, "references").upper())
    lines.append("-" * 78)

    seen_owasp = set()
    for finding in combined:
        owasp = finding.get("owasp_category", "")
        for code, url in OWASP_LINKS.items():
            if code in owasp and code not in seen_owasp:
                lines.append(f"OWASP {code}: {url}")
                seen_owasp.add(code)

    seen_mitre = set()
    for finding in combined:
        mappings = finding.get("mitre_attack", []) or []
        if isinstance(mappings, dict):
            mappings = [mappings]
        if isinstance(mappings, str):
            mappings = []
        for mapping in mappings:
            technique_id = mapping.get("technique_id") if isinstance(mapping, dict) else ""
            if technique_id and technique_id not in seen_mitre:
                lines.append(f"MITRE {technique_id}: {_mitre_url(technique_id)}")
                seen_mitre.add(technique_id)
    lines.append("")


def _append_wrapped_block(lines: list[str], title: str, text: str) -> None:
    lines.append(f"  {title}:")
    if not text:
        lines.append("    N/A")
    else:
        for wrapped in _wrap(str(text), 70):
            lines.append(f"    {wrapped}")
    lines.append("")


def _wrap(text: str, width: int) -> list[str]:
    if not text:
        return [""]
    wrapped_lines: list[str] = []
    for paragraph in str(text).splitlines() or [""]:
        words = paragraph.split()
        if not words:
            wrapped_lines.append("")
            continue
        current: list[str] = []
        for word in words:
            current_length = sum(len(item) for item in current) + max(len(current) - 1, 0)
            if current and current_length + len(word) + 1 > width:
                wrapped_lines.append(" ".join(current))
                current = [word]
            else:
                current.append(word)
        if current:
            wrapped_lines.append(" ".join(current))
    return wrapped_lines or [""]


def _mitre_url(technique_id: str) -> str:
    parts = technique_id.replace("T", "").split(".")
    if len(parts) == 2:
        return f"https://attack.mitre.org/techniques/T{parts[0]}/{parts[1]}/"
    return f"https://attack.mitre.org/techniques/{technique_id}/"
