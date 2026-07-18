from __future__ import annotations

import html
import re
from collections import defaultdict
from typing import Any
from urllib.parse import unquote_plus

import pandas as pd

from threat_knowledge import (
    format_mitre_attack,
    get_threat_profile,
    normalize_threat_type,
)


PATTERNS: dict[str, dict[str, Any]] = {
    "SQL Injection": {
        "score": 45,
        "base_confidence": 0.58,
        "patterns": [
            {"regex": r"\bunion\s+(?:all\s+)?select\b", "confidence": 0.90, "indicator": "UNION SELECT payload"},
            {"regex": r"\bselect\b.{0,80}\bfrom\b", "confidence": 0.72, "indicator": "SELECT ... FROM sequence"},
            {"regex": r"\b(?:insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+table|alter\s+table)\b", "confidence": 0.78, "indicator": "stacked SQL statement"},
            {"regex": r"(?:'|\"|%27|%22)\s*(?:or|and)\s*(?:'|\"|%27|%22)?\s*\d+\s*=\s*\d+", "confidence": 0.88, "indicator": "boolean tautology"},
            {"regex": r"\bor\b\s+1\s*=\s*1\b|\band\b\s+1\s*=\s*1\b", "confidence": 0.84, "indicator": "OR/AND tautology"},
            {"regex": r"\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b", "confidence": 0.92, "indicator": "time-based injection"},
            {"regex": r"\b(?:information_schema|sysobjects|sqlite_master|pg_catalog)\b", "confidence": 0.86, "indicator": "database metadata access"},
            {"regex": r"\b(?:extractvalue|updatexml|load_file|xp_cmdshell)\s*\(", "confidence": 0.90, "indicator": "database function abuse"},
            {"regex": r"(?:--|#|/\*)\s*(?:$|[A-Za-z0-9])", "confidence": 0.62, "indicator": "SQL comment delimiter"},
            {"regex": r";\s*(?:select|insert|update|delete|drop|exec)\b", "confidence": 0.82, "indicator": "stacked query delimiter"},
        ],
    },
    "XSS": {
        "score": 38,
        "base_confidence": 0.55,
        "patterns": [
            {"regex": r"<\s*script\b", "confidence": 0.90, "indicator": "script tag"},
            {"regex": r"<\s*(?:img|svg|body|iframe|object|embed|video|audio|details)\b[^>]*(?:onerror|onload|onclick|onmouseover|onfocus)\s*=", "confidence": 0.88, "indicator": "event-handler HTML payload"},
            {"regex": r"\bjavascript\s*:", "confidence": 0.82, "indicator": "javascript URI"},
            {"regex": r"\b(?:alert|confirm|prompt)\s*\(", "confidence": 0.66, "indicator": "browser dialog payload"},
            {"regex": r"\bdocument\.(?:cookie|location|write)\b", "confidence": 0.70, "indicator": "DOM access"},
            {"regex": r"<\s*iframe\b|srcdoc\s*=", "confidence": 0.72, "indicator": "iframe/srcdoc injection"},
            {"regex": r"data\s*:\s*text/html", "confidence": 0.78, "indicator": "HTML data URI"},
            {"regex": r"&lt;\s*script|%3c\s*script", "confidence": 0.86, "indicator": "encoded script tag"},
        ],
    },
    "Path Traversal": {
        "score": 42,
        "base_confidence": 0.58,
        "patterns": [
            {"regex": r"(?:\.\.[\\/]){1,}", "confidence": 0.86, "indicator": "dot-dot path traversal"},
            {"regex": r"(?:%2e%2e|%252e%252e)(?:%2f|/|%5c|\\)", "confidence": 0.88, "indicator": "encoded traversal"},
            {"regex": r"\.\.(?:%2f|%5c|/|\\)", "confidence": 0.84, "indicator": "mixed encoded traversal"},
            {"regex": r"(?:/etc/passwd|/etc/shadow|/proc/self/environ|/proc/version)", "confidence": 0.92, "indicator": "Linux sensitive path"},
            {"regex": r"(?:c:\\windows\\win\.ini|boot\.ini|windows/system32|winnt/win\.ini)", "confidence": 0.88, "indicator": "Windows sensitive path"},
            {"regex": r"(?:file|path|page|include|template|download|doc)=.{0,30}(?:\.\.|%2e%2e)", "confidence": 0.84, "indicator": "path parameter traversal"},
            {"regex": r"%00|\\x00", "confidence": 0.70, "indicator": "null byte path suffix"},
        ],
    },
    "Command Injection": {
        "score": 50,
        "base_confidence": 0.62,
        "patterns": [
            {"regex": r"(?:[;&|`]|%3b|%26|%7c|\$\(|\${IFS})\s*(?:cat|id|whoami|uname|pwd|ls|wget|curl|bash|sh|nc|ncat|python|perl|php|ruby)\b", "confidence": 0.90, "indicator": "shell metacharacter followed by command"},
            {"regex": r"\b(?:cmd\.exe|powershell(?:\.exe)?|bash\s+-c|sh\s+-c|certutil|bitsadmin)\b", "confidence": 0.86, "indicator": "shell or living-off-the-land command"},
            {"regex": r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(", "confidence": 0.80, "indicator": "dangerous server-side execution call"},
            {"regex": r"\b(?:os\.system|os\.popen|subprocess\.(?:run|call|Popen)|child_process\.exec)\s*\(", "confidence": 0.80, "indicator": "dangerous code execution API"},
            {"regex": r"(?:/bin/sh|/bin/bash|/dev/tcp/|mkfifo|chmod\s+\+x)", "confidence": 0.88, "indicator": "post-exploitation shell primitive"},
            {"regex": r"\b(?:ping|nslookup|dig)\b.{0,80}(?:[;&|`]\s*\w+|\$\()", "confidence": 0.76, "indicator": "network utility command chaining"},
        ],
    },
    "Suspicious User-Agent": {
        "score": 28,
        "base_confidence": 0.50,
        "patterns": [
            {"regex": r"\b(?:sqlmap|nikto|nmap|masscan|zgrab|nuclei|nessus|openvas|acunetix|wpscan|whatweb|ffuf|dirbuster|gobuster|hydra|medusa|metasploit|havij|w3af)\b", "confidence": 0.88, "indicator": "known scanner user agent"},
            {"regex": r"\b(?:burpsuite|owasp\s+zap|zap|crawler|spider|scanner|vulnerability|exploit)\b", "confidence": 0.68, "indicator": "scanner keyword"},
            {"regex": r"\b(?:python-requests|libwww-perl|curl/[0-9]|wget/[0-9]|go-http-client|java/[0-9]|okhttp|aiohttp)\b", "confidence": 0.54, "indicator": "automation library user agent"},
            {"regex": r"^\s*(?:-|null|none|unknown)\s*$", "confidence": 0.42, "indicator": "empty or hidden user agent"},
        ],
    },
    "Exposed Config Files": {
        "score": 44,
        "base_confidence": 0.58,
        "patterns": [
            {"regex": r"(?:^|[/?&\s])(?:\.env|\.env\.\w+|\.env\.backup|\.env\.bak)(?:$|[?\s&/])", "confidence": 0.90, "indicator": "environment file request"},
            {"regex": r"(?:^|[/?&\s])(?:\.git/(?:config|head|index)|\.svn/entries|\.hg/store)(?:$|[?\s&/])", "confidence": 0.90, "indicator": "repository metadata exposure"},
            {"regex": r"(?:^|[/?&\s])(?:config|settings|secrets|credentials)\.(?:php|json|ya?ml|ini|bak|old|txt)(?:$|[?\s&/])", "confidence": 0.84, "indicator": "configuration file request"},
            {"regex": r"(?:web\.config|appsettings\.json|localsettings\.json|wp-config\.php|configuration\.php)", "confidence": 0.84, "indicator": "framework config file"},
            {"regex": r"(?:id_rsa|id_dsa|\.ssh/config|\.aws/credentials|service-account\.json)", "confidence": 0.92, "indicator": "credential file request"},
            {"regex": r"(?:docker-compose\.ya?ml|dockerfile|kubeconfig|\.kube/config|terraform\.tfstate)", "confidence": 0.78, "indicator": "deployment config request"},
        ],
    },
    "Sensitive File Access": {
        "score": 34,
        "base_confidence": 0.50,
        "patterns": [
            {"regex": r"(?:backup|dump|database|db|sql)\.(?:sql|bak|dump|zip|tar|gz|7z)(?:$|[?\s&])", "confidence": 0.82, "indicator": "database backup request"},
            {"regex": r"(?:phpmyadmin|adminer\.php|setup-config\.php|server-status|server-info)", "confidence": 0.70, "indicator": "admin or server info probe"},
            {"regex": r"(?:\.htpasswd|\.htaccess|crossdomain\.xml|sitemap\.xml|robots\.txt)", "confidence": 0.55, "indicator": "sensitive web metadata request"},
            {"regex": r"(?:/var/log/|/var/www/|/home/[^/\s]+/|/root/)", "confidence": 0.78, "indicator": "absolute local path request"},
        ],
    },
    "Hardcoded Credentials": {
        "score": 46,
        "base_confidence": 0.60,
        "patterns": [
            {"regex": r"\b(?:password|passwd|pwd|secret|api[_-]?key|token|access[_-]?key|private[_-]?key|client[_-]?secret|jwt[_-]?secret)\b\s*[:=]\s*['\"][^'\"\n]{8,}['\"]", "confidence": 0.88, "indicator": "secret assignment"},
            {"regex": r"\bAKIA[0-9A-Z]{16}\b", "confidence": 0.94, "indicator": "AWS access key"},
            {"regex": r"\bAIza[0-9A-Za-z_-]{30,}\b", "confidence": 0.90, "indicator": "Google API key"},
            {"regex": r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b", "confidence": 0.92, "indicator": "GitHub token"},
            {"regex": r"\b(?:xoxb|xoxp|xoxa)-[A-Za-z0-9-]{20,}\b", "confidence": 0.90, "indicator": "Slack token"},
            {"regex": r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----", "confidence": 0.96, "indicator": "private key block"},
            {"regex": r"(?:mysql|postgres(?:ql)?|mongodb|redis)://[^:\s]+:[^@\s]+@", "confidence": 0.88, "indicator": "credentialed connection string"},
        ],
    },
    "Weak Cryptography": {
        "score": 32,
        "base_confidence": 0.50,
        "patterns": [
            {"regex": r"\b(?:md5|sha1)\s*\(", "confidence": 0.72, "indicator": "weak hash function"},
            {"regex": r"\bhashlib\.(?:md5|sha1)\s*\(", "confidence": 0.78, "indicator": "weak Python hash"},
            {"regex": r"\b(?:DES|3DES|RC4|ARC4)\b|Crypto\.Cipher\.(?:DES|ARC4)", "confidence": 0.78, "indicator": "weak cipher"},
            {"regex": r"ssl\.(?:PROTOCOL_SSLv2|PROTOCOL_SSLv3|PROTOCOL_TLSv1(?:_1)?)", "confidence": 0.82, "indicator": "legacy TLS protocol"},
            {"regex": r"\bverify\s*=\s*False\b", "confidence": 0.70, "indicator": "TLS verification disabled"},
            {"regex": r"\b(?:ECB|MODE_ECB)\b", "confidence": 0.72, "indicator": "ECB block mode"},
        ],
    },
}

# Precompile regexes for optimal detection performance
for _cfg in PATTERNS.values():
    for _p in _cfg["patterns"]:
        _p["compiled"] = re.compile(_p["regex"], re.IGNORECASE)




BRUTE_FORCE_MIN_FAILS = 5
AUTH_PATH_HINTS = ("login", "signin", "auth", "account", "admin", "wp-login", "session")


def detect_brute_force(df: pd.DataFrame) -> list[dict[str, Any]]:
    """Detect repeated authentication failures by source IP and target path."""
    findings: list[dict[str, Any]] = []
    required = {"ip", "status", "path", "raw"}
    if df.empty or not required.issubset(df.columns):
        return findings

    fail_df = df[df["status"].isin([401, 403, 429])].copy()
    if fail_df.empty:
        return findings

    groups = fail_df.groupby(["ip", "path"]).size().reset_index(name="count")
    brute = groups[groups["count"] >= BRUTE_FORCE_MIN_FAILS]

    for _, row in brute.iterrows():
        path = str(row["path"])
        count = int(row["count"])
        matched = fail_df[
            (fail_df["ip"] == row["ip"]) & (fail_df["path"] == row["path"])
        ]["raw"].head(20).tolist()

        sensitive_path = any(hint in path.lower() for hint in AUTH_PATH_HINTS)
        confidence = min(0.98, 0.55 + min(count / 40, 0.25) + (0.12 if sensitive_path else 0))
        indicator = f"{count} failed responses from {row['ip']} to {path}"

        findings.append(_build_rule_finding(
            "Brute Force",
            matched_lines=[indicator],
            flagged_raw=matched,
            indicator_hits=[indicator],
            hit_confidences=[confidence],
            extra={
                "source_ip": row["ip"],
                "target_path": path,
                "failure_count": count,
            },
        ))

    return findings


def run_rule_detection(df: pd.DataFrame, raw_text: str = "") -> list[dict[str, Any]]:
    """
    Run all rule-based detectors on parsed logs or raw code.

    Returns findings with confidence, OWASP mapping, MITRE mapping, remediation,
    business impact, false-positive notes, and matched evidence.
    """
    if not df.empty and "raw" in df.columns:
        scan_lines = [str(line) for line in df["raw"].tolist()]
    else:
        scan_lines = [line for line in raw_text.splitlines() if line.strip()]

    threat_hits: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "matched_lines": [],
        "flagged_raw": [],
        "indicator_hits": [],
        "hit_confidences": [],
    })

    for original_line in scan_lines:
        variants = _line_variants(original_line)
        for threat_name, cfg in PATTERNS.items():
            for pattern in cfg["patterns"]:
                if any(pattern["compiled"].search(variant) for variant in variants):
                    hit = threat_hits[threat_name]
                    _append_unique(hit["matched_lines"], original_line)
                    _append_unique(hit["flagged_raw"], original_line)
                    _append_unique(hit["indicator_hits"], pattern["indicator"])
                    hit["hit_confidences"].append(pattern["confidence"])

    findings = [
        _build_rule_finding(
            threat_name,
            data["matched_lines"],
            data["flagged_raw"],
            data["indicator_hits"],
            data["hit_confidences"],
        )
        for threat_name, data in threat_hits.items()
        if data["matched_lines"]
    ]

    if not df.empty:
        findings.extend(detect_brute_force(df))

    return sorted(findings, key=lambda item: (item.get("pattern_score", 0), item.get("confidence", 0)), reverse=True)


def get_flagged_content_for_gemini(findings: list[dict[str, Any]], max_chars: int = 5000) -> str:
    """Bundle flagged lines into a compact string for Gemini prompt."""
    parts: list[str] = []
    total = 0
    for finding in findings:
        confidence_pct = int(float(finding.get("confidence", 0)) * 100)
        header = (
            f"[{finding['threat_type']} | rule confidence {confidence_pct}% | "
            f"{finding.get('owasp_category', 'N/A')} | MITRE: {finding.get('mitre_attack_summary', 'N/A')}]"
        )
        for line in finding.get("flagged_raw", []) or finding.get("matched_lines", []):
            entry = f"{header} {line}\n"
            if total + len(entry) > max_chars:
                return "".join(parts)
            parts.append(entry)
            total += len(entry)
    return "".join(parts)


def summarize_rule_findings(findings: list[dict[str, Any]]) -> str:
    """Human-readable rule-finding summary for Gemini context."""
    if not findings:
        return "No suspicious patterns detected by rule-based filter."

    lines = []
    for finding in findings:
        confidence_pct = int(float(finding.get("confidence", 0)) * 100)
        indicators = ", ".join(finding.get("indicator_hits", [])[:4])
        lines.append(
            f"- {finding['threat_type']}: {len(finding.get('matched_lines', []))} line(s), "
            f"rule confidence {confidence_pct}%, pattern score {finding.get('pattern_score', 0)}, "
            f"{finding.get('owasp_category', 'N/A')}, MITRE {finding.get('mitre_attack_summary', 'N/A')}. "
            f"Indicators: {indicators or 'N/A'}"
        )
    return "\n".join(lines)


def _build_rule_finding(
    threat_type: str,
    matched_lines: list[str],
    flagged_raw: list[str],
    indicator_hits: list[str],
    hit_confidences: list[float],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized = normalize_threat_type(threat_type)
    profile = get_threat_profile(normalized)
    cfg = PATTERNS.get(normalized, {"score": 30, "base_confidence": 0.5})
    confidence = _calculate_confidence(cfg, matched_lines, indicator_hits, hit_confidences)
    pattern_score = _calculate_pattern_score(cfg["score"], confidence, matched_lines, indicator_hits)
    evidence = "\n".join(matched_lines[:5])

    finding = {
        "threat_detected": True,
        "threat_type": normalized,
        "analysis_source": "Rule Engine",
        "severity": profile["default_severity"],
        "confidence": confidence,
        "rule_confidence": confidence,
        "pattern_score": pattern_score,
        "owasp_category": profile["owasp"],
        "mitre_attack": profile["mitre_attack"],
        "mitre_attack_summary": format_mitre_attack(profile["mitre_attack"]),
        "matched_lines": matched_lines[:20],
        "flagged_raw": flagged_raw[:20],
        "indicator_hits": indicator_hits[:10],
        "evidence": evidence,
        "explanation": (
            f"Rule engine matched {normalized} indicators: "
            f"{', '.join(indicator_hits[:5]) or 'suspicious pattern'}."
        ),
        "immediate_fix": profile["immediate_fix"],
        "long_term_fix": profile["long_term_fix"],
        "recommended_fix": (
            f"Immediate fix: {profile['immediate_fix']} "
            f"Long-term fix: {profile['long_term_fix']}"
        ),
        "business_impact": profile["business_impact"],
        "false_positive_note": profile["false_positive_note"],
    }
    if extra:
        finding.update(extra)
    return finding


def _line_variants(line: str) -> list[str]:
    variants = [line]
    decoded_once = unquote_plus(line)
    decoded_twice = unquote_plus(decoded_once)
    html_decoded = html.unescape(decoded_twice)
    for variant in (decoded_once, decoded_twice, html_decoded):
        _append_unique(variants, variant)
    return variants


def _calculate_confidence(
    cfg: dict[str, Any],
    matched_lines: list[str],
    indicator_hits: list[str],
    hit_confidences: list[float],
) -> float:
    base = float(cfg.get("base_confidence", 0.5))
    max_hit = max(hit_confidences) if hit_confidences else base
    line_bonus = min(len(matched_lines) * 0.025, 0.18)
    diversity_bonus = min(len(set(indicator_hits)) * 0.035, 0.18)
    confidence = max(base, max_hit) + line_bonus + diversity_bonus
    return round(min(confidence, 0.98), 2)


def _calculate_pattern_score(
    base_score: int,
    confidence: float,
    matched_lines: list[str],
    indicator_hits: list[str],
) -> int:
    volume_bonus = min(len(matched_lines) * 2, 16)
    diversity_bonus = min(len(set(indicator_hits)) * 3, 18)
    return int(min(100, base_score + volume_bonus + diversity_bonus + (confidence * 10)))


def _append_unique(items: list[Any], value: Any) -> None:
    if value not in items:
        items.append(value)
