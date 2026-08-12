from __future__ import annotations

import importlib.metadata
import json
import os
import re
from typing import Any

from google import genai
from google.genai import errors
from google.genai import types

from threat_knowledge import enrich_finding


DEFAULT_MODEL_NAME = "gemini-3.5-flash"
DEFAULT_REQUEST_TIMEOUT_SECONDS = 45

LANGUAGE_NAMES = {
    "en": "English",
}


class GeminiAPIError(RuntimeError):
    """Raised when Gemini enrichment fails before producing validated output."""

    def __init__(
        self,
        message: str,
        *,
        error_type: str = "GEMINI_ERROR",
        status_code: int | None = None,
        stage: str = "analysis",
    ) -> None:
        sanitized_message = sanitize_error_message(message)
        self.error = {
            "type": error_type,
            "status_code": status_code,
            "message": sanitized_message,
            "stage": stage,
        }
        super().__init__(format_gemini_error(self.error))


def get_sdk_version() -> str:
    try:
        return importlib.metadata.version("google-genai")
    except importlib.metadata.PackageNotFoundError:
        return "not-installed"


def get_model_name() -> str:
    return (os.environ.get("GEMINI_MODEL") or DEFAULT_MODEL_NAME).strip() or DEFAULT_MODEL_NAME


def sanitize_error_message(message: Any) -> str:
    text = str(message or "").replace("\n", " ").strip()
    text = re.sub(r"AIza[0-9A-Za-z_\-]{20,}", "[REDACTED_API_KEY]", text)
    text = re.sub(r"(?i)(api[_-]?key['\"]?\s*[:=]\s*['\"]?)[^'\"\s,&}]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)(key=)[^&\s]+", r"\1[REDACTED]", text)
    return text[:700] if text else "No error message was returned."


def format_gemini_error(error: dict[str, Any] | str | None) -> str:
    if isinstance(error, str):
        return sanitize_error_message(error)
    if not isinstance(error, dict):
        return "Gemini request failed."

    stage = error.get("stage") or "gemini"
    error_type = error.get("type") or "GEMINI_ERROR"
    status_code = error.get("status_code")
    message = sanitize_error_message(error.get("message"))
    code_prefix = f"{status_code} " if status_code else ""
    return f"{stage}: {code_prefix}{error_type}: {message}"


def _get_client(api_key: str, timeout_seconds: int = DEFAULT_REQUEST_TIMEOUT_SECONDS):
    timeout_ms = max(1, int(timeout_seconds * 1000))
    return genai.Client(
        api_key=api_key,
        http_options=types.HttpOptions(timeout=timeout_ms),
    )


def _extract_json(text: str):
    """Extract JSON from Gemini output even when wrapped in markdown fences."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        for start_char, end_char in [("[", "]"), ("{", "}")]:
            start = text.find(start_char)
            end = text.rfind(end_char)
            if start != -1 and end != -1:
                try:
                    return json.loads(text[start:end + 1])
                except json.JSONDecodeError:
                    continue
    return None


LOG_ANALYSIS_PROMPT = """You are ThreatLens AI, a senior cybersecurity analyst embedded in a threat detection system.

Analyze the following security log entries pre-flagged as suspicious by an automated rule-based filter.

FLAGGED LOG ENTRIES:
{log_content}

PRE-DETECTION LABELS (from rule-based filter):
{pre_labels}

Perform deep analysis and return a structured JSON array. Each element is one threat finding.
Write all human-readable fields in {output_language}.

RULES:
- Respond ONLY with a valid JSON array. No markdown, no extra text.
- If no real threats exist, return: []
- Quote the exact suspicious log entry in evidence.
- Explanation must be understandable by a junior analyst.
- Include OWASP Top 10 and MITRE ATT&CK mapping.
- Split remediation into immediate_fix and long_term_fix.
- recommended_fix may summarize both fixes, but do not omit the split fields.

Return exactly this structure:
[
  {{
    "threat_detected": true,
    "threat_type": "SQL Injection | XSS | Brute Force | Path Traversal | Command Injection | Suspicious User-Agent | Exposed Config Files | Sensitive File Access | Other",
    "severity": "Critical | High | Medium | Low | Informational",
    "confidence": 0.0,
    "evidence": "exact log line that triggered this",
    "explanation": "clear explanation of what this attack is and why it is dangerous",
    "owasp_category": "A03:2021 - Injection",
    "mitre_attack": [
      {{"technique_id": "T1190", "technique": "Exploit Public-Facing Application", "tactic": "Initial Access"}}
    ],
    "immediate_fix": "urgent containment or code/config fix to apply now",
    "long_term_fix": "durable engineering or process improvement",
    "recommended_fix": "short combined remediation summary",
    "business_impact": "what damage could occur if this attack succeeds",
    "false_positive_note": "when this might be a false positive"
  }}
]"""


CODE_ANALYSIS_PROMPT = """You are ThreatLens AI, a senior application security engineer specializing in OWASP vulnerabilities.

Analyze the following code snippet for security vulnerabilities.
Write all human-readable fields in {output_language}.

LANGUAGE: {language}

CODE:
{code_snippet}

PRE-DETECTED PATTERNS (from static analysis):
{pre_labels}

RULES:
- Respond ONLY with a valid JSON array. No markdown, no extra text outside JSON.
- Each vulnerability is a separate object in the array.
- Include exact vulnerable line(s) in evidence.
- Include OWASP Top 10 and MITRE ATT&CK mapping.
- Split remediation into immediate_fix and long_term_fix.
- recommended_fix must include corrected code or specific fix instructions where possible.
- If code is secure, return: []

Return exactly this structure:
[
  {{
    "threat_detected": true,
    "threat_type": "SQL Injection | XSS | CSRF | Command Injection | Path Traversal | Hardcoded Credentials | Weak Cryptography | Broken Auth | Other",
    "severity": "Critical | High | Medium | Low | Informational",
    "confidence": 0.0,
    "evidence": "exact vulnerable line(s) from the code",
    "explanation": "why this code is vulnerable and how an attacker could exploit it",
    "owasp_category": "A03:2021 - Injection",
    "mitre_attack": [
      {{"technique_id": "T1059", "technique": "Command and Scripting Interpreter", "tactic": "Execution"}}
    ],
    "immediate_fix": "specific safe code or configuration change to make now",
    "long_term_fix": "durable secure coding or architecture improvement",
    "recommended_fix": "corrected code or specific fix instructions",
    "business_impact": "real-world consequence if this vulnerability is exploited",
    "false_positive_note": "conditions under which this would actually be safe"
  }}
]"""


EXECUTIVE_SUMMARY_PROMPT = """You are ThreatLens AI generating an executive security report for a non-technical business audience.

ANALYSIS FINDINGS:
{findings_json}

OVERALL RISK SCORE: {risk_score}/100
SEVERITY LABEL: {severity_label}

Write a clear executive summary that a CEO or business manager can act on.
Write all human-readable fields in {output_language}.

RULES:
- Respond ONLY with a valid JSON object. No markdown, no text outside JSON.
- Use plain language. Avoid jargon.
- Be honest about risk level.
- Recommended next steps must be prioritized by business risk.

Return exactly this structure:
{{
  "overall_status": "Critical | High Risk | Medium Risk | Low Risk | Clean",
  "summary_paragraph": "2-3 sentence plain-English summary of the security situation",
  "top_priority_action": "the single most important thing to do right now",
  "estimated_business_risk": "description of potential damage if issues are not addressed within 48 hours",
  "positive_notes": "any strengths or reassuring context",
  "recommended_next_steps": ["step 1", "step 2", "step 3"]
}}"""


TURKISH_EXPLANATION_PROMPT = """Sen ThreatLens AI'sin. Teknik bilgisi olmayan kullanicilara sade Turkce ile siber guvenlik analizi yapan bir asistansin.

Asagidaki teknik guvenlik bulgusunu Turkce olarak acikla. Hedef kitle: kucuk isletme sahibi veya teknik olmayan yonetici.

TEKNIK BULGU:
{technical_finding}

KURAL:
- Sadece gecerli JSON dondur. JSON disinda hicbir metin olmasin.

Bu yapiyi dondur:
{{
  "basit_aciklama": "Teknik olmayan birinin anlayacagi sade Turkce aciklama",
  "tehlike_seviyesi": "Kritik | Yuksek | Orta | Dusuk",
  "ne_olabilir": "Bu acik kotuye kullanilirsa ne olur",
  "hemen_yapilacaklar": ["adim 1", "adim 2", "adim 3"],
  "uzun_vadeli_cozum": ["adim 1", "adim 2"],
  "is_etkisi": "Bu guvenlik acigi isletmenize nasil zarar verebilir"
}}"""


def _classify_api_error(exc: Exception, stage: str) -> GeminiAPIError:
    if isinstance(exc, GeminiAPIError):
        return exc

    if isinstance(exc, errors.APIError):
        status_code = getattr(exc, "code", None)
        status = getattr(exc, "status", None) or "API_ERROR"
        message = getattr(exc, "message", None) or str(exc)
        error_type = str(status)
        if status_code == 404 and re.search(r"model|not found", str(message), re.IGNORECASE):
            error_type = "MODEL_NOT_FOUND"
        return GeminiAPIError(message, error_type=error_type, status_code=status_code, stage=stage)

    class_name = type(exc).__name__
    message = str(exc)
    lowered = message.lower()
    if "timed out" in lowered or "timeout" in lowered or class_name.lower().endswith("timeout"):
        return GeminiAPIError(message, error_type="REQUEST_TIMEOUT", stage=stage)
    if "name resolution" in lowered or "dns" in lowered:
        return GeminiAPIError(message, error_type="DNS_NETWORK_ERROR", stage=stage)
    if "connect" in lowered or "network" in lowered or "connection" in lowered:
        return GeminiAPIError(message, error_type="NETWORK_ERROR", stage=stage)
    if isinstance(exc, json.JSONDecodeError):
        return GeminiAPIError(message, error_type="INVALID_JSON_RESPONSE", stage=stage)
    return GeminiAPIError(message or class_name, error_type=class_name, stage=stage)


def _json_config(max_output_tokens: int) -> types.GenerateContentConfig:
    return types.GenerateContentConfig(
        max_output_tokens=max_output_tokens,
        response_mime_type="application/json",
        thinking_config=types.ThinkingConfig(thinking_level="low"),
    )


def _call_gemini(
    api_key: str,
    prompt: str,
    *,
    stage: str,
    max_output_tokens: int = 4096,
    timeout_seconds: int = DEFAULT_REQUEST_TIMEOUT_SECONDS,
) -> str:
    api_key = (api_key or "").strip()
    if not api_key:
        raise GeminiAPIError("Gemini API key is missing.", error_type="KEY_MISSING", stage=stage)

    try:
        client = _get_client(api_key, timeout_seconds=timeout_seconds)
        response = client.models.generate_content(
            model=get_model_name(),
            contents=prompt,
            config=_json_config(max_output_tokens),
        )
        text = (response.text or "").strip()
        if not text:
            raise GeminiAPIError("Gemini returned an empty response.", error_type="EMPTY_RESPONSE", stage=stage)
        return text
    except Exception as exc:
        raise _classify_api_error(exc, stage) from exc


def analyze_logs(
    log_content: str,
    pre_labels: str,
    api_key: str,
    language: str = "en",
    timeout_seconds: int = DEFAULT_REQUEST_TIMEOUT_SECONDS,
) -> list:
    prompt = LOG_ANALYSIS_PROMPT.format(
        log_content=log_content[:5000],
        pre_labels=pre_labels,
        output_language=LANGUAGE_NAMES.get(language, "English"),
    )
    text = _call_gemini(api_key, prompt, stage="analysis", timeout_seconds=timeout_seconds)
    result = _extract_json(text)
    if not isinstance(result, list):
        raise GeminiAPIError(
            "Gemini response was not valid JSON in the expected findings-array format.",
            error_type="INVALID_JSON_RESPONSE",
            stage="analysis",
        )
    return _enrich_result(result)


def analyze_code(
    code_snippet: str,
    code_language: str,
    pre_labels: str,
    api_key: str,
    language: str = "en",
    timeout_seconds: int = DEFAULT_REQUEST_TIMEOUT_SECONDS,
) -> list:
    prompt = CODE_ANALYSIS_PROMPT.format(
        language=code_language,
        code_snippet=code_snippet[:5000],
        pre_labels=pre_labels,
        output_language=LANGUAGE_NAMES.get(language, "English"),
    )
    text = _call_gemini(api_key, prompt, stage="analysis", timeout_seconds=timeout_seconds)
    result = _extract_json(text)
    if not isinstance(result, list):
        raise GeminiAPIError(
            "Gemini response was not valid JSON in the expected findings-array format.",
            error_type="INVALID_JSON_RESPONSE",
            stage="analysis",
        )
    return _enrich_result(result)


def generate_executive_summary(
    findings: list,
    risk_score: int,
    severity_label: str,
    api_key: str,
    language: str = "en",
    timeout_seconds: int = DEFAULT_REQUEST_TIMEOUT_SECONDS,
) -> dict:
    prompt = EXECUTIVE_SUMMARY_PROMPT.format(
        findings_json=json.dumps(findings, indent=2)[:3500],
        risk_score=risk_score,
        severity_label=severity_label,
        output_language=LANGUAGE_NAMES.get(language, "English"),
    )
    text = _call_gemini(
        api_key,
        prompt,
        stage="summary",
        max_output_tokens=2048,
        timeout_seconds=timeout_seconds,
    )
    result = _extract_json(text)
    if not isinstance(result, dict):
        raise GeminiAPIError(
            "Gemini response was not valid JSON in the expected summary-object format.",
            error_type="INVALID_JSON_RESPONSE",
            stage="summary",
        )
    return result


def translate_to_turkish(finding: dict, api_key: str) -> dict:
    prompt = TURKISH_EXPLANATION_PROMPT.format(
        technical_finding=json.dumps(finding, indent=2, ensure_ascii=False)[:2500]
    )
    try:
        text = _call_gemini(api_key, prompt, stage="translation", max_output_tokens=2048)
        result = _extract_json(text)
        return result if isinstance(result, dict) else {}
    except Exception as exc:
        error = exc.error if isinstance(exc, GeminiAPIError) else _classify_api_error(exc, "translation").error
        return {"error": format_gemini_error(error)}


def test_api_key(
    api_key: str,
    model_name: str | None = None,
    timeout_seconds: int = 15,
) -> tuple[bool, str]:
    try:
        client = _get_client((api_key or "").strip(), timeout_seconds=timeout_seconds)
        response = client.models.generate_content(
            model=(model_name or get_model_name()).strip(),
            contents='Return exactly this JSON: {"status":"ok"}',
            config=types.GenerateContentConfig(
                max_output_tokens=16,
                response_mime_type="application/json",
            ),
        )
        text = (response.text or "").strip()
        result = _extract_json(text)
        if not isinstance(result, dict) or result.get("status") != "ok":
            raise GeminiAPIError(
                "Gemini test returned an invalid JSON response.",
                error_type="INVALID_JSON_RESPONSE",
                stage="connection_test",
            )
        return True, "Gemini connected and returned valid JSON."
    except Exception as exc:
        error = exc.error if isinstance(exc, GeminiAPIError) else _classify_api_error(exc, "connection_test").error
        return False, format_gemini_error(error)


def inspect_model(api_key: str, model_name: str | None = None, timeout_seconds: int = 15) -> dict[str, Any]:
    model_id = (model_name or get_model_name()).strip()
    try:
        client = _get_client((api_key or "").strip(), timeout_seconds=timeout_seconds)
        model = client.models.get(model=model_id)
        actions = [str(action) for action in (getattr(model, "supported_actions", None) or [])]
        return {
            "ok": any("generateContent" in action or "generate_content" in action for action in actions),
            "model": model_id,
            "display_name": getattr(model, "display_name", ""),
            "supported_actions": actions,
            "error": None,
        }
    except Exception as exc:
        error = exc.error if isinstance(exc, GeminiAPIError) else _classify_api_error(exc, "model_inspection").error
        return {
            "ok": False,
            "model": model_id,
            "display_name": "",
            "supported_actions": [],
            "error": error,
        }


def _enrich_result(result: list) -> list:
    return [
        enrich_finding(item)
        for item in result
        if isinstance(item, dict)
    ]


def _default_summary(severity_label: str, error: str = "") -> dict:
    suffix = f" {error}" if error else ""
    return {
        "overall_status": severity_label,
        "summary_paragraph": f"Analysis completed with severity: {severity_label}.{suffix}",
        "top_priority_action": "Review the highest-risk findings and apply the immediate fixes first.",
        "estimated_business_risk": "Business risk depends on whether the suspicious activity reached sensitive systems.",
        "positive_notes": "Rule-based detection and structured reporting completed successfully.",
        "recommended_next_steps": [
            "Validate the top findings",
            "Apply immediate containment fixes",
            "Plan the long-term remediation work",
        ],
    }
