from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

AnalysisKind = Literal["log", "code"]


@dataclass(frozen=True)
class InputProfile:
    key: str
    label: str
    icon: str
    analysis_kind: AnalysisKind
    source_type: str
    minimum_score: int
    strong_patterns: tuple[str, ...]
    weak_patterns: tuple[str, ...] = ()


@dataclass(frozen=True)
class DetectedInput:
    key: str
    label: str
    icon: str
    analysis_kind: AnalysisKind
    source_type: str
    confidence: float

    @property
    def display_name(self) -> str:
        return f"{self.icon} {self.label}"

    def as_dict(self) -> dict[str, str | float]:
        return {
            "key": self.key,
            "label": self.label,
            "icon": self.icon,
            "analysis_kind": self.analysis_kind,
            "source_type": self.source_type,
            "confidence": self.confidence,
            "display_name": self.display_name,
        }


GENERIC_INPUT = DetectedInput(
    key="generic_code",
    label="Generic Source Code",
    icon="\U0001f4c4",
    analysis_kind="code",
    source_type="generic source code",
    confidence=0.0,
)

INPUT_PROFILES: tuple[InputProfile, ...] = (
    InputProfile(
        key="apache_log",
        label="Apache Log",
        icon="\U0001f310",
        analysis_kind="log",
        source_type="apache/nginx access log",
        minimum_score=5,
        strong_patterns=(
            r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP/\d(?:\.\d)?\b",
            r"\b\d{3}\s+\d+\b.*\"[^\"]*(?:Mozilla|curl|sqlmap|python-requests|Chrome|Safari|Firefox)[^\"]*\"",
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b\s+-\s+-\s+\[[^\]]+\]",
        ),
        weak_patterns=(
            r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b",
            r"\b(?:200|201|204|301|302|400|401|403|404|500|502|503)\b",
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            r"\b(?:User-Agent|Mozilla|curl|sqlmap|python-requests|nginx|apache)\b",
        ),
    ),
    InputProfile(
        key="php_code",
        label="PHP Source Code",
        icon="\U0001f418",
        analysis_kind="code",
        source_type="php",
        minimum_score=4,
        strong_patterns=(
            r"<\?php",
            r"\$_(?:GET|POST|REQUEST|COOKIE|SESSION|SERVER)\b",
            r"\b(?:mysql_|mysqli_)\w+\s*\(",
        ),
        weak_patterns=(
            r"\becho\b",
            r"\b(?:include|require)(?:_once)?\b",
            r"\$[A-Za-z_]\w*\s*=",
            r"->\w+\s*\(",
        ),
    ),
    InputProfile(
        key="python_flask",
        label="Python / Flask",
        icon="\U0001f40d",
        analysis_kind="code",
        source_type="python/flask",
        minimum_score=4,
        strong_patterns=(
            r"\bfrom\s+flask\s+import\b",
            r"\bFlask\s*\(",
            r"@app\.route\s*\(",
        ),
        weak_patterns=(
            r"\brequest\.",
            r"\bos\.system\s*\(",
            r"\bsubprocess\.",
            r"\bhashlib\.",
            r"^\s*def\s+\w+\s*\(",
            r"^\s*import\s+\w+",
        ),
    ),
)


def detect_input(content: str) -> DetectedInput:
    text = (content or "").strip()
    if not text:
        return GENERIC_INPUT

    best_profile: InputProfile | None = None
    best_score = 0
    for profile in INPUT_PROFILES:
        score = _score_profile(text, profile)
        if score > best_score:
            best_profile = profile
            best_score = score

    if not best_profile or best_score < best_profile.minimum_score:
        return GENERIC_INPUT

    confidence = min(best_score / (best_profile.minimum_score + 4), 1.0)
    return DetectedInput(
        key=best_profile.key,
        label=best_profile.label,
        icon=best_profile.icon,
        analysis_kind=best_profile.analysis_kind,
        source_type=best_profile.source_type,
        confidence=round(confidence, 2),
    )


def _score_profile(text: str, profile: InputProfile) -> int:
    score = 0
    for pattern in profile.strong_patterns:
        if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
            score += 3
    for pattern in profile.weak_patterns:
        if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
            score += 1
    return score
