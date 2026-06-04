from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any


APP_DIR = Path(__file__).parent
PROJECT_DB_PATH = APP_DIR.parent / "threatlensai.db"
DEFAULT_STATE_DIR = Path(
    os.environ.get(
        "THREATLENSAI_STATE_DIR",
        os.environ.get(
            "SENTINELAI_STATE_DIR",
            Path(os.environ.get("LOCALAPPDATA", APP_DIR / "runtime_data")) / "ThreatLensAI",
        ),
    )
)
DB_PATH = Path(
    os.environ.get("THREATLENSAI_DB_PATH")
    or os.environ.get("SENTINELAI_DB_PATH")
    or (PROJECT_DB_PATH if PROJECT_DB_PATH.exists() else DEFAULT_STATE_DIR / "threatlensai.db")
)
DB_AVAILABLE = True
DB_ERROR = ""


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            analysis_type TEXT NOT NULL,
            input_filename TEXT,
            input_preview TEXT,
            overall_risk_score INTEGER,
            severity_label TEXT,
            total_findings INTEGER DEFAULT 0,
            executive_summary TEXT,
            language TEXT DEFAULT 'en',
            top_recommendations TEXT,
            attack_timeline TEXT
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            threat_detected INTEGER DEFAULT 1,
            threat_type TEXT,
            severity TEXT,
            confidence REAL,
            rule_confidence REAL DEFAULT 0,
            evidence TEXT,
            explanation TEXT,
            owasp_category TEXT,
            mitre_attack TEXT,
            mitre_attack_summary TEXT,
            immediate_fix TEXT,
            long_term_fix TEXT,
            recommended_fix TEXT,
            business_impact TEXT,
            false_positive_note TEXT,
            pattern_score INTEGER DEFAULT 0,
            analysis_source TEXT,
            FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS uploaded_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            filename TEXT,
            file_size INTEGER,
            file_type TEXT,
            uploaded_at TEXT,
            line_count INTEGER DEFAULT 0,
            flagged_line_count INTEGER DEFAULT 0,
            FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
        );
    """)

    _ensure_column(cursor, "analyses", "top_recommendations", "TEXT")
    _ensure_column(cursor, "analyses", "attack_timeline", "TEXT")
    _ensure_column(cursor, "findings", "rule_confidence", "REAL DEFAULT 0")
    _ensure_column(cursor, "findings", "mitre_attack", "TEXT")
    _ensure_column(cursor, "findings", "mitre_attack_summary", "TEXT")
    _ensure_column(cursor, "findings", "immediate_fix", "TEXT")
    _ensure_column(cursor, "findings", "long_term_fix", "TEXT")
    _ensure_column(cursor, "findings", "analysis_source", "TEXT")

    conn.commit()
    conn.close()


def save_analysis(
    analysis_type,
    input_filename,
    input_preview,
    risk_score,
    severity_label,
    findings: list,
    executive_summary="",
    language="en",
    top_recommendations: list[str] | None = None,
    attack_timeline: list[dict[str, Any]] | None = None,
):
    if not DB_AVAILABLE:
        return None
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()

    cursor.execute("""
        INSERT INTO analyses (
            created_at, analysis_type, input_filename, input_preview,
            overall_risk_score, severity_label, total_findings,
            executive_summary, language, top_recommendations, attack_timeline
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        now,
        analysis_type,
        input_filename,
        input_preview,
        risk_score,
        severity_label,
        len(findings),
        _json_or_text(executive_summary),
        language,
        json.dumps(top_recommendations or [], ensure_ascii=False),
        json.dumps(attack_timeline or [], ensure_ascii=False),
    ))

    analysis_id = cursor.lastrowid

    for finding in findings:
        cursor.execute("""
            INSERT INTO findings (
                analysis_id, threat_detected, threat_type, severity,
                confidence, rule_confidence, evidence, explanation,
                owasp_category, mitre_attack, mitre_attack_summary,
                immediate_fix, long_term_fix, recommended_fix,
                business_impact, false_positive_note, pattern_score,
                analysis_source
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            analysis_id,
            int(finding.get("threat_detected", True)),
            finding.get("threat_type", "Unknown"),
            finding.get("severity", "Unknown"),
            float(finding.get("confidence", 0.5) or 0.5),
            float(finding.get("rule_confidence", 0) or 0),
            finding.get("evidence", ""),
            finding.get("explanation", ""),
            finding.get("owasp_category", ""),
            json.dumps(finding.get("mitre_attack", []), ensure_ascii=False),
            finding.get("mitre_attack_summary", ""),
            finding.get("immediate_fix", ""),
            finding.get("long_term_fix", ""),
            finding.get("recommended_fix", ""),
            finding.get("business_impact", ""),
            finding.get("false_positive_note", ""),
            int(finding.get("pattern_score", 0) or 0),
            finding.get("analysis_source", ""),
        ))

    conn.commit()
    conn.close()
    return analysis_id


def save_uploaded_file(analysis_id, filename, file_size, file_type, line_count=0, flagged_count=0):
    if not DB_AVAILABLE or analysis_id is None:
        return
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO uploaded_files (
            analysis_id, filename, file_size, file_type,
            uploaded_at, line_count, flagged_line_count
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        analysis_id,
        filename,
        file_size,
        file_type,
        datetime.now().isoformat(),
        line_count,
        flagged_count,
    ))
    conn.commit()
    conn.close()


def get_all_analyses(limit=50):
    if not DB_AVAILABLE:
        return []
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM analyses ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_analysis_detail(analysis_id):
    if not DB_AVAILABLE:
        return {"analysis": {}, "findings": [], "files": []}
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,))
    analysis = dict(cursor.fetchone() or {})

    cursor.execute("SELECT * FROM findings WHERE analysis_id = ?", (analysis_id,))
    findings = [_decode_finding(dict(row)) for row in cursor.fetchall()]

    cursor.execute("SELECT * FROM uploaded_files WHERE analysis_id = ?", (analysis_id,))
    files = [dict(row) for row in cursor.fetchall()]

    if analysis:
        analysis["top_recommendations"] = _json_loads(analysis.get("top_recommendations"), [])
        analysis["attack_timeline"] = _json_loads(analysis.get("attack_timeline"), [])

    conn.close()
    return {"analysis": analysis, "findings": findings, "files": files}


def get_stats():
    if not DB_AVAILABLE:
        return {
            "total_analyses": 0,
            "by_severity": {},
            "top_threats": [],
            "avg_risk_score": 0,
        }
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM analyses")
    total = cursor.fetchone()["total"]

    cursor.execute("SELECT severity_label, COUNT(*) as cnt FROM analyses GROUP BY severity_label")
    by_severity = {row["severity_label"]: row["cnt"] for row in cursor.fetchall()}

    cursor.execute("""
        SELECT threat_type, COUNT(*) as cnt
        FROM findings
        GROUP BY threat_type
        ORDER BY cnt DESC
        LIMIT 5
    """)
    top_threats = [dict(row) for row in cursor.fetchall()]

    cursor.execute("SELECT AVG(overall_risk_score) as avg FROM analyses")
    avg_score = cursor.fetchone()["avg"] or 0

    conn.close()
    return {
        "total_analyses": total,
        "by_severity": by_severity,
        "top_threats": top_threats,
        "avg_risk_score": round(avg_score, 1),
    }


def delete_analysis(analysis_id):
    if not DB_AVAILABLE:
        return
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
    conn.commit()
    conn.close()


def _ensure_column(cursor, table: str, column: str, definition: str) -> None:
    cursor.execute(f"PRAGMA table_info({table})")
    existing = {row[1] for row in cursor.fetchall()}
    if column not in existing:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _decode_finding(finding: dict[str, Any]) -> dict[str, Any]:
    finding["mitre_attack"] = _json_loads(finding.get("mitre_attack"), [])
    return finding


def _json_loads(value: Any, default: Any) -> Any:
    if not value:
        return default
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def _json_or_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value or {}, ensure_ascii=False)


try:
    init_db()
except (PermissionError, sqlite3.Error) as exc:
    DB_AVAILABLE = False
    DB_ERROR = str(exc)
