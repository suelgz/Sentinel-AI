from __future__ import annotations

from typing import Any

def safe_float(value: Any, default: float = 0.0) -> float:
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value)
    val_str = str(value).strip().lower()
    if not val_str:
        return default
    if val_str.endswith("%"):
        try:
            return float(val_str[:-1].strip()) / 100.0
        except ValueError:
            pass
    if "high" in val_str:
        return 0.85
    if "medium" in val_str or "mod" in val_str:
        return 0.60
    if "low" in val_str:
        return 0.30
    try:
        return float(val_str)
    except ValueError:
        return default

def safe_int(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return int(value)
    val_str = str(value).strip().lower()
    if not val_str:
        return default
    if val_str in ("true", "yes", "1"):
        return 1
    if val_str in ("false", "no", "0"):
        return 0
    try:
        return int(float(val_str))
    except ValueError:
        return default

def safe_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    val_str = str(value).strip().lower()
    if val_str in ("true", "yes", "1"):
        return True
    if val_str in ("false", "no", "0"):
        return False
    return default
