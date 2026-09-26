"""
JSON reporter: serialize a full AnalysisResult to machine-readable JSON.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime
from pathlib import Path

from ..scoring.result import AnalysisResult


def _serializable(obj):
    """Recursively convert dataclasses and datetimes to JSON-safe types."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _serializable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, dict):
        return {k: _serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_serializable(i) for i in obj]
    return obj


def to_dict(result: AnalysisResult) -> dict:
    """Convert AnalysisResult to a plain dict, stripping the raw manifest (too verbose)."""
    d = _serializable(result)

    # Strip raw manifest dict from JSON output - it's huge and redundant
    if "manifest" in d and d["manifest"] and "raw" in d["manifest"]:
        del d["manifest"]["raw"]

    return d


def write(result: AnalysisResult, path: Path | None = None) -> str:
    """
    Serialize result to JSON string.
    If path is provided, write to file.
    Returns the JSON string.
    """
    d = to_dict(result)
    output = json.dumps(d, indent=2, ensure_ascii=False)

    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output, encoding="utf-8")

    return output


def write_bulk(results: list[AnalysisResult], path: Path) -> None:
    """Write a list of results as a JSON array to a file."""
    dicts = [to_dict(r) for r in results]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dicts, indent=2, ensure_ascii=False), encoding="utf-8")
