"""
Static categorizer: keyword-based extension category detection.
Input: name + description string.
Output: (category, confidence)
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_DATA_DIR = Path(__file__).parent.parent / "data"

with open(_DATA_DIR / "category_baselines.json", encoding="utf-8") as _f:
    _BASELINES: dict[str, dict] = json.load(_f)

# Build keyword -> category map from baselines
_KEYWORD_MAP: dict[str, str] = {}
for _cat, _data in _BASELINES.items():
    for _kw in _data.get("keywords", []):
        _KEYWORD_MAP[_kw.lower()] = _cat


def categorize(name: str, description: str) -> tuple[str, str]:
    """
    Returns (category, confidence) where confidence is HIGH / MEDIUM / LOW / UNKNOWN.

    Scoring: count keyword hits per category, return highest scorer.
    Ties: prefer categories with more specific keywords (less common ones).
    """
    if not name and not description:
        return "UNKNOWN", "UNKNOWN"

    text = (name + " " + description).lower()
    scores: dict[str, int] = {}

    for keyword, category in _KEYWORD_MAP.items():
        # Word-boundary match to avoid 'proxy' matching 'proxynator'
        if re.search(r"\b" + re.escape(keyword) + r"\b", text):
            scores[category] = scores.get(category, 0) + 1

    if not scores:
        return "UNKNOWN", "UNKNOWN"

    best_category = max(scores, key=lambda c: scores[c])
    best_score = scores[best_category]

    if best_score >= 3:
        confidence = "HIGH"
    elif best_score == 2:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return best_category, confidence
