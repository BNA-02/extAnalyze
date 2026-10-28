"""
Scoring configuration loaded from data/scoring.json.

All weights live in data so calibration results (see the crx-census project) land as a
reviewable data change. `rule_points` overrides the severity-based points of a single
code-review rule id (CR-*).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

_DATA = Path(__file__).resolve().parent.parent / "data" / "scoring.json"


@dataclass(frozen=True)
class ScoringConfig:
    combo_points: dict[str, int]
    perm_points: dict[str, int]
    code_points: dict[str, int]
    rule_points: dict[str, int]
    rt_points: dict[str, int]
    exfil_flow_points: int
    code_review_cap: int
    dynamic_cap: int
    all_urls_points: int
    unexpected_permission_points: int
    ti: dict
    thresholds: list[tuple[int, str]]
    version: int = 1
    raw: dict = field(default_factory=dict, compare=False, repr=False)

    def level_for(self, score: int) -> str:
        for threshold, level in self.thresholds:
            if score >= threshold:
                return level
        return "SAFE"


def from_dict(d: dict) -> ScoringConfig:
    thresholds = sorted(((int(t), str(lvl)) for t, lvl in d["thresholds"]), reverse=True)
    if not thresholds or thresholds[-1][0] != 0:
        raise ValueError("scoring thresholds must include a 0 entry")
    return ScoringConfig(
        combo_points=dict(d["combo_points"]),
        perm_points=dict(d["perm_points"]),
        code_points=dict(d["code_points"]),
        rule_points={str(k): int(v) for k, v in d.get("rule_points", {}).items()},
        rt_points=dict(d["rt_points"]),
        exfil_flow_points=int(d["exfil_flow_points"]),
        code_review_cap=int(d["code_review_cap"]),
        dynamic_cap=int(d["dynamic_cap"]),
        all_urls_points=int(d["all_urls_points"]),
        unexpected_permission_points=int(d["unexpected_permission_points"]),
        ti=dict(d["ti"]),
        thresholds=thresholds,
        version=int(d.get("version", 1)),
        raw=d,
    )


@lru_cache(maxsize=1)
def default_config() -> ScoringConfig:
    return from_dict(json.loads(_DATA.read_text(encoding="utf-8")))


def load(path: Path | None = None) -> ScoringConfig:
    """Load a specific file (for calibration experiments) or the packaged default."""
    if path is None:
        return default_config()
    return from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
