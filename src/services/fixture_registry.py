"""Trusted, preinstalled synthetic fixture registry (no live engine, no models).

Only these scorer IDs and recorded trial outcomes can be referenced by a suite or
replayed by the fixture worker. Outcomes are synthetic recorded fixtures declared
in `fixtures/paired_trials.json`; they are NOT evidence that any skill works.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, Mapping, Optional, Tuple

from src.core.canonical import sha256_hex

FIXTURE_PATH = Path(__file__).resolve().parents[2] / "fixtures" / "paired_trials.json"

# Built-in scorer identifiers compiled into the trusted dispatcher.
FIXTURE_SCORER_IDS = frozenset({"exact_match", "json_equals", "regex_match", "numeric_tolerance"})

# Task IDs with a recorded synthetic trial outcome.
KNOWN_TASK_IDS = frozenset(f"task-{index:02d}" for index in range(12))

RIGHTS_DECLARATION = "Synthetic authored fixture; no personal or third-party data."
LABELS = ["synthetic_recorded_trials", "simulation_not_measured_skill_benefit"]


@dataclass(frozen=True)
class RecordedTrial:
    outcome: str
    cost: str


@lru_cache(maxsize=4)
def _load(path: str) -> Tuple[Dict[Tuple[str, int, str], RecordedTrial], int, str]:
    data = json.loads(Path(path).read_text())
    repetitions = int(data.get("repetitions", 0))
    trials: Dict[Tuple[str, int, str], RecordedTrial] = {}
    for row in data.get("trials", []):
        key = (str(row["task_id"]), int(row["repeat"]), str(row["arm"]))
        if key in trials:
            raise ValueError("duplicate_fixture_trial")
        trials[key] = RecordedTrial(outcome=str(row["outcome"]), cost=str(row.get("cost", "0")))
    return trials, repetitions, sha256_hex(data)


def registry() -> Tuple[Dict[Tuple[str, int, str], RecordedTrial], int, str]:
    return _load(str(FIXTURE_PATH))


def recorded_trial(task_id: str, repeat: int, arm: str) -> Optional[RecordedTrial]:
    trials, _repetitions, _digest = registry()
    return trials.get((task_id, int(repeat), arm))


def fixture_digest() -> str:
    return registry()[2]


def fixture_repetitions() -> int:
    return registry()[1]


def rights() -> Mapping[str, str]:
    return {"declaration": RIGHTS_DECLARATION, "fixture_sha256": fixture_digest()}
