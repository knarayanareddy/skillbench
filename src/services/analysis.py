"""Task-level paired analysis for SkillBench (independent implementation).

Method (frozen before execution; docs/03 and docs/06):
  * scheduled universe = planned tasks x repeats x two arms;
  * pass = 1; fail/policy_block/activation_failed = 0 for the declared
    intention-to-evaluate estimand; infra_error/cancelled/absent = unknown;
  * each arm's per-task mean is computed over its planned repeats (complete
    tasks only, secondary when missingness exists);
  * complete-task delta = mean over complete tasks of (treatment mean - baseline
    mean); tasks are the resampling unit (repeats are correlated);
  * conservative population bounds average, over ALL planned tasks, the
    per-task lower/upper extremes (unknown treatment success treated as 0 / 1 and
    unknown baseline success as 1 / 0);
  * fewer than 10 complete distinct tasks: no interval, status insufficient;
  * bootstrap: Python ``random.Random(seed)``, ``iterations`` resamples with
    replacement of size n_complete, percentile rule type 7 (linear interpolation).
No efficacy, equivalence, winner or safety label is produced.

This module is application code. reference/oracles.py is NOT imported.
"""
from __future__ import annotations

import math
import random
from typing import Dict, Iterable, List, Mapping, Optional, Sequence

ANALYSIS_VERSION = "paired-task-bootstrap/1"
MIN_COMPLETE_TASKS = 10
PASS_OUTCOMES = {"pass"}
ZERO_OUTCOMES = {"fail", "policy_block", "activation_failed"}
UNKNOWN_OUTCOMES = {"infra_error", "cancelled"}
VALID_OUTCOMES = PASS_OUTCOMES | ZERO_OUTCOMES | UNKNOWN_OUTCOMES
ARMS = ("baseline", "treatment")


class AnalysisError(ValueError):
    """Invalid analysis input. Never silently repaired."""


def _mean(values: Sequence[float]) -> float:
    return sum(values) / len(values)


def _round(value: Optional[float]) -> Optional[float]:
    return None if value is None else round(float(value), 10)


def percentile(sorted_values: Sequence[float], p: float) -> float:
    """Linear interpolation between order statistics (type 7)."""
    if not sorted_values:
        raise AnalysisError("empty_sample")
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    position = (len(sorted_values) - 1) * p
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(sorted_values[lower])
    weight = position - lower
    return float(sorted_values[lower] + (sorted_values[upper] - sorted_values[lower]) * weight)


def select_last_attempts(trials: Iterable[Mapping]) -> List[Dict]:
    """Choose the last persisted attempt per (task, repeat, arm).

    Reconciliation is by attempt order, never by score: a later retry cannot
    erase an earlier failure, and an infrastructure failure is not promoted.
    """
    selected: Dict[tuple, Dict] = {}
    for trial in trials:
        key = (trial["task_id"], int(trial["repeat"]), trial["arm"])
        attempt = int(trial["attempt"])
        current = selected.get(key)
        if current is None or attempt > int(current["attempt"]):
            selected[key] = dict(trial)
    return [selected[key] for key in sorted(selected)]


def analyze(
    trials: Sequence[Mapping],
    task_ids: Sequence[str],
    repetitions: int,
    *,
    seed: int = 17,
    iterations: int = 2000,
    minimum_complete_tasks: int = MIN_COMPLETE_TASKS,
) -> Dict:
    """Return the contract-shaped descriptive analysis body."""
    if not task_ids:
        raise AnalysisError("no_tasks")
    if len(set(task_ids)) != len(task_ids):
        raise AnalysisError("duplicate_task")
    if repetitions < 1:
        raise AnalysisError("invalid_repetitions")
    if iterations < 100 or iterations > 10000:
        raise AnalysisError("invalid_iterations")
    if seed < 0:
        raise AnalysisError("invalid_seed")

    task_set = set(task_ids)
    index: Dict[tuple, Mapping] = {}
    for trial in trials:
        task_id = trial["task_id"]
        repeat = int(trial["repeat"])
        arm = trial["arm"]
        if task_id not in task_set:
            raise AnalysisError("unknown_trial_task")
        if not 0 <= repeat < repetitions:
            raise AnalysisError("unknown_trial_repeat")
        if arm not in ARMS:
            raise AnalysisError("invalid_arm")
        if trial["outcome"] not in VALID_OUTCOMES:
            raise AnalysisError("unknown_outcome")
        key = (task_id, repeat, arm)
        if key in index:
            raise AnalysisError("duplicate_trial")
        index[key] = trial

    missing = 0
    lower_bounds: List[float] = []
    upper_bounds: List[float] = []
    deltas: List[float] = []

    for task_id in sorted(task_ids):
        arm_values: Dict[str, List[Optional[int]]] = {arm: [] for arm in ARMS}
        for arm in ARMS:
            for repeat in range(repetitions):
                trial = index.get((task_id, repeat, arm))
                outcome = trial["outcome"] if trial else None
                if outcome in PASS_OUTCOMES:
                    value: Optional[int] = 1
                elif outcome in ZERO_OUTCOMES:
                    value = 0
                else:
                    value = None
                    missing += 1
                arm_values[arm].append(value)
        baseline = arm_values["baseline"]
        treatment = arm_values["treatment"]
        lower_bounds.append(_mean([v or 0 for v in treatment]) - _mean([1 if v is None else v for v in baseline]))
        upper_bounds.append(_mean([1 if v is None else v for v in treatment]) - _mean([v or 0 for v in baseline]))
        if None not in baseline and None not in treatment:
            deltas.append(_mean(treatment) - _mean(baseline))

    n_tasks = len(task_ids)
    n_complete = len(deltas)
    if n_complete == n_tasks and n_complete >= minimum_complete_tasks:
        status = "valid"
    elif n_complete >= minimum_complete_tasks:
        status = "partial"
    else:
        status = "insufficient"

    delta = _mean(deltas) if deltas else None
    ci_low: Optional[float] = None
    ci_high: Optional[float] = None
    if n_complete >= minimum_complete_tasks:
        rng = random.Random(seed)
        replicates = sorted(
            _mean([deltas[rng.randrange(n_complete)] for _ in range(n_complete)]) for _ in range(iterations)
        )
        ci_low = percentile(replicates, 0.025)
        ci_high = percentile(replicates, 0.975)

    return {
        "analysis_version": ANALYSIS_VERSION,
        "status": status,
        "n_tasks": n_tasks,
        "n_complete_tasks": n_complete,
        "delta": _round(delta),
        "ci_low": _round(ci_low),
        "ci_high": _round(ci_high),
        "bound_low": _round(_mean(lower_bounds)),
        "bound_high": _round(_mean(upper_bounds)),
        "interpretation": "descriptive_no_certification",
        "missing_trials": missing,
    }


def analysis_input_digest(rows: Sequence[Mapping]) -> str:
    """Digest the frozen analysis input (order-independent, attempts preserved)."""
    from src.core.canonical import sha256_hex

    canonical_rows = [
        {
            "task_id": row["task_id"],
            "repeat": int(row["repeat"]),
            "arm": row["arm"],
            "attempt": int(row["attempt"]),
            "outcome": row["outcome"],
            "cost": str(row["cost"]) if row.get("cost") is not None else None,
        }
        for row in sorted(
            rows, key=lambda r: (r["task_id"], int(r["repeat"]), r["arm"], int(r["attempt"]))
        )
    ]
    return sha256_hex({"analysis_version": ANALYSIS_VERSION, "trials": canonical_rows})
