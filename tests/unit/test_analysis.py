"""Descriptive paired analysis: effects, clustering, missing pairs, reproducibility."""
from __future__ import annotations

import pytest

from src.services.analysis import (
    ANALYSIS_VERSION,
    AnalysisError,
    analysis_input_digest,
    analyze,
    percentile,
    select_last_attempts,
)


def trials(pattern, *, repetitions: int = 3, task_count: int = 12, missing=(), attempts=None):
    """Build paired trials from a per-task delta pattern.

    ``pattern`` maps a task index to +1 (treatment better), 0 (equal) or -1.
    """
    rows = []
    for index in range(task_count):
        task_id = f"task-{index:02d}"
        direction = pattern[index % len(pattern)]
        baseline = "fail" if direction == 1 else "pass"
        treatment = "fail" if direction == -1 else "pass"
        for repeat in range(repetitions):
            if (task_id, repeat, "baseline") not in missing:
                rows.append(
                    {
                        "task_id": task_id,
                        "repeat": repeat,
                        "arm": "baseline",
                        "outcome": baseline,
                        "attempt": 1,
                    }
                )
            if (task_id, repeat, "treatment") not in missing:
                rows.append(
                    {
                        "task_id": task_id,
                        "repeat": repeat,
                        "arm": "treatment",
                        "outcome": treatment,
                        "attempt": 1,
                    }
                )
    return rows


def task_ids(task_count: int = 12):
    return [f"task-{index:02d}" for index in range(task_count)]


def test_positive_effect_is_reported_descriptively():
    body = analyze(trials([1]), task_ids(), 3)
    assert body["analysis_version"] == ANALYSIS_VERSION
    assert body["status"] == "valid"
    assert body["delta"] == pytest.approx(1.0)
    assert body["interpretation"] == "descriptive_no_certification"
    assert body["n_tasks"] == body["n_complete_tasks"] == 12
    assert body["missing_trials"] == 0


def test_zero_effect_has_zero_delta():
    body = analyze(trials([0]), task_ids(), 3)
    assert body["delta"] == pytest.approx(0.0)
    assert body["bound_low"] <= 0 <= body["bound_high"]
    assert body["status"] == "valid"


def test_negative_effect_is_signed():
    body = analyze(trials([-1]), task_ids(), 3)
    assert body["delta"] == pytest.approx(-1.0)
    assert body["ci_high"] <= 0


def test_analysis_is_clustered_by_task_not_by_trial():
    """A task with 3 repeats counts once; a single task cannot dominate the mean."""
    rows = []
    # Task 0 always passes under treatment; 11 tasks are unchanged, but only one
    # repeat each is measured to prove repetition does not weight the estimate.
    for repeat in range(3):
        rows.append({"task_id": "task-00", "repeat": repeat, "arm": "baseline", "outcome": "fail", "attempt": 1})
        rows.append({"task_id": "task-00", "repeat": repeat, "arm": "treatment", "outcome": "pass", "attempt": 1})
    for index in range(1, 12):
        for repeat in range(3):
            for arm in ("baseline", "treatment"):
                rows.append(
                    {
                        "task_id": f"task-{index:02d}",
                        "repeat": repeat,
                        "arm": arm,
                        "outcome": "pass",
                        "attempt": 1,
                    }
                )
    body = analyze(rows, task_ids(), 3)
    assert body["delta"] == pytest.approx(1 / 12)


def test_missing_pairs_are_bounded_not_silently_dropped():
    incomplete = {("task-00", 0, "treatment")}
    body = analyze(trials([1], missing=incomplete), task_ids(), 3)
    assert body["status"] == "partial"
    assert body["missing_trials"] == 1
    assert body["n_complete_tasks"] == 11
    assert body["bound_low"] is not None and body["bound_high"] is not None
    # Missing treatment outcomes can only widen the interval, never improve it.
    assert body["bound_low"] < 1.0 and body["bound_high"] <= 1.0


def test_bounds_are_widest_plausible_ranges_for_unknowns():
    incomplete = {("task-00", repeat, "treatment") for repeat in range(3)}
    body = analyze(trials([1], missing=incomplete), task_ids(), 3)
    # task-00's treatment outcome is unknown: its delta lies in [0, 1] while the
    # eleven complete tasks are exactly +1, so the bounds are 11/12 and 1.
    assert body["bound_low"] == pytest.approx(11 / 12)
    assert body["bound_high"] == pytest.approx(1.0)
    assert body["delta"] == pytest.approx(1.0)  # complete tasks only
    assert body["status"] == "partial"


def test_fewer_than_ten_tasks_is_insufficient():
    body = analyze(trials([1], task_count=9), task_ids(9), 3)
    assert body["status"] == "insufficient"
    assert body["ci_low"] is None and body["ci_high"] is None


def test_fixed_seed_is_reproducible_and_seed_changes_only_the_interval():
    rows = trials([1, 0, -1])
    first = analyze(rows, task_ids(), 3, seed=17)
    again = analyze(rows, task_ids(), 3, seed=17)
    other_seed = analyze(rows, task_ids(), 3, seed=18)
    assert first == again
    assert first["delta"] == other_seed["delta"]
    assert (first["ci_low"], first["ci_high"]) == (other_seed["ci_low"], other_seed["ci_high"])
    assert analysis_input_digest(rows) == analysis_input_digest(list(reversed(rows)))


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (lambda rows: rows + [dict(rows[0])], "duplicate_trial"),
        (lambda rows: [dict(rows[0], task_id="task-99")] + rows[1:], "unknown_trial_task"),
        (lambda rows: [dict(rows[0], repeat=5)] + rows[1:], "unknown_trial_repeat"),
        (lambda rows: [dict(rows[0], arm="sideways")] + rows[1:], "invalid_arm"),
        (lambda rows: [dict(rows[0], outcome="great")] + rows[1:], "unknown_outcome"),
    ],
)
def test_invalid_input_is_refused(mutation, code):
    with pytest.raises(AnalysisError) as error:
        analyze(mutation(trials([1])), task_ids(), 3)
    assert str(error.value) == code


def test_duplicate_task_ids_are_refused():
    with pytest.raises(AnalysisError):
        analyze(trials([1]), ["task-00"] * 12, 3)


def test_percentile_uses_type_seven_interpolation():
    values = [1.0, 2.0, 3.0, 4.0]
    assert percentile(values, 0.5) == pytest.approx(2.5)
    assert percentile(values, 0.0) == 1.0
    assert percentile(values, 1.0) == 4.0


def test_last_attempt_wins_never_the_best_attempt():
    rows = [
        {"task_id": "t", "repeat": 0, "arm": "baseline", "attempt": 1, "outcome": "pass"},
        {"task_id": "t", "repeat": 0, "arm": "baseline", "attempt": 2, "outcome": "fail"},
        {"task_id": "t", "repeat": 0, "arm": "treatment", "attempt": 1, "outcome": "fail"},
        {"task_id": "t", "repeat": 0, "arm": "treatment", "attempt": 3, "outcome": "pass"},
    ]
    selected = {(row["arm"]): row for row in select_last_attempts(rows)}
    assert selected["baseline"]["outcome"] == "fail"
    assert selected["treatment"]["outcome"] == "pass"
    assert selected["baseline"]["attempt"] == 2
