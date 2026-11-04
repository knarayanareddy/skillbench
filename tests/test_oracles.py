"""Independent Acceptance Tests against Reference Oracles for SkillBench (SKB)."""
import json
from pathlib import Path
import pytest
from reference.oracles import task_analysis

ROOT = Path(__file__).resolve().parents[1]


def test_statistics_known_effect_deterministic():
    fixture_path = ROOT / "fixtures/paired_trials.json"
    assert fixture_path.exists(), "Missing required fixture fixtures/paired_trials.json"
    data = json.loads(fixture_path.read_text())

    res_a = task_analysis(data['trials'], data['task_ids'], repetitions=3, seed=17)
    res_b = task_analysis(data['trials'], data['task_ids'], repetitions=3, seed=17)
    assert res_a == res_b
    assert res_a['delta'] == pytest.approx(0.5)
    assert res_a['missing_trials'] == 0
    assert res_a['ci_low'] <= 0.5 <= res_a['ci_high']
    assert res_a['bound_low'] == res_a['bound_high'] == pytest.approx(0.5)
    assert res_a['n_tasks'] == 12 and res_a['n_complete_tasks'] == 12


def test_statistics_missing_trial_handling():
    fixture_path = ROOT / "fixtures/paired_trials.json"
    data = json.loads(fixture_path.read_text())
    trials = list(data['trials'])
    trials[0] = dict(trials[0], outcome='infra_error')

    res = task_analysis(trials, data['task_ids'], repetitions=3, seed=17)
    assert res['status'] == 'partial'
    assert res['missing_trials'] == 1
    assert res['bound_low'] < res['bound_high']
    assert res['n_complete_tasks'] == 11


def test_statistics_insufficient_sample_size():
    res = task_analysis([], ['task-1'], repetitions=3)
    assert res['status'] == 'insufficient'
    assert res['delta'] is None
    assert res['ci_low'] is None
    assert res['bound_low'] == -1 and res['bound_high'] == 1
