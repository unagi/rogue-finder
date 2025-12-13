import pytest

from nmap_gui.eta import EstimatorConfig, ParallelJobTimeEstimator, TaskSpec, WorkBasedEstimator


def test_estimate_before_start_zero_tasks():
    estimator = ParallelJobTimeEstimator(parallelism=2, min_per_task=5.0, max_per_task=60.0)
    estimate = estimator.estimate_before_start(0)
    assert estimate.estimate_sec == 0
    assert estimate.lower_sec == 0
    assert estimate.upper_sec == 0


def test_estimate_before_start_returns_expected_range():
    estimator = ParallelJobTimeEstimator(parallelism=2, min_per_task=5.0, max_per_task=60.0)
    estimate = estimator.estimate_before_start(6)
    assert estimate.lower_sec == pytest.approx(15.0)
    assert estimate.upper_sec == pytest.approx(180.0)
    assert estimate.estimate_sec == pytest.approx(125.0)


def test_register_completion_adjusts_bounds():
    estimator = ParallelJobTimeEstimator(parallelism=2, min_per_task=5.0, max_per_task=60.0)
    estimator.register_completion(12.0)
    estimator.register_completion(8.0)
    estimate = estimator.estimate_before_start(4)
    assert estimate.lower_sec == pytest.approx(16.0)
    assert estimate.upper_sec == pytest.approx(24.0)


def test_update_progress_with_completions_uses_ewma():
    config = EstimatorConfig(window_sec=5.0, ewma_alpha=0.5)
    estimator = ParallelJobTimeEstimator(
        parallelism=2,
        min_per_task=5.0,
        max_per_task=60.0,
        config=config,
    )
    estimator.estimate_before_start(6)
    estimator.register_completion(10.0)
    estimator.register_completion(12.0)
    estimate = estimator.update_progress(remaining_tasks=4, window_sec=5.0)
    expected_lower = 20.0
    expected_upper = 24.0
    assert estimate.lower_sec == pytest.approx(expected_lower)
    assert estimate.upper_sec == pytest.approx(expected_upper)
    assert expected_lower <= estimate.estimate_sec <= expected_upper


def test_update_progress_without_completions_uses_upper():
    config = EstimatorConfig(window_sec=5.0, fallback_on_zero_done="use_upper")
    estimator = ParallelJobTimeEstimator(parallelism=2, min_per_task=5.0, max_per_task=60.0, config=config)
    estimator.estimate_before_start(2)
    estimate = estimator.update_progress(remaining_tasks=2, window_sec=5.0)
    assert estimate.estimate_sec == estimate.upper_sec


def test_reset_keeps_observed_history_by_default():
    estimator = ParallelJobTimeEstimator(parallelism=1, min_per_task=5.0, max_per_task=60.0)
    estimator.register_completion(6.0)
    estimator.register_completion(8.0)
    estimator.reset()
    estimate = estimator.estimate_before_start(2)
    assert estimate.lower_sec == pytest.approx(12.0)
    assert estimate.upper_sec == pytest.approx(16.0)


def test_reset_can_drop_history():
    estimator = ParallelJobTimeEstimator(parallelism=1, min_per_task=5.0, max_per_task=60.0)
    estimator.register_completion(6.0)
    estimator.reset(keep_history=False)
    estimate = estimator.estimate_before_start(2)
    assert estimate.lower_sec == pytest.approx(10.0)
    assert estimate.upper_sec == pytest.approx(120.0)


def test_work_based_estimate_before_start_uses_initial_rate():
    estimator = WorkBasedEstimator(worker_count=1, initial_rate=2.0)
    tasks = [TaskSpec(task_id="a", size=4.0)]
    estimate = estimator.estimate_before_start(tasks)
    assert estimate.estimate_sec == pytest.approx(2.0)
    assert estimate.upper_sec > estimate.estimate_sec


def test_work_based_update_refines_rate():
    estimator = WorkBasedEstimator(worker_count=1, initial_rate=1.0, alpha=0.5)
    tasks = [TaskSpec(task_id="a", size=2.0), TaskSpec(task_id="b", size=3.0)]
    estimator.estimate_before_start(tasks)
    estimator.update(now_ts=0.0, completed=[], remaining=tasks)
    estimate = estimator.update(
        now_ts=2.0,
        completed=[TaskSpec(task_id="a", size=2.0)],
        remaining=[TaskSpec(task_id="b", size=3.0)],
    )
    assert estimate.estimate_sec <= estimate.upper_sec
    assert estimate.lower_sec >= 0.0
