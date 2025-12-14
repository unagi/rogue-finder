import pytest

from nmap_gui.eta import (
    EstimatorConfig,
    ParallelJobTimeEstimator,
    TaskSpec,
    WorkBasedEstimator,
    _ceil_div,
)


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


def test_update_progress_reuses_previous_throughput_when_window_idle():
    config = EstimatorConfig(window_sec=5.0, ewma_alpha=0.5)
    estimator = ParallelJobTimeEstimator(parallelism=1, min_per_task=5.0, max_per_task=10.0, config=config)
    estimator.estimate_before_start(3)
    estimator.register_completion(6.0)
    first = estimator.update_progress(remaining_tasks=2, window_sec=5.0)
    assert first.estimate_sec <= first.upper_sec
    second = estimator.update_progress(remaining_tasks=2, window_sec=5.0)
    assert second.meta["throughput_ewma"] == pytest.approx(first.meta["throughput_ewma"])
    assert second.meta["done_in_window"] == 0


def test_update_progress_returns_zero_when_remaining_tasks_done():
    estimator = ParallelJobTimeEstimator(parallelism=1, min_per_task=5.0, max_per_task=10.0)
    estimator.estimate_before_start(1)
    estimator.register_completion(5.0)
    estimate = estimator.update_progress(remaining_tasks=0)
    assert estimate.estimate_sec == 0.0
    assert estimate.meta["remaining_tasks"] == 0


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


def test_ceil_div_handles_non_positive_values():
    assert _ceil_div(-5, 3) == 0
    assert _ceil_div(10, 0) == 0


def test_parallel_estimator_respects_observed_bounds():
    estimator = ParallelJobTimeEstimator(
        parallelism=2,
        min_per_task=1.0,
        max_per_task=10.0,
        observed_bounds=(2.0, 4.0),
    )
    estimate = estimator.estimate_before_start(4)
    assert estimate.lower_sec == pytest.approx(4.0)
    assert estimate.upper_sec == pytest.approx(8.0)


def test_register_completion_ignores_non_positive_duration():
    estimator = ParallelJobTimeEstimator(parallelism=1, min_per_task=2.0, max_per_task=10.0)
    estimator.register_completion(-1.0)
    estimator.register_completion(0.0)
    estimator.register_completion(None)
    estimator.register_completion(5.0)
    estimate = estimator.estimate_before_start(2)
    assert estimate.lower_sec == pytest.approx(10.0)
    assert estimate.upper_sec == pytest.approx(10.0)


def test_update_progress_without_history_returns_upper_bound():
    estimator = ParallelJobTimeEstimator(parallelism=1, min_per_task=2.0, max_per_task=4.0)
    estimator.estimate_before_start(2)
    estimate = estimator.update_progress(remaining_tasks=2, window_sec=5.0)
    assert estimate.estimate_sec == estimate.upper_sec


def test_update_progress_updates_existing_ewma():
    estimator = ParallelJobTimeEstimator(
        parallelism=1,
        min_per_task=2.0,
        max_per_task=6.0,
        config=EstimatorConfig(window_sec=5.0, ewma_alpha=0.25),
    )
    estimator.estimate_before_start(3)
    estimator.register_completion(4.0)
    estimator.update_progress(remaining_tasks=2, window_sec=4.0)
    estimator.register_completion(4.0)
    estimate = estimator.update_progress(remaining_tasks=1, window_sec=4.0)
    assert estimate.meta["throughput_ewma"] is not None


def test_work_based_estimate_handles_zero_work():
    estimator = WorkBasedEstimator(worker_count=1)
    estimate = estimator.estimate_before_start([])
    assert estimate.estimate_sec == 0.0
    assert estimate.meta["total_work"] == 0.0


def test_work_based_update_returns_zero_when_done():
    estimator = WorkBasedEstimator(worker_count=1)
    estimator.estimate_before_start([TaskSpec(task_id="a", size=1.0)])
    estimate = estimator.update(
        now_ts=0.0,
        completed=[TaskSpec(task_id="a", size=1.0)],
        remaining=[],
    )
    assert estimate.estimate_sec == 0.0


def test_work_based_update_sets_inst_rate_and_ewma():
    estimator = WorkBasedEstimator(worker_count=1, alpha=0.5)
    tasks = [TaskSpec(task_id="a", size=2.0), TaskSpec(task_id="b", size=2.0)]
    estimator.estimate_before_start(tasks)
    estimator.update(now_ts=0.0, completed=[], remaining=tasks)
    estimate = estimator.update(
        now_ts=2.0,
        completed=[TaskSpec(task_id="a", size=2.0)],
        remaining=[TaskSpec(task_id="b", size=2.0)],
    )
    assert estimate.meta["inst_rate"] == pytest.approx(1.0)
    assert estimate.meta["rate_ewma"] == pytest.approx(1.0)


def test_work_based_reset_clears_state():
    estimator = WorkBasedEstimator(worker_count=1)
    tasks = [TaskSpec(task_id="a", size=1.0)]
    estimator.estimate_before_start(tasks)
    estimator.update(now_ts=1.0, completed=tasks, remaining=[])
    estimator.reset()
    estimator.estimate_before_start(tasks)
    estimate = estimator.update(now_ts=2.0, completed=[], remaining=tasks)
    assert estimate.meta["rate_ewma"] is None


def test_work_based_update_blends_existing_rate():
    estimator = WorkBasedEstimator(worker_count=1, alpha=0.5)
    tasks = [
        TaskSpec(task_id="a", size=2.0),
        TaskSpec(task_id="b", size=2.0),
    ]
    estimator.estimate_before_start(tasks)
    estimator.update(now_ts=0.0, completed=[], remaining=tasks)
    estimator.update(
        now_ts=2.0,
        completed=[TaskSpec(task_id="a", size=2.0)],
        remaining=[TaskSpec(task_id="b", size=2.0)],
    )
    estimate = estimator.update(
        now_ts=4.0,
        completed=[TaskSpec(task_id="b", size=2.0)],
        remaining=[],
    )
    assert estimate.meta["rate_ewma"] == pytest.approx(1.0)
