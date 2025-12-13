"""Helpers for estimating remaining wall-clock time for parallel jobs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Optional


def _ceil_div(value: int, divisor: int) -> int:
    if divisor <= 0:
        return 0
    if value <= 0:
        return 0
    return (value + divisor - 1) // divisor


def _clip(value: float, lower: float, upper: float) -> float:
    upper = max(upper, lower)
    return max(lower, min(value, upper))


@dataclass
class EstimateRange:
    """Represents a representative ETA and its optimistic/pessimistic bounds."""

    estimate_sec: float
    lower_sec: float
    upper_sec: float
    meta: Dict[str, float | int | None]


@dataclass
class EstimatorConfig:
    """Tunable coefficients for ETA smoothing."""

    beta: float = 0.5
    ewma_alpha: float = 0.3
    min_throughput: float = 1e-9
    fallback_on_zero_done: str = "keep_prev"  # or "use_upper"
    window_sec: float = 5.0


class ParallelJobTimeEstimator:
    """Predicts ETA for single-target jobs executed with bounded parallelism."""

    def __init__(
        self,
        *,
        parallelism: int,
        min_per_task: float,
        max_per_task: float,
        config: EstimatorConfig | None = None,
        observed_bounds: tuple[float | None, float | None] | None = None,
    ) -> None:
        self._parallelism = max(1, parallelism)
        self._min_per_task = max(0.0, min(min_per_task, max_per_task))
        self._max_per_task = max(self._min_per_task, max_per_task)
        self._config = config or EstimatorConfig()
        self._observed_min: float | None = None
        self._observed_max: float | None = None
        if observed_bounds:
            self._observed_min, self._observed_max = observed_bounds
        self._total_tasks = 0
        self._completed_total = 0
        self._window_completed = 0
        self._throughput_ewma: Optional[float] = None

    def estimate_before_start(self, total_tasks: int) -> EstimateRange:
        total = max(0, total_tasks)
        self._total_tasks = total
        if total <= 0:
            return EstimateRange(0.0, 0.0, 0.0, {"mode": "pre", "mu": 0.0, "beta": self._config.beta})
        min_eff, max_eff = self._effective_bounds()
        batches = _ceil_div(total, self._parallelism)
        lower = min_eff * batches
        upper = max_eff * batches
        mu = 0.5 * (min_eff + max_eff)
        estimate = (total * mu) / self._parallelism + self._config.beta * (max_eff - min_eff)
        estimate = _clip(estimate, lower, upper)
        return EstimateRange(
            estimate,
            lower,
            upper,
            {
                "mode": "pre",
                "mu": mu,
                "beta": self._config.beta,
                "min_eff": min_eff,
                "max_eff": max_eff,
                "parallelism": self._parallelism,
                "total_tasks": total,
            },
        )

    def register_completion(self, duration_seconds: float | None = None) -> None:
        self._completed_total += 1
        self._window_completed += 1
        if duration_seconds is None or duration_seconds <= 0:
            return
        if self._observed_min is None or duration_seconds < self._observed_min:
            self._observed_min = duration_seconds
        if self._observed_max is None or duration_seconds > self._observed_max:
            self._observed_max = duration_seconds

    def update_progress(self, remaining_tasks: int, window_sec: float | None = None) -> EstimateRange:
        remaining = max(0, remaining_tasks)
        if remaining <= 0:
            return EstimateRange(0.0, 0.0, 0.0, {"mode": "running", "remaining_tasks": 0})
        min_eff, max_eff = self._effective_bounds()
        batches = _ceil_div(remaining, self._parallelism)
        lower = min_eff * batches
        upper = max_eff * batches
        window = window_sec if window_sec and window_sec > 0 else self._config.window_sec
        done = self._window_completed
        self._window_completed = 0
        inst_throughput = done / window if window > 0 else 0.0
        meta: Dict[str, float | int | None] = {
            "mode": "running",
            "throughput_inst": inst_throughput,
            "throughput_ewma": self._throughput_ewma,
            "alpha": self._config.ewma_alpha,
            "window_sec": window,
            "done_in_window": done,
            "remaining_tasks": remaining,
        }
        if done > 0 and window > 0:
            if self._throughput_ewma is None:
                self._throughput_ewma = inst_throughput
            else:
                alpha = self._config.ewma_alpha
                self._throughput_ewma = alpha * inst_throughput + (1 - alpha) * self._throughput_ewma
            meta["throughput_ewma"] = self._throughput_ewma
        elif done == 0:
            if self._config.fallback_on_zero_done == "use_upper":
                return EstimateRange(upper, lower, upper, meta)
            if self._throughput_ewma is None:
                return EstimateRange(upper, lower, upper, meta)
        throughput = max(self._throughput_ewma or inst_throughput, self._config.min_throughput)
        raw_remaining = remaining / throughput if throughput > 0 else upper
        estimate = _clip(raw_remaining, lower, upper)
        return EstimateRange(estimate, lower, upper, meta)

    def reset(self, *, keep_history: bool = True) -> None:
        self._total_tasks = 0
        self._completed_total = 0
        self._window_completed = 0
        self._throughput_ewma = None
        if not keep_history:
            self._observed_min = None
            self._observed_max = None

    def _effective_bounds(self) -> tuple[float, float]:
        min_eff = self._min_per_task
        max_eff = self._max_per_task
        if self._observed_min is not None:
            min_eff = max(0.0, min(self._observed_min, max_eff))
        if self._observed_max is not None:
            max_eff = max(min_eff, min(self._observed_max, self._max_per_task))
        return min_eff, max_eff


@dataclass
class TaskSpec:
    """Represents a unit of work for the work-based ETA estimator."""

    task_id: str
    size: float


class WorkBasedEstimator:
    """ETA estimator for single-job scenarios where work cannot be parallelized."""

    def __init__(
        self,
        *,
        worker_count: int,
        alpha: float = 0.3,
        epsilon: float = 1e-9,
        initial_rate: float = 0.01,
    ) -> None:
        self._workers = max(1, worker_count)
        self._alpha = max(0.0, min(alpha, 1.0))
        self._epsilon = max(epsilon, 1e-12)
        self._initial_rate = max(initial_rate, self._epsilon)
        self._rate_ewma: Optional[float] = None
        self._last_ts: Optional[float] = None

    def estimate_before_start(self, tasks: Iterable[TaskSpec]) -> EstimateRange:
        task_list = list(tasks)
        total_work = sum(max(task.size, 0.0) for task in task_list)
        if total_work <= 0:
            return EstimateRange(0.0, 0.0, 0.0, {"mode": "pre", "total_work": 0.0})
        rate = self._rate_ewma or self._initial_rate
        estimate = total_work / rate
        max_work = max(task.size for task in task_list)
        upper = estimate + (max_work / rate)
        lower = 0.0
        return EstimateRange(
            estimate,
            lower,
            upper,
            {
                "mode": "pre",
                "rate_init": rate,
                "total_work": total_work,
                "max_work": max_work,
            },
        )

    def update(
        self,
        *,
        now_ts: float,
        completed: Iterable[TaskSpec],
        remaining: Iterable[TaskSpec],
    ) -> EstimateRange:
        remaining_list = list(remaining)
        remaining_work = sum(max(task.size, 0.0) for task in remaining_list)
        done_work = sum(max(task.size, 0.0) for task in completed)
        meta: Dict[str, float | int | None] = {
            "mode": "running",
            "done_work": done_work,
            "remaining_work": remaining_work,
        }
        inst_rate = None
        if self._last_ts is not None and now_ts > self._last_ts and done_work > 0:
            dt = now_ts - self._last_ts
            inst_rate = done_work / dt if dt > 0 else None
            if inst_rate is not None:
                if self._rate_ewma is None:
                    self._rate_ewma = inst_rate
                else:
                    self._rate_ewma = self._alpha * inst_rate + (1 - self._alpha) * self._rate_ewma
        elif self._last_ts is None:
            # First tick before completion data; avoid rate jumps
            self._last_ts = now_ts
        meta["inst_rate"] = inst_rate
        meta["rate_ewma"] = self._rate_ewma
        self._last_ts = now_ts
        if remaining_work <= 0:
            return EstimateRange(0.0, 0.0, 0.0, meta)
        rate = self._rate_ewma or inst_rate or self._initial_rate
        rate = max(rate, self._epsilon)
        raw_eta = remaining_work / rate
        max_remaining_work = max((task.size for task in remaining_list), default=0.0)
        lb = max_remaining_work / rate if max_remaining_work > 0 else 0.0
        ub = raw_eta + lb
        estimate = _clip(raw_eta, lb, ub)
        meta["remaining_lb"] = lb
        return EstimateRange(estimate, lb, ub, meta)

    def reset(self) -> None:
        self._rate_ewma = None
        self._last_ts = None
