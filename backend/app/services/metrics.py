"""In-process Prometheus-style metrics for VibeCheck task execution.

No third-party Prometheus client is required: values are collected in
process memory and rendered on GET /metrics in text exposition format.

Label cardinality is intentionally low. FORBIDDEN labels:
repo_url, owner, repo_name, task_id, file paths, source code, API keys.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any

_LOCK = threading.Lock()

# Counters: name -> {label_key -> value} or plain float when unlabeled
_counters: dict[str, float] = defaultdict(float)
_labeled_counters: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))

# Gauges: name -> value
_gauges: dict[str, float] = {}

# Histograms: name -> list of observations + optional labels
_observations: dict[str, list[float]] = defaultdict(list)
_labeled_observations: dict[str, dict[str, list[float]]] = defaultdict(
    lambda: defaultdict(list)
)

# Start time for process uptime
_PROCESS_START = time.time()


def inc_counter(name: str, labels: dict[str, str] | None = None, value: float = 1.0) -> None:
    """Increment a counter metric."""
    with _LOCK:
        if labels:
            key = _format_label_key(labels)
            _labeled_counters[name][key] += value
        else:
            _counters[name] += value


def set_gauge(name: str, value: float) -> None:
    """Set a gauge metric value."""
    with _LOCK:
        _gauges[name] = float(value)


def observe(name: str, value: float, labels: dict[str, str] | None = None) -> None:
    """Record a duration observation (seconds)."""
    with _LOCK:
        if labels:
            key = _format_label_key(labels)
            _labeled_observations[name][key].append(float(value))
        else:
            _observations[name].append(float(value))
        # Cap memory: keep last 5000 samples per series.
        if labels:
            series = _labeled_observations[name][_format_label_key(labels)]
            if len(series) > 5000:
                del series[:-5000]
        elif len(_observations[name]) > 5000:
            del _observations[name][:-5000]


def _format_label_key(labels: dict[str, str]) -> str:
    """Stable label key: k=v sorted, values escaped for exposition."""
    parts = []
    for k in sorted(labels):
        v = str(labels[k]).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
        parts.append(f'{k}="{v}"')
    return ",".join(parts)


def _render_labels(label_key: str) -> str:
    return f"{{{label_key}}}" if label_key else ""


def _quantile(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    idx = q * (len(sorted_vals) - 1)
    low = int(idx)
    high = min(low + 1, len(sorted_vals) - 1)
    frac = idx - low
    return sorted_vals[low] * (1 - frac) + sorted_vals[high] * frac


def render_prometheus() -> str:
    """Render all metrics in Prometheus text exposition format."""
    with _LOCK:
        lines: list[str] = []
        lines.append("# HELP vibecheck_process_uptime_seconds Process uptime")
        lines.append("# TYPE vibecheck_process_uptime_seconds gauge")
        lines.append(
            f"vibecheck_process_uptime_seconds {time.time() - _PROCESS_START:.3f}"
        )

        known_gauges = {
            "vibecheck_queue_depth": "Pending tasks in SQLite queue",
            "vibecheck_active_tasks": "Tasks currently running",
            "vibecheck_temp_bytes": "Approximate bytes used under tmp_dir",
            "vibecheck_llm_keys_in_memory": "BYOK credentials currently in memory (count only)",
        }
        for name, help_text in known_gauges.items():
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {_gauges.get(name, 0.0)}")

        for name, value in sorted(_counters.items()):
            metric = name if name.startswith("vibecheck_") else f"vibecheck_{name}"
            lines.append(f"# TYPE {metric} counter")
            lines.append(f"{metric} {value}")

        for name, series in sorted(_labeled_counters.items()):
            metric = name if name.startswith("vibecheck_") else f"vibecheck_{name}"
            lines.append(f"# TYPE {metric} counter")
            if not series:
                lines.append(f"{metric} 0")
            for label_key, value in sorted(series.items()):
                lines.append(f"{metric}{_render_labels(label_key)} {value}")

        for name, vals in sorted(_observations.items()):
            metric = name if name.startswith("vibecheck_") else f"vibecheck_{name}"
            lines.append(f"# TYPE {metric} summary")
            sorted_vals = sorted(vals)
            lines.append(f"{metric}{{quantile=\"0.5\"}} {_quantile(sorted_vals, 0.5):.6f}")
            lines.append(f"{metric}{{quantile=\"0.95\"}} {_quantile(sorted_vals, 0.95):.6f}")
            lines.append(f"{metric}{{quantile=\"0.99\"}} {_quantile(sorted_vals, 0.99):.6f}")
            lines.append(f"{metric}_sum {sum(sorted_vals):.6f}")
            lines.append(f"{metric}_count {len(sorted_vals)}")

        for name, by_label in sorted(_labeled_observations.items()):
            metric = name if name.startswith("vibecheck_") else f"vibecheck_{name}"
            lines.append(f"# TYPE {metric} summary")
            for label_key, vals in sorted(by_label.items()):
                sorted_vals = sorted(vals)
                base = f"{metric}{_render_labels(label_key)}"
                # Summary quantiles need quantile label merged with existing.
                if label_key:
                    lines.append(
                        f'{metric}{{{label_key},quantile="0.5"}} '
                        f"{_quantile(sorted_vals, 0.5):.6f}"
                    )
                    lines.append(
                        f'{metric}{{{label_key},quantile="0.95"}} '
                        f"{_quantile(sorted_vals, 0.95):.6f}"
                    )
                    lines.append(
                        f'{metric}{{{label_key},quantile="0.99"}} '
                        f"{_quantile(sorted_vals, 0.99):.6f}"
                    )
                else:
                    lines.append(f'{metric}{{quantile="0.5"}} {_quantile(sorted_vals, 0.5):.6f}')
                    lines.append(f'{metric}{{quantile="0.95"}} {_quantile(sorted_vals, 0.95):.6f}')
                    lines.append(f'{metric}{{quantile="0.99"}} {_quantile(sorted_vals, 0.99):.6f}')
                sum_name = f"{metric}_sum" if not label_key else f"{metric}_sum{_render_labels(label_key)}"
                count_name = (
                    f"{metric}_count" if not label_key else f"{metric}_count{_render_labels(label_key)}"
                )
                # Avoid double braces when label_key already has braces form.
                if label_key:
                    lines.append(f"{metric}_sum{_render_labels(label_key)} {sum(sorted_vals):.6f}")
                    lines.append(f"{metric}_count{_render_labels(label_key)} {len(sorted_vals)}")
                else:
                    lines.append(f"{metric}_sum {sum(sorted_vals):.6f}")
                    lines.append(f"{metric}_count {len(sorted_vals)}")
                _ = (base, sum_name, count_name)

        # Known named metrics that may be zero
        zero_defaults = [
            ("vibecheck_retries_total", "counter"),
            ("vibecheck_recoveries_total", "counter"),
            ("vibecheck_lease_expirations_total", "counter"),
            ("vibecheck_deduplicated_tasks_total", "counter"),
            ("vibecheck_cancelled_tasks_total", "counter"),
            ("vibecheck_cleanup_failures_total", "counter"),
            ("vibecheck_tasks_total", "counter"),
        ]
        existing = set()
        for line in lines:
            if line.startswith("vibecheck_") and " " in line:
                existing.add(line.split(" ")[0].split("{")[0])
        for name, mtype in zero_defaults:
            if name not in existing and f"vibecheck_{name}" not in existing:
                metric = name if name.startswith("vibecheck_") else f"vibecheck_{name}"
                lines.append(f"# TYPE {metric} {mtype}")
                lines.append(f"{metric} 0")

        return "\n".join(lines) + "\n"


def reset_metrics() -> None:
    """Reset all metrics — for testing only."""
    global _counters, _labeled_counters, _gauges, _observations, _labeled_observations
    with _LOCK:
        _counters = defaultdict(float)
        _labeled_counters = defaultdict(lambda: defaultdict(float))
        _gauges = {}
        _observations = defaultdict(list)
        _labeled_observations = defaultdict(lambda: defaultdict(list))


def snapshot() -> dict[str, Any]:
    """Return a plain dict snapshot — for tests and load reports."""
    with _LOCK:
        return {
            "counters": dict(_counters),
            "labeled_counters": {
                k: dict(v) for k, v in _labeled_counters.items()
            },
            "gauges": dict(_gauges),
        }
