"""
NetGuard IDS — Performance Benchmark Suite
===========================================

Measures throughput, latency, and memory usage for the core IDS pipeline.
Run standalone:

    python benchmarks/benchmark_suite.py

Or via pytest-benchmark:

    pip install pytest-benchmark
    pytest benchmarks/ -v

Outputs a JSON report to benchmarks/results/benchmark_<timestamp>.json
"""

from __future__ import annotations

import gc
import io
import json
import os
import sys
import time
import tracemalloc
from dataclasses import dataclass, field, asdict
from typing import Any

# Force UTF-8 output so emoji don't crash on Windows cp1252 consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class BenchmarkResult:
    name:           str
    iterations:     int
    total_time_s:   float
    mean_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    throughput_ops:  float        # ops per second
    peak_memory_mb:  float
    passed:          bool = True
    notes:           str  = ""


@dataclass
class BenchmarkReport:
    timestamp:   str
    python:      str
    platform:    str
    results:     list[BenchmarkResult] = field(default_factory=list)
    summary:     dict[str, Any]        = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

class BenchmarkHarness:
    """Run a callable *n* times, collecting per-iteration latencies."""

    def __init__(self, name: str, warmup: int = 10) -> None:
        self.name   = name
        self.warmup = warmup

    def run(
        self,
        fn: Any,
        args: tuple = (),
        kwargs: dict | None = None,
        iterations: int = 1000,
    ) -> BenchmarkResult:
        kwargs = kwargs or {}
        latencies: list[float] = []

        # Warm-up
        for _ in range(self.warmup):
            fn(*args, **kwargs)

        gc.disable()
        tracemalloc.start()

        for _ in range(iterations):
            t0 = time.perf_counter()
            fn(*args, **kwargs)
            latencies.append((time.perf_counter() - t0) * 1000)  # ms

        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        gc.enable()

        latencies.sort()
        n = len(latencies)
        total = sum(latencies)

        return BenchmarkResult(
            name=self.name,
            iterations=iterations,
            total_time_s=total / 1000,
            mean_latency_ms=total / n,
            p50_latency_ms=latencies[int(n * 0.50)],
            p95_latency_ms=latencies[int(n * 0.95)],
            p99_latency_ms=latencies[int(n * 0.99)],
            throughput_ops=n / (total / 1000),
            peak_memory_mb=peak / 1_048_576,
        )


# ---------------------------------------------------------------------------
# Benchmark definitions
# ---------------------------------------------------------------------------

def _make_events(n: int = 20) -> list[Any]:
    """Build a list of mock connection events."""
    from unittest.mock import MagicMock
    base = time.time()
    return [
        MagicMock(ip="10.0.0.1", port=80 + i, timestamp=base + i * 0.5)
        for i in range(n)
    ]


def bench_threshold_detector(harness: BenchmarkHarness) -> BenchmarkResult:
    from core.detector_registry import ThresholdDetector
    detector = ThresholdDetector(threshold=10, window_seconds=60)
    events   = _make_events(20)
    return harness.run(detector.analyze, args=("10.0.0.1", events), iterations=10_000)


def bench_rule_engine(harness: BenchmarkHarness) -> BenchmarkResult:
    from core.rule_engine import RuleEngine
    from unittest.mock import MagicMock
    engine = RuleEngine()
    events = _make_events(20)
    ip = "10.0.0.1"
    return harness.run(engine.match, args=(ip, events), iterations=5_000)


def bench_dpi_detector(harness: BenchmarkHarness) -> BenchmarkResult:
    from core.dpi_plugin import DPIDetector
    dpi = DPIDetector(config={})
    dpi.on_start()
    events = _make_events(5)
    dpi.feed_packet("5.5.5.5", b"GET /search?q=normal+query HTTP/1.1\r\nHost: example.com\r\n")
    return harness.run(dpi.analyze, args=("5.5.5.5", events), iterations=5_000)


def bench_event_bus(harness: BenchmarkHarness) -> BenchmarkResult:
    from core.event_bus import EventBus
    bus = EventBus()
    received = []
    bus.subscribe("connection", lambda e: received.append(e))

    class _Evt:
        type = "connection"
        data = {"ip": "1.2.3.4"}

    evt = _Evt()

    def publish():
        bus.publish(evt)

    return harness.run(publish, iterations=20_000)


def bench_config_loader(harness: BenchmarkHarness) -> BenchmarkResult:
    import tempfile, pathlib
    from utils.config_loader import load
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("ids:\n  alert_threshold: 10\nfirewall:\n  log_path: '/tmp/test.log'\n")
        path = f.name
    result = harness.run(load, args=(path,), iterations=2_000)
    os.unlink(path)
    return result


def bench_whitelist_lookup(harness: BenchmarkHarness) -> BenchmarkResult:
    import core.whitelist as wl
    # Pre-populate whitelist BEFORE timing starts
    for i in range(100):
        wl.add(f"192.168.1.{i}")
    # Build a fixed lookup set -- only lookups are benchmarked, not adds
    ips_to_check = ("10.0.0.1", "192.168.1.50", "8.8.8.8", "192.168.1.99")

    def check():
        for ip in ips_to_check:
            wl.is_whitelisted(ip)

    return harness.run(check, iterations=10_000)


def bench_ab_tester(harness: BenchmarkHarness) -> BenchmarkResult:
    from core.advanced_features import MLABTester
    from core.detector_registry import ThresholdDetector

    champion   = ThresholdDetector(threshold=5)
    challenger = ThresholdDetector(threshold=8)
    tester     = MLABTester(champion, challenger, min_samples=100)
    events     = _make_events(15)

    def run():
        tester.run("10.0.0.2", events)

    return harness.run(run, iterations=2_000)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

BENCHMARKS = [
    ("Threshold Detector",  bench_threshold_detector),
    ("Rule Engine",         bench_rule_engine),
    ("DPI Detector",        bench_dpi_detector),
    ("Event Bus Publish",   bench_event_bus),
    ("Config Loader",       bench_config_loader),
    ("Whitelist Lookup",    bench_whitelist_lookup),
    ("ML A/B Tester",       bench_ab_tester),
]

# Acceptance thresholds (fail the benchmark if exceeded)
THRESHOLDS_P99_MS = {
    "Threshold Detector": 1.0,
    "Rule Engine":        5.0,
    "DPI Detector":       3.0,
    "Event Bus Publish":  2.0,    # Windows timer resolution ~1ms
    "Config Loader":      50.0,
    "Whitelist Lookup":   10.0,   # Lookup-only (no disk write); 10ms headroom for Windows
    "ML A/B Tester":      10.0,
}


def main() -> None:
    import platform
    from datetime import datetime, timezone

    print("=" * 60)
    print("  NetGuard IDS — Performance Benchmark Suite")
    print("=" * 60)
    print(f"  Python  : {sys.version.split()[0]}")
    print(f"  Platform: {platform.system()} {platform.release()} {platform.machine()}")
    print()

    report = BenchmarkReport(
        timestamp=datetime.now(timezone.utc).isoformat(),
        python=sys.version,
        platform=f"{platform.system()} {platform.release()} {platform.machine()}",
    )

    all_passed = True
    for name, bench_fn in BENCHMARKS:
        harness = BenchmarkHarness(name, warmup=5)
        print(f"  Running: {name}...", end="", flush=True)
        try:
            result = bench_fn(harness)
            thresh = THRESHOLDS_P99_MS.get(name, 999)
            result.passed = result.p99_latency_ms <= thresh
            if not result.passed:
                result.notes = f"p99 {result.p99_latency_ms:.2f}ms > threshold {thresh}ms"
                all_passed = False
            report.results.append(result)
            icon = "[PASS]" if result.passed else "[FAIL]"
            print(
                "  {} {:<30} mean={:.3f}ms  p99={:.3f}ms  tput={:,.0f}/s  mem={:.2f}MB".format(
                    icon, name, result.mean_latency_ms,
                    result.p99_latency_ms, result.throughput_ops,
                    result.peak_memory_mb,
                )
            )
        except Exception as exc:
            print("  [WARN] {:<30} ERROR: {}".format(name, exc))
            report.results.append(
                BenchmarkResult(name=name, iterations=0, total_time_s=0,
                                mean_latency_ms=0, p50_latency_ms=0,
                                p95_latency_ms=0, p99_latency_ms=0,
                                throughput_ops=0, peak_memory_mb=0,
                                passed=False, notes=str(exc))
            )
            all_passed = False

    # Summary
    report.summary = {
        "total_benchmarks": len(report.results),
        "passed": sum(1 for r in report.results if r.passed),
        "failed": sum(1 for r in report.results if not r.passed),
        "all_passed": all_passed,
    }

    print()
    print(f"  Results: {report.summary['passed']}/{report.summary['total_benchmarks']} passed")

    # Save JSON report
    os.makedirs("benchmarks/results", exist_ok=True)
    ts = report.timestamp.replace(":", "-").replace(".", "-")[:19]
    out_path = f"benchmarks/results/benchmark_{ts}.json"
    with open(out_path, "w") as f:
        json.dump(asdict(report), f, indent=2)
    print(f"  Report : {out_path}")
    print()

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
