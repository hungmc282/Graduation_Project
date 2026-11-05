"""Local repeat benchmark; measured Python allocation peak is not process RSS."""

import argparse
import json
import platform
import statistics
import tracemalloc
from functools import partial
from pathlib import Path
from time import perf_counter


def percentile95(samples):
    ordered = sorted(samples)
    position = 0.95 * (len(ordered) - 1)
    lower = int(position)
    fraction = position - lower
    return (
        ordered[lower] * (1 - fraction)
        + ordered[min(lower + 1, len(ordered) - 1)] * fraction
    )


def main():
    from common.schemas import DatasetSnapshot, GraphConfig, RiskConfig
    from sv2_attack_graph.service import build_graph

    from sv3_risk.research.service import analyze_detailed

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument(
        "--output", type=Path, default=Path("outputs/evaluation/benchmark.json")
    )
    args = parser.parse_args()
    if args.runs < 2:
        parser.error("Use at least two measured runs")
    root = Path(__file__).resolve().parents[1] / "data" / "scenarios"
    rows = []
    for directory in sorted(root.iterdir()):
        dataset = DatasetSnapshot.model_validate_json(
            (directory / "dataset.json").read_text(encoding="utf-8")
        )
        cfg = json.loads((directory / "config.json").read_text())
        graph = GraphConfig.model_validate(cfg["graph_config"])
        risk = RiskConfig.model_validate(cfg["risk_config"])
        # One warm-up, then identical runs; post-patch recalculation measured separately.
        analyze_detailed(dataset, [], graph, risk)
        stages = {
            "graph_build": [],
            "initial_analysis": [],
            "reanalysis_after_patch": [],
        }
        for _ in range(args.runs):
            for name, func in (
                ("graph_build", partial(build_graph, dataset, [], graph)),
                (
                    "initial_analysis",
                    partial(analyze_detailed, dataset, [], graph, risk),
                ),
                (
                    "reanalysis_after_patch",
                    partial(
                        analyze_detailed,
                        dataset,
                        [dataset.findings[0].finding_id],
                        graph,
                        risk,
                    ),
                ),
            ):
                start = perf_counter()
                func()
                stages[name].append((perf_counter() - start) * 1000)
        tracemalloc.start()
        analyze_detailed(dataset, [], graph, risk)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        rows.append(
            {
                "scenario": directory.name,
                "assets": len(dataset.assets),
                "findings": len(dataset.findings),
                "python_allocation_peak_bytes": peak,
                "stages": {
                    name: {
                        "samples_ms": values,
                        "p50_ms": statistics.median(values),
                        "p95_ms": percentile95(values),
                    }
                    for name, values in stages.items()
                },
            }
        )
    payload = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "runs": args.runs,
        "cpu": platform.processor(),
        "note": "Tiny synthetic reference lab only; not enterprise scalability evidence. Memory is tracemalloc peak, not RSS.",
        "rows": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Saved benchmark: {args.output}")


if __name__ == "__main__":
    main()
