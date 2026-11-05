"""Reproducible baseline/Top-k evaluation on declared synthetic scenarios.

Selection ties are resolved by ID for experiment reproducibility only. Report
expert assessment as not conducted; these experiments are not external validation.
"""

from __future__ import annotations

import argparse
import csv
import json
import platform
import subprocess
from pathlib import Path
from time import perf_counter


def evaluate_scenario(scenario: Path):
    from common.schemas import DatasetSnapshot, GraphConfig, RiskConfig
    from sv2_attack_graph.service import build_graph

    from sv3_risk.research.engine import MODEL_VERSION, compute_state
    from sv3_risk.research.service import analyze_detailed

    dataset = DatasetSnapshot.model_validate_json(
        (scenario / "dataset.json").read_text(encoding="utf-8")
    )
    config = json.loads((scenario / "config.json").read_text(encoding="utf-8"))
    graph_config = GraphConfig.model_validate(config["graph_config"])
    risk_config = RiskConfig.model_validate(config["risk_config"])
    start = perf_counter()
    graph = build_graph(dataset, [], graph_config)
    graph_ms = (perf_counter() - start) * 1000
    start = perf_counter()
    initial = analyze_detailed(dataset, [], graph_config, risk_config)
    analysis_ms = (perf_counter() - start) * 1000
    initial_targets = {p.target_asset_id for p in graph.paths}
    high = {
        f.finding_id for f in dataset.findings if f.is_kev or f.epss_probability >= 0.5
    }
    fixed_orders = {
        method: [item["finding_id"] for item in rows]
        for method, rows in initial.detail["baselines"].items()
    }
    # Static proposed ranking is a useful dynamic-reranking ablation.
    fixed_orders["proposed_static"] = [
        item.finding_id for item in initial.analysis.results
    ]
    methods = [
        *fixed_orders,
        "proposed_dynamic",
        "ablation_no_propagation",
        "ablation_no_target_context",
    ]
    rows = []
    for method in methods:
        patched = []
        current = initial
        for k in range(len(dataset.findings) + 1):
            selected_graph = build_graph(dataset, patched, graph_config)
            if not selected_graph.search_complete:
                raise ValueError("Evaluation requires complete paths")
            current_targets = {p.target_asset_id for p in selected_graph.paths}
            before_risk = initial.analysis.risk_before
            reduction = before_risk - current.analysis.risk_before
            rows.append(
                {
                    "scenario": scenario.name,
                    "method": method,
                    "k": k,
                    "patched_finding_ids": ";".join(patched),
                    "risk_before": before_risk,
                    "risk_after": current.analysis.risk_before,
                    "risk_reduction": reduction,
                    "risk_reduction_at_k": reduction / before_risk
                    if before_risk
                    else None,
                    "paths_remaining": len(selected_graph.paths),
                    "paths_removed": len(graph.paths) - len(selected_graph.paths),
                    "critical_targets_no_longer_reachable": len(
                        initial_targets - current_targets
                    ),
                    "high_exploitability_precision_at_k": (
                        len(set(patched) & high) / k if k else None
                    ),
                    "high_exploitability_recall_at_k": (
                        len(set(patched) & high) / len(high) if high else None
                    ),
                    "graph_build_ms": graph_ms,
                    "initial_analysis_ms": analysis_ms,
                    "expert_assessment": "not_conducted",
                }
            )
            if k == len(dataset.findings):
                break
            if method == "proposed_dynamic":
                next_id = current.analysis.results[0].finding_id
            elif method.startswith("ablation_"):
                options = {
                    "path_aggregation": "max_local"
                    if method == "ablation_no_propagation"
                    else "product",
                    "ignore_target_context": method == "ablation_no_target_context",
                }
                cfg = current.detail["parameters"]
                ablated_before = compute_state(
                    dataset, selected_graph, cfg, **options
                ).system_risk
                choices = []
                for finding in dataset.findings:
                    if finding.finding_id in patched:
                        continue
                    trial = build_graph(
                        dataset, sorted([*patched, finding.finding_id]), graph_config
                    )
                    if not trial.search_complete:
                        raise ValueError("Incomplete ablation search")
                    impact = (
                        ablated_before
                        - compute_state(dataset, trial, cfg, **options).system_risk
                    )
                    choices.append((-round(impact, 9), finding.finding_id))
                next_id = min(choices)[1]
            else:
                next_id = fixed_orders[method][k]
            patched.append(next_id)
            current = analyze_detailed(dataset, patched, graph_config, risk_config)
    # Controlled weight sensitivity: same graph/data, only published parameters change.
    sensitivity = []
    variants = {
        "default": {},
        "severity_heavy": {
            "severity_weight": 0.65,
            "epss_weight": 0.15,
            "kev_weight": 0.10,
            "exposure_weight": 0.10,
        },
        "epss_heavy": {
            "severity_weight": 0.15,
            "epss_weight": 0.65,
            "kev_weight": 0.10,
            "exposure_weight": 0.10,
        },
    }
    for label, weights in variants.items():
        alternate = RiskConfig(
            model_version=MODEL_VERSION,
            ranking_metric="remediation_impact",
            parameters=weights,
        )
        result = analyze_detailed(dataset, [], graph_config, alternate)
        sensitivity.append(
            {
                "scenario": scenario.name,
                "variant": label,
                "model_version": MODEL_VERSION,
                "parameters": result.detail["parameters"],
                "risk": result.analysis.risk_before,
                "ranks": [
                    {
                        "finding_id": r.finding_id,
                        "rank": r.priority_rank,
                        "impact": r.remediation_impact,
                    }
                    for r in result.analysis.results
                ],
            }
        )
    return rows, sensitivity, initial


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/evaluation"))
    args = parser.parse_args()
    scenario_root = Path(__file__).resolve().parents[1] / "data" / "scenarios"
    all_rows, all_sensitivity, identities = [], [], []
    for scenario in sorted(scenario_root.iterdir()):
        rows, sensitivity, initial = evaluate_scenario(scenario)
        all_rows.extend(rows)
        all_sensitivity.extend(sensitivity)
        identities.append(
            {
                "scenario": scenario.name,
                "analysis_id": initial.analysis.analysis_id,
                "dataset_hash": initial.detail["dataset_hash"],
                "config_hash": initial.analysis.config_hash,
                "parameters": initial.detail["parameters"],
            }
        )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    with (args.output_dir / "baseline_comparison.csv").open(
        "w", encoding="utf-8", newline=""
    ) as f:
        writer = csv.DictWriter(f, fieldnames=list(all_rows[0]))
        writer.writeheader()
        writer.writerows(all_rows)
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        commit = "unavailable; use SOURCE_MANIFEST.json shipped with artifact"
    payload = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "base_commit": commit,
        "source_note": "working-tree source; use shipped source hashes for exact identity",
        "data_source": "synthetic only",
        "score_meaning": "relative heuristic, not probability",
        "timing_note": "single local measurements, not p95 performance claims",
        "experiments": identities,
        "weight_sensitivity": all_sensitivity,
        "ablation": "static reranking; max-local instead of product propagation; target loss set to 1. All policies evaluated against full model risk.",
        "expert_assessment": "not conducted",
        "tie_selection": "ID only to select reproducibly under equal ranks",
    }
    (args.output_dir / "experiment_manifest.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"Wrote {len(all_rows)} Top-k records across 3 synthetic scenarios and 8 policies."
    )


if __name__ == "__main__":
    main()
