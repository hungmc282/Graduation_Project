"""Run full SV3 on a snapshot; reference lab is selected only via PYTHONPATH."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main():
    from common.schemas import DatasetSnapshot, GraphConfig, RiskConfig

    from sv3_risk.research.service import analyze_detailed

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario", choices=["chain", "diamond", "multi-target"], default="diamond"
    )
    parser.add_argument("--dataset", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--patched", nargs="*", default=[])
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/sv3"))
    args = parser.parse_args()
    scenario = (
        Path(__file__).resolve().parents[1] / "data" / "scenarios" / args.scenario
    )
    dataset_path = args.dataset or scenario / "dataset.json"
    config_path = args.config or scenario / "config.json"
    dataset = DatasetSnapshot.model_validate_json(
        dataset_path.read_text(encoding="utf-8")
    )
    config = json.loads(config_path.read_text(encoding="utf-8"))
    report = analyze_detailed(
        dataset,
        args.patched,
        GraphConfig.model_validate(config["graph_config"]),
        RiskConfig.model_validate(config["risk_config"]),
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "analysis.json").write_text(
        report.analysis.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "details.json").write_text(
        json.dumps(report.detail, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    print(f"Dataset: {dataset.dataset_id}; model: {report.analysis.risk_model_version}")
    print(
        f"Heuristic system risk: {report.analysis.risk_before:.6f}/100 (not a probability)"
    )
    for row in report.analysis.results:
        print(
            f"{row.finding_id}: rank={row.priority_rank}, RI={row.remediation_impact:.6f}, paths blocked={row.paths_blocked}"
        )
    print("Warnings: " + "; ".join(report.analysis.warnings))
    print(f"Saved analysis.json and details.json in {args.output_dir}")


if __name__ == "__main__":
    main()
