"""Run SV3 with real SV2 by default, or an explicit fixture replay mock."""

from __future__ import annotations

import argparse
import json
import sys
import types
from pathlib import Path
from unittest.mock import patch


def main() -> None:
    from common.schemas import DatasetSnapshot, GraphConfig, GraphResult, RiskConfig

    from .service import analyze

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mock-graph", action="store_true", help="Explicit test-only SV2 mock"
    )
    parser.add_argument("--patched", nargs="*", default=[])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    fixture_dir = Path(__file__).parent / "tests" / "fixtures"
    dataset = DatasetSnapshot.model_validate_json(
        (fixture_dir / "dataset-week1.json").read_text(encoding="utf-8")
    )
    config = json.loads(
        (fixture_dir / "analysis-config.json").read_text(encoding="utf-8")
    )
    graph_config = GraphConfig.model_validate(config["graph_config"])
    risk_config = RiskConfig.model_validate(config["risk_config"])

    if args.mock_graph:
        # Replay known synthetic paths; NOT graph discovery or a production SV2 implementation.
        initial = GraphResult.model_validate_json(
            (fixture_dir / "graph-unpatched.json").read_text(encoding="utf-8")
        )

        def replay(dataset, patched, config):
            return GraphResult(
                schema_version="1.0.0",
                dataset_id=dataset.dataset_id,
                graph_model_version=config.model_version,
                patched_finding_ids=list(patched),
                entry_point_ids=config.entry_point_ids,
                target_asset_ids=config.target_asset_ids,
                paths=[
                    p for p in initial.paths if not set(p.finding_ids) & set(patched)
                ],
                search_complete=True,
                warnings=["MOCK_SV2: replay of fixed synthetic paths"],
            )

        module = types.ModuleType("sv2_attack_graph.service")
        module.build_graph = replay
        with patch.dict(sys.modules, {"sv2_attack_graph.service": module}):
            result = analyze(dataset, args.patched, graph_config, risk_config)
        print("MOCK SV2 — this is not live integration.", file=sys.stderr)
    else:
        result = analyze(dataset, args.patched, graph_config, risk_config)
    output = result.model_dump_json(indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
