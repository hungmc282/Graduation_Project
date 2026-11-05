"""Application orchestration using real SV1, SV2 and SV3 public facades."""

from pathlib import Path

from common.schemas import GraphConfig, RiskConfig
from sv1_data.service import load_dataset
from sv2_attack_graph.service import build_graph
from sv3_risk.service import analyze

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def run_analysis(
    data_dir: Path,
    patched_finding_ids: list[str],
    target_asset_ids: list[str],
    *,
    max_depth: int = 12,
    max_paths: int = 10000,
) -> dict:
    snapshot = load_dataset(data_dir)
    config = GraphConfig(
        model_version="1.0.0",
        entry_point_ids=["INTERNET"],
        target_asset_ids=target_asset_ids,
        max_depth=max_depth,
        max_paths=max_paths,
    )
    graph = build_graph(snapshot, patched_finding_ids, config)
    risk = RiskConfig(
        model_version="context-path-v1",
        ranking_metric="remediation_impact",
        parameters={},
    )
    analysis = analyze(snapshot, patched_finding_ids, config, risk)
    return {
        "dataset": snapshot.model_dump(mode="json"),
        "graph": graph.model_dump(mode="json"),
        "analysis": analysis.model_dump(mode="json"),
    }
