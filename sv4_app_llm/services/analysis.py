"""Real SV1–SV3 analysis for both saved snapshots and sample workspaces."""

import json

from common.schemas import DatasetSnapshot, GraphConfig, RiskConfig
from sv1_data.service import validate_dataset
from sv2_attack_graph.service import build_graph
from sv3_risk.research.service import analyze_detailed


def analyze_dataset(dataset, targets, patched=(), *, max_depth=12, max_paths=10000):
    snapshot = DatasetSnapshot.model_validate_json(json.dumps(dataset, allow_nan=False))
    validate_dataset(snapshot)
    if not snapshot.exploit_rules:
        raise ValueError(
            "Chưa có điều kiện khai thác. Cần bổ sung trước khi đánh giá đường tấn công."
        )
    config = GraphConfig(
        model_version="1.0.0",
        entry_point_ids=["INTERNET"],
        target_asset_ids=list(targets),
        max_depth=max_depth,
        max_paths=max_paths,
    )
    graph = build_graph(snapshot, list(patched), config)
    report = analyze_detailed(
        snapshot,
        list(patched),
        config,
        RiskConfig(
            model_version="context-path-v1",
            ranking_metric="remediation_impact",
            parameters={},
        ),
    )
    return {
        "source": snapshot.source,
        "report": {
            "analysis": report.analysis.model_dump(mode="json"),
            "details": report.detail,
            "graph": graph.model_dump(mode="json"),
        },
    }
