"""Full SV3 context risk facade; SV2 still owns all graph construction."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sv3_risk.errors import RiskContractError, UnsupportedRiskModelError
from sv3_risk.prioritization import blocked_path_ids, rank_cvss
from sv3_risk.research.engine import (
    MODEL_VERSION,
    baselines,
    compute_state,
    float_ranks,
    local_components,
    parameters,
    require_complete,
)


@dataclass
class DetailedReport:
    """Sidecar detail; the existing AnalysisResult remains the public 1.0 contract."""

    analysis: Any
    detail: dict[str, Any]

    def model_dump(self, mode="json"):
        return {"analysis": self.analysis.model_dump(mode=mode), "detail": self.detail}


def analyze_detailed(
    dataset, patched_finding_ids, graph_config, risk_config
) -> DetailedReport:
    from common.schemas import (
        AnalysisResult,
        DatasetSnapshot,
        GraphConfig,
        GraphResult,
        PriorityItem,
        RiskConfig,
    )
    from sv2_attack_graph.service import build_graph

    from sv3_risk.service import _hash, _validate_graph

    if any(
        not isinstance(value, model)
        for value, model in (
            (dataset, DatasetSnapshot),
            (graph_config, GraphConfig),
            (risk_config, RiskConfig),
        )
    ):
        raise RiskContractError("Use shared common.schemas models at public boundaries")
    snapshot = DatasetSnapshot.model_validate(dataset.model_dump())
    graph_config = GraphConfig.model_validate(graph_config.model_dump())
    risk_config = RiskConfig.model_validate(risk_config.model_dump())
    if (
        risk_config.model_version != MODEL_VERSION
        or risk_config.ranking_metric != "remediation_impact"
    ):
        raise UnsupportedRiskModelError("context-path-v1 requires remediation_impact")
    config = parameters(risk_config.parameters)
    require_complete(snapshot)
    if type(patched_finding_ids) is not list or any(
        type(fid) is not str for fid in patched_finding_ids
    ):
        raise RiskContractError("patched_finding_ids must be list[str]")
    patched = sorted(patched_finding_ids)
    findings = {finding.finding_id: finding for finding in snapshot.findings}
    if len(patched) != len(set(patched)) or not set(patched) <= set(findings):
        raise RiskContractError("Unknown or duplicate patched finding IDs")
    assets = {asset.asset_id for asset in snapshot.assets}
    entries, targets = graph_config.entry_point_ids, graph_config.target_asset_ids
    if (
        not entries
        or not targets
        or len(entries) != len(set(entries))
        or len(targets) != len(set(targets))
        or not set(entries) <= assets | {"INTERNET"}
        or not set(targets) <= assets
    ):
        raise RiskContractError("Invalid entry/target configuration")
    before_dump = snapshot.model_dump()
    config_dump = graph_config.model_dump()

    def graph_at(state):
        call_dataset = DatasetSnapshot.model_validate(before_dump)
        call_config = GraphConfig.model_validate(config_dump)
        call_state = list(state)
        value = build_graph(call_dataset, call_state, call_config)
        if (
            call_dataset.model_dump() != before_dump
            or call_config.model_dump() != config_dump
            or call_state != state
        ):
            raise RiskContractError("SV2 mutated input")
        if not isinstance(value, GraphResult):
            raise RiskContractError("SV2 must return shared GraphResult")
        value = GraphResult.model_validate(value.model_dump())
        _validate_graph(value, snapshot, graph_config, state)
        return value

    before_graph = graph_at(patched)
    before = compute_state(snapshot, before_graph, config)
    before_paths = {path.path_id: path for path in before_graph.paths}
    components = local_components(snapshot, config)
    warnings = set(before_graph.warnings)
    if snapshot.source == "synthetic":
        warnings.add(
            "SYNTHETIC_DATA: not evidence of effectiveness on real infrastructure"
        )
    warnings.add("HEURISTIC_INDEX: scores are not calibrated attack probabilities")
    rows = []
    candidate_details = {}
    for fid in sorted(set(findings) - set(patched)):
        after_graph = graph_at(sorted([*patched, fid]))
        warnings.update(after_graph.warnings)
        for path in after_graph.paths:
            if path.path_id in before_paths and path != before_paths[path.path_id]:
                raise RiskContractError("SV2 reused path ID with different contents")
        removed = blocked_path_ids(
            before_paths, (path.path_id for path in after_graph.paths)
        )
        after = compute_state(snapshot, after_graph, config)
        impact = before.system_risk - after.system_risk
        if impact < -1e-9:
            raise RiskContractError("Risk increased in a removal-only patch model")
        if abs(impact) <= 1e-12:
            impact = 0.0
        reasons = []
        if impact > 0:
            reasons.append("REDUCES_SYSTEM_RISK")
        if removed:
            reasons.append("BLOCKS_TARGET_PATH")
        if not reasons:
            reasons.append("NO_ADDITIONAL_RISK_REDUCTION")
        importance = before.path_importance[fid]
        if importance > 0:
            reasons.append("ON_CRITICAL_TARGET_PATH")
        finding = findings[fid]
        rows.append(
            PriorityItem(
                finding_id=fid,
                asset_id=finding.asset_id,
                cvss_score=finding.cvss_score,
                paths_before=len(before_graph.paths),
                paths_after=len(after_graph.paths),
                paths_blocked=len(removed),
                blocked_path_ids=removed,
                risk_after=after.system_risk,
                remediation_impact=impact,
                priority_rank=None,
                reason_codes=reasons,
            )
        )
        candidate_details[fid] = {
            "local_components": components[fid],
            "path_importance": importance,
            "risk_before": before.system_risk,
            "risk_after": after.system_risk,
            "remediation_impact": impact,
            "remaining_target_risk": after.target_details,
        }
    ranks = float_ranks({item.finding_id: item.remediation_impact for item in rows})
    for item in rows:
        item.priority_rank = ranks[item.finding_id]
    rows.sort(key=lambda item: (item.priority_rank, item.finding_id))
    # Resolve defaults BEFORE hashing: implicit and explicit defaults identify the same model.
    resolved_risk_config = risk_config.model_dump(mode="json") | {"parameters": config}
    config_hash = _hash(
        {
            "graph_config": graph_config.model_dump(mode="json"),
            "risk_config": resolved_risk_config,
        }
    )
    dataset_hash = _hash(snapshot.model_dump(mode="json"))
    identity = _hash(
        {
            "dataset_hash": dataset_hash,
            "config_hash": config_hash,
            "patched_finding_ids": patched,
        }
    )
    analysis = AnalysisResult(
        schema_version="1.0.0",
        dataset_id=snapshot.dataset_id,
        analysis_id=identity,
        created_at=datetime.now(UTC),
        graph_model_version=graph_config.model_version,
        risk_model_version=MODEL_VERSION,
        config_hash=config_hash,
        patched_finding_ids=patched,
        target_asset_ids=targets,
        ranking_metric="remediation_impact",
        risk_score_status="complete",
        risk_before=before.system_risk,
        baseline_cvss_order=rank_cvss(
            [findings[fid] for fid in findings if fid not in patched]
        ),
        results=rows,
        warnings=sorted(warnings),
    )
    detail = {
        "report_schema_version": "1.0.0",
        "graph_result_hash": _hash(before_graph.model_dump(mode="json")),
        "analysis_id": identity,
        "dataset_hash": dataset_hash,
        "model_version": MODEL_VERSION,
        "parameters": config,
        "score_meaning": "Relative heuristic index on [0,100], not a probability",
        "action_unit": "finding_id occurrence; group patch = recompute with union of IDs",
        "tie_policy": "Dense ranks after rounding RI to 9 decimal places; ID for display only",
        "graph_config": graph_config.model_dump(mode="json"),
        "before": before.to_dict(),
        "candidate_details": candidate_details,
        "baselines": baselines(snapshot, patched, config),
        "assumptions": [
            "SV2 supplies a complete feasible path set under configured model and limits",
            "Patching removes transitions; no new paths or configuration side effects",
            "Trust steps retain multiplier 1; this is a lab assumption",
            "Max over alternative paths is a conservative ranking proxy, not probability union",
            "Only target-reaching path prefixes are reported as node strengths",
        ],
    }
    return DetailedReport(analysis, detail)
