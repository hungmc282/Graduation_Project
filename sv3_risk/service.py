"""Public SV3 facade aligned with ARCHITECTURE.md contract 1.0.0."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from .errors import (
    IncompletePathSearchError,
    RiskContractError,
    UnsupportedRiskModelError,
)
from .prioritization import blocked_path_ids, dense_ranks, rank_cvss

if TYPE_CHECKING:
    from common.schemas import AnalysisResult, DatasetSnapshot, GraphConfig, RiskConfig

RISK_MODEL_VERSION = "blocked-paths-v1"
SUPPORTED_GRAPH_MODEL_VERSION = "demo-graph-v1"


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _validate_graph(graph, dataset, config, patched):
    """Validate snapshot provenance and path consistency at the service boundary."""
    if (
        graph.dataset_id != dataset.dataset_id
        or graph.graph_model_version != config.model_version
        or len(graph.patched_finding_ids) != len(set(graph.patched_finding_ids))
        or set(graph.patched_finding_ids) != set(patched)
        or graph.entry_point_ids != config.entry_point_ids
        or graph.target_asset_ids != config.target_asset_ids
    ):
        raise RiskContractError(
            "SV2 result does not match dataset/config/patched state"
        )
    if not graph.search_complete:
        raise IncompletePathSearchError(
            "INCOMPLETE_PATH_SEARCH: cannot compute exact path-count ranking; "
            "adjust graph budget or use a separately versioned approximate model"
        )
    assets = {asset.asset_id for asset in dataset.assets}
    findings = {item.finding_id: item for item in dataset.findings}
    rules = {rule.rule_id: rule for rule in dataset.exploit_rules}
    path_ids = set()
    for path in graph.paths:
        if path.path_id in path_ids:
            raise RiskContractError("Duplicate path_id returned by SV2")
        path_ids.add(path.path_id)
        if (
            path.target_asset_id not in config.target_asset_ids
            or not path.asset_ids
            or path.asset_ids[0] not in config.entry_point_ids
            or path.asset_ids[-1] != path.target_asset_id
            or any(
                item not in assets | set(config.entry_point_ids)
                for item in path.asset_ids
            )
            or len(path.rule_ids) + 1 != len(path.asset_ids)
            or len(path.rule_ids) != len(set(path.rule_ids))
            or len(path.finding_ids) != len(set(path.finding_ids))
        ):
            raise RiskContractError("Invalid path shape, entry, or target")
        required_ids = set()
        for index, rule_id in enumerate(path.rule_ids):
            rule = rules.get(rule_id)
            if rule is None:
                raise RiskContractError("Path refers to a rule outside snapshot")
            if (rule.source_asset_id, rule.target_asset_id) != (
                path.asset_ids[index],
                path.asset_ids[index + 1],
            ):
                raise RiskContractError("Path rule order does not match asset sequence")
            if rule.required_finding_id is not None:
                required_ids.add(rule.required_finding_id)
        if (
            set(path.finding_ids) != required_ids
            or not required_ids <= set(findings)
            or required_ids & set(patched)
        ):
            raise RiskContractError("Path findings do not match active snapshot rules")


def _analyze_blocked(
    dataset: DatasetSnapshot,
    patched_finding_ids: list[str],
    graph_config: GraphConfig,
    risk_config: RiskConfig,
) -> AnalysisResult:
    """Compute exact marginal blocked-path ranking from an immutable snapshot.

    Receives shared Pydantic models; rejects dicts, unknown IDs/configs and
    incomplete graph searches. Each candidate is simulated from the same S.
    Risk scores/RI remain null; model version is blocked-paths-v1.
    Requires common.schemas and the actual SV2 facade at runtime.
    """
    from common.schemas import (
        AnalysisResult,
        DatasetSnapshot,
        GraphConfig,
        GraphResult,
        PriorityItem,
        RiskConfig,
    )

    # Revalidate copies (rather than trusting an already-created mutable model).
    for value, expected in (
        (dataset, DatasetSnapshot),
        (graph_config, GraphConfig),
        (risk_config, RiskConfig),
    ):
        if not isinstance(value, expected):
            raise RiskContractError(f"Expected shared {expected.__name__} model")
    snapshot = DatasetSnapshot.model_validate(dataset.model_dump())
    graph_config = GraphConfig.model_validate(graph_config.model_dump())
    risk_config = RiskConfig.model_validate(risk_config.model_dump())
    if (
        risk_config.model_version != RISK_MODEL_VERSION
        or risk_config.ranking_metric != "critical_paths_blocked"
        or risk_config.parameters
    ):
        raise UnsupportedRiskModelError(
            "blocked-paths-v1 supports critical_paths_blocked with parameters={} only"
        )
    if graph_config.model_version != SUPPORTED_GRAPH_MODEL_VERSION:
        raise UnsupportedRiskModelError(
            "Only demo-graph-v1 removal-only model is supported"
        )
    if type(patched_finding_ids) is not list or any(
        type(item) is not str for item in patched_finding_ids
    ):
        raise RiskContractError("patched_finding_ids must be list[str]")
    if len(patched_finding_ids) != len(set(patched_finding_ids)):
        raise RiskContractError("Duplicate patched finding IDs")
    known_findings = {item.finding_id for item in snapshot.findings}
    patched = sorted(patched_finding_ids)
    if not set(patched) <= known_findings:
        raise RiskContractError("Patched finding does not exist in snapshot")
    assets = {item.asset_id for item in snapshot.assets}
    entries, targets = graph_config.entry_point_ids, graph_config.target_asset_ids
    if (
        not entries
        or not targets
        or len(entries) != len(set(entries))
        or len(targets) != len(set(targets))
        or not set(entries) <= assets | {"INTERNET"}
        or not set(targets) <= assets
    ):
        raise RiskContractError("Invalid/duplicate graph entry points or targets")

    from sv2_attack_graph.service import build_graph

    # SV2 gets a fresh copy for EVERY call. Upstream mutation is an error, not a
    # change that may silently influence the next candidate or the caller.
    snapshot_dump = snapshot.model_dump()
    config_dump = graph_config.model_dump()

    def graph_at(state):
        call_dataset = DatasetSnapshot.model_validate(snapshot_dump)
        call_config = GraphConfig.model_validate(config_dump)
        call_state = list(state)
        result = build_graph(call_dataset, call_state, call_config)
        if (
            call_dataset.model_dump() != snapshot_dump
            or call_config.model_dump() != config_dump
            or call_state != state
        ):
            raise RiskContractError("SV2 mutated its input")
        if not isinstance(result, GraphResult):
            raise RiskContractError("SV2 must return shared GraphResult model")
        result = GraphResult.model_validate(result.model_dump())
        _validate_graph(result, snapshot, graph_config, state)
        return result

    before = graph_at(patched)
    before_by_id = {path.path_id: path for path in before.paths}
    candidates = sorted(
        (item for item in snapshot.findings if item.finding_id not in patched),
        key=lambda item: item.finding_id,
    )
    warnings = set(before.warnings)
    rows = []
    for finding in candidates:
        state = sorted([*patched, finding.finding_id])
        after = graph_at(state)
        warnings.update(after.warnings)
        for path in after.paths:
            if path.path_id in before_by_id and path != before_by_id[path.path_id]:
                raise RiskContractError("SV2 reused path_id for different path content")
        blocked = blocked_path_ids(before_by_id, (path.path_id for path in after.paths))
        reasons = ["BLOCKS_TARGET_PATH" if blocked else "NO_ADDITIONAL_PATH_BLOCKED"]
        if finding.cvss_score is None:
            reasons.append("MISSING_CVSS")
            warnings.add(f"MISSING_CVSS:{finding.finding_id}")
        rows.append(
            PriorityItem(
                finding_id=finding.finding_id,
                asset_id=finding.asset_id,
                cvss_score=finding.cvss_score,
                paths_before=len(before.paths),
                paths_after=len(after.paths),
                paths_blocked=len(blocked),
                blocked_path_ids=blocked,
                risk_after=None,
                remediation_impact=None,
                priority_rank=None,
                reason_codes=reasons,
            )
        )
    ranks = dense_ranks({item.finding_id: item.paths_blocked for item in rows})
    for item in rows:
        item.priority_rank = ranks[item.finding_id]
    rows.sort(key=lambda item: (item.priority_rank, item.finding_id))
    config_hash = _hash(
        {
            "graph_config": graph_config.model_dump(mode="json"),
            "risk_config": risk_config.model_dump(mode="json"),
        }
    )
    analysis_id = _hash(
        {
            "dataset_hash": _hash(snapshot.model_dump(mode="json")),
            "config_hash": config_hash,
            "patched_finding_ids": patched,
        }
    )
    return AnalysisResult(
        schema_version="1.0.0",
        dataset_id=snapshot.dataset_id,
        analysis_id=analysis_id,
        created_at=datetime.now(UTC),
        graph_model_version=graph_config.model_version,
        risk_model_version=risk_config.model_version,
        config_hash=config_hash,
        patched_finding_ids=patched,
        target_asset_ids=list(targets),
        ranking_metric="critical_paths_blocked",
        risk_score_status="not_implemented",
        risk_before=None,
        baseline_cvss_order=rank_cvss(candidates),
        results=rows,
        warnings=sorted(warnings),
    )


def analyze(
    dataset: DatasetSnapshot,
    patched_finding_ids: list[str],
    graph_config: GraphConfig,
    risk_config: RiskConfig,
) -> AnalysisResult:
    """Version-dispatched public facade: blocked-paths-v1 or context-path-v1."""
    if getattr(risk_config, "model_version", None) == "context-path-v1":
        from sv3_risk.research.service import analyze_detailed

        return analyze_detailed(
            dataset, patched_finding_ids, graph_config, risk_config
        ).analysis
    return _analyze_blocked(dataset, patched_finding_ids, graph_config, risk_config)
