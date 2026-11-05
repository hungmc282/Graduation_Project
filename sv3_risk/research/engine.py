"""Heuristic risk indices; NONE of the outputs are calibrated probabilities.

Only SV2 supplies feasible paths. This module never discovers or edits graph edges.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from math import isclose, isfinite
from typing import Any

from sv3_risk.errors import RiskContractError

MODEL_VERSION = "context-path-v1"
DEFAULT_PARAMETERS = {
    "severity_weight": 0.35,
    "epss_weight": 0.35,
    "kev_weight": 0.20,
    "exposure_weight": 0.10,
    "criticality_weight": 0.80,
    "sensitive_weight": 0.20,
}


class MissingRiskDataError(RiskContractError):
    """Required inputs are unknown; never silently substitute zero."""


def parameters(overrides: dict[str, float]) -> dict[str, float]:
    unknown = set(overrides) - set(DEFAULT_PARAMETERS)
    if unknown:
        raise RiskContractError(f"Unknown risk parameters: {sorted(unknown)}")
    result = DEFAULT_PARAMETERS | overrides
    if any(not isfinite(value) or not 0 <= value <= 1 for value in result.values()):
        raise RiskContractError("Risk weights must be finite and in [0,1]")
    for keys in (
        ("severity_weight", "epss_weight", "kev_weight", "exposure_weight"),
        ("criticality_weight", "sensitive_weight"),
    ):
        if not isclose(sum(result[key] for key in keys), 1.0, abs_tol=1e-12):
            raise RiskContractError(f"Weights must sum to one: {keys}")
    return result


def readiness(dataset) -> list[str]:
    """Inventory missing fields before running a strict complete analysis."""
    missing = []
    for asset in dataset.assets:
        for field in ("internet_facing", "criticality", "sensitive_data"):
            if getattr(asset, field) is None:
                missing.append(f"asset:{asset.asset_id}:{field}")
    for finding in dataset.findings:
        for field in ("cvss_score", "epss_probability", "is_kev"):
            if getattr(finding, field) is None:
                missing.append(f"finding:{finding.finding_id}:{field}")
    return sorted(missing)


def require_complete(dataset) -> None:
    missing = readiness(dataset)
    if missing:
        raise MissingRiskDataError("Missing risk data: " + ", ".join(missing))


def local_components(dataset, config: dict[str, float]) -> dict[str, dict[str, float]]:
    """S/E/K/X indices and a local-only baseline. Reachability stays in SV2."""
    require_complete(dataset)
    assets = {asset.asset_id: asset for asset in dataset.assets}
    components = {}
    for finding in dataset.findings:
        asset = assets[finding.asset_id]
        severity = finding.cvss_score / 10.0
        epss = finding.epss_probability
        kev = float(finding.is_kev)
        exposure = float(asset.internet_facing)
        criticality = asset.criticality / 5.0
        context = float(asset.sensitive_data)
        transition = (
            config["severity_weight"] * severity
            + config["epss_weight"] * epss
            + config["kev_weight"] * kev
            + config["exposure_weight"] * exposure
        )
        loss = (
            config["criticality_weight"] * criticality
            + config["sensitive_weight"] * context
        )
        components[finding.finding_id] = {
            "severity": severity,
            "epss": epss,
            "kev": kev,
            "exposure": exposure,
            "asset_criticality": criticality,
            "sensitive_context": context,
            "transition_index": transition,
            "asset_loss_index": loss,
            "weighted_no_graph_score": 100.0 * transition * loss,
        }
    return components


@dataclass(frozen=True)
class RiskState:
    system_risk: float
    path_details: list[dict[str, Any]]
    target_details: list[dict[str, Any]]
    node_strengths: dict[str, float]
    path_importance: dict[str, float]

    def to_dict(self):
        return asdict(self)


def compute_state(
    dataset,
    graph,
    config: dict[str, float],
    *,
    path_aggregation: str = "product",
    ignore_target_context: bool = False,
) -> RiskState:
    """Max-product path propagation and target-loss aggregation.

    Each finding contributes at most once to a path's index. Trust steps have
    multiplier 1, an explicit conservative assumption, never an inferred EPSS.
    Overlapping paths are not added as independent probabilities.
    """
    if path_aggregation not in {"product", "max_local"}:
        raise RiskContractError("Unsupported path aggregation")
    components = local_components(dataset, config)
    assets = {asset.asset_id: asset for asset in dataset.assets}
    rules = {rule.rule_id: rule for rule in dataset.exploit_rules}
    targets = graph.target_asset_ids
    if not targets:
        raise RiskContractError("At least one target is required")
    target_loss = {
        target: config["criticality_weight"] * assets[target].criticality / 5.0
        + config["sensitive_weight"] * float(assets[target].sensitive_data)
        for target in targets
    }
    if ignore_target_context:
        target_loss = dict.fromkeys(targets, 1.0)
    details = []
    node_strengths = {entry: 1.0 for entry in graph.entry_point_ids}
    target_best = {target: 0.0 for target in targets}
    best_paths = {target: [] for target in targets}
    counts = {
        target: sum(p.target_asset_id == target for p in graph.paths)
        for target in targets
    }
    importance = {finding.finding_id: 0.0 for finding in dataset.findings}
    for path in sorted(graph.paths, key=lambda p: p.path_id):
        strength = 1.0 if path_aggregation == "product" else 0.0
        seen = set()
        steps = []
        for rule_id in path.rule_ids:
            rule = rules[rule_id]
            fid = rule.required_finding_id
            multiplier = 1.0
            if fid is not None and fid not in seen:
                multiplier = components[fid]["transition_index"]
                seen.add(fid)
            if path_aggregation == "product":
                strength *= multiplier
            else:
                strength = max(
                    (components[item]["transition_index"] for item in seen), default=1.0
                )
            node_strengths[rule.target_asset_id] = max(
                node_strengths.get(rule.target_asset_id, 0.0), strength
            )
            steps.append(
                {
                    "rule_id": rule_id,
                    "finding_id": fid,
                    "multiplier": multiplier,
                    "cumulative_strength": strength,
                }
            )
        target = path.target_asset_id
        weighted = 100.0 * target_loss[target] * strength
        details.append(
            {
                "path_id": path.path_id,
                "target_asset_id": target,
                "finding_ids": list(path.finding_ids),
                "strength_index": strength,
                "weighted_risk": weighted,
                "steps": steps,
            }
        )
        if strength > target_best[target]:
            target_best[target] = strength
            best_paths[target] = [path.path_id]
        elif strength == target_best[target]:
            best_paths[target].append(path.path_id)
        for fid in set(path.finding_ids):
            importance[fid] += target_loss[target] / counts[target] / len(targets)
    target_details = [
        {
            "target_asset_id": target,
            "loss_index": target_loss[target],
            "strongest_path_index": target_best[target],
            "weighted_risk": 100.0 * target_loss[target] * target_best[target],
            "strongest_path_ids": best_paths[target],
            "reachable_path_count": counts[target],
        }
        for target in sorted(targets)
    ]
    system = sum(item["weighted_risk"] for item in target_details) / len(targets)
    return RiskState(
        system,
        details,
        target_details,
        dict(sorted(node_strengths.items())),
        dict(sorted(importance.items())),
    )


def float_ranks(scores: dict[str, float], precision: int = 9) -> dict[str, int]:
    """Versioned tie policy: round to 9 decimal places, then dense rank."""
    values = {key: round(value, precision) for key, value in scores.items()}
    if any(not isfinite(value) for value in values.values()):
        raise RiskContractError("Non-finite ranking score")
    ranks = {
        value: index
        for index, value in enumerate(sorted(set(values.values()), reverse=True), 1)
    }
    return {key: ranks[value] for key, value in values.items()}


def baselines(
    dataset, patched: list[str], config: dict[str, float]
) -> dict[str, list[dict]]:
    """Four mandatory baselines on the same candidate set.

    CVSS+KEV uses lexicographic (known exploited first, CVSS second), versioned
    as a baseline policy, not a standardized external formula.
    """
    components = local_components(dataset, config)
    candidates = [
        finding for finding in dataset.findings if finding.finding_id not in patched
    ]
    result = {}
    for method in ("cvss_only", "epss_only", "cvss_kev", "weighted_no_graph"):
        keys = {}
        for finding in candidates:
            if method == "cvss_only":
                score = finding.cvss_score
            elif method == "epss_only":
                score = finding.epss_probability
            elif method == "cvss_kev":
                score = (int(finding.is_kev), finding.cvss_score)
            else:
                score = components[finding.finding_id]["weighted_no_graph_score"]
            keys[finding.finding_id] = score
        if method == "cvss_kev":
            values = sorted(set(keys.values()), reverse=True)
            ranks = {key: values.index(value) + 1 for key, value in keys.items()}
        else:
            ranks = float_ranks(keys)
        result[method] = [
            {
                "finding_id": fid,
                "rank": ranks[fid],
                "score": list(keys[fid]) if isinstance(keys[fid], tuple) else keys[fid],
            }
            for fid in sorted(keys, key=lambda fid: (ranks[fid], fid))
        ]
    return result
