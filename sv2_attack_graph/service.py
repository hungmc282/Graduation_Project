"""SV2 public facade: deterministic, state-aware attack-path enumeration.

Model 1.0.0: a rule fires iff its source state equals required_state,
there is an explicitly allowed matching directed connection, and (for
exploit) the required target finding has not been patched. Trust rules
without a finding require evidence. Initial entry state is 'initial'.
No implicit escalation, automatic exposure assumption, or network probing.
"""
from __future__ import annotations

import hashlib
import json
import networkx as nx

from common.errors import ContractError, InvalidReferenceError, UnsupportedVersionError
from common.schemas import INTERNET_ID, SCHEMA_VERSION, DatasetSnapshot, ExploitRule
from sv1_data.service import validate_dataset
from .graph_models import AttackPath, GraphConfig, GraphResult

GRAPH_MODEL_VERSION = "1.0.0"
INITIAL_STATE = "initial"


def _path_id(rule_ids: tuple[str, ...]) -> str:
    payload = json.dumps(rule_ids, ensure_ascii=False, separators=(",", ":"))
    return "ap-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]


def _check_config(dataset: DatasetSnapshot, patched: list[str], config: GraphConfig) -> None:
    if dataset.schema_version != SCHEMA_VERSION:
        raise UnsupportedVersionError("Unsupported dataset schema_version.", [
            {"field": "schema_version", "record_id": dataset.schema_version}])
    if config.model_version != GRAPH_MODEL_VERSION:
        raise UnsupportedVersionError("Unsupported graph model_version.", [
            {"field": "model_version", "record_id": config.model_version}])
    assets = {a.asset_id for a in dataset.assets}
    findings = {f.finding_id for f in dataset.findings}
    errors = []
    for field, seq, valid in (
        ("patched_finding_ids", patched, findings),
        ("entry_point_ids", config.entry_point_ids, assets | {INTERNET_ID}),
        ("target_asset_ids", config.target_asset_ids, assets),
    ):
        for item in seq:
            if item not in valid:
                errors.append({"field": field, "record_id": item})
            if seq.count(item) > 1:
                errors.append({"field": field, "record_id": item, "reason": "duplicate"})
    if errors:
        raise InvalidReferenceError("Invalid graph request IDs.", errors)
    if not config.entry_point_ids or not config.target_asset_ids:
        raise ContractError("At least one entry point and target are required.")


def _matching_connections(dataset: DatasetSnapshot, rule: ExploitRule) -> bool:
    findings = {f.finding_id: f for f in dataset.findings}
    required_service = None
    if rule.required_finding_id is not None:
        required_service = findings[rule.required_finding_id].service_id
    for conn in dataset.connections:
        if (conn.allowed and conn.source_asset_id == rule.source_asset_id
                and conn.target_asset_id == rule.target_asset_id
                and (required_service is None or conn.target_service_id is None
                     or conn.target_service_id == required_service)):
            return True
    return False


def build_graph(dataset: DatasetSnapshot, patched_finding_ids: list[str], config: GraphConfig) -> GraphResult:
    """Build simple asset-path attack graph. No mutation and deterministic ordering.

    max_depth counts transitions (rules). max_paths limits returned paths;
    reaching an additional valid path sets search_complete=False.
    Hitting depth cutoff with possible unexplored transitions also marks incomplete.
    """
    validate_dataset(dataset)
    _check_config(dataset, patched_finding_ids, config)
    patched = set(patched_finding_ids)
    warnings: list[str] = []
    graph = nx.MultiDiGraph()
    graph.add_nodes_from([INTERNET_ID] + [a.asset_id for a in dataset.assets])
    for rule in sorted(dataset.exploit_rules, key=lambda r: r.rule_id):
        if rule.rule_type == "trust":
            if rule.required_finding_id is None and not rule.evidence:
                raise ContractError("Trust rule without finding requires evidence.", [
                    {"field": "evidence", "record_id": rule.rule_id}])
        elif rule.required_finding_id is None:
            raise ContractError("Exploit rule requires finding.", [
                {"field": "required_finding_id", "record_id": rule.rule_id}])
        if _matching_connections(dataset, rule) and rule.required_finding_id not in patched:
            graph.add_edge(rule.source_asset_id, rule.target_asset_id, key=rule.rule_id, rule=rule)
    paths: list[AttackPath] = []
    complete = True
    depth_cutoff = False
    path_limit = False
    targets = set(config.target_asset_ids)

    def walk(current: str, state: str, assets: tuple[str, ...], rules: tuple[str, ...], findings: tuple[str, ...]) -> None:
        nonlocal complete, depth_cutoff, path_limit
        if not complete:
            return
        if current in targets and rules:
            if len(paths) >= config.max_paths:
                complete = False
                path_limit = True
                return
            paths.append(AttackPath(path_id=_path_id(rules), target_asset_id=current,
                                    asset_ids=list(assets), rule_ids=list(rules),
                                    finding_ids=list(dict.fromkeys(findings))))
            return  # targets are terminal in model 1.0.0
        eligible = [data["rule"] for _, _, _, data in graph.out_edges(current, keys=True, data=True)
                    if data["rule"].required_state == state
                    and data["rule"].target_asset_id not in assets]
        eligible.sort(key=lambda r: r.rule_id)
        if len(rules) >= config.max_depth:
            if eligible:
                complete = False
                depth_cutoff = True
            return
        for rule in eligible:
            walk(rule.target_asset_id, rule.resulting_state,
                 assets + (rule.target_asset_id,), rules + (rule.rule_id,),
                 findings + ((rule.required_finding_id,) if rule.required_finding_id else ()))
            if path_limit:
                break

    for entry in config.entry_point_ids:
        walk(entry, INITIAL_STATE, (entry,), (), ())
        if path_limit:
            break
    if path_limit:
        warnings.append("Path search truncated by max_paths; results are incomplete.")
    if depth_cutoff:
        warnings.append("Path search truncated by max_depth; results are incomplete.")
    return GraphResult(schema_version=SCHEMA_VERSION, dataset_id=dataset.dataset_id,
                       graph_model_version=GRAPH_MODEL_VERSION,
                       patched_finding_ids=sorted(patched),
                       entry_point_ids=list(config.entry_point_ids),
                       target_asset_ids=list(config.target_asset_ids),
                       paths=paths, search_complete=complete, warnings=warnings)
