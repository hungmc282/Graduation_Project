"""SV3 tests with an explicitly mocked SV2 facade, never real integration."""

import json
import sys
import types
from pathlib import Path

import pytest
from common.schemas import DatasetSnapshot, GraphConfig, GraphResult, RiskConfig

from sv3_risk.errors import (
    IncompletePathSearchError,
    RiskContractError,
    UnsupportedRiskModelError,
)
from sv3_risk.prioritization import blocked_path_ids, dense_ranks
from sv3_risk.service import analyze

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def inputs():
    dataset = DatasetSnapshot.model_validate_json(
        (FIXTURES / "dataset-week1.json").read_text(encoding="utf-8")
    )
    config = json.loads((FIXTURES / "analysis-config.json").read_text(encoding="utf-8"))
    return (
        dataset,
        GraphConfig.model_validate(config["graph_config"]),
        RiskConfig.model_validate(config["risk_config"]),
    )


@pytest.fixture
def upstream(monkeypatch):
    calls = []

    def fake_graph(dataset, patched, config):
        # TEST-ONLY oracle for this synthetic rule chain; not a graph engine.
        calls.append(tuple(patched))
        paths = []
        if not set(patched) & {"F01", "F02"}:
            paths = [
                {
                    "path_id": "path:R01>R02>R03",
                    "target_asset_id": "DB01",
                    "asset_ids": ["INTERNET", "WEB01", "APP01", "DB01"],
                    "rule_ids": ["R01", "R02", "R03"],
                    "finding_ids": ["F01", "F02"],
                }
            ]
        return GraphResult(
            schema_version="1.0.0",
            dataset_id=dataset.dataset_id,
            graph_model_version=config.model_version,
            patched_finding_ids=list(patched),
            entry_point_ids=list(config.entry_point_ids),
            target_asset_ids=list(config.target_asset_ids),
            paths=paths,
            search_complete=True,
            warnings=[],
        )

    module = types.ModuleType("sv2_attack_graph.service")
    module.build_graph = fake_graph
    monkeypatch.setitem(sys.modules, "sv2_attack_graph.service", module)
    return module, calls, fake_graph


def run(inputs, patched=None):
    dataset, graph, risk = inputs
    return analyze(dataset, [] if patched is None else patched, graph, risk)


def test_initial_ranking_and_ties(inputs, upstream):
    result = run(inputs)
    assert result.baseline_cvss_order == ["F03", "F02", "F01"]
    assert [
        (r.finding_id, r.paths_blocked, r.priority_rank) for r in result.results
    ] == [
        ("F01", 1, 1),
        ("F02", 1, 1),
        ("F03", 0, 2),
    ]
    assert upstream[1] == [(), ("F01",), ("F02",), ("F03",)]
    assert result.risk_score_status == "not_implemented"
    assert result.risk_before is None
    assert all(
        r.risk_after is None and r.remediation_impact is None for r in result.results
    )


@pytest.mark.parametrize(
    "patched,expected",
    [
        (["F01"], [("F02", 0, 1), ("F03", 0, 1)]),
        (["F02"], [("F01", 0, 1), ("F03", 0, 1)]),
        (["F03"], [("F01", 1, 1), ("F02", 1, 1)]),
        (["F01", "F02"], [("F03", 0, 1)]),
        (["F01", "F02", "F03"], []),
    ],
)
def test_marginal_ranking_after_patch(inputs, upstream, patched, expected):
    result = run(inputs, patched)
    assert [
        (r.finding_id, r.paths_blocked, r.priority_rank) for r in result.results
    ] == expected
    assert not set(patched) & set(result.baseline_cvss_order)


def test_missing_cvss_and_equal_cvss(inputs, upstream):
    inputs[0].findings[0].cvss_score = None
    inputs[0].findings[1].cvss_score = 9.8
    result = run(inputs)
    assert result.baseline_cvss_order == ["F02", "F03", "F01"]
    assert "MISSING_CVSS:F01" in result.warnings
    assert result.results[0].priority_rank == result.results[1].priority_rank


def test_reproducibility_and_input_preservation(inputs, upstream):
    original = [value.model_dump() for value in inputs]
    first, second = run(inputs), run(inputs)
    a, b = first.model_dump(), second.model_dump()
    a.pop("created_at")
    b.pop("created_at")
    assert a == b
    assert original == [value.model_dump() for value in inputs]
    assert (
        run(inputs, ["F02", "F01"]).analysis_id
        == run(inputs, ["F01", "F02"]).analysis_id
    )
    assert first.analysis_id != run(inputs, ["F01"]).analysis_id
    inputs[0].assets[0].name = "Changed"
    assert first.analysis_id != run(inputs).analysis_id


@pytest.mark.parametrize("patched", [["UNKNOWN"], ["F01", "F01"], "F01", [1]])
def test_invalid_patch_ids(inputs, upstream, patched):
    with pytest.raises(RiskContractError):
        run(inputs, patched)
    assert upstream[1] == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("model_version", "unknown"),
        ("ranking_metric", "remediation_impact"),
        ("parameters", {"weight": 0.5}),
    ],
)
def test_unsupported_risk_config(inputs, upstream, field, value):
    setattr(inputs[2], field, value)
    with pytest.raises(UnsupportedRiskModelError):
        run(inputs)


@pytest.mark.parametrize(
    "field,value",
    [
        ("entry_point_ids", []),
        ("target_asset_ids", ["MISSING"]),
        ("target_asset_ids", ["DB01", "DB01"]),
    ],
)
def test_invalid_graph_targets(inputs, upstream, field, value):
    setattr(inputs[1], field, value)
    with pytest.raises(RiskContractError):
        run(inputs)


@pytest.mark.parametrize("candidate_only", [False, True])
def test_incomplete_search_fails_without_exact_ranking(
    inputs, upstream, candidate_only
):
    module, _, original = upstream

    def truncated(*args):
        result = original(*args)
        if not candidate_only or args[1]:
            result.search_complete = False
            result.warnings = ["Budget exhausted"]
        return result

    module.build_graph = truncated
    with pytest.raises(IncompletePathSearchError):
        run(inputs)


@pytest.mark.parametrize(
    "field,value",
    [
        ("dataset_id", "wrong"),
        ("graph_model_version", "wrong"),
        ("patched_finding_ids", ["F03"]),
        ("target_asset_ids", ["WEB01"]),
    ],
)
def test_upstream_provenance_mismatch(inputs, upstream, field, value):
    module, _, original = upstream

    def changed(*args):
        result = original(*args)
        # model_construct bypasses producer validation to test boundary defense.
        return result.model_copy(update={field: value})

    module.build_graph = changed
    with pytest.raises((RiskContractError, ValueError)):
        run(inputs)


def test_upstream_mutation_rejected_and_caller_preserved(inputs, upstream):
    module, _, original = upstream
    before = inputs[0].model_dump()

    def mutating(dataset, patched, config):
        result = original(dataset, patched, config)
        dataset.assets[0].name = "mutated"
        return result

    module.build_graph = mutating
    with pytest.raises(RiskContractError, match="mutated"):
        run(inputs)
    assert inputs[0].model_dump() == before


def test_added_path_rejected():
    with pytest.raises(RiskContractError):
        blocked_path_ids(["P1"], ["P1", "P2"])


def test_dense_ranks_are_stable():
    assert dense_ranks({"B": 1, "A": 1, "C": 0}) == {"B": 1, "A": 1, "C": 2}
    assert dense_ranks({}) == {}


def test_non_demo_finding_ids_not_hardcoded(inputs, upstream):
    # Verify production SV3 accepts arbitrary IDs; only this test fake knows graph rules.
    dataset = inputs[0]
    mapping = {"F01": "X", "F02": "Y", "F03": "Z"}
    for finding in dataset.findings:
        finding.finding_id = mapping[finding.finding_id]
    for rule in dataset.exploit_rules:
        if rule.required_finding_id:
            rule.required_finding_id = mapping[rule.required_finding_id]

    def renamed_graph(dataset, patched, config):
        paths = (
            []
            if set(patched) & {"X", "Y"}
            else [
                {
                    "path_id": "arbitrary-path",
                    "target_asset_id": "DB01",
                    "asset_ids": ["INTERNET", "WEB01", "APP01", "DB01"],
                    "rule_ids": ["R01", "R02", "R03"],
                    "finding_ids": ["X", "Y"],
                }
            ]
        )
        return GraphResult(
            schema_version="1.0.0",
            dataset_id=dataset.dataset_id,
            graph_model_version=config.model_version,
            patched_finding_ids=patched,
            entry_point_ids=config.entry_point_ids,
            target_asset_ids=config.target_asset_ids,
            paths=paths,
            search_complete=True,
            warnings=[],
        )

    upstream[0].build_graph = renamed_graph
    result = run(inputs)
    assert [(r.finding_id, r.paths_blocked) for r in result.results] == [
        ("X", 1),
        ("Y", 1),
        ("Z", 0),
    ]


def test_two_independent_paths_rerank_after_patch(inputs, upstream):
    from common.schemas import Connection, ExploitRule

    dataset = inputs[0]
    dataset.connections.append(
        Connection(
            connection_id="C05",
            source_asset_id="TEST01",
            target_asset_id="DB01",
            target_service_id=None,
            allowed=True,
            evidence=["Test-only alternate trust"],
        )
    )
    dataset.exploit_rules.append(
        ExploitRule(
            rule_id="R05",
            source_asset_id="TEST01",
            target_asset_id="DB01",
            required_finding_id=None,
            required_state="controlled",
            resulting_state="accessible",
            rule_type="trust",
            evidence=["Test-only alternate trust"],
        )
    )
    original = upstream[2]

    def two_paths(dataset, patched, config):
        result = original(dataset, patched, config)
        if "F03" not in patched:
            from common.schemas import AttackPath

            result.paths.append(
                AttackPath(
                    path_id="alternate",
                    target_asset_id="DB01",
                    asset_ids=["INTERNET", "TEST01", "DB01"],
                    rule_ids=["R04", "R05"],
                    finding_ids=["F03"],
                )
            )
        return result

    upstream[0].build_graph = two_paths
    initial = run(inputs)
    assert [r.priority_rank for r in initial.results] == [1, 1, 1]
    changed = run(inputs, ["F01"])
    assert [
        (r.finding_id, r.paths_blocked, r.priority_rank) for r in changed.results
    ] == [("F03", 1, 1), ("F02", 0, 2)]
