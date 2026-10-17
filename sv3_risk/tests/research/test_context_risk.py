"""Independent hand-computed oracles plus synthetic reference integration tests."""

import itertools
import json
from pathlib import Path

import pytest
from common.schemas import DatasetSnapshot, GraphConfig, RiskConfig
from sv2_attack_graph.service import build_graph

from sv3_risk.errors import IncompletePathSearchError, RiskContractError
from sv3_risk.research.engine import (
    DEFAULT_PARAMETERS,
    MissingRiskDataError,
    baselines,
    compute_state,
    parameters,
    readiness,
)
from sv3_risk.research.evaluate import evaluate_scenario
from sv3_risk.research.service import analyze_detailed
from sv3_risk.service import analyze

ROOT = Path(__file__).resolve().parents[2] / "data" / "scenarios"


def load(name="diamond"):
    directory = ROOT / name
    dataset = DatasetSnapshot.model_validate_json(
        (directory / "dataset.json").read_text(encoding="utf-8")
    )
    config = json.loads((directory / "config.json").read_text(encoding="utf-8"))
    return (
        dataset,
        GraphConfig.model_validate(config["graph_config"]),
        RiskConfig.model_validate(config["risk_config"]),
    )


def test_chain_hand_calculated_risk_and_impact():
    dataset, graph, risk = load("chain")
    report = analyze_detailed(dataset, [], graph, risk)
    # q(F01)=.35*.75 + .35*.8 + .2*1 + .1*1 = .8425
    # q(F02)=.35*.8 + .35*.6 + .2*0 + .1*0 = .49
    # DB loss=.8*(5/5)+.2*1=1; Risk=100*.8425*.49=41.2825
    assert report.analysis.risk_before == pytest.approx(41.2825)
    rows = {row.finding_id: row for row in report.analysis.results}
    assert rows["F01"].remediation_impact == pytest.approx(41.2825)
    assert rows["F02"].remediation_impact == pytest.approx(41.2825)
    assert rows["F03"].remediation_impact == 0
    assert [rows[fid].priority_rank for fid in ["F01", "F02", "F03"]] == [1, 1, 2]
    assert report.analysis.risk_score_status == "complete"
    assert "HEURISTIC_INDEX" in " ".join(report.analysis.warnings)


def test_diamond_hand_calculated_backup_path():
    dataset, graph, risk = load()
    report = analyze_detailed(dataset, [], graph, risk)
    rows = {row.finding_id: row for row in report.analysis.results}
    # Backup q(F04)=.35*.6+.35*.2=.28; risk after F02=100*.8425*.28=23.59.
    assert rows["F02"].risk_after == pytest.approx(23.59)
    assert rows["F02"].remediation_impact == pytest.approx(17.6925)
    assert rows["F04"].paths_blocked == 1
    assert rows["F04"].remediation_impact == 0  # strongest path still exists
    assert report.detail["before"]["path_importance"]["F01"] == 1
    assert report.detail["before"]["path_importance"]["F02"] == 0.5


def test_multitarget_criticality_sensitive_context():
    dataset, graph, risk = load("multi-target")
    report = analyze_detailed(dataset, [], graph, risk)
    # DB01 risk 41.2825; DB02 loss=.8*.8+.2= .84, F03 q=.9755.
    assert report.analysis.risk_before == pytest.approx(
        (41.2825 + 100 * 0.84 * 0.9755) / 2
    )
    by_id = {row.finding_id: row for row in report.analysis.results}
    assert by_id["F03"].priority_rank == 1
    assert by_id["F01"].risk_after == pytest.approx(100 * 0.84 * 0.9755 / 2)


def test_public_facade_dispatch():
    dataset, graph, risk = load()
    assert analyze(dataset, [], graph, risk).risk_model_version == "context-path-v1"


@pytest.mark.parametrize(
    "subset",
    [
        list(combo)
        for n in range(5)
        for combo in itertools.combinations(["F01", "F02", "F03", "F04"], n)
    ],
)
def test_all_patch_subsets_monotonic_and_no_mutation(subset):
    dataset, graph, risk = load()
    original = dataset.model_dump_json()
    result = analyze_detailed(dataset, subset, graph, risk).analysis
    assert 0 <= result.risk_before <= 100
    assert not set(subset) & {row.finding_id for row in result.results}
    for row in result.results:
        assert 0 <= row.risk_after <= result.risk_before + 1e-9
        assert row.remediation_impact == pytest.approx(
            result.risk_before - row.risk_after
        )
    assert dataset.model_dump_json() == original


def test_group_impact_not_sum():
    dataset, graph, risk = load("chain")
    initial = analyze(dataset, [], graph, risk)
    group = analyze(dataset, ["F01", "F02"], graph, risk)
    assert initial.risk_before - group.risk_before == pytest.approx(41.2825)
    assert sum(r.remediation_impact for r in initial.results) == pytest.approx(82.565)
    after = analyze(dataset, ["F01"], graph, risk)
    assert all(row.remediation_impact == 0 for row in after.results)


@pytest.mark.parametrize("field", ["cvss_score", "epss_probability", "is_kev"])
def test_missing_finding_data_is_not_zero(field):
    dataset, graph, risk = load()
    setattr(dataset.findings[0], field, None)
    assert readiness(dataset)
    with pytest.raises(MissingRiskDataError):
        analyze(dataset, [], graph, risk)


@pytest.mark.parametrize("field", ["criticality", "internet_facing", "sensitive_data"])
def test_missing_asset_context_is_not_zero(field):
    dataset, graph, risk = load()
    setattr(dataset.assets[0], field, None)
    with pytest.raises(MissingRiskDataError):
        analyze(dataset, [], graph, risk)


def test_zero_false_are_valid_data():
    dataset, graph, risk = load()
    for finding in dataset.findings:
        finding.cvss_score = 0.0
        finding.epss_probability = 0.0
        finding.is_kev = False
    for asset in dataset.assets:
        asset.internet_facing = False
    assert readiness(dataset) == []
    assert analyze(dataset, [], graph, risk).risk_before == 0


@pytest.mark.parametrize(
    "overrides",
    [
        {"unknown": 0.1},
        {"severity_weight": 1.2},
        {"severity_weight": 0.9},
        {"epss_weight": float("nan")},
    ],
)
def test_invalid_parameters(overrides):
    with pytest.raises(RiskContractError):
        parameters(overrides)


def test_defaults_explicit_and_implicit_same_identity():
    dataset, graph, risk = load()
    a = analyze(dataset, [], graph, risk)
    risk.parameters = dict(DEFAULT_PARAMETERS)
    b = analyze(dataset, [], graph, risk)
    assert a.analysis_id == b.analysis_id
    assert a.config_hash == b.config_hash


def test_altered_weights_change_identity():
    dataset, graph, risk = load()
    a = analyze(dataset, [], graph, risk)
    risk.parameters = {
        "severity_weight": 0.65,
        "epss_weight": 0.15,
        "kev_weight": 0.1,
        "exposure_weight": 0.1,
    }
    b = analyze(dataset, [], graph, risk)
    assert a.analysis_id != b.analysis_id
    assert a.risk_before != b.risk_before


def test_no_double_count_overlapping_paths():
    dataset, config, _ = load("chain")
    graph = build_graph(dataset, [], config)
    first = compute_state(dataset, graph, parameters({}))
    duplicate = graph.paths[0].model_copy(update={"path_id": "another-id"})
    graph.paths.append(duplicate)
    second = compute_state(dataset, graph, parameters({}))
    assert second.system_risk == first.system_risk


def test_four_baselines_cover_identical_candidates():
    dataset, _, _ = load()
    result = baselines(dataset, ["F01"], parameters({}))
    assert set(result) == {"cvss_only", "epss_only", "cvss_kev", "weighted_no_graph"}
    for rows in result.values():
        assert {r["finding_id"] for r in rows} == {"F02", "F03", "F04"}
    assert result["cvss_only"][0]["finding_id"] == "F03"
    assert result["epss_only"][0]["finding_id"] == "F03"


def test_reachability_is_required():
    dataset, graph, risk = load()
    dataset.connections = [
        c for c in dataset.connections if c.source_asset_id != "INTERNET"
    ]
    assert analyze(dataset, [], graph, risk).risk_before == 0


def test_rule_state_preconditions_are_required():
    dataset, graph, risk = load("chain")
    dataset.exploit_rules[1].required_state = "unavailable_privilege"
    assert analyze(dataset, [], graph, risk).risk_before == 0


@pytest.mark.parametrize("field,value", [("max_paths", 1), ("max_depth", 1)])
def test_incomplete_reference_search_rejected(field, value):
    dataset, graph, risk = load()
    setattr(graph, field, value)
    with pytest.raises(IncompletePathSearchError):
        analyze(dataset, [], graph, risk)


def test_evaluation_baseline_coverage():
    rows, sensitivity, _ = evaluate_scenario(ROOT / "diamond")
    assert {row["method"] for row in rows} == {
        "cvss_only",
        "epss_only",
        "cvss_kev",
        "weighted_no_graph",
        "proposed_static",
        "proposed_dynamic",
        "ablation_no_propagation",
        "ablation_no_target_context",
    }
    assert len(rows) == 8 * 5
    assert len(sensitivity) == 3
    assert all(row["expert_assessment"] == "not_conducted" for row in rows)
    final = [row for row in rows if row["k"] == 4]
    assert all(row["risk_reduction_at_k"] == pytest.approx(1) for row in final)


def test_group_api_and_explicit_cve_scope():
    from sv3_risk.research.remediation import (
        finding_ids_for_vulnerability,
        simulate_patch_group,
    )

    dataset, graph, risk = load("chain")
    result = simulate_patch_group(dataset, [], ["F01", "F02"], graph, risk)
    assert result["remediation_impact"] == pytest.approx(41.2825)
    assert len(result["blocked_path_ids"]) == 1
    assert finding_ids_for_vulnerability(dataset, "DEMO-A") == ["F01"]
    assert finding_ids_for_vulnerability(dataset, "DEMO-A", ["WEB01"]) == ["F01"]
    with pytest.raises(RiskContractError):
        finding_ids_for_vulnerability(dataset, "DEMO-A", ["APP01"])
    with pytest.raises(RiskContractError):
        simulate_patch_group(dataset, [], ["F01", "F01"], graph, risk)


def test_zero_risk_evaluation_is_undefined_ratio(tmp_path):
    dataset, graph, risk = load("chain")
    for finding in dataset.findings:
        finding.cvss_score = 0.0
        finding.epss_probability = 0.0
        finding.is_kev = False
    for asset in dataset.assets:
        asset.internet_facing = False
    (tmp_path / "dataset.json").write_text(dataset.model_dump_json(), encoding="utf-8")
    (tmp_path / "config.json").write_text(
        json.dumps(
            {
                "graph_config": graph.model_dump(mode="json"),
                "risk_config": risk.model_dump(mode="json"),
            }
        ),
        encoding="utf-8",
    )
    rows, _, _ = evaluate_scenario(tmp_path)
    assert all(row["risk_before"] == 0 for row in rows)
    assert all(row["risk_reduction_at_k"] is None for row in rows)
