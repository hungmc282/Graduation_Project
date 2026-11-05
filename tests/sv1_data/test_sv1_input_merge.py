"""Regression tests for malformed input and observation conflicts."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from common.errors import ContractError
from sv1_data.adapters.nmap_xml import parse_nmap_xml
from sv1_data.adapters.trivy_json import parse_trivy_json
from sv1_data.pipeline import PipelineConfig, TrivyInput, main, run_pipeline

FIXTURES = Path(__file__).resolve().parents[2] / "data/samples/sv1_milestone1/run1"


@pytest.mark.parametrize("value", [1, {}, "bad", [1], [None]])
def test_trivy_invalid_results_report_file_and_field(tmp_path, value):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"SchemaVersion": 2, "Results": value}))
    with pytest.raises(ContractError) as caught:
        parse_trivy_json(path, "WEB01")
    assert str(path) in caught.value.message
    assert caught.value.details[0]["field"].startswith("Results")


@pytest.mark.parametrize(
    "field,value",
    [("Vulnerabilities", {}), ("Vulnerabilities", [1]), ("Secrets", 3), ("Target", {})],
)
def test_trivy_nested_shapes(tmp_path, field, value):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"SchemaVersion": 2, "Results": [{field: value}]}))
    with pytest.raises(ContractError):
        parse_trivy_json(path, "WEB01")


@pytest.mark.parametrize("value", ["abc", "", "0", "65536", "-1", "1.5"])
def test_nmap_invalid_port_is_contract_error(tmp_path, value):
    path = tmp_path / "bad.xml"
    path.write_text(
        (FIXTURES / "nmap.xml").read_text().replace('portid="443"', f'portid="{value}"')
    )
    with pytest.raises(ContractError) as caught:
        parse_nmap_xml(path)
    assert caught.value.details[0]["field"] == "ports.port.portid"
    assert caught.value.details[0]["file"] == str(path)


def config(tmp_path, files):
    return PipelineConfig(
        dataset_id="merge-test",
        output_dir=str(tmp_path / "out"),
        nmap_xml=[str(p) for p in files],
        enrich=False,
    )


def test_nmap_conflicts_both_orders_and_no_output(tmp_path):
    a, b = tmp_path / "a.xml", tmp_path / "b.xml"
    a.write_bytes((FIXTURES / "nmap.xml").read_bytes())
    b.write_text(a.read_text().replace('version="1.0"', 'version="2.0"'))
    for files in ([a, b], [b, a]):
        with pytest.raises(ContractError) as caught:
            run_pipeline(config(tmp_path, files), tmp_path)
        assert any(d["field"] == "product_version" for d in caught.value.details)
        assert set(caught.value.details[0]["sources"]) == {str(a), str(b)}
        assert not (tmp_path / "out").exists()


def test_identical_nmap_deduplicates_and_reports_counts(tmp_path):
    path = FIXTURES / "nmap.xml"
    result = run_pipeline(config(tmp_path, [path, path]), tmp_path)
    assert len(result.dataset.assets) == len(result.dataset.services) == 2
    assert result.report["merge_stats"]["duplicate_assets"] == 2
    assert result.report["merge_stats"]["duplicate_services"] == 2


def test_non_conflicting_input_permutations_produce_same_snapshot(tmp_path):
    a, b = tmp_path / "a.xml", tmp_path / "b.xml"
    a.write_bytes((FIXTURES / "nmap.xml").read_bytes())
    b.write_text(
        a.read_text()
        .replace("10.10.0.10", "10.10.0.11")
        .replace("10.10.0.20", "10.10.0.21")
    )
    now = datetime(2026, 10, 30, tzinfo=UTC)
    first = run_pipeline(config(tmp_path, [a, b]), tmp_path, now=now)
    second = run_pipeline(config(tmp_path, [b, a]), tmp_path, now=now)
    assert first.dataset == second.dataset


def test_trivy_conflicting_duplicate_within_file(tmp_path):
    data = json.loads((FIXTURES / "trivy.json").read_text())
    item = data["Results"][0]["Vulnerabilities"][0]
    other = json.loads(json.dumps(item))
    other["CVSS"]["nvd"]["V3Score"] = 1.0
    data["Results"][0]["Vulnerabilities"].append(other)
    path = tmp_path / "conflict.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ContractError) as caught:
        parse_trivy_json(path, "WEB01")
    assert any(d["field"] == "cvss_score" for d in caught.value.details)


@pytest.mark.parametrize("change", ["score", "target", "artifact", "identical"])
def test_trivy_across_files(tmp_path, change):
    data = json.loads((FIXTURES / "trivy.json").read_text())
    if change == "score":
        data["Results"][0]["Vulnerabilities"][0]["CVSS"]["nvd"]["V3Score"] = 1.0
    if change == "target":
        data["Results"][0]["Target"] = "other-target"
    if change == "artifact":
        data["ArtifactName"] = "other-artifact"
    path = tmp_path / "second.json"
    path.write_text(json.dumps(data))
    settings = PipelineConfig(
        dataset_id="trivy-test",
        output_dir=str(tmp_path / "out"),
        inventory_csv=str(FIXTURES / "inventory.csv"),
        enrich=False,
        trivy=[
            TrivyInput(path=str(p), asset_id="WEB01")
            for p in (FIXTURES / "trivy.json", path)
        ],
    )
    if change == "identical":
        result = run_pipeline(settings, tmp_path)
        assert result.report["merge_stats"]["duplicate_findings"] == 3
    else:
        with pytest.raises(ContractError):
            run_pipeline(settings, tmp_path)
        assert not (tmp_path / "out").exists()


def test_cli_malformed_file_has_no_traceback(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text('{"SchemaVersion":2,"Results":[1]}')
    settings = {
        "dataset_id": "bad",
        "output_dir": "out",
        "enrich": False,
        "trivy": [{"path": "bad.json", "asset_id": "WEB01"}],
    }
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps(settings))
    assert main([str(cfg)]) == 1
    error = capsys.readouterr().err
    assert "Results[0]" in error and "bad.json" in error and "Traceback" not in error
