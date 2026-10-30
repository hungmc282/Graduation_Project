"""Kiểm tra quy trình một lệnh: inventory + Nmap + Trivy + EPSS/KEV -> dataset.json."""

import gzip
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from common.errors import ContractError, InvalidReferenceError, ResourceNotFoundError
from sv1_data.db import DATABASE_URL_ENV, DatabaseError, apply_migrations, create_db_engine
from sv1_data.enrichment.service import EPSS_CACHE_NAME, KEV_CACHE_NAME
from sv1_data.history import ScanHistory
from sv1_data.pipeline import main, run_pipeline_from_file
from sv1_data.repository import DatasetRepository
from sv1_data.service import load_dataset

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)

CSV_TEXT = (
    "asset_id,name,asset_type,internet_facing,criticality,sensitive_data,addresses\n"
    "WEB01,Web Server,web_server,true,3,false,10.0.1.10\n"
)
NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.80">
<host><status state="up"/><address addr="10.0.1.10" addrtype="ipv4"/>
<hostnames><hostname name="web.lab" type="user"/></hostnames>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="https" product="nginx" version="1.18.0"/></port></ports></host>
</nmaprun>
"""
EPSS_TEXT = (
    "#model_version:v2025.03.14,score_date:2026-10-18T12:55:00+0000\n"
    "cve,epss,percentile\n"
    "CVE-2021-44228,0.97500,1.00000\n"
    "CVE-2019-10082,0.00832,0.74000\n"
)
KEV_JSON = {
    "catalogVersion": "2026.10.15",
    "dateReleased": "2026-10-15T14:00:00.000Z",
    "count": 1,
    "vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}],
}


def trivy_vuln(vuln_id: str, pkg: str, score: float | None) -> dict[str, Any]:
    vuln: dict[str, Any] = {
        "VulnerabilityID": vuln_id,
        "PkgID": f"{pkg}@1.0",
        "PkgName": pkg,
        "InstalledVersion": "1.0",
        "Severity": "HIGH",
    }
    if score is not None:
        vuln["CVSS"] = {"nvd": {"V3Score": score}}
    return vuln


TRIVY_REPORT = {
    "SchemaVersion": 2,
    "CreatedAt": "2026-10-18T16:14:22.74541532Z",
    "Results": [
        {
            "Target": "image",
            "Vulnerabilities": [
                trivy_vuln("CVE-2021-44228", "apache2", 10.0),
                trivy_vuln("CVE-2019-10082", "libapr1", 9.1),
                trivy_vuln("DLA-1-1", "libfoo", None),
            ],
        }
    ],
}


NUCLEI_RECORDS = [
    {
        "template-id": "cookies-without-secure",
        "info": {"name": "Cookies without Secure attribute", "severity": "info"},
        "port": "443",
        "matched-at": "https://web.lab:443",
        "request": "SECRETREQUEST",
        "timestamp": "2026-10-18T16:14:22.74541532Z",
        "matcher-status": True,
    },
    {
        "template-id": "log4j-rce",
        "info": {
            "name": "Log4j RCE",
            "severity": "critical",
            "classification": {"cve-id": ["cve-2021-44228"], "cvss-score": 10.0},
        },
        "port": "443",
        "matched-at": "https://web.lab:443/api",
        "timestamp": "2026-10-18T16:14:23Z",
        "matcher-status": True,
    },
]


def set_fresh(path: Path) -> None:
    stamp = (NOW - timedelta(hours=1)).timestamp()
    os.utime(path, (stamp, stamp))


def write_inputs(root: Path) -> None:
    (root / "assets.csv").write_text(CSV_TEXT, encoding="utf-8")
    (root / "nmap.xml").write_text(NMAP_XML, encoding="utf-8")
    (root / "trivy.json").write_text(json.dumps(TRIVY_REPORT), encoding="utf-8")
    (root / "nuclei.jsonl").write_text(
        "\n".join(json.dumps(r) for r in NUCLEI_RECORDS), encoding="utf-8"
    )
    cache = root / "cache"
    cache.mkdir()
    (cache / EPSS_CACHE_NAME).write_bytes(gzip.compress(EPSS_TEXT.encode("utf-8")))
    (cache / KEV_CACHE_NAME).write_text(json.dumps(KEV_JSON), encoding="utf-8")
    set_fresh(cache / EPSS_CACHE_NAME)
    set_fresh(cache / KEV_CACHE_NAME)


def write_config(root: Path, **override: Any) -> Path:
    config: dict[str, Any] = {
        "dataset_id": "test-lab",
        "output_dir": "out",
        "inventory_csv": "assets.csv",
        "nmap_xml": ["nmap.xml"],
        "trivy": [
            {
                "path": "trivy.json",
                "asset_id": "WEB01",
                "service_by_package": {"apache2": "WEB01:tcp/443"},
            }
        ],
        "enrich": True,
        "cache_dir": "cache",
    }
    config.update(override)
    path = root / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


@pytest.fixture
def root(tmp_path: Path) -> Path:
    write_inputs(tmp_path)
    return tmp_path


def test_full_pipeline_builds_valid_dataset(root: Path) -> None:
    result = run_pipeline_from_file(write_config(root), now=NOW)
    dataset = result.dataset
    assert dataset.source == "mixed"
    assert [a.asset_id for a in dataset.assets] == ["WEB01"]
    assert dataset.assets[0].criticality == 3  # từ inventory
    assert [s.service_id for s in dataset.services] == ["WEB01:tcp/443"]
    assert dataset.services[0].product == "nginx"  # từ Nmap

    by_vuln = {f.vulnerability_id: f for f in dataset.findings}
    assert len(by_vuln) == 3
    log4j = by_vuln["CVE-2021-44228"]
    assert log4j.service_id == "WEB01:tcp/443"
    assert (log4j.is_kev, log4j.epss_probability) == (True, 0.975)
    assert by_vuln["CVE-2019-10082"].service_id is None
    assert by_vuln["CVE-2019-10082"].is_kev is False
    vendor_id = by_vuln["DLA-1-1"]
    assert (vendor_id.cvss_score, vendor_id.is_kev, vendor_id.enriched_at) == (None, None, None)


def test_output_files_are_written_and_reloadable(root: Path) -> None:
    result = run_pipeline_from_file(write_config(root), now=NOW)
    assert result.dataset_path == root / "out" / "dataset.json"
    assert load_dataset(root / "out") == result.dataset
    assert result.report_path.is_file()


def test_report_has_counts_hashes_versions_and_timings(root: Path) -> None:
    report = run_pipeline_from_file(write_config(root), now=NOW).report
    assert report["counts"] == {
        "assets": 1,
        "services": 1,
        "findings": 3,
        "connections": 0,
        "exploit_rules": 0,
    }
    kinds = {item["kind"] for item in report["inputs"]}
    assert kinds == {"inventory", "nmap", "trivy"}
    assert all(len(item["sha256"]) == 64 for item in report["inputs"])
    assert report["threat_data"] == {
        "epss_model_version": "v2025.03.14",
        "epss_score_date": "2026-10-18",
        "kev_catalog_version": "2026.10.15",
        "kev_entries": 1,
    }
    assert {"inventory", "nmap", "trivy", "merge", "enrichment", "total"} <= set(
        report["timings_seconds"]
    )
    assert report["enrichment_stats"]["kev_listed"] == 1
    written = json.loads((root / "out" / "report.json").read_text(encoding="utf-8"))
    assert written["counts"] == report["counts"]


def test_pipeline_is_deterministic(root: Path) -> None:
    config = write_config(root)
    run_pipeline_from_file(config, now=NOW)
    first = (root / "out" / "dataset.json").read_bytes()
    run_pipeline_from_file(config, now=NOW)
    assert (root / "out" / "dataset.json").read_bytes() == first


def test_relative_paths_resolve_from_config_directory(root: Path) -> None:
    config = write_config(root)
    elsewhere = root / "somewhere"
    elsewhere.mkdir()
    previous = Path.cwd()
    os.chdir(elsewhere)
    try:
        run_pipeline_from_file(config, now=NOW)
    finally:
        os.chdir(previous)
    assert (root / "out" / "dataset.json").is_file()


def test_enrich_false_leaves_values_unknown_and_needs_no_cache(root: Path) -> None:
    config = write_config(root, enrich=False, cache_dir=None)
    result = run_pipeline_from_file(config, now=NOW)
    assert result.report["threat_data"] is None
    assert all(f.is_kev is None and f.epss_probability is None for f in result.dataset.findings)


def test_enrich_true_without_cache_dir_is_rejected(root: Path) -> None:
    with pytest.raises(ContractError):
        run_pipeline_from_file(write_config(root, cache_dir=None), now=NOW)


def test_scanner_only_dataset_uses_addresses_as_ids(root: Path) -> None:
    config = write_config(
        root,
        inventory_csv=None,
        trivy=[
            {
                "path": "trivy.json",
                "asset_id": "10.0.1.10",
                "service_by_package": {"apache2": "10.0.1.10:tcp/443"},
            }
        ],
    )
    dataset = run_pipeline_from_file(config, now=NOW).dataset
    assert dataset.source == "scanner"
    assert dataset.assets[0].asset_id == "10.0.1.10"
    assert dataset.assets[0].criticality is None  # không có inventory: chưa biết


def test_same_nmap_file_listed_twice_is_deduplicated(root: Path) -> None:
    config = write_config(root, nmap_xml=["nmap.xml", "nmap.xml"])
    result = run_pipeline_from_file(config, now=NOW)
    assert len(result.dataset.services) == 1
    assert len(result.dataset.assets) == 1


def test_topology_file_is_included_and_validated(root: Path) -> None:
    topology = {
        "connections": [
            {
                "connection_id": "C1",
                "source_asset_id": "INTERNET",
                "target_asset_id": "WEB01",
                "target_service_id": "WEB01:tcp/443",
                "allowed": True,
                "evidence": [],
            }
        ],
        "exploit_rules": [],
    }
    (root / "topology.json").write_text(json.dumps(topology), encoding="utf-8")
    result = run_pipeline_from_file(write_config(root, topology_json="topology.json"), now=NOW)
    assert [c.connection_id for c in result.dataset.connections] == ["C1"]

    topology["connections"][0]["target_asset_id"] = "NOPE"
    (root / "topology.json").write_text(json.dumps(topology), encoding="utf-8")
    with pytest.raises(InvalidReferenceError):
        run_pipeline_from_file(write_config(root, topology_json="topology.json"), now=NOW)


def test_invalid_topology_shape_is_rejected(root: Path) -> None:
    (root / "topology.json").write_text('{"connections": "x"}', encoding="utf-8")
    with pytest.raises(ContractError):
        run_pipeline_from_file(write_config(root, topology_json="topology.json"), now=NOW)


def test_unknown_asset_in_trivy_input_writes_nothing(root: Path) -> None:
    bad = write_config(
        root, trivy=[{"path": "trivy.json", "asset_id": "NOPE", "service_by_package": {}}]
    )
    with pytest.raises(InvalidReferenceError):
        run_pipeline_from_file(bad, now=NOW)
    assert not (root / "out" / "dataset.json").exists()


def test_mapping_to_nonexistent_service_is_rejected(root: Path) -> None:
    bad = write_config(
        root,
        trivy=[
            {
                "path": "trivy.json",
                "asset_id": "WEB01",
                "service_by_package": {"apache2": "WEB01:tcp/9999"},
            }
        ],
    )
    with pytest.raises(InvalidReferenceError):
        run_pipeline_from_file(bad, now=NOW)


def test_missing_input_file_and_missing_config(root: Path) -> None:
    with pytest.raises(ResourceNotFoundError):
        run_pipeline_from_file(write_config(root, nmap_xml=["nope.xml"]), now=NOW)
    with pytest.raises(ResourceNotFoundError):
        run_pipeline_from_file(root / "no-config.json", now=NOW)


def test_config_with_unknown_key_or_no_source_is_rejected(root: Path) -> None:
    with pytest.raises(ContractError):
        run_pipeline_from_file(write_config(root, surprise=1), now=NOW)
    empty = write_config(root, inventory_csv=None, nmap_xml=[], trivy=[])
    with pytest.raises(ContractError):
        run_pipeline_from_file(empty, now=NOW)


def test_command_line_success_and_failure(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # enrich = false để kiểm thử không phụ thuộc mạng hay thời gian của cache
    assert main([str(write_config(root, enrich=False, cache_dir=None))]) == 0
    assert "dataset.json" in capsys.readouterr().out

    assert main([str(root / "no-config.json")]) == 1
    assert "LỖI" in capsys.readouterr().err


def test_history_is_off_by_default(root: Path) -> None:
    assert run_pipeline_from_file(write_config(root), now=NOW).report["history"] is None


def test_history_records_runs_and_reports_changes(root: Path) -> None:
    config = write_config(root, history_dir="history")
    first = run_pipeline_from_file(config, now=NOW)
    assert first.report["history"]["previous_run_id"] is None
    assert first.report["history"]["diff"] is None

    kev = {
        **KEV_JSON,
        "count": 2,
        "vulnerabilities": [
            *KEV_JSON["vulnerabilities"],
            {"cveID": "CVE-2019-10082", "dateAdded": "2026-10-19"},
        ],
    }
    kev_cache = root / "cache" / KEV_CACHE_NAME
    kev_cache.write_text(json.dumps(kev), encoding="utf-8")
    set_fresh(kev_cache)
    second = run_pipeline_from_file(config, now=NOW + timedelta(hours=1))
    info = second.report["history"]
    assert info["previous_run_id"] == first.report["history"]["run_id"]
    assert info["diff"]["newly_kev"] == 1
    assert info["diff"]["added_findings"] == 0
    assert info["newly_kev"] == ["WEB01:CVE-2019-10082:libapr1@1.0"]
    assert len(ScanHistory(root / "history").runs()) == 2


def test_rerun_with_identical_input_adds_no_history_entry(root: Path) -> None:
    config = write_config(root, history_dir="history")
    run_pipeline_from_file(config, now=NOW)
    second = run_pipeline_from_file(config, now=NOW)
    info = second.report["history"]
    assert info["run_id"] == info["previous_run_id"]
    assert all(value == 0 for key, value in info["diff"].items() if key != "persisting_findings")
    assert len(ScanHistory(root / "history").runs()) == 1


def nuclei_config(root: Path, **override: Any) -> Path:
    item: dict[str, Any] = {
        "path": "nuclei.jsonl",
        "asset_id": "WEB01",
        "service_by_port": {"443": "WEB01:tcp/443"},
    }
    item.update(override)
    return write_config(root, nuclei=[item])


def test_nuclei_findings_join_the_dataset_and_are_enriched(root: Path) -> None:
    result = run_pipeline_from_file(nuclei_config(root), now=NOW)
    nuclei = [f for f in result.dataset.findings if ":nuclei:" in f.finding_id]
    assert len(nuclei) == 2
    assert {f.vulnerability_id for f in nuclei} == {"cookies-without-secure", "CVE-2021-44228"}
    assert all(f.service_id == "WEB01:tcp/443" for f in nuclei)

    log4j = next(f for f in nuclei if f.vulnerability_id == "CVE-2021-44228")
    assert (log4j.cvss_score, log4j.is_kev, log4j.epss_probability) == (10.0, True, 0.975)
    cookie = next(f for f in nuclei if f.vulnerability_id == "cookies-without-secure")
    assert (cookie.is_kev, cookie.enriched_at) == (None, None)  # không phải CVE: chưa biết
    assert all("SECRETREQUEST" not in " ".join(f.evidence) for f in nuclei)


def test_nuclei_input_is_reported(root: Path) -> None:
    report = run_pipeline_from_file(nuclei_config(root), now=NOW).report
    assert "nuclei" in {item["kind"] for item in report["inputs"]}
    assert report["nuclei_stats"]["findings"] == 2
    assert "nuclei" in report["timings_seconds"]
    assert report["counts"]["findings"] == 5  # 3 của Trivy và 2 của Nuclei


def test_nuclei_min_severity_is_applied(root: Path) -> None:
    result = run_pipeline_from_file(nuclei_config(root, min_severity="high"), now=NOW)
    nuclei = [f for f in result.dataset.findings if ":nuclei:" in f.finding_id]
    assert [f.vulnerability_id for f in nuclei] == ["CVE-2021-44228"]
    assert result.report["nuclei_stats"]["below_min_severity"] == 1


def test_nuclei_only_dataset_needs_a_cache_when_enriching(root: Path) -> None:
    config = write_config(
        root,
        inventory_csv=None,
        nmap_xml=[],
        trivy=[],
        nuclei=[{"path": "nuclei.jsonl", "asset_id": "WEB01"}],
        cache_dir=None,
    )
    with pytest.raises(ContractError):
        run_pipeline_from_file(config, now=NOW)


def add_kev_entry(root: Path) -> None:
    kev = {
        **KEV_JSON,
        "count": 2,
        "vulnerabilities": [
            *KEV_JSON["vulnerabilities"],
            {"cveID": "CVE-2019-10082", "dateAdded": "2026-10-19"},
        ],
    }
    cache_file = root / "cache" / KEV_CACHE_NAME
    cache_file.write_text(json.dumps(kev), encoding="utf-8")
    set_fresh(cache_file)


def test_dataset_id_is_the_base_name_plus_a_content_hash(root: Path) -> None:
    result = run_pipeline_from_file(write_config(root), now=NOW)
    assert result.dataset.dataset_id.startswith("test-lab-")
    assert len(result.dataset.dataset_id) == len("test-lab-") + 12
    assert result.report["base_dataset_id"] == "test-lab"
    assert len(result.report["content_sha256"]) == 64


def test_same_content_keeps_the_id_even_when_run_at_another_time(root: Path) -> None:
    config = write_config(root)
    first = run_pipeline_from_file(config, now=NOW)
    second = run_pipeline_from_file(config, now=NOW + timedelta(hours=1))
    assert second.dataset.created_at != first.dataset.created_at
    assert second.dataset.dataset_id == first.dataset.dataset_id
    assert second.report["content_sha256"] == first.report["content_sha256"]


def test_changed_content_gets_a_new_id(root: Path) -> None:
    config = write_config(root)
    first = run_pipeline_from_file(config, now=NOW)
    add_kev_entry(root)
    second = run_pipeline_from_file(config, now=NOW)
    assert second.dataset.dataset_id != first.dataset.dataset_id
    assert second.report["content_sha256"] != first.report["content_sha256"]


def database_engine(root: Path, monkeypatch: pytest.MonkeyPatch, *, migrate: bool = True) -> Any:
    url = f"sqlite:///{(root / 'pipeline.db').as_posix()}"
    monkeypatch.setenv(DATABASE_URL_ENV, url)
    engine = create_db_engine(url)
    if migrate:
        apply_migrations(engine)
    return engine


def test_database_is_off_by_default(root: Path) -> None:
    assert run_pipeline_from_file(write_config(root), now=NOW).report["database"] is None


def test_pipeline_saves_the_dataset_to_the_database(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = database_engine(root, monkeypatch)
    config = write_config(root, database=True)
    first = run_pipeline_from_file(config, now=NOW)
    assert first.report["database"] == {"saved": True}
    stored = DatasetRepository(engine).load(first.dataset.dataset_id)
    assert stored == first.dataset

    second = run_pipeline_from_file(config, now=NOW + timedelta(hours=1))
    assert second.dataset.dataset_id == first.dataset.dataset_id
    assert second.report["database"] == {"saved": False}  # cùng nội dung, không ghi lại


def test_database_option_needs_the_url_variable(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(DATABASE_URL_ENV, raising=False)
    with pytest.raises(ContractError):
        run_pipeline_from_file(write_config(root, database=True), now=NOW)


def test_database_option_needs_migrations(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    database_engine(root, monkeypatch, migrate=False)
    with pytest.raises(DatabaseError):
        run_pipeline_from_file(write_config(root, database=True), now=NOW)
