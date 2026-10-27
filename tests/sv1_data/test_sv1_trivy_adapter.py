"""Kiểm tra adapter Trivy JSON."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from common.errors import ContractError, ResourceNotFoundError, UnsupportedVersionError
from common.schemas import Asset, DatasetSnapshot, Service
from sv1_data.adapters.trivy_json import parse_trivy_json, parse_trivy_json_bytes
from sv1_data.service import validate_dataset

CREATED_AT = "2026-10-18T16:14:22.74541532Z"  # Trivy ghi 9 chữ số phần thập phân


def make_vuln(
    vuln_id: str = "CVE-2019-10082",
    pkg: str = "apache2",
    version: str = "2.4.25-3+deb9u5",
    **extra: Any,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "VulnerabilityID": vuln_id,
        "PkgID": f"{pkg}@{version}",
        "PkgName": pkg,
        "InstalledVersion": version,
        "FixedVersion": "2.4.25-3+deb9u8",
        "Status": "fixed",
        "Severity": "CRITICAL",
        "Title": "httpd: read-after-free in h2 connection shutdown",
        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-10082",
        "CVSS": {"nvd": {"V2Score": 6.4, "V3Score": 9.1}, "redhat": {"V3Score": 6.5}},
    }
    data.update(extra)
    return data


def make_report(vulns: list[dict[str, Any]], **extra: Any) -> bytes:
    report: dict[str, Any] = {
        "SchemaVersion": 2,
        "CreatedAt": CREATED_AT,
        "ArtifactName": "vulnerables/web-dvwa",
        "Results": [{"Target": "vulnerables/web-dvwa (debian 9.5)", "Vulnerabilities": vulns}],
    }
    report.update(extra)
    return json.dumps(report).encode("utf-8")


def test_basic_conversion() -> None:
    scan = parse_trivy_json_bytes(make_report([make_vuln()]), "WEB01")
    assert len(scan.findings) == 1
    finding = scan.findings[0]
    assert finding.finding_id == "WEB01:CVE-2019-10082:apache2@2.4.25-3+deb9u5"
    assert finding.asset_id == "WEB01"
    assert finding.service_id is None
    assert finding.vulnerability_id == "CVE-2019-10082"
    assert finding.cvss_score == 9.1
    assert finding.source == "scanner"


def test_unknown_enrichment_stays_null_and_timestamp_is_parsed() -> None:
    finding = parse_trivy_json_bytes(make_report([make_vuln()]), "WEB01").findings[0]
    assert finding.epss_probability is None
    assert finding.is_kev is None
    assert finding.enriched_at is None
    assert finding.observed_at == datetime(2026, 10, 18, 16, 14, 22, 745415, tzinfo=UTC)


def test_evidence_has_package_fix_and_cvss_source() -> None:
    finding = parse_trivy_json_bytes(make_report([make_vuln()]), "WEB01").findings[0]
    assert "package: apache2 2.4.25-3+deb9u5" in finding.evidence
    assert "fixed version: 2.4.25-3+deb9u8" in finding.evidence
    assert "cvss source: nvd v3" in finding.evidence
    assert "reference: https://avd.aquasec.com/nvd/cve-2019-10082" in finding.evidence


def test_cvss_prefers_nvd_v3() -> None:
    finding = parse_trivy_json_bytes(make_report([make_vuln()]), "WEB01").findings[0]
    assert finding.cvss_score == 9.1


def test_cvss_falls_back_to_other_vendor_v3() -> None:
    cvss = {"nvd": {"V2Score": 5.0}, "redhat": {"V3Score": 6.5}}
    finding = parse_trivy_json_bytes(make_report([make_vuln(CVSS=cvss)]), "WEB01").findings[0]
    assert finding.cvss_score == 6.5
    assert "cvss source: redhat v3" in finding.evidence


def test_cvss_never_uses_v2_scores() -> None:
    cvss = {"nvd": {"V2Score": 5.0}}
    scan = parse_trivy_json_bytes(make_report([make_vuln(CVSS=cvss)]), "WEB01")
    assert scan.findings[0].cvss_score is None
    assert scan.stats["without_cvss"] == 1


def test_missing_cvss_is_null_not_zero() -> None:
    vuln = make_vuln(Severity="UNKNOWN")
    del vuln["CVSS"]
    scan = parse_trivy_json_bytes(make_report([vuln]), "WEB01")
    assert scan.findings[0].cvss_score is None
    assert any("không có điểm CVSS" in w for w in scan.warnings)


def test_out_of_range_cvss_ignored_and_counted() -> None:
    cvss = {"nvd": {"V3Score": 11.0}}
    scan = parse_trivy_json_bytes(make_report([make_vuln(CVSS=cvss)]), "WEB01")
    assert scan.findings[0].cvss_score is None
    assert scan.stats["invalid_cvss_ignored"] == 1


def test_duplicates_removed() -> None:
    scan = parse_trivy_json_bytes(make_report([make_vuln(), make_vuln()]), "WEB01")
    assert len(scan.findings) == 1
    assert scan.stats["duplicates_removed"] == 1
    assert scan.stats["vulnerabilities_read"] == 2


def test_same_cve_in_different_packages_is_kept() -> None:
    vulns = [make_vuln(), make_vuln(pkg="libapr1", version="1.5.2-5")]
    scan = parse_trivy_json_bytes(make_report(vulns), "WEB01")
    assert len(scan.findings) == 2
    assert len({f.finding_id for f in scan.findings}) == 2


def test_record_without_id_is_skipped() -> None:
    vuln = make_vuln()
    del vuln["VulnerabilityID"]
    scan = parse_trivy_json_bytes(make_report([vuln, make_vuln("CVE-2020-1")]), "WEB01")
    assert [f.vulnerability_id for f in scan.findings] == ["CVE-2020-1"]
    assert scan.stats["skipped_no_id"] == 1


def test_secrets_are_counted_but_never_copied() -> None:
    report = json.loads(make_report([make_vuln()]))
    report["Results"].append(
        {
            "Target": "/etc/ssl/private/example.key",
            "Class": "secret",
            "Secrets": [{"RuleID": "private-key", "Match": "-----BEGIN PRIVATE KEY-----"}],
        }
    )
    scan = parse_trivy_json_bytes(json.dumps(report).encode("utf-8"), "WEB01")
    assert scan.stats["secrets_skipped"] == 1
    assert all("PRIVATE KEY" not in e for f in scan.findings for e in f.evidence)


def test_service_mapping_is_explicit_only() -> None:
    vulns = [make_vuln(), make_vuln(pkg="libapr1", version="1.5.2-5")]
    scan = parse_trivy_json_bytes(make_report(vulns), "WEB01", {"apache2": "WEB01:tcp/8080"})
    by_pkg = {f.finding_id.split(":")[-1].split("@")[0]: f for f in scan.findings}
    assert by_pkg["apache2"].service_id == "WEB01:tcp/8080"
    assert by_pkg["libapr1"].service_id is None


def test_utf8_bom_is_accepted() -> None:
    data = b"\xef\xbb\xbf" + make_report([make_vuln()])
    assert len(parse_trivy_json_bytes(data, "WEB01").findings) == 1


def test_unsupported_trivy_schema_version() -> None:
    with pytest.raises(UnsupportedVersionError):
        parse_trivy_json_bytes(make_report([], SchemaVersion=3), "WEB01")


def test_nan_rejected() -> None:
    data = (
        b'{"SchemaVersion": 2, "Results": '
        b'[{"Vulnerabilities": [{"CVSS": {"nvd": {"V3Score": NaN}}}]}]}'
    )
    with pytest.raises(ContractError):
        parse_trivy_json_bytes(data, "WEB01")


def test_broken_json_rejected() -> None:
    with pytest.raises(ContractError):
        parse_trivy_json_bytes(b"{not json", "WEB01")


def test_empty_asset_id_rejected() -> None:
    with pytest.raises(ContractError):
        parse_trivy_json_bytes(make_report([make_vuln()]), "  ")


def test_parse_from_file_and_missing_file(tmp_path: Path) -> None:
    path = tmp_path / "trivy.json"
    path.write_bytes(make_report([make_vuln()]))
    assert len(parse_trivy_json(path, "WEB01").findings) == 1
    with pytest.raises(ResourceNotFoundError):
        parse_trivy_json(tmp_path / "nope.json", "WEB01")


def test_findings_fit_into_a_valid_snapshot() -> None:
    scan = parse_trivy_json_bytes(
        make_report([make_vuln(), make_vuln(pkg="libapr1", version="1.5.2-5")]),
        "WEB01",
        {"apache2": "WEB01:tcp/8080"},
    )
    snapshot = DatasetSnapshot(
        schema_version="1.0.0",
        dataset_id="trivy-dvwa-test",
        created_at=datetime(2026, 10, 18, tzinfo=UTC),
        source="scanner",
        assets=[
            Asset(
                asset_id="WEB01",
                name="DVWA",
                asset_type=None,
                internet_facing=None,
                criticality=None,
                sensitive_data=None,
            )
        ],
        services=[
            Service(
                service_id="WEB01:tcp/8080",
                asset_id="WEB01",
                protocol="tcp",
                port=8080,
                product="Apache httpd",
                product_version="2.4.25",
            )
        ],
        findings=scan.findings,
        connections=[],
        exploit_rules=[],
    )
    validate_dataset(snapshot)
