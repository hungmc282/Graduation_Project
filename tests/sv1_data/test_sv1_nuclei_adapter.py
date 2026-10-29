"""Kiểm tra adapter Nuclei JSONL (dựng theo cấu trúc bản ghi thật của Nuclei)."""

import copy
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from common.errors import ContractError, ResourceNotFoundError
from common.schemas import Asset, DatasetSnapshot, Service
from sv1_data.adapters.nuclei_jsonl import parse_nuclei_jsonl, parse_nuclei_jsonl_bytes
from sv1_data.service import validate_dataset

CANARY = "SESSIONCANARY"

BASE_RECORD: dict[str, Any] = {
    "template": "http/misconfiguration/cookies-without-secure.yaml",
    "template-id": "cookies-without-secure",
    "template-path": "/root/nuclei-templates/http/misconfiguration/cookies-without-secure.yaml",
    "info": {
        "name": "Cookies without Secure attribute - Detect",
        "tags": ["misconfig", "http", "cookie"],
        "reference": ["https://owasp.org/www-community/controls/SecureCookieAttribute"],
        "severity": "info",
        "classification": {
            "cve-id": None,
            "cwe-id": ["cwe-614"],
            "cvss-metrics": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        },
    },
    "type": "javascript",
    "host": "host.docker.internal",
    "port": "8080",
    "url": "http://host.docker.internal:8080",
    "matched-at": "host.docker.internal:8080",
    "extracted-results": ["PHPSESSID", "security"],
    "request": "content = template.http_all_headers",
    "response": "[PHPSESSID PHPSESSID security]",
    "timestamp": "2026-10-28T06:21:38.87553847Z",
    "curl-command": "curl -X 'POST' 'http://host.docker.internal:8080'",
    "matcher-status": True,
}


def record(**updates: Any) -> dict[str, Any]:
    result = copy.deepcopy(BASE_RECORD)
    result.update(updates)
    return result


def with_info(base: dict[str, Any], **info: Any) -> dict[str, Any]:
    base["info"].update(info)
    return base


def with_classification(base: dict[str, Any], **classification: Any) -> dict[str, Any]:
    base["info"]["classification"].update(classification)
    return base


def jsonl(*records: Any) -> bytes:
    return "\n".join(json.dumps(r) for r in records).encode("utf-8")


def parse(*records: Any, **kwargs: Any) -> Any:
    return parse_nuclei_jsonl_bytes(jsonl(*records), "WEB01", **kwargs)


def test_non_cve_template_uses_template_id_and_has_no_score() -> None:
    scan = parse(record(), service_by_port={8080: "WEB01:tcp/8080"})
    assert len(scan.findings) == 1
    finding = scan.findings[0]
    assert finding.vulnerability_id == "cookies-without-secure"
    assert finding.asset_id == "WEB01"
    assert finding.service_id == "WEB01:tcp/8080"
    assert finding.cvss_score is None
    assert (finding.epss_probability, finding.is_kev, finding.enriched_at) == (None, None, None)
    assert finding.source == "scanner"
    assert finding.finding_id.startswith("WEB01:cookies-without-secure:nuclei:")


def test_timestamp_with_nine_fraction_digits_is_parsed() -> None:
    finding = parse(record()).findings[0]
    assert finding.observed_at == datetime(2026, 10, 28, 6, 21, 38, 875538, tzinfo=UTC)


def test_cve_template_uses_cve_id_and_template_score() -> None:
    rec = with_classification(
        record(),
        **{"cve-id": ["cve-2021-41773"], "cvss-score": 7.5, "cvss-metrics": "CVSS:3.1/AV:N"},
    )
    finding = parse(rec).findings[0]
    assert finding.vulnerability_id == "CVE-2021-41773"
    assert finding.cvss_score == 7.5
    assert "cvss source: nuclei template" in finding.evidence
    assert "cvss vector: CVSS:3.1/AV:N" in finding.evidence


def test_each_cve_of_a_template_becomes_its_own_finding() -> None:
    rec = with_classification(record(), **{"cve-id": ["CVE-2021-1111", "cve-2022-2222"]})
    findings = parse(rec).findings
    assert [f.vulnerability_id for f in findings] == ["CVE-2021-1111", "CVE-2022-2222"]
    assert len({f.finding_id for f in findings}) == 2


def test_cve_id_given_as_string_or_invalid_is_handled() -> None:
    as_string = with_classification(record(), **{"cve-id": "cve-2021-3333"})
    assert parse(as_string).findings[0].vulnerability_id == "CVE-2021-3333"
    invalid = with_classification(record(), **{"cve-id": ["not-a-cve", 42]})
    assert parse(invalid).findings[0].vulnerability_id == "cookies-without-secure"


def test_vector_without_score_stays_null_and_is_kept_as_evidence() -> None:
    finding = parse(record()).findings[0]
    assert finding.cvss_score is None
    assert any(e.startswith("cvss vector: CVSS:3.0") for e in finding.evidence)
    assert not any("cvss source" in e for e in finding.evidence)


def test_out_of_range_or_non_numeric_score_is_ignored() -> None:
    scan = parse(
        with_classification(record(**{"matched-at": "a"}), **{"cvss-score": 11.0}),
        with_classification(record(**{"matched-at": "b"}), **{"cvss-score": "9.8"}),
        with_classification(record(**{"matched-at": "c"}), **{"cvss-score": True}),
    )
    assert [f.cvss_score for f in scan.findings] == [None, None, None]
    assert scan.stats["invalid_cvss_ignored"] == 1


def test_sensitive_request_response_and_query_strings_are_never_copied() -> None:
    rec = record(
        request=f"GET / HTTP/1.1\r\nCookie: {CANARY}",
        response=f"HTTP/1.1 200\r\nSet-Cookie: {CANARY}",
        **{
            "extracted-results": [CANARY],
            "curl-command": f"curl -H 'Cookie: {CANARY}'",
            "matched-at": f"http://h:8080/login.php?token={CANARY}#frag{CANARY}",
        },
    )
    finding = parse(rec).findings[0]
    joined = "\n".join(finding.evidence)
    assert CANARY not in joined
    assert "matched at: http://h:8080/login.php" in finding.evidence


def test_long_text_is_truncated() -> None:
    rec = with_info(record(), name="N" * 1000)
    name_line = next(e for e in parse(rec).findings[0].evidence if e.startswith("name: "))
    assert len(name_line) <= len("name: ") + 200


def test_identical_records_are_deduplicated_but_different_matches_are_kept() -> None:
    scan = parse(
        record(),
        record(),
        record(**{"matched-at": "http://h:8080/other.php"}),
        record(**{"matcher-name": "second"}),
    )
    assert len(scan.findings) == 3
    assert scan.stats["duplicates_removed"] == 1
    assert len({f.finding_id for f in scan.findings}) == 3


def test_finding_ids_are_stable_between_runs() -> None:
    first = [f.finding_id for f in parse(record()).findings]
    second = [f.finding_id for f in parse(record()).findings]
    assert first == second


def test_min_severity_filters_lower_levels_but_keeps_unknown() -> None:
    records = [
        with_info(record(**{"matched-at": "1"}), severity="info"),
        with_info(record(**{"matched-at": "2"}), severity="medium"),
        with_info(record(**{"matched-at": "3"}), severity="critical"),
        with_info(record(**{"matched-at": "4"}), severity="mystery"),
    ]
    scan = parse(*records, min_severity="medium")
    kept = [next(e for e in f.evidence if e.startswith("nuclei severity")) for f in scan.findings]
    assert kept == [
        "nuclei severity: medium",
        "nuclei severity: critical",
        "nuclei severity: unknown",
    ]
    assert scan.stats["below_min_severity"] == 1
    assert scan.stats["severity_info"] == 1


def test_unmatched_and_templateless_records_are_skipped() -> None:
    no_template = record()
    del no_template["template-id"]
    scan = parse(record(**{"matcher-status": False}), no_template)
    assert scan.findings == []
    assert scan.stats["skipped_unmatched"] == 1
    assert scan.stats["skipped_no_template"] == 1
    assert any("Không có finding nào" in w for w in scan.warnings)


@pytest.mark.parametrize("port", ["8080", 8080])
def test_service_mapping_uses_the_port_in_the_record(port: Any) -> None:
    mapping = {8080: "WEB01:tcp/8080"}
    assert parse(record(port=port), service_by_port=mapping).findings[0].service_id == (
        "WEB01:tcp/8080"
    )


@pytest.mark.parametrize("port", ["9999", "abc", None, True, "70000"])
def test_unmapped_or_invalid_port_gives_no_service(port: Any) -> None:
    mapping = {8080: "WEB01:tcp/8080"}
    assert parse(record(port=port), service_by_port=mapping).findings[0].service_id is None


def test_broken_lines_are_skipped_and_counted() -> None:
    data = (
        jsonl(record())
        + b"\n\n{not json\n"
        + b'{"template-id": "x", "n": NaN}\n'
        + b"[1, 2]\n"
        + b'{"template-id": "cut'
    )
    scan = parse_nuclei_jsonl_bytes(data, "WEB01")
    assert len(scan.findings) == 1
    assert scan.stats["invalid_lines"] == 4


def test_json_array_input_is_accepted() -> None:
    data = json.dumps([record(), record(**{"matched-at": "other"}), 5]).encode("utf-8")
    scan = parse_nuclei_jsonl_bytes(data, "WEB01")
    assert len(scan.findings) == 2
    assert scan.stats["invalid_lines"] == 1


def test_broken_json_array_is_rejected() -> None:
    with pytest.raises(ContractError):
        parse_nuclei_jsonl_bytes(b"[{broken", "WEB01")


def test_utf8_bom_and_empty_file() -> None:
    assert len(parse_nuclei_jsonl_bytes(b"\xef\xbb\xbf" + jsonl(record()), "WEB01").findings) == 1
    empty = parse_nuclei_jsonl_bytes(b"", "WEB01")
    assert empty.findings == []
    assert empty.warnings


def test_invalid_arguments_and_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ContractError):
        parse_nuclei_jsonl_bytes(jsonl(record()), "  ")
    with pytest.raises(ContractError):
        parse_nuclei_jsonl_bytes(jsonl(record()), "WEB01", min_severity="urgent")
    with pytest.raises(ContractError):
        parse_nuclei_jsonl_bytes(b"\xff\xfe\x00bad", "WEB01")
    with pytest.raises(ResourceNotFoundError):
        parse_nuclei_jsonl(tmp_path / "nope.jsonl", "WEB01")


def test_parse_from_file(tmp_path: Path) -> None:
    path = tmp_path / "nuclei.jsonl"
    path.write_bytes(jsonl(record()))
    assert len(parse_nuclei_jsonl(path, "WEB01").findings) == 1


def test_findings_fit_into_a_valid_snapshot() -> None:
    scan = parse(record(), service_by_port={8080: "WEB01:tcp/8080"})
    snapshot = DatasetSnapshot(
        schema_version="1.0.0",
        dataset_id="nuclei-test",
        created_at=datetime(2026, 10, 28, tzinfo=UTC),
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
