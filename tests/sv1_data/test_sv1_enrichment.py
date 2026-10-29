"""Kiểm tra làm giàu EPSS/KEV: phân tích dữ liệu, cache, và điền vào Finding."""

import gzip
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from common.errors import ContractError, ResourceNotFoundError
from common.schemas import Finding
from sv1_data.enrichment.cache import fetch_cached
from sv1_data.enrichment.epss import EPSS_URL, parse_epss
from sv1_data.enrichment.kev import KEV_URL, parse_kev
from sv1_data.enrichment.service import (
    EPSS_CACHE_NAME,
    KEV_CACHE_NAME,
    enrich_dataset,
    enrich_findings,
    load_threat_data,
)
from sv1_data.service import load_dataset, validate_dataset

SAMPLE_DIR = Path(__file__).resolve().parents[2] / "data" / "samples" / "demo_lab_v1"
NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)

EPSS_TEXT = (
    "#model_version:v2025.03.14,score_date:2026-10-18T12:55:00+0000\n"
    "cve,epss,percentile\n"
    "CVE-2019-10082,0.00832,0.74000\n"
    "CVE-2021-44228,0.97500,1.00000\n"
    "bad-row,abc,def\n"
    "CVE-2020-0001,1.5,0.9\n"
)
KEV_JSON = json.dumps(
    {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.10.15",
        "dateReleased": "2026-10-15T14:00:00.000Z",
        "count": 2,
        "vulnerabilities": [
            {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"},
            {"cveID": "CVE-2023-0001", "dateAdded": "2023-01-05"},
        ],
    }
)


def make_finding(vuln_id: str, **override: Any) -> Finding:
    data: dict[str, Any] = {
        "finding_id": f"WEB01:{vuln_id}",
        "asset_id": "WEB01",
        "service_id": None,
        "vulnerability_id": vuln_id,
        "cvss_score": 7.5,
        "epss_probability": None,
        "is_kev": None,
        "source": "scanner",
        "evidence": ["package: apache2 2.4.25"],
        "observed_at": None,
        "enriched_at": None,
    }
    data.update(override)
    return Finding(**data)


# ---------- EPSS ----------


def test_parse_epss_plain_text() -> None:
    data = parse_epss(EPSS_TEXT.encode("utf-8"))
    assert data.model_version == "v2025.03.14"
    assert data.score_date == "2026-10-18"
    assert data.scores["CVE-2021-44228"].probability == 0.975
    assert data.scores["CVE-2019-10082"].percentile == 0.74


def test_parse_epss_gzip_and_skips_invalid_rows() -> None:
    data = parse_epss(gzip.compress(EPSS_TEXT.encode("utf-8")))
    assert set(data.scores) == {"CVE-2019-10082", "CVE-2021-44228"}
    assert data.skipped_rows == 2  # "abc" không phải số, 1.5 ngoài khoảng 0-1


def test_parse_epss_rejects_missing_columns_empty_and_bad_gzip() -> None:
    with pytest.raises(ContractError):
        parse_epss(b"cve,score\nCVE-2020-1,0.1\n")
    with pytest.raises(ContractError):
        parse_epss(b"cve,epss,percentile\n")
    with pytest.raises(ContractError):
        parse_epss(b"\x1f\x8bnot really gzip")


def test_parse_epss_rejects_nan_and_infinity_scores() -> None:
    with pytest.raises(ContractError):
        parse_epss(b"cve,epss,percentile\nCVE-2020-1,nan,0.5\nCVE-2020-2,inf,0.5\n")


# ---------- KEV ----------


def test_parse_kev() -> None:
    catalog = parse_kev(KEV_JSON.encode("utf-8"))
    assert set(catalog.entries) == {"CVE-2021-44228", "CVE-2023-0001"}
    assert catalog.entries["CVE-2021-44228"].date_added == "2021-12-10"
    assert catalog.catalog_version == "2026.10.15"


def test_parse_kev_rejects_bad_shapes() -> None:
    for bad in (b"{not json", b"[]", b'{"vulnerabilities": []}', b'{"vulnerabilities": "x"}'):
        with pytest.raises(ContractError):
            parse_kev(bad)


def test_parse_kev_rejects_nan() -> None:
    with pytest.raises(ContractError):
        parse_kev(b'{"vulnerabilities": [{"cveID": "CVE-2021-1", "x": NaN}]}')


# ---------- điền vào Finding ----------


def enrich(findings: list[Finding]) -> Any:
    return enrich_findings(
        findings,
        parse_epss(EPSS_TEXT.encode("utf-8")),
        parse_kev(KEV_JSON.encode("utf-8")),
        now=NOW,
    )


def test_enrich_values_for_kev_epss_missing_and_unlisted() -> None:
    result = enrich(
        [
            make_finding("CVE-2021-44228"),
            make_finding("CVE-2019-10082"),
            make_finding("CVE-2024-9999"),
        ]
    )
    log4j, apache, unknown = result.findings
    assert (log4j.epss_probability, log4j.is_kev, log4j.enriched_at) == (0.975, True, NOW)
    assert (apache.epss_probability, apache.is_kev) == (0.00832, False)
    assert (unknown.epss_probability, unknown.is_kev) == (None, False)  # thiếu EPSS: null
    assert result.stats["epss_found"] == 2
    assert result.stats["epss_missing"] == 1
    assert result.stats["kev_listed"] == 1


def test_non_cve_finding_is_left_unchanged() -> None:
    original = make_finding("SYN-WEB-001")
    result = enrich([original])
    assert result.findings[0] == original
    assert result.findings[0].is_kev is None
    assert result.findings[0].enriched_at is None
    assert result.stats["non_cve_skipped"] == 1


def test_cve_id_matching_ignores_case_and_spaces() -> None:
    result = enrich([make_finding(" cve-2021-44228 ")])
    assert result.findings[0].is_kev is True


def test_evidence_records_sources_and_keeps_existing_lines() -> None:
    finding = enrich([make_finding("CVE-2021-44228")]).findings[0]
    assert "package: apache2 2.4.25" in finding.evidence
    assert any(e.startswith("epss: 0.97500") and "v2025.03.14" in e for e in finding.evidence)
    assert any(e.startswith("kev: listed") and "2021-12-10" in e for e in finding.evidence)


def test_enrichment_is_idempotent() -> None:
    once = enrich([make_finding("CVE-2021-44228")]).findings
    twice = enrich(once).findings
    assert twice[0].evidence == once[0].evidence


def test_original_finding_is_not_modified() -> None:
    original = make_finding("CVE-2021-44228")
    enrich([original])
    assert original.is_kev is None
    assert original.enriched_at is None


def test_naive_now_rejected() -> None:
    with pytest.raises(ContractError):
        enrich_findings(
            [],
            parse_epss(EPSS_TEXT.encode("utf-8")),
            parse_kev(KEV_JSON.encode("utf-8")),
            now=datetime(2026, 10, 19),
        )


# ---------- cache ----------


def set_age(path: Path, age: timedelta) -> None:
    stamp = (NOW - age).timestamp()
    os.utime(path, (stamp, stamp))


def client_returning(body: bytes) -> tuple[httpx.Client, list[str]]:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, content=body)

    return httpx.Client(transport=httpx.MockTransport(handler)), calls


def offline_client() -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_downloads_and_writes_cache_when_missing(tmp_path: Path) -> None:
    client, calls = client_returning(b"data")
    path = tmp_path / "sub" / "file.bin"
    data, warnings = fetch_cached("https://example.test/f", path, client=client, now=NOW)
    assert (data, warnings) == (b"data", [])
    assert path.read_bytes() == b"data"
    assert len(calls) == 1
    assert not path.with_name("file.bin.tmp").exists()


def test_fresh_cache_is_used_without_network(tmp_path: Path) -> None:
    path = tmp_path / "file.bin"
    path.write_bytes(b"cached")
    set_age(path, timedelta(hours=1))
    client, calls = client_returning(b"new")
    data, _ = fetch_cached("https://example.test/f", path, client=client, now=NOW)
    assert data == b"cached"
    assert calls == []


def test_stale_cache_is_refreshed(tmp_path: Path) -> None:
    path = tmp_path / "file.bin"
    path.write_bytes(b"old")
    set_age(path, timedelta(hours=48))
    client, calls = client_returning(b"new")
    data, warnings = fetch_cached("https://example.test/f", path, client=client, now=NOW)
    assert (data, warnings) == (b"new", [])
    assert path.read_bytes() == b"new"
    assert len(calls) == 1


def test_offline_falls_back_to_stale_cache_with_warning(tmp_path: Path) -> None:
    path = tmp_path / "file.bin"
    path.write_bytes(b"old")
    set_age(path, timedelta(hours=48))
    data, warnings = fetch_cached("https://example.test/f", path, client=offline_client(), now=NOW)
    assert data == b"old"
    assert len(warnings) == 1
    assert "cache cũ" in warnings[0]


def test_offline_without_cache_raises(tmp_path: Path) -> None:
    with pytest.raises(ResourceNotFoundError):
        fetch_cached(
            "https://example.test/f", tmp_path / "none.bin", client=offline_client(), now=NOW
        )


def test_http_error_status_is_treated_like_offline(tmp_path: Path) -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(503)))
    with pytest.raises(ResourceNotFoundError):
        fetch_cached("https://example.test/f", tmp_path / "none.bin", client=client, now=NOW)


# ---------- toàn bộ quy trình ----------


def threat_data_client() -> tuple[httpx.Client, list[str]]:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if str(request.url) == EPSS_URL:
            return httpx.Response(200, content=gzip.compress(EPSS_TEXT.encode("utf-8")))
        if str(request.url) == KEV_URL:
            return httpx.Response(200, content=KEV_JSON.encode("utf-8"))
        return httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler)), calls


def test_load_threat_data_downloads_both_sources_into_cache_dir(tmp_path: Path) -> None:
    client, calls = threat_data_client()
    epss, kev, warnings = load_threat_data(tmp_path, now=NOW, client=client)
    assert "CVE-2021-44228" in epss.scores
    assert "CVE-2021-44228" in kev.entries
    assert warnings == []
    assert (tmp_path / EPSS_CACHE_NAME).is_file()
    assert (tmp_path / KEV_CACHE_NAME).is_file()
    assert sorted(calls) == sorted([EPSS_URL, KEV_URL])


def test_second_run_uses_cache_only(tmp_path: Path) -> None:
    client, _ = threat_data_client()
    load_threat_data(tmp_path, now=NOW, client=client)
    for name in (EPSS_CACHE_NAME, KEV_CACHE_NAME):
        set_age(tmp_path / name, timedelta(hours=1))
    second_client, calls = threat_data_client()
    load_threat_data(tmp_path, now=NOW, client=second_client)
    assert calls == []


def test_enrich_dataset_end_to_end(tmp_path: Path) -> None:
    dataset = load_dataset(SAMPLE_DIR).model_copy(deep=True)
    dataset.findings[0].vulnerability_id = "CVE-2021-44228"
    client, _ = threat_data_client()
    enriched, result = enrich_dataset(dataset, tmp_path, now=NOW, client=client)
    assert enriched.findings[0].is_kev is True
    assert enriched.findings[0].epss_probability == 0.975
    assert enriched.findings[1] == dataset.findings[1]  # mã synthetic: giữ nguyên
    assert dataset.findings[0].epss_probability == 0.72  # snapshot gốc không bị sửa
    assert result.stats["enriched"] == 1
    validate_dataset(enriched)
