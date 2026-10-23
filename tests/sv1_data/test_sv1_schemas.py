"""Kiểm tra hợp đồng Asset, Service, Finding (ARCHITECTURE.md, mục 6.1 và 6.2)."""

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from common.schemas import Asset, Finding, Service

UTC_NOW = datetime(2026, 10, 17, tzinfo=UTC)


def asset_kwargs(**override: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "asset_id": "WEB01",
        "name": "Web Server",
        "asset_type": "web_server",
        "internet_facing": True,
        "criticality": 3,
        "sensitive_data": False,
    }
    data.update(override)
    return data


def service_kwargs(**override: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "service_id": "S1",
        "asset_id": "WEB01",
        "protocol": "tcp",
        "port": 443,
        "product": "nginx",
        "product_version": "1.18.0",
    }
    data.update(override)
    return data


def finding_kwargs(**override: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "finding_id": "F1",
        "asset_id": "WEB01",
        "service_id": "S1",
        "vulnerability_id": "SYN-001",
        "cvss_score": 8.8,
        "epss_probability": 0.72,
        "is_kev": True,
        "source": "synthetic",
        "evidence": [],
        "observed_at": UTC_NOW,
        "enriched_at": None,
    }
    data.update(override)
    return data


def test_valid_models_accepted() -> None:
    Asset(**asset_kwargs())
    Service(**service_kwargs())
    Finding(**finding_kwargs())


def test_nullable_values_accepted_as_unknown() -> None:
    Asset(
        **asset_kwargs(asset_type=None, internet_facing=None, criticality=None, sensitive_data=None)
    )
    Service(**service_kwargs(product=None, product_version=None))
    Finding(
        **finding_kwargs(
            service_id=None, cvss_score=None, epss_probability=None, is_kev=None, observed_at=None
        )
    )


@pytest.mark.parametrize("criticality", [0, 6])
def test_asset_criticality_must_be_1_to_5(criticality: int) -> None:
    with pytest.raises(ValidationError):
        Asset(**asset_kwargs(criticality=criticality))


@pytest.mark.parametrize("port", [0, 65536])
def test_service_port_out_of_range(port: int) -> None:
    with pytest.raises(ValidationError):
        Service(**service_kwargs(port=port))


def test_service_protocol_only_tcp_or_udp() -> None:
    with pytest.raises(ValidationError):
        Service(**service_kwargs(protocol="icmp"))


@pytest.mark.parametrize("score", [-0.1, 10.1, float("nan"), float("inf")])
def test_cvss_score_must_be_0_to_10(score: float) -> None:
    with pytest.raises(ValidationError):
        Finding(**finding_kwargs(cvss_score=score))


@pytest.mark.parametrize("probability", [-0.01, 1.01, float("nan")])
def test_epss_probability_must_be_0_to_1(probability: float) -> None:
    with pytest.raises(ValidationError):
        Finding(**finding_kwargs(epss_probability=probability))


def test_strict_rejects_string_for_number_and_bool() -> None:
    with pytest.raises(ValidationError):
        Finding(**finding_kwargs(cvss_score="8.8"))
    with pytest.raises(ValidationError):
        Finding(**finding_kwargs(is_kev="true"))
    with pytest.raises(ValidationError):
        Service(**service_kwargs(port="443"))


def test_nullable_field_must_still_be_present() -> None:
    data = finding_kwargs()
    del data["is_kev"]
    with pytest.raises(ValidationError):
        Finding(**data)


def test_extra_field_forbidden() -> None:
    with pytest.raises(ValidationError):
        Finding(**finding_kwargs(cvss=8.8))


def test_naive_datetime_rejected() -> None:
    with pytest.raises(ValidationError):
        Finding(**finding_kwargs(observed_at=datetime(2026, 10, 17)))


def test_finding_source_excludes_mixed() -> None:
    with pytest.raises(ValidationError):
        Finding(**finding_kwargs(source="mixed"))


def test_empty_ids_rejected() -> None:
    with pytest.raises(ValidationError):
        Asset(**asset_kwargs(asset_id=""))
    with pytest.raises(ValidationError):
        Finding(**finding_kwargs(finding_id=""))
