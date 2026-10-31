"""Kiểm tra bản nháp thuộc tính tài sản do LLM đề xuất."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from common.errors import ContractError, InvalidReferenceError
from common.schemas import DatasetSnapshot
from sv1_data.asset_draft import (
    ALLOWED_ATTRIBUTES,
    apply_asset_attributes,
    validate_asset_attributes,
)
from sv1_data.service import load_dataset, validate_dataset

SAMPLE_DIR = Path(__file__).resolve().parents[2] / "data" / "samples" / "demo_lab_v1"
NOW = datetime(2026, 10, 30, 9, 0, tzinfo=UTC)


@pytest.fixture
def dataset() -> DatasetSnapshot:
    return load_dataset(SAMPLE_DIR)


def test_allowed_attributes_are_exactly_the_contract_fields() -> None:
    assert set(ALLOWED_ATTRIBUTES) == {
        "asset_type",
        "internet_facing",
        "criticality",
        "sensitive_data",
    }


def test_valid_attributes_are_accepted_and_trimmed() -> None:
    cleaned = validate_asset_attributes(
        {
            "asset_type": " file_server ",
            "internet_facing": False,
            "criticality": 4,
            "sensitive_data": True,
        }
    )
    assert cleaned == {
        "asset_type": "file_server",
        "internet_facing": False,
        "criticality": 4,
        "sensitive_data": True,
    }


def test_null_values_are_kept_as_unknown() -> None:
    attributes = dict.fromkeys(ALLOWED_ATTRIBUTES)
    assert validate_asset_attributes(attributes) == attributes


def test_empty_draft_is_valid_to_validate() -> None:
    assert validate_asset_attributes({}) == {}


@pytest.mark.parametrize("name", ["asset_id", "name", "owner", "ip_address", "criticality "])
def test_attributes_outside_the_contract_are_rejected(name: str) -> None:
    with pytest.raises(ContractError) as info:
        validate_asset_attributes({name: "x"})
    assert info.value.details[0]["field"] == name


@pytest.mark.parametrize("value", ["true", "false", "unknown", "yes", "no", 1, 0, "", "null"])
@pytest.mark.parametrize("name", ["internet_facing", "sensitive_data"])
def test_booleans_are_never_coerced_from_other_types(name: str, value: Any) -> None:
    with pytest.raises(ContractError):
        validate_asset_attributes({name: value})


@pytest.mark.parametrize("value", [0, 6, -1, "3", 3.0, 2.5, True, False, "high"])
def test_criticality_must_be_an_integer_from_1_to_5(value: Any) -> None:
    with pytest.raises(ContractError):
        validate_asset_attributes({"criticality": value})


@pytest.mark.parametrize("value", ["", "   ", 5, True, "a" * 65, "web;server", "../etc"])
def test_asset_type_must_be_a_short_plain_label(value: Any) -> None:
    with pytest.raises(ContractError):
        validate_asset_attributes({"asset_type": value})


def test_every_problem_is_reported_together() -> None:
    with pytest.raises(ContractError) as info:
        validate_asset_attributes({"criticality": 9, "internet_facing": "yes", "owner": "x"})
    assert {d["field"] for d in info.value.details} == {"criticality", "internet_facing", "owner"}


def test_input_is_not_a_mapping() -> None:
    with pytest.raises(ContractError):
        validate_asset_attributes(["criticality", 3])  # type: ignore[arg-type]


def test_input_mapping_is_not_modified() -> None:
    attributes = {"asset_type": " web_server "}
    validate_asset_attributes(attributes)
    assert attributes == {"asset_type": " web_server "}


def test_apply_changes_only_the_given_fields(dataset: DatasetSnapshot) -> None:
    result = apply_asset_attributes(dataset, "WEB01", {"criticality": 5}, now=NOW)
    web = next(a for a in result.assets if a.asset_id == "WEB01")
    original = next(a for a in dataset.assets if a.asset_id == "WEB01")
    assert web.criticality == 5
    assert (web.name, web.asset_type, web.internet_facing, web.sensitive_data) == (
        original.name,
        original.asset_type,
        original.internet_facing,
        original.sensitive_data,
    )
    assert [a for a in result.assets if a.asset_id != "WEB01"] == [
        a for a in dataset.assets if a.asset_id != "WEB01"
    ]
    assert result.services == dataset.services
    assert result.findings == dataset.findings


def test_apply_returns_a_new_snapshot_and_leaves_the_original(dataset: DatasetSnapshot) -> None:
    before = dataset.model_dump()
    result = apply_asset_attributes(dataset, "WEB01", {"criticality": 5}, now=NOW)
    assert dataset.model_dump() == before
    assert result.dataset_id != dataset.dataset_id
    assert result.dataset_id.startswith("demo-lab-v1-")
    assert result.created_at == NOW
    validate_dataset(result)


def test_applying_the_same_attributes_twice_gives_the_same_id(dataset: DatasetSnapshot) -> None:
    first = apply_asset_attributes(dataset, "WEB01", {"criticality": 5}, now=NOW)
    second = apply_asset_attributes(first, "WEB01", {"criticality": 5}, now=NOW)
    assert second.dataset_id == first.dataset_id


def test_unknown_stays_null_when_the_draft_says_null(dataset: DatasetSnapshot) -> None:
    result = apply_asset_attributes(dataset, "DB01", {"sensitive_data": None}, now=NOW)
    db = next(a for a in result.assets if a.asset_id == "DB01")
    assert db.sensitive_data is None  # xoá một giá trị đã biết thành "chưa biết", không thành false


def test_apply_rejects_unknown_asset_empty_draft_and_bad_values(dataset: DatasetSnapshot) -> None:
    with pytest.raises(InvalidReferenceError):
        apply_asset_attributes(dataset, "NOPE", {"criticality": 3}, now=NOW)
    with pytest.raises(ContractError):
        apply_asset_attributes(dataset, "WEB01", {}, now=NOW)
    with pytest.raises(ContractError):
        apply_asset_attributes(dataset, "WEB01", {"internet_facing": "unknown"}, now=NOW)
