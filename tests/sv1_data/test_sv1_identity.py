"""Kiểm tra định danh theo nội dung của DatasetSnapshot."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from common.schemas import DatasetSnapshot
from sv1_data.identity import (
    HASH_SUFFIX_LENGTH,
    base_id_of,
    content_hash,
    derive_dataset_id,
    with_content_id,
)
from sv1_data.service import load_dataset

SAMPLE_DIR = Path(__file__).resolve().parents[2] / "data" / "samples" / "demo_lab_v1"


@pytest.fixture
def dataset() -> DatasetSnapshot:
    return load_dataset(SAMPLE_DIR)


@pytest.fixture
def copy(dataset: DatasetSnapshot) -> DatasetSnapshot:
    return dataset.model_copy(deep=True)


def test_hash_is_a_64_character_hex_digest(dataset: DatasetSnapshot) -> None:
    value = content_hash(dataset)
    assert len(value) == 64
    int(value, 16)


def test_hash_ignores_id_creation_time_and_enrichment_time(
    dataset: DatasetSnapshot, copy: DatasetSnapshot
) -> None:
    copy.dataset_id = "another-name"
    copy.created_at = datetime(2030, 1, 1, tzinfo=UTC)
    copy.findings[0].enriched_at = datetime(2030, 1, 1, tzinfo=UTC)
    assert content_hash(copy) == content_hash(dataset)


@pytest.mark.parametrize("change", ["score", "kev", "asset", "service", "finding_removed"])
def test_hash_changes_when_real_data_changes(
    dataset: DatasetSnapshot, copy: DatasetSnapshot, change: str
) -> None:
    if change == "score":
        copy.findings[0].cvss_score = 9.9
    elif change == "kev":
        copy.findings[1].is_kev = True
    elif change == "asset":
        copy.assets[0].criticality = 5
    elif change == "service":
        copy.services[0].product_version = "9.9"
    else:
        copy.findings.pop()
    assert content_hash(copy) != content_hash(dataset)


def test_hash_changes_when_observation_time_changes(
    dataset: DatasetSnapshot, copy: DatasetSnapshot
) -> None:
    copy.findings[0].observed_at = datetime(2030, 1, 1, tzinfo=UTC)
    assert content_hash(copy) != content_hash(dataset)


def test_derived_id_has_the_base_name_and_a_short_hash(dataset: DatasetSnapshot) -> None:
    new_id = derive_dataset_id("lab", dataset)
    assert new_id == f"lab-{content_hash(dataset)[:HASH_SUFFIX_LENGTH]}"


def test_base_id_strips_only_a_hash_suffix() -> None:
    assert base_id_of("lab-3fa9c2d1b7e4") == "lab"
    assert base_id_of("lab") == "lab"
    assert base_id_of("demo-lab-v1") == "demo-lab-v1"
    assert base_id_of("lab-3FA9C2D1B7E4") == "lab-3FA9C2D1B7E4"  # chỉ nhận hex chữ thường
    assert base_id_of("lab-3fa9c2d1b7e") == "lab-3fa9c2d1b7e"  # thiếu một ký tự


def test_with_content_id_does_not_stack_suffixes(dataset: DatasetSnapshot) -> None:
    once = with_content_id(dataset, "lab")
    twice = with_content_id(once)
    assert twice.dataset_id == once.dataset_id


def test_with_content_id_returns_a_new_object_and_leaves_the_original(
    dataset: DatasetSnapshot,
) -> None:
    original_id = dataset.dataset_id
    result = with_content_id(dataset)
    assert dataset.dataset_id == original_id
    assert result is not dataset
    assert result.findings is not dataset.findings
    assert result.dataset_id != original_id


def test_same_content_gets_the_same_id_and_different_content_does_not(
    dataset: DatasetSnapshot, copy: DatasetSnapshot
) -> None:
    assert with_content_id(dataset).dataset_id == with_content_id(copy).dataset_id
    copy.findings[0].cvss_score = 9.9
    assert with_content_id(dataset).dataset_id != with_content_id(copy).dataset_id
