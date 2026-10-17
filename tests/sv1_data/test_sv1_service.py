"""Kiểm tra facade SV1: load_dataset, save_dataset, validate_dataset."""

from pathlib import Path

import pytest

from common.errors import (
    ContractError,
    InvalidReferenceError,
    ResourceNotFoundError,
    UnsupportedVersionError,
)
from common.schemas import INTERNET_ID, Asset, Connection, DatasetSnapshot, ExploitRule
from sv1_data.service import DATASET_FILENAME, load_dataset, save_dataset, validate_dataset

SAMPLE_DIR = Path(__file__).resolve().parents[2] / "data" / "samples" / "demo_lab_v1"


@pytest.fixture
def snapshot() -> DatasetSnapshot:
    """Bản sao sâu của dữ liệu mẫu để mỗi test tự sửa mà không ảnh hưởng test khác."""
    return load_dataset(SAMPLE_DIR).model_copy(deep=True)


def make_rule(**override: object) -> ExploitRule:
    data: dict[str, object] = {
        "rule_id": "R1",
        "source_asset_id": "WEB01",
        "target_asset_id": "APP01",
        "required_finding_id": "F-APP-001",
        "required_state": "web_foothold",
        "resulting_state": "app_foothold",
        "rule_type": "exploit",
        "evidence": [],
    }
    data.update(override)
    return ExploitRule(**data)  # type: ignore[arg-type]


def reasons(exc: InvalidReferenceError) -> set[tuple[str, str]]:
    return {(d["record_id"], d["field"]) for d in exc.details}


def test_load_sample_dataset(snapshot: DatasetSnapshot) -> None:
    assert snapshot.dataset_id == "demo-lab-v1"
    assert snapshot.source == "synthetic"
    assert len(snapshot.assets) == 4
    assert len(snapshot.services) == 4
    assert len(snapshot.findings) == 4
    assert snapshot.exploit_rules == []


def test_sample_has_decoy_server_outside_path_to_data(snapshot: DatasetSnapshot) -> None:
    by_id = {f.finding_id: f for f in snapshot.findings}
    assert by_id["F-TEST-001"].cvss_score == 9.8
    assert all(f.cvss_score < 9.8 for f in snapshot.findings if f.finding_id != "F-TEST-001")
    assert not any(c.source_asset_id == "TEST01" for c in snapshot.connections)


def test_save_then_load_round_trip(tmp_path: Path, snapshot: DatasetSnapshot) -> None:
    save_dataset(snapshot, tmp_path)
    assert load_dataset(tmp_path) == snapshot


def test_missing_file_raises_not_found(tmp_path: Path) -> None:
    with pytest.raises(ResourceNotFoundError):
        load_dataset(tmp_path)


def test_unsupported_schema_version(tmp_path: Path, snapshot: DatasetSnapshot) -> None:
    path = save_dataset(snapshot, tmp_path)
    text = path.read_text(encoding="utf-8")
    assert '"schema_version": "1.0.0"' in text
    path.write_text(
        text.replace('"schema_version": "1.0.0"', '"schema_version": "2.0.0"'), encoding="utf-8"
    )
    with pytest.raises(UnsupportedVersionError):
        load_dataset(tmp_path)


def test_nan_in_json_rejected(tmp_path: Path, snapshot: DatasetSnapshot) -> None:
    path = save_dataset(snapshot, tmp_path)
    text = path.read_text(encoding="utf-8")
    assert '"cvss_score": 8.8' in text
    path.write_text(text.replace('"cvss_score": 8.8', '"cvss_score": NaN'), encoding="utf-8")
    with pytest.raises(ContractError):
        load_dataset(tmp_path)


def test_broken_json_rejected(tmp_path: Path) -> None:
    (tmp_path / DATASET_FILENAME).write_text("{not json", encoding="utf-8")
    with pytest.raises(ContractError):
        load_dataset(tmp_path)


def test_wrong_type_in_file_rejected(tmp_path: Path, snapshot: DatasetSnapshot) -> None:
    path = save_dataset(snapshot, tmp_path)
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace('"port": 443', '"port": "443"'), encoding="utf-8")
    with pytest.raises(ContractError):
        load_dataset(tmp_path)


def test_validate_accepts_sample(snapshot: DatasetSnapshot) -> None:
    validate_dataset(snapshot)


def test_finding_with_unknown_asset(snapshot: DatasetSnapshot) -> None:
    snapshot.findings[0].asset_id = "NOPE"
    with pytest.raises(InvalidReferenceError) as info:
        validate_dataset(snapshot)
    assert ("F-WEB-001", "asset_id") in reasons(info.value)


def test_finding_with_unknown_service(snapshot: DatasetSnapshot) -> None:
    snapshot.findings[0].service_id = "S-NOPE"
    with pytest.raises(InvalidReferenceError) as info:
        validate_dataset(snapshot)
    assert ("F-WEB-001", "service_id") in reasons(info.value)


def test_finding_service_must_belong_to_same_asset(snapshot: DatasetSnapshot) -> None:
    snapshot.findings[0].service_id = "S-DB-5432"  # service của DB01, finding thuộc WEB01
    with pytest.raises(InvalidReferenceError) as info:
        validate_dataset(snapshot)
    assert ("F-WEB-001", "service_id") in reasons(info.value)


def test_finding_without_service_is_allowed(snapshot: DatasetSnapshot) -> None:
    snapshot.findings[0].service_id = None
    validate_dataset(snapshot)


def test_service_with_unknown_asset(snapshot: DatasetSnapshot) -> None:
    snapshot.services[0].asset_id = "NOPE"
    with pytest.raises(InvalidReferenceError) as info:
        validate_dataset(snapshot)
    assert ("S-WEB-443", "asset_id") in reasons(info.value)


def test_all_problems_reported_together(snapshot: DatasetSnapshot) -> None:
    snapshot.findings[0].asset_id = "NOPE"
    snapshot.services[0].asset_id = "NOPE"
    with pytest.raises(InvalidReferenceError) as info:
        validate_dataset(snapshot)
    assert len(info.value.details) >= 2


def test_duplicate_ids_rejected(snapshot: DatasetSnapshot) -> None:
    snapshot.assets.append(snapshot.assets[0].model_copy())
    with pytest.raises(ContractError) as info:
        validate_dataset(snapshot)
    assert {"field": "asset_id", "record_id": "WEB01"} in info.value.details


def test_internet_id_reserved(snapshot: DatasetSnapshot) -> None:
    snapshot.assets.append(
        Asset(
            asset_id=INTERNET_ID,
            name="x",
            asset_type=None,
            internet_facing=None,
            criticality=None,
            sensitive_data=None,
        )
    )
    with pytest.raises(ContractError):
        validate_dataset(snapshot)


def test_connection_target_must_be_asset(snapshot: DatasetSnapshot) -> None:
    snapshot.connections.append(
        Connection(
            connection_id="C-BAD",
            source_asset_id="WEB01",
            target_asset_id=INTERNET_ID,
            target_service_id=None,
            allowed=True,
            evidence=[],
        )
    )
    with pytest.raises(InvalidReferenceError) as info:
        validate_dataset(snapshot)
    assert ("C-BAD", "target_asset_id") in reasons(info.value)


def test_connection_service_must_belong_to_target(snapshot: DatasetSnapshot) -> None:
    snapshot.connections[1].target_service_id = "S-DB-5432"  # C-WEB-APP trỏ service của DB01
    with pytest.raises(InvalidReferenceError) as info:
        validate_dataset(snapshot)
    assert ("C-WEB-APP", "target_service_id") in reasons(info.value)


def test_valid_exploit_rule_accepted(snapshot: DatasetSnapshot) -> None:
    snapshot.exploit_rules.append(make_rule())
    validate_dataset(snapshot)


def test_exploit_rule_finding_must_belong_to_target(snapshot: DatasetSnapshot) -> None:
    snapshot.exploit_rules.append(make_rule(required_finding_id="F-DB-001"))
    with pytest.raises(InvalidReferenceError) as info:
        validate_dataset(snapshot)
    assert ("R1", "required_finding_id") in reasons(info.value)


def test_exploit_rule_requires_finding(snapshot: DatasetSnapshot) -> None:
    snapshot.exploit_rules.append(make_rule(required_finding_id=None))
    with pytest.raises(InvalidReferenceError):
        validate_dataset(snapshot)


def test_trust_rule_may_omit_finding(snapshot: DatasetSnapshot) -> None:
    snapshot.exploit_rules.append(make_rule(required_finding_id=None, rule_type="trust"))
    validate_dataset(snapshot)
