"""Kiểm tra lịch sử quét: so sánh hai snapshot và kho lưu các lần chạy."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from common.errors import ResourceNotFoundError
from common.schemas import Connection, DatasetSnapshot, Service
from sv1_data.history import INDEX_FILENAME, ScanHistory, diff_datasets
from sv1_data.service import load_dataset

SAMPLE_DIR = Path(__file__).resolve().parents[2] / "data" / "samples" / "demo_lab_v1"


@pytest.fixture
def old() -> DatasetSnapshot:
    return load_dataset(SAMPLE_DIR)


@pytest.fixture
def new(old: DatasetSnapshot) -> DatasetSnapshot:
    return old.model_copy(deep=True)


def test_identical_snapshots_have_empty_diff(old: DatasetSnapshot, new: DatasetSnapshot) -> None:
    diff = diff_datasets(old, new)
    assert diff.is_empty()
    assert diff.persisting_findings == 4
    assert diff.newly_kev == []


def test_added_and_removed_findings(old: DatasetSnapshot, new: DatasetSnapshot) -> None:
    removed = new.findings.pop()  # F-TEST-001
    new.findings.append(new.findings[0].model_copy(update={"finding_id": "F-NEW-001"}))
    diff = diff_datasets(old, new)
    assert diff.removed_findings == [removed.finding_id]
    assert diff.added_findings == ["F-NEW-001"]
    assert diff.persisting_findings == 3
    assert not diff.is_empty()


def test_changed_cvss_is_reported_with_old_and_new_value(
    old: DatasetSnapshot, new: DatasetSnapshot
) -> None:
    new.findings[0].cvss_score = 9.9
    diff = diff_datasets(old, new)
    assert diff.changed_findings == {"F-WEB-001": {"cvss_score": (8.8, 9.9)}}


def test_finding_becoming_kev_is_flagged(old: DatasetSnapshot, new: DatasetSnapshot) -> None:
    new.findings[1].is_kev = True  # F-APP-001: false -> true
    diff = diff_datasets(old, new)
    assert diff.newly_kev == ["F-APP-001"]  # F-WEB-001 đã là KEV từ trước nên không có mặt


def test_unknown_kev_becoming_true_counts_as_newly_kev(
    old: DatasetSnapshot, new: DatasetSnapshot
) -> None:
    old.findings[1].is_kev = None
    new.findings[1].is_kev = True
    assert diff_datasets(old, new).newly_kev == ["F-APP-001"]


def test_kev_removal_is_a_change_but_not_newly_kev(
    old: DatasetSnapshot, new: DatasetSnapshot
) -> None:
    new.findings[0].is_kev = False
    diff = diff_datasets(old, new)
    assert diff.newly_kev == []
    assert diff.changed_findings["F-WEB-001"]["is_kev"] == (True, False)


def test_small_epss_noise_is_ignored_but_large_change_is_not(
    old: DatasetSnapshot, new: DatasetSnapshot
) -> None:
    new.findings[0].epss_probability = 0.725  # 0.72 -> 0.725
    assert diff_datasets(old, new).is_empty()
    assert (
        "epss_probability"
        in diff_datasets(old, new, epss_tolerance=0.0).changed_findings["F-WEB-001"]
    )
    new.findings[0].epss_probability = 0.80
    assert diff_datasets(old, new).changed_findings["F-WEB-001"]["epss_probability"] == (0.72, 0.8)


def test_epss_changing_between_unknown_and_known_is_always_reported(
    old: DatasetSnapshot, new: DatasetSnapshot
) -> None:
    old.findings[0].epss_probability = None
    new.findings[0].epss_probability = 0.001
    assert "epss_probability" in diff_datasets(old, new).changed_findings["F-WEB-001"]


def test_enrichment_timestamps_do_not_count_as_changes(
    old: DatasetSnapshot, new: DatasetSnapshot
) -> None:
    new.findings[0].enriched_at = datetime(2030, 1, 1, tzinfo=UTC)
    new.findings[0].observed_at = datetime(2030, 1, 1, tzinfo=UTC)
    assert diff_datasets(old, new).is_empty()


def test_asset_context_change_is_reported(old: DatasetSnapshot, new: DatasetSnapshot) -> None:
    new.assets[0].criticality = 5
    diff = diff_datasets(old, new)
    assert diff.changed_assets == {"WEB01": {"criticality": (3, 5)}}


def test_added_and_removed_assets_and_services(old: DatasetSnapshot, new: DatasetSnapshot) -> None:
    gone = new.assets.pop()  # TEST01
    new.services.pop()
    new.assets.append(new.assets[0].model_copy(update={"asset_id": "NEW01"}))
    new.services.append(
        Service(
            service_id="NEW01:tcp/22",
            asset_id="NEW01",
            protocol="tcp",
            port=22,
            product=None,
            product_version=None,
        )
    )
    diff = diff_datasets(old, new)
    assert diff.removed_assets == [gone.asset_id]
    assert diff.added_assets == ["NEW01"]
    assert diff.removed_services == ["S-TEST-8443"]
    assert diff.added_services == ["NEW01:tcp/22"]


def test_service_version_change_is_reported(old: DatasetSnapshot, new: DatasetSnapshot) -> None:
    new.services[0].product_version = "1.22.1"
    diff = diff_datasets(old, new)
    assert diff.changed_services == {"S-WEB-443": {"product_version": ("1.18.0", "1.22.1")}}


def test_topology_changes_are_reported(old: DatasetSnapshot, new: DatasetSnapshot) -> None:
    new.connections[0].allowed = False
    new.connections.pop()
    new.connections.append(
        Connection(
            connection_id="C-NEW",
            source_asset_id="APP01",
            target_asset_id="TEST01",
            target_service_id=None,
            allowed=True,
            evidence=[],
        )
    )
    diff = diff_datasets(old, new)
    assert diff.changed_connections == {"C-INTERNET-WEB": {"allowed": (True, False)}}
    assert diff.removed_connections == ["C-WEB-TEST"]
    assert diff.added_connections == ["C-NEW"]


def test_diff_does_not_modify_its_inputs(old: DatasetSnapshot, new: DatasetSnapshot) -> None:
    new.findings[0].cvss_score = 9.9
    old_before, new_before = old.model_dump(), new.model_dump()
    diff_datasets(old, new)
    assert old.model_dump() == old_before
    assert new.model_dump() == new_before


def test_summary_has_integer_counts(old: DatasetSnapshot, new: DatasetSnapshot) -> None:
    new.findings[1].is_kev = True
    summary = diff_datasets(old, new).summary()
    assert summary["newly_kev"] == 1
    assert summary["changed_findings"] == 1
    assert all(isinstance(value, int) for value in summary.values())


# ---------- kho lưu các lần chạy ----------


def test_empty_history(tmp_path: Path) -> None:
    history = ScanHistory(tmp_path / "h")
    assert history.runs() == []
    assert history.latest() is None


def test_record_two_runs_and_load_them_back(
    tmp_path: Path, old: DatasetSnapshot, new: DatasetSnapshot
) -> None:
    history = ScanHistory(tmp_path / "h")
    first = history.record(old)
    new.created_at = datetime(2026, 10, 2, tzinfo=UTC)
    new.findings[0].cvss_score = 9.9
    second = history.record(new)

    assert first.run_id != second.run_id
    assert [r.run_id for r in history.runs()] == [first.run_id, second.run_id]
    assert history.latest() == second
    assert history.load(first.run_id) == old
    assert history.load(second.run_id) == new
    assert first.counts == {"assets": 4, "services": 4, "findings": 4, "connections": 4}


def test_recording_identical_content_twice_adds_nothing(
    tmp_path: Path, old: DatasetSnapshot
) -> None:
    history = ScanHistory(tmp_path / "h")
    first = history.record(old)
    again = history.record(old)
    assert again == first
    assert len(history.runs()) == 1


def test_history_survives_a_new_instance(tmp_path: Path, old: DatasetSnapshot) -> None:
    ScanHistory(tmp_path / "h").record(old)
    reopened = ScanHistory(tmp_path / "h")
    assert len(reopened.runs()) == 1
    index = json.loads((tmp_path / "h" / INDEX_FILENAME).read_text(encoding="utf-8"))
    assert index["runs"][0]["dataset_id"] == old.dataset_id


def test_loading_unknown_run_raises(tmp_path: Path) -> None:
    with pytest.raises(ResourceNotFoundError):
        ScanHistory(tmp_path / "h").load("20260101T000000Z-deadbeef")
