"""Kiểm tra kho lưu DatasetSnapshot (SQLite trong thư mục tạm, cùng SQL với PostgreSQL)."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import Engine

from common.errors import ContractError, InvalidReferenceError, ResourceNotFoundError
from common.schemas import Asset, DatasetSnapshot, ExploitRule, Finding
from sv1_data.db import DATABASE_URL_ENV, DatabaseError, apply_migrations, create_db_engine
from sv1_data.repository import DatasetRepository, main
from sv1_data.service import load_dataset
from sv1_data.synthetic import generate_dataset

SAMPLE_DIR = Path(__file__).resolve().parents[2] / "data" / "samples" / "demo_lab_v1"
NOW = datetime(2026, 10, 30, 8, 0, tzinfo=UTC)


@pytest.fixture
def url(tmp_path: Path) -> str:
    return f"sqlite:///{(tmp_path / 'repo.db').as_posix()}"


@pytest.fixture
def engine(url: str) -> Engine:
    engine = create_db_engine(url)
    apply_migrations(engine)
    return engine


@pytest.fixture
def repo(engine: Engine) -> DatasetRepository:
    return DatasetRepository(engine)


@pytest.fixture
def sample() -> DatasetSnapshot:
    return load_dataset(SAMPLE_DIR)


def test_save_then_load_gives_back_the_same_snapshot(
    repo: DatasetRepository, sample: DatasetSnapshot
) -> None:
    assert repo.save(sample, now=NOW) is True
    assert repo.load(sample.dataset_id) == sample


def test_a_large_snapshot_round_trips_in_the_same_order(repo: DatasetRepository) -> None:
    dataset = generate_dataset(seed=3, n_assets=50)
    repo.save(dataset)
    loaded = repo.load(dataset.dataset_id)
    assert loaded == dataset
    assert [f.finding_id for f in loaded.findings] == [f.finding_id for f in dataset.findings]
    assert [c.connection_id for c in loaded.connections] == [
        c.connection_id for c in dataset.connections
    ]


def test_saving_the_same_content_again_writes_nothing(
    repo: DatasetRepository, sample: DatasetSnapshot
) -> None:
    assert repo.save(sample, now=NOW) is True
    assert repo.save(sample, now=NOW) is False
    assert len(repo.list_datasets()) == 1


def test_only_timestamps_changing_is_not_new_content(
    repo: DatasetRepository, sample: DatasetSnapshot
) -> None:
    repo.save(sample)
    later = sample.model_copy(deep=True)
    later.created_at = datetime(2030, 1, 1, tzinfo=UTC)
    later.findings[0].enriched_at = datetime(2031, 1, 1, tzinfo=UTC)
    assert repo.save(later) is False
    assert repo.load(sample.dataset_id).created_at == sample.created_at  # bản đầu được giữ


def test_the_same_id_with_different_content_is_refused(
    repo: DatasetRepository, sample: DatasetSnapshot
) -> None:
    repo.save(sample)
    changed = sample.model_copy(deep=True)
    changed.findings[0].cvss_score = 9.9
    with pytest.raises(ContractError) as info:
        repo.save(changed)
    assert info.value.details[0]["field"] == "dataset_id"
    assert repo.load(sample.dataset_id) == sample  # dữ liệu đã lưu không bị đổi


def test_invalid_snapshots_are_refused_before_touching_the_database(
    repo: DatasetRepository, sample: DatasetSnapshot
) -> None:
    broken = sample.model_copy(deep=True)
    broken.dataset_id = "broken"
    broken.findings[0].asset_id = "NOPE"
    with pytest.raises(InvalidReferenceError):
        repo.save(broken)
    assert not repo.exists("broken")


def test_unknown_values_unicode_and_microseconds_survive(repo: DatasetRepository) -> None:
    dataset = generate_dataset(seed=4, n_assets=10)
    dataset.dataset_id = "edge-case"
    first = dataset.assets[0]
    dataset.assets[0] = Asset(
        asset_id=first.asset_id,
        name="Máy chủ tiếng Việt",
        asset_type=None,
        internet_facing=None,
        criticality=None,
        sensitive_data=None,
    )
    old = dataset.findings[0]
    dataset.findings[0] = Finding(
        finding_id=old.finding_id,
        asset_id=old.asset_id,
        service_id=None,
        vulnerability_id=old.vulnerability_id,
        cvss_score=None,
        epss_probability=None,
        is_kev=None,
        source="synthetic",
        evidence=["bằng chứng: có dấu", "line two"],
        observed_at=datetime(2026, 10, 1, 1, 2, 3, 456789, tzinfo=UTC),
        enriched_at=None,
    )
    dataset.exploit_rules.append(
        ExploitRule(
            rule_id="R1",
            source_asset_id="INTERNET",
            target_asset_id=first.asset_id,
            required_finding_id=None,
            required_state="start",
            resulting_state="foothold",
            rule_type="trust",
            evidence=["ok"],
        )
    )
    repo.save(dataset)
    loaded = repo.load("edge-case")
    assert loaded == dataset
    assert loaded.assets[0].internet_facing is None  # chưa biết vẫn là chưa biết, không thành False
    assert loaded.findings[0].is_kev is None


def test_several_datasets_can_share_asset_ids(
    repo: DatasetRepository, sample: DatasetSnapshot
) -> None:
    other = sample.model_copy(deep=True)
    other.dataset_id = "demo-lab-v2"
    other.assets[0].criticality = 5
    repo.save(sample)
    repo.save(other)
    assert repo.load("demo-lab-v1").assets[0].criticality == 3
    assert repo.load("demo-lab-v2").assets[0].criticality == 5


def test_exists_list_and_missing_dataset(repo: DatasetRepository, sample: DatasetSnapshot) -> None:
    assert not repo.exists(sample.dataset_id)
    repo.save(sample, now=NOW)
    assert repo.exists(sample.dataset_id)
    [record] = repo.list_datasets()
    assert record.dataset_id == sample.dataset_id
    assert record.source == "synthetic"
    assert record.recorded_at == NOW
    assert len(record.content_sha256) == 64
    with pytest.raises(ResourceNotFoundError):
        repo.load("nope")


def test_a_missing_migration_gives_a_helpful_error(url: str, sample: DatasetSnapshot) -> None:
    unmigrated = DatasetRepository(create_db_engine(url))
    with pytest.raises(DatabaseError) as info:
        unmigrated.save(sample)
    assert "migrate" in info.value.message


def test_command_line_save_list_and_export(
    url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    sample: DatasetSnapshot,
) -> None:
    monkeypatch.setenv(DATABASE_URL_ENV, url)
    apply_migrations(create_db_engine(url))

    assert main(["save", str(SAMPLE_DIR)]) == 0
    assert "Đã lưu demo-lab-v1" in capsys.readouterr().out
    assert main(["save", str(SAMPLE_DIR)]) == 0
    assert "Đã có sẵn" in capsys.readouterr().out
    assert main(["list"]) == 0
    assert "demo-lab-v1" in capsys.readouterr().out

    out = tmp_path / "exported"
    assert main(["export", "demo-lab-v1", str(out)]) == 0
    assert load_dataset(out) == sample
    capsys.readouterr()

    assert main(["export", "nope", str(out)]) == 1
    assert "LỖI" in capsys.readouterr().err
