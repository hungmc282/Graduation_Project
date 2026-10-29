"""Kiểm tra bộ sinh dữ liệu giả lập: tái lập, hợp lệ, đúng hình dạng và phân bố."""

import json
from collections import Counter
from datetime import datetime
from pathlib import Path

import pytest

from common.errors import ContractError
from common.schemas import INTERNET_ID, DatasetSnapshot
from sv1_data.service import load_dataset, save_dataset, validate_dataset
from sv1_data.synthetic import MANIFEST_FILENAME, generate_dataset, generate_scenarios, main


def prefix_counts(dataset: DatasetSnapshot) -> dict[str, int]:
    return dict(Counter(a.asset_id.rstrip("0123456789") for a in dataset.assets))


def inbound_sources(dataset: DatasetSnapshot) -> dict[str, set[str]]:
    inbound: dict[str, set[str]] = {}
    for connection in dataset.connections:
        inbound.setdefault(connection.target_asset_id, set()).add(connection.source_asset_id)
    return inbound


@pytest.fixture(scope="module")
def big() -> DatasetSnapshot:
    return generate_dataset(seed=42, n_assets=200)


def test_same_seed_gives_identical_files(tmp_path: Path) -> None:
    first = generate_dataset(seed=1, n_assets=10)
    second = generate_dataset(seed=1, n_assets=10)
    assert first == second
    path_a = save_dataset(first, tmp_path / "a")
    path_b = save_dataset(second, tmp_path / "b")
    assert path_a.read_bytes() == path_b.read_bytes()


def test_different_seed_gives_different_dataset() -> None:
    first = generate_dataset(seed=1, n_assets=50)
    second = generate_dataset(seed=2, n_assets=50)
    assert first != second
    assert [f.cvss_score for f in first.findings] != [f.cvss_score for f in second.findings]


def test_tier_counts_for_ten_assets() -> None:
    assert prefix_counts(generate_dataset(seed=1, n_assets=10)) == {
        "WEB": 2,
        "APP": 3,
        "DB": 2,
        "OTH": 3,
    }


@pytest.mark.parametrize("size", [4, 5, 10, 50, 200])
def test_generated_dataset_is_valid_for_any_size(size: int) -> None:
    dataset = generate_dataset(seed=42, n_assets=size)
    validate_dataset(dataset)
    assert len(dataset.assets) == size
    assert len(dataset.services) == size


def test_too_few_assets_and_naive_timestamp_rejected() -> None:
    with pytest.raises(ContractError):
        generate_dataset(seed=1, n_assets=3)
    with pytest.raises(ContractError):
        generate_dataset(seed=1, n_assets=10, created_at=datetime(2026, 10, 1))


def test_everything_is_marked_synthetic(big: DatasetSnapshot) -> None:
    assert big.source == "synthetic"
    assert all(f.source == "synthetic" for f in big.findings)
    assert all(f.vulnerability_id.startswith("SYN-") for f in big.findings)
    assert all("synthetic" in " ".join(f.evidence) for f in big.findings)


def test_tier_attributes(big: DatasetSnapshot) -> None:
    for asset in big.assets:
        tier = asset.asset_id.rstrip("0123456789")
        assert asset.internet_facing is (tier == "WEB")
        if tier == "DB":
            assert asset.sensitive_data is True
            assert asset.criticality in (None, 4, 5)
        if tier == "OTH":
            assert asset.criticality in (None, 1, 2)


def test_attack_chain_is_reachable_through_every_tier(big: DatasetSnapshot) -> None:
    inbound = inbound_sources(big)
    webs = {a.asset_id for a in big.assets if a.asset_id.startswith("WEB")}
    apps = {a.asset_id for a in big.assets if a.asset_id.startswith("APP")}
    dbs = {a.asset_id for a in big.assets if a.asset_id.startswith("DB")}
    assert all(INTERNET_ID in inbound[w] for w in webs)
    assert all(inbound[a] & webs for a in apps)
    assert all(inbound[d] & apps for d in dbs)


def test_connection_count_grows_roughly_linearly(big: DatasetSnapshot) -> None:
    assert len(big.connections) <= 3 * len(big.assets)


def test_some_connections_are_blocked_but_most_are_allowed(big: DatasetSnapshot) -> None:
    blocked = sum(1 for c in big.connections if not c.allowed)
    assert 0 < blocked < len(big.connections) * 0.2


def test_exploit_rules_are_left_to_sv2(big: DatasetSnapshot) -> None:
    assert big.exploit_rules == []


def test_score_distribution_resembles_calibration_source(big: DatasetSnapshot) -> None:
    findings = big.findings
    total = len(findings)
    assert 600 <= total <= 2000
    kev = sum(1 for f in findings if f.is_kev)
    critical = sum(1 for f in findings if f.cvss_score is not None and f.cvss_score >= 9)
    high_epss = sum(1 for f in findings if (f.epss_probability or 0) >= 0.5)
    missing = sum(1 for f in findings if f.cvss_score is None)
    assert 0 < kev / total < 0.05
    assert 0.08 < critical / total < 0.30
    assert 0.04 < high_epss / total < 0.20
    assert missing / total < 0.04


def test_missing_scores_are_all_null_together(big: DatasetSnapshot) -> None:
    for f in big.findings:
        unknown = (f.cvss_score is None, f.epss_probability is None, f.is_kev is None)
        assert len(set(unknown)) == 1


def test_known_exploited_vulnerabilities_have_high_epss(big: DatasetSnapshot) -> None:
    assert all((f.epss_probability or 0) >= 0.5 for f in big.findings if f.is_kev)


def test_vulnerability_scores_are_the_same_on_every_asset(big: DatasetSnapshot) -> None:
    seen: dict[str, tuple[float | None, float | None, bool | None]] = {}
    for f in big.findings:
        values = (f.cvss_score, f.epss_probability, f.is_kev)
        assert seen.setdefault(f.vulnerability_id, values) == values


def test_scenarios_are_written_reloadable_and_reproducible(tmp_path: Path) -> None:
    manifest = generate_scenarios(tmp_path, seed=7, sizes=(5, 12))
    assert [m["assets"] for m in manifest] == [5, 12]
    for item in manifest:
        dataset = load_dataset(tmp_path / item["directory"])
        assert len(dataset.assets) == item["assets"]
        assert len(dataset.findings) == item["findings"]
    written = json.loads((tmp_path / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    assert written["seed"] == 7
    assert len(written["scenarios"]) == 2

    before = (tmp_path / "synthetic_12" / "dataset.json").read_bytes()
    generate_scenarios(tmp_path, seed=7, sizes=(5, 12))
    assert (tmp_path / "synthetic_12" / "dataset.json").read_bytes() == before


def test_command_line(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--out", str(tmp_path), "--seed", "3", "--sizes", "5", "8"]) == 0
    assert "synthetic_5" in capsys.readouterr().out
    assert (tmp_path / "synthetic_8" / "dataset.json").is_file()

    assert main(["--out", str(tmp_path), "--sizes", "2"]) == 1
    assert "LỖI" in capsys.readouterr().err
