"""Acceptance tests use real adapters/pipeline/history; HTTP must never occur."""

import shutil

import httpx
import pytest

from common.errors import ContractError, ResourceNotFoundError
from sv1_data.demo import FIXTURE_DIR, run_demo
from sv1_data.enrichment.cache import fetch_cached
from sv1_data.enrichment.service import EPSS_CACHE_NAME, load_threat_data


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def reject(*args, **kwargs):
        pytest.fail("Offline milestone attempted HTTP")

    monkeypatch.setattr(httpx.Client, "send", reject)


def test_two_runs_reload_history_and_expected_oracle(tmp_path):
    result = run_demo(tmp_path / "output")
    assert result["passed"]
    assert result["observed"]["diff"]["summary"]["newly_kev"] == 1
    assert (tmp_path / "output/input-manifest.json").is_file()


def test_offline_stale_cache_never_attempts_http(tmp_path):
    from datetime import UTC, datetime

    cache = FIXTURE_DIR / "run1/feeds"
    epss, kev, warnings = load_threat_data(
        cache, offline=True, now=datetime(2099, 1, 1, tzinfo=UTC)
    )
    assert epss.scores["CVE-2099-0001"].probability == 0.2
    assert "CVE-2099-0003" in kev.entries
    assert len(warnings) == 2


def test_offline_missing_cache_is_explicit_error(tmp_path):
    with pytest.raises(ResourceNotFoundError, match="Offline"):
        load_threat_data(tmp_path, offline=True)


def test_offline_corrupt_feed_fails_without_replacing_it(tmp_path):
    shutil.copytree(FIXTURE_DIR / "run1/feeds", tmp_path / "feeds")
    path = tmp_path / "feeds" / EPSS_CACHE_NAME
    path.write_bytes(b"not an EPSS CSV")
    with pytest.raises(ContractError):
        load_threat_data(tmp_path / "feeds", offline=True)
    assert path.read_bytes() == b"not an EPSS CSV"


def test_offline_does_not_invoke_supplied_client(tmp_path):
    cache = tmp_path / "feed"
    cache.write_bytes(b"fixture")
    with httpx.Client() as client:
        data, warnings = fetch_cached(
            "https://example.invalid", cache, offline=True, client=client
        )
    assert data == b"fixture" and warnings


def test_demo_preserves_existing_output(tmp_path):
    out = tmp_path / "output"
    out.mkdir()
    (out / "keep.txt").write_text("preserve")
    with pytest.raises(ContractError, match="không ghi đè"):
        run_demo(out)
    assert (out / "keep.txt").read_text() == "preserve"


def test_demo_snapshot_bytes_reproducible(tmp_path):
    run_demo(tmp_path / "a")
    run_demo(tmp_path / "b")
    for run in ("run1", "run2"):
        assert (tmp_path / "a" / run / "dataset.json").read_bytes() == (
            tmp_path / "b" / run / "dataset.json"
        ).read_bytes()


def test_demo_rejects_incorrect_expected_answer(tmp_path):
    shutil.copytree(FIXTURE_DIR, tmp_path / "fixtures")
    import json

    path = tmp_path / "fixtures/expected.json"
    expected = json.loads(path.read_text())
    expected["counts"]["findings"] = 999
    path.write_text(json.dumps(expected))
    with pytest.raises(ContractError, match="không khớp"):
        run_demo(tmp_path / "output", tmp_path / "fixtures")
