"""Offline two-run walkthrough: python -m sv1_data.demo."""

import argparse
import hashlib
import json
import tempfile
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from common.errors import AppError, ContractError
from sv1_data.history import ScanHistory, diff_datasets
from sv1_data.pipeline import load_config, run_pipeline
from sv1_data.service import load_dataset

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = PROJECT_ROOT / "data/samples/sv1_milestone1"


def _view(snapshot):
    alpha = next(f for f in snapshot.findings if f.vulnerability_id == "CVE-2099-0001")
    return {
        "source": snapshot.source,
        "finding_ids": sorted(f.finding_id for f in snapshot.findings),
        "alpha_epss": alpha.epss_probability,
        "alpha_is_kev": alpha.is_kev,
        "db_criticality": next(
            a.criticality for a in snapshot.assets if a.asset_id == "DB01"
        ),
        "web_version": next(
            s.product_version
            for s in snapshot.services
            if s.service_id == "WEB01:tcp/443"
        ),
    }


def run_demo(output_dir: Path, fixture_dir: Path = FIXTURE_DIR) -> dict:
    """Run actual pipeline twice, reload output/history, compare independent oracle.

    Requires a fresh folder, so existing user results are never overwritten.
    No HTTP clients or download helpers are replaced by this runner.
    """
    output_dir = Path(output_dir).resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ContractError(
            "Chọn thư mục đầu ra mới hoặc rỗng; demo không ghi đè kết quả cũ."
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    fixture_dir = Path(fixture_dir).resolve()
    expected = json.loads((fixture_dir / "expected.json").read_text(encoding="utf-8"))
    snapshots, counts, reports = [], [], []
    for number in (1, 2):
        config, base_dir = load_config(fixture_dir / f"run{number}/config.json")
        config = config.model_copy(
            update={
                "output_dir": str(output_dir / f"run{number}"),
                "history_dir": str(output_dir / "history"),
            }
        )
        result = run_pipeline(
            config, base_dir, now=datetime(2026, 10, 28 + number, 9, tzinfo=UTC)
        )
        reloaded = load_dataset(result.dataset_path.parent)
        if reloaded != result.dataset:
            raise ContractError("Snapshot nạp lại khác dữ liệu vừa xuất.")
        if any(f.source != "synthetic" for f in reloaded.findings):
            raise ContractError("Finding demo phải mang nguồn synthetic.")
        snapshots.append(reloaded)
        counts.append(result.report["counts"])
        reports.append(result.report)
    history = ScanHistory(output_dir / "history")
    runs = history.runs()
    if len(runs) != 2 or any(
        history.load(r.run_id) != s for r, s in zip(runs, snapshots)
    ):
        raise ContractError("Lịch sử không khớp hai snapshots đã xuất.")
    diff = diff_datasets(*snapshots)
    observed = {
        "counts": counts[0],
        "run1": _view(snapshots[0]),
        "run2": _view(snapshots[1]),
        "diff": {
            "summary": diff.summary(),
            **{
                key: getattr(diff, key)
                for key in (
                    "added_findings",
                    "removed_findings",
                    "newly_kev",
                    "changed_findings",
                    "changed_assets",
                    "changed_services",
                )
            },
        },
    }
    observed = json.loads(json.dumps(observed))
    passed = (
        observed == expected
        and counts[1] == expected["counts"]
        and reports[1]["history"]["diff"] == expected["diff"]["summary"]
    )
    payload = {
        "passed": passed,
        "observed": observed,
        "expected": expected,
        "full_diff": asdict(diff),
        "history_runs": [asdict(r) for r in runs],
    }
    (output_dir / "verification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    manifest = {
        str(p.relative_to(fixture_dir)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(fixture_dir.rglob("*"))
        if p.is_file()
    }
    (output_dir / "input-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    if not passed:
        raise ContractError(
            f"Kết quả không khớp expected.json; xem {output_dir}/verification.json."
        )
    return payload


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Chạy và kiểm chứng hai lần nhập dữ liệu SV1 offline."
    )
    parser.add_argument("--output", type=Path, help="Thư mục mới/rỗng để lưu kết quả")
    args = parser.parse_args(argv)
    if args.output is None:
        root = PROJECT_ROOT / "outputs/sv1-milestone1"
        root.mkdir(parents=True, exist_ok=True)
        output = Path(tempfile.mkdtemp(prefix="demo-", dir=root))
    else:
        output = args.output
    try:
        result = run_demo(output)
    except (AppError, OSError) as error:
        print(f"Không hoàn thành demo: {error}")
        return 1
    print("ĐẠT: nhập → enrichment offline → xuất → nạp lại → lịch sử → so sánh đáp án.")
    print("Mỗi lần: 2 tài sản, 2 dịch vụ, 3 findings. Toàn bộ dữ liệu là synthetic.")
    print("Lần hai: thêm 1, mất dấu 1, đổi 1 finding; đổi 1 tài sản và 1 dịch vụ.")
    print(f"Chi tiết: {output.resolve() / 'verification.json'}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
