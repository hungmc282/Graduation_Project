"""Lịch sử quét: so sánh hai lần chạy và lưu các lần chạy (đề tài mục 5, module 2).

`diff_datasets(cu, moi)` cho biết giữa hai snapshot có gì thay đổi: finding mới, finding không
còn xuất hiện, thay đổi điểm CVSS/EPSS/KEV, thay đổi ngữ cảnh tài sản, dịch vụ và kết nối.
Đây là đầu vào cho việc tính lại thứ tự ưu tiên khi dữ liệu thay đổi (đề tài mục 13, điểm 5).

Lưu ý khi đọc kết quả: finding "không còn xuất hiện" có thể do đã khắc phục, nhưng cũng có thể do
lần quét sau không phủ hết phạm vi. Module này không kết luận là đã khắc phục.

`ScanHistory` lưu mỗi lần chạy thành `<root>/runs/<run_id>/dataset.json` và danh sách các lần
chạy trong `<root>/index.json`. Ghi cùng một nội dung hai lần liên tiếp không tạo bản trùng.
"""

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import UTC
from pathlib import Path
from typing import Any

from common.errors import ResourceNotFoundError
from common.schemas import DatasetSnapshot
from sv1_data.service import DATASET_FILENAME, load_dataset

DEFAULT_EPSS_TOLERANCE = 0.01
INDEX_FILENAME = "index.json"

_FINDING_FIELDS = ("service_id", "cvss_score", "epss_probability", "is_kev")
_ASSET_FIELDS = ("name", "asset_type", "internet_facing", "criticality", "sensitive_data")
_SERVICE_FIELDS = ("asset_id", "protocol", "port", "product", "product_version")
_CONNECTION_FIELDS = ("source_asset_id", "target_asset_id", "target_service_id", "allowed")


@dataclass(frozen=True)
class DatasetDiff:
    """Khác biệt giữa hai snapshot. Danh sách chứa ID, đã sắp xếp để kết quả ổn định."""

    added_findings: list[str] = field(default_factory=list)
    removed_findings: list[str] = field(default_factory=list)
    persisting_findings: int = 0
    changed_findings: dict[str, dict[str, tuple[Any, Any]]] = field(default_factory=dict)
    newly_kev: list[str] = field(default_factory=list)
    added_assets: list[str] = field(default_factory=list)
    removed_assets: list[str] = field(default_factory=list)
    changed_assets: dict[str, dict[str, tuple[Any, Any]]] = field(default_factory=dict)
    added_services: list[str] = field(default_factory=list)
    removed_services: list[str] = field(default_factory=list)
    changed_services: dict[str, dict[str, tuple[Any, Any]]] = field(default_factory=dict)
    added_connections: list[str] = field(default_factory=list)
    removed_connections: list[str] = field(default_factory=list)
    changed_connections: dict[str, dict[str, tuple[Any, Any]]] = field(default_factory=dict)

    def is_empty(self) -> bool:
        return not any(
            (
                self.added_findings,
                self.removed_findings,
                self.changed_findings,
                self.added_assets,
                self.removed_assets,
                self.changed_assets,
                self.added_services,
                self.removed_services,
                self.changed_services,
                self.added_connections,
                self.removed_connections,
                self.changed_connections,
            )
        )

    def summary(self) -> dict[str, int]:
        return {
            "added_findings": len(self.added_findings),
            "removed_findings": len(self.removed_findings),
            "persisting_findings": self.persisting_findings,
            "changed_findings": len(self.changed_findings),
            "newly_kev": len(self.newly_kev),
            "added_assets": len(self.added_assets),
            "removed_assets": len(self.removed_assets),
            "changed_assets": len(self.changed_assets),
            "added_services": len(self.added_services),
            "removed_services": len(self.removed_services),
            "changed_services": len(self.changed_services),
            "added_connections": len(self.added_connections),
            "removed_connections": len(self.removed_connections),
            "changed_connections": len(self.changed_connections),
        }


def diff_datasets(
    old: DatasetSnapshot,
    new: DatasetSnapshot,
    *,
    epss_tolerance: float = DEFAULT_EPSS_TOLERANCE,
) -> DatasetDiff:
    """So sánh hai snapshot theo ID bản ghi. Không sửa dữ liệu đầu vào.

    `epss_tolerance`: chênh lệch EPSS nhỏ hơn hoặc bằng ngưỡng này bị coi là nhiễu và bỏ qua
    (EPSS thay đổi nhẹ mỗi ngày). Chuyển giữa null và có giá trị luôn được tính là thay đổi.
    """
    old_findings = {f.finding_id: f for f in old.findings}
    new_findings = {f.finding_id: f for f in new.findings}
    persisting = sorted(old_findings.keys() & new_findings.keys())

    changed_findings: dict[str, dict[str, tuple[Any, Any]]] = {}
    newly_kev: list[str] = []
    for finding_id in persisting:
        before, after = old_findings[finding_id], new_findings[finding_id]
        changes = _changes(before, after, _FINDING_FIELDS, epss_tolerance)
        if changes:
            changed_findings[finding_id] = changes
        if after.is_kev is True and before.is_kev is not True:
            newly_kev.append(finding_id)
    # Finding mới xuất hiện và đã nằm trong KEV cũng đáng chú ý, nhưng thuộc "added_findings".

    asset_added, asset_removed, asset_changed = _compare(
        {a.asset_id: a for a in old.assets}, {a.asset_id: a for a in new.assets}, _ASSET_FIELDS
    )
    service_added, service_removed, service_changed = _compare(
        {s.service_id: s for s in old.services},
        {s.service_id: s for s in new.services},
        _SERVICE_FIELDS,
    )
    conn_added, conn_removed, conn_changed = _compare(
        {c.connection_id: c for c in old.connections},
        {c.connection_id: c for c in new.connections},
        _CONNECTION_FIELDS,
    )
    return DatasetDiff(
        added_findings=sorted(new_findings.keys() - old_findings.keys()),
        removed_findings=sorted(old_findings.keys() - new_findings.keys()),
        persisting_findings=len(persisting),
        changed_findings=changed_findings,
        newly_kev=newly_kev,
        added_assets=asset_added,
        removed_assets=asset_removed,
        changed_assets=asset_changed,
        added_services=service_added,
        removed_services=service_removed,
        changed_services=service_changed,
        added_connections=conn_added,
        removed_connections=conn_removed,
        changed_connections=conn_changed,
    )


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    dataset_id: str
    created_at: str
    sha256: str
    counts: dict[str, int]


class ScanHistory:
    """Kho lưu các lần chạy trên đĩa."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)

    def runs(self) -> list[RunRecord]:
        """Các lần chạy theo thứ tự ghi nhận (cũ nhất trước)."""
        index = self._root / INDEX_FILENAME
        if not index.is_file():
            return []
        payload = json.loads(index.read_text(encoding="utf-8"))
        return [RunRecord(**item) for item in payload["runs"]]

    def latest(self) -> RunRecord | None:
        runs = self.runs()
        return runs[-1] if runs else None

    def load(self, run_id: str) -> DatasetSnapshot:
        directory = self._root / "runs" / run_id
        if not (directory / DATASET_FILENAME).is_file():
            raise ResourceNotFoundError(
                f"Không có lần chạy {run_id} trong lịch sử.",
                [{"field": "run_id", "record_id": run_id}],
            )
        return load_dataset(directory)

    def record(self, dataset: DatasetSnapshot) -> RunRecord:
        """Ghi một lần chạy. Nội dung giống hệt lần chạy gần nhất thì trả về bản ghi cũ."""
        payload = _serialize(dataset)
        digest = hashlib.sha256(payload).hexdigest()
        latest = self.latest()
        if latest is not None and latest.sha256 == digest:
            return latest

        stamp = dataset.created_at.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
        run_id = f"{stamp}-{digest[:8]}"
        directory = self._root / "runs" / run_id
        directory.mkdir(parents=True, exist_ok=True)
        (directory / DATASET_FILENAME).write_bytes(payload)

        record = RunRecord(
            run_id=run_id,
            dataset_id=dataset.dataset_id,
            created_at=dataset.created_at.astimezone(UTC).isoformat(),
            sha256=digest,
            counts={
                "assets": len(dataset.assets),
                "services": len(dataset.services),
                "findings": len(dataset.findings),
                "connections": len(dataset.connections),
            },
        )
        runs = [r for r in self.runs() if r.run_id != run_id] + [record]
        self._write_index(runs)
        return record

    def _write_index(self, runs: list[RunRecord]) -> None:
        self._root.mkdir(parents=True, exist_ok=True)
        index = self._root / INDEX_FILENAME
        temp = index.with_name(index.name + ".tmp")
        body = {"runs": [record.__dict__ for record in runs]}
        temp.write_text(
            json.dumps(body, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        os.replace(temp, index)


def _serialize(dataset: DatasetSnapshot) -> bytes:
    """Cùng định dạng với `save_dataset` (UTF-8, LF, có newline cuối)."""
    text = json.dumps(
        dataset.model_dump(mode="json"), ensure_ascii=False, indent=2, allow_nan=False
    )
    return (text + "\n").encode("utf-8")


def _compare(
    old: dict[str, Any], new: dict[str, Any], fields: tuple[str, ...]
) -> tuple[list[str], list[str], dict[str, dict[str, tuple[Any, Any]]]]:
    changed: dict[str, dict[str, tuple[Any, Any]]] = {}
    for key in sorted(old.keys() & new.keys()):
        changes = _changes(old[key], new[key], fields, None)
        if changes:
            changed[key] = changes
    return sorted(new.keys() - old.keys()), sorted(old.keys() - new.keys()), changed


def _changes(
    before: Any, after: Any, fields: tuple[str, ...], epss_tolerance: float | None
) -> dict[str, tuple[Any, Any]]:
    result: dict[str, tuple[Any, Any]] = {}
    for name in fields:
        old_value, new_value = getattr(before, name), getattr(after, name)
        if old_value == new_value:
            continue
        if (
            name == "epss_probability"
            and epss_tolerance is not None
            and old_value is not None
            and new_value is not None
            and abs(old_value - new_value) <= epss_tolerance
        ):
            continue
        result[name] = (old_value, new_value)
    return result
