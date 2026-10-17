"""Facade công khai của SV1 (ARCHITECTURE.md, mục 7).

Module khác chỉ import `load_dataset` và `validate_dataset` từ đây.
"""

import json
from collections import Counter
from pathlib import Path
from typing import Any, NoReturn

from pydantic import ValidationError

from common.errors import (
    ContractError,
    InvalidReferenceError,
    ResourceNotFoundError,
    UnsupportedVersionError,
)
from common.schemas import INTERNET_ID, SCHEMA_VERSION, DatasetSnapshot

DATASET_FILENAME = "dataset.json"


def load_dataset(data_dir: Path) -> DatasetSnapshot:
    """Đọc `<data_dir>/dataset.json`, kiểm tra schema rồi kiểm tra tham chiếu.

    Raises:
        ResourceNotFoundError: thiếu file.
        UnsupportedVersionError: schema_version khác bản được hỗ trợ.
        ContractError: JSON hỏng, có NaN/Infinity, hoặc sai schema.
        InvalidReferenceError: tham chiếu giữa các bản ghi không hợp lệ.
    """
    path = Path(data_dir) / DATASET_FILENAME
    if not path.is_file():
        raise ResourceNotFoundError(
            f"Không tìm thấy {DATASET_FILENAME} trong {data_dir}.",
            [{"field": "data_dir", "record_id": str(data_dir)}],
        )
    text = path.read_text(encoding="utf-8")
    try:
        raw = json.loads(text, parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise ContractError(
            f"File JSON không hợp lệ: {exc.msg}.",
            [{"field": "<json>", "record_id": str(path)}],
        ) from exc

    version = raw.get("schema_version") if isinstance(raw, dict) else None
    if version != SCHEMA_VERSION:
        raise UnsupportedVersionError(
            f"schema_version {version!r} chưa được hỗ trợ (cần {SCHEMA_VERSION}).",
            [{"field": "schema_version", "record_id": str(version)}],
        )

    try:
        dataset = DatasetSnapshot.model_validate_json(text)
    except ValidationError as exc:
        raise ContractError("Dữ liệu không đúng schema.", _validation_details(exc)) from exc

    validate_dataset(dataset)
    return dataset


def save_dataset(dataset: DatasetSnapshot, data_dir: Path) -> Path:
    """Ghi snapshot ra `<data_dir>/dataset.json` (UTF-8, LF, có newline cuối)."""
    validate_dataset(dataset)
    directory = Path(data_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / DATASET_FILENAME
    payload = json.dumps(
        dataset.model_dump(mode="json"), ensure_ascii=False, indent=2, allow_nan=False
    )
    path.write_text(payload + "\n", encoding="utf-8", newline="\n")
    return path


def validate_dataset(dataset: DatasetSnapshot) -> None:
    """Kiểm tra ID duy nhất và mọi tham chiếu chéo. Không sửa dữ liệu.

    Raises:
        ContractError: ID trùng hoặc dùng ID dành riêng.
        InvalidReferenceError: tham chiếu tới bản ghi không tồn tại hoặc sai quan hệ.
    """
    _check_unique_ids(dataset)
    _check_references(dataset)


def _check_unique_ids(dataset: DatasetSnapshot) -> None:
    groups = (
        ("asset_id", [a.asset_id for a in dataset.assets]),
        ("service_id", [s.service_id for s in dataset.services]),
        ("finding_id", [f.finding_id for f in dataset.findings]),
        ("connection_id", [c.connection_id for c in dataset.connections]),
        ("rule_id", [r.rule_id for r in dataset.exploit_rules]),
    )
    details: list[dict[str, Any]] = []
    for field, ids in groups:
        for record_id, count in Counter(ids).items():
            if count > 1:
                details.append({"field": field, "record_id": record_id})
    if any(a.asset_id == INTERNET_ID for a in dataset.assets):
        details.append({"field": "asset_id", "record_id": INTERNET_ID})
    if details:
        raise ContractError("ID bị trùng hoặc dùng ID dành riêng.", details)


def _check_references(dataset: DatasetSnapshot) -> None:
    asset_ids = {a.asset_id for a in dataset.assets}
    services = {s.service_id: s for s in dataset.services}
    findings = {f.finding_id: f for f in dataset.findings}
    problems: list[dict[str, Any]] = []

    def bad(field: str, record_id: str, reason: str) -> None:
        problems.append({"field": field, "record_id": record_id, "reason": reason})

    for service in dataset.services:
        if service.asset_id not in asset_ids:
            bad("asset_id", service.service_id, "asset không tồn tại")

    for finding in dataset.findings:
        if finding.asset_id not in asset_ids:
            bad("asset_id", finding.finding_id, "asset không tồn tại")
        if finding.service_id is not None:
            service = services.get(finding.service_id)
            if service is None:
                bad("service_id", finding.finding_id, "service không tồn tại")
            elif service.asset_id != finding.asset_id:
                bad("service_id", finding.finding_id, "service không thuộc asset của finding")

    # Giả định: INTERNET_ID được phép làm source của connection và rule; đích phải là asset.
    for conn in dataset.connections:
        if conn.source_asset_id != INTERNET_ID and conn.source_asset_id not in asset_ids:
            bad("source_asset_id", conn.connection_id, "asset nguồn không tồn tại")
        if conn.target_asset_id not in asset_ids:
            bad("target_asset_id", conn.connection_id, "asset đích không tồn tại")
        if conn.target_service_id is not None:
            service = services.get(conn.target_service_id)
            if service is None:
                bad("target_service_id", conn.connection_id, "service không tồn tại")
            elif service.asset_id != conn.target_asset_id:
                bad("target_service_id", conn.connection_id, "service không thuộc asset đích")

    for rule in dataset.exploit_rules:
        if rule.source_asset_id != INTERNET_ID and rule.source_asset_id not in asset_ids:
            bad("source_asset_id", rule.rule_id, "asset nguồn không tồn tại")
        if rule.target_asset_id not in asset_ids:
            bad("target_asset_id", rule.rule_id, "asset đích không tồn tại")
        if rule.required_finding_id is None:
            if rule.rule_type == "exploit":
                bad("required_finding_id", rule.rule_id, "rule exploit phải có finding")
        else:
            finding = findings.get(rule.required_finding_id)
            if finding is None:
                bad("required_finding_id", rule.rule_id, "finding không tồn tại")
            elif finding.asset_id != rule.target_asset_id:
                bad("required_finding_id", rule.rule_id, "finding không thuộc asset đích")

    if problems:
        raise InvalidReferenceError("Có tham chiếu không hợp lệ trong dữ liệu.", problems)


def _reject_constant(name: str) -> NoReturn:
    raise ContractError(
        "JSON chứa giá trị không hợp lệ (NaN/Infinity).",
        [{"field": "<json>", "record_id": name}],
    )


def _validation_details(exc: ValidationError) -> list[dict[str, Any]]:
    return [
        {
            "field": ".".join(str(part) for part in err["loc"]),
            "record_id": "",
            "reason": err["msg"],
        }
        for err in exc.errors()
    ]
