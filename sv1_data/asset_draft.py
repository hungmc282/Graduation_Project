"""Kiểm tra bản nháp thuộc tính tài sản do LLM đề xuất (ARCHITECTURE.md, mục 6.7).

SV4 cho LLM trích xuất bản nháp từ mô tả tài sản; SV1 là nơi kiểm tra trước khi tạo snapshot mới
(người dùng phải xác nhận bản nháp trước khi gọi `apply_asset_attributes`). Quy tắc:

- Chỉ cho phép các thuộc tính đã định nghĩa: asset_type, internet_facing, criticality,
  sensitive_data. `asset_id` và `name` do người dùng cung cấp, LLM không được đề xuất.
- Đầu ra của LLM không đáng tin: kiểm tra kiểu NGHIÊM NGẶT, không ép kiểu. Chuỗi như "true",
  "yes" hay "unknown" bị từ chối, nên "không rõ" không bao giờ bị coi là false.
- Giá trị null nghĩa là chưa biết và được giữ nguyên. Không đoán `criticality`.
"""

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from common.errors import ContractError, InvalidReferenceError
from common.schemas import Asset, DatasetSnapshot
from sv1_data.identity import with_content_id
from sv1_data.service import validate_dataset

ALLOWED_ATTRIBUTES = ("asset_type", "internet_facing", "criticality", "sensitive_data")
_BOOLEAN_ATTRIBUTES = ("internet_facing", "sensitive_data")


def validate_asset_attributes(attributes: Mapping[str, Any]) -> dict[str, Any]:
    """Kiểm tra và làm sạch các thuộc tính được đề xuất. Trả về dict mới, không sửa đầu vào.

    Raises:
        ContractError: có thuộc tính không được phép hoặc giá trị sai kiểu/miền; `details` liệt
            kê tất cả vấn đề cùng lúc.
    """
    if not isinstance(attributes, Mapping):
        raise ContractError(
            "Bản nháp thuộc tính phải là một đối tượng (mapping).",
            [{"field": "proposed_attributes", "record_id": ""}],
        )
    problems: list[dict[str, Any]] = []
    cleaned: dict[str, Any] = {}

    for name in attributes:
        if name not in ALLOWED_ATTRIBUTES:
            problems.append(
                {"field": str(name), "record_id": "", "reason": "thuộc tính không được phép"}
            )
    for name in ALLOWED_ATTRIBUTES:
        if name not in attributes:
            continue
        value = attributes[name]
        reason = _check(name, value)
        if reason is not None:
            problems.append({"field": name, "record_id": "", "reason": reason})
        else:
            cleaned[name] = value.strip() if isinstance(value, str) else value

    if problems:
        raise ContractError("Bản nháp thuộc tính không hợp lệ.", problems)
    return cleaned


def apply_asset_attributes(
    dataset: DatasetSnapshot,
    asset_id: str,
    attributes: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> DatasetSnapshot:
    """Áp các thuộc tính đã được người dùng xác nhận vào một tài sản, trả về snapshot MỚI.

    Snapshot gốc không bị sửa. Snapshot mới có `dataset_id` theo nội dung (xem identity.py) và
    `created_at` là thời điểm áp dụng.

    Raises:
        InvalidReferenceError: asset_id không tồn tại trong snapshot.
        ContractError: thuộc tính không hợp lệ hoặc không có thuộc tính nào để áp.
    """
    cleaned = validate_asset_attributes(attributes)
    if not cleaned:
        raise ContractError(
            "Không có thuộc tính nào để áp dụng.",
            [{"field": "proposed_attributes", "record_id": asset_id}],
        )
    target = next((a for a in dataset.assets if a.asset_id == asset_id), None)
    if target is None:
        raise InvalidReferenceError(
            f"Tài sản {asset_id} không tồn tại trong snapshot.",
            [{"field": "asset_id", "record_id": asset_id}],
        )

    updated = Asset(**{**target.model_dump(), **cleaned})
    assets = [updated if a.asset_id == asset_id else a for a in dataset.assets]
    snapshot = dataset.model_copy(
        update={"assets": assets, "created_at": now or datetime.now(UTC)}, deep=True
    )
    result = with_content_id(snapshot)
    validate_dataset(result)
    return result


def _check(name: str, value: Any) -> str | None:
    """Trả về lý do bị từ chối, hoặc None nếu hợp lệ."""
    if value is None:
        return None  # null nghĩa là chưa biết
    if name in _BOOLEAN_ATTRIBUTES:
        if isinstance(value, bool):
            return None
        return "phải là true, false hoặc null (chuỗi như 'unknown' không được coi là false)"
    if name == "criticality":
        if isinstance(value, bool) or not isinstance(value, int):
            return "phải là số nguyên từ 1 đến 5 hoặc null"
        return None if 1 <= value <= 5 else "phải nằm trong khoảng 1 đến 5"
    # asset_type
    if not isinstance(value, str) or not value.strip():
        return "phải là chuỗi không rỗng hoặc null"
    if not re.fullmatch(r"[A-Za-z0-9_\- ]{1,64}", value.strip()):
        return "chỉ gồm chữ, số, gạch dưới, gạch nối, khoảng trắng và dài tối đa 64 ký tự"
    return None
