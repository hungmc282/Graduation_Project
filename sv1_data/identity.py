"""Định danh theo nội dung cho DatasetSnapshot (ARCHITECTURE.md, mục 6.4).

Quy tắc của hợp đồng: đổi dữ liệu thì phải đổi `dataset_id`, và không tái sử dụng một ID cho nội
dung khác. Vì vậy `dataset_id` được ghép từ tên gốc và mã băm nội dung:

    dvwa-lab-v1-3fa9c2d1b7e4

Mã băm KHÔNG tính `dataset_id`, `created_at` và `enriched_at` của từng finding (ba giá trị này
đổi mỗi lần chạy nhưng không phải dữ liệu mới). Nhờ đó chạy lại với cùng đầu vào cho cùng ID,
còn thay đổi thật (finding mới, điểm KEV hoặc EPSS khác, thuộc tính tài sản khác) cho ID mới.
"""

import hashlib
import json
import re
from typing import Any

from common.schemas import DatasetSnapshot

HASH_SUFFIX_LENGTH = 12
_SUFFIX = re.compile("-[0-9a-f]{" + str(HASH_SUFFIX_LENGTH) + "}$")


def content_hash(dataset: DatasetSnapshot) -> str:
    """Mã băm SHA-256 (64 ký tự hex) của nội dung, bỏ qua các trường đổi theo thời điểm chạy."""
    payload: dict[str, Any] = dataset.model_dump(mode="json")
    payload.pop("dataset_id", None)
    payload.pop("created_at", None)
    for finding in payload["findings"]:
        finding.pop("enriched_at", None)
    text = json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    )
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def base_id_of(dataset_id: str) -> str:
    """Bỏ hậu tố mã băm (nếu có) để lấy lại tên gốc, tránh nối hậu tố hai lần."""
    return _SUFFIX.sub("", dataset_id)


def derive_dataset_id(base_id: str, dataset: DatasetSnapshot) -> str:
    return f"{base_id_of(base_id)}-{content_hash(dataset)[:HASH_SUFFIX_LENGTH]}"


def with_content_id(dataset: DatasetSnapshot, base_id: str | None = None) -> DatasetSnapshot:
    """Trả về snapshot có `dataset_id` theo nội dung. Không sửa đối tượng gốc."""
    new_id = derive_dataset_id(base_id or dataset.dataset_id, dataset)
    return dataset.model_copy(update={"dataset_id": new_id}, deep=True)
