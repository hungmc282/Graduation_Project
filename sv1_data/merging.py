"""Conservative scanner merge: identical models deduplicate, conflicts fail."""

from typing import TypeVar

from pydantic import BaseModel

from common.errors import ContractError

Record = TypeVar("Record", bound=BaseModel)


def merge_record(
    records: dict[str, Record],
    origins: dict[str, str],
    record_id: str,
    value: Record,
    origin: str,
) -> bool:
    """Return True for an exact duplicate. Never choose a conflicting observation."""
    if record_id not in records:
        records[record_id] = value
        origins[record_id] = origin
        return False
    before, after = records[record_id].model_dump(), value.model_dump()
    fields = sorted(key for key in before if before[key] != after[key])
    if fields:
        raise ContractError(
            f"Xung đột bản ghi {record_id}: {origins[record_id]} và {origin}.",
            [
                {
                    "field": key,
                    "record_id": record_id,
                    "sources": [origins[record_id], origin],
                    "reason": "Cùng ID nhưng khác nội dung; cần chọn/sửa nguồn đầu vào.",
                }
                for key in fields
            ],
        )
    return True
