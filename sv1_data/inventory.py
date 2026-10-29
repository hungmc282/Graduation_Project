"""Asset Inventory: nhập tài sản từ CSV (đề tài mục 5, module 1; ARCHITECTURE.md mục 6.1).

Định dạng CSV (dòng đầu là tiêu đề, UTF-8 có hoặc không BOM, dấu phân cách `,` `;` hoặc Tab
được tự nhận, nên file xuất từ Excel tiếng Việt vẫn đọc được):

    asset_id,name,asset_type,internet_facing,criticality,sensitive_data,addresses

- Bắt buộc: `asset_id`, `name`. Các cột khác là tuỳ chọn; ô trống nghĩa là chưa biết (null).
- `internet_facing`, `sensitive_data`: true/false (cũng nhận yes/no, 1/0).
- `criticality`: số nguyên 1-5. Không bao giờ suy ra từ tên máy.
- `addresses`: một hoặc nhiều địa chỉ IP, ngăn cách bằng `|` hoặc khoảng trắng. Cột này không
  thuộc hợp đồng Asset; nó chỉ dùng để đổi IP trong kết quả quét thành asset_id chuẩn.
- Cột khác (ví dụ `subnet`) bị bỏ qua kèm cảnh báo, vì hợp đồng chưa có trường tương ứng.
"""

import csv
import io
import ipaddress
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from common.errors import ContractError, ResourceNotFoundError
from common.schemas import INTERNET_ID, Asset

KNOWN_COLUMNS = (
    "asset_id",
    "name",
    "asset_type",
    "internet_facing",
    "criticality",
    "sensitive_data",
    "addresses",
)
REQUIRED_COLUMNS = ("asset_id", "name")
_TRUE = {"true", "yes", "1"}
_FALSE = {"false", "no", "0"}
_ADDRESS_SEPARATOR = re.compile(r"[|\s]+")


@dataclass(frozen=True)
class AssetInventory:
    """Kết quả đọc file tài sản."""

    assets: list[Asset]
    address_to_asset_id: dict[str, str]
    warnings: list[str] = field(default_factory=list)


def load_asset_inventory(path: Path) -> AssetInventory:
    """Đọc file CSV tài sản.

    Raises:
        ResourceNotFoundError: không có file.
        ContractError: thiếu cột bắt buộc hoặc có dòng sai; `details` liệt kê TẤT CẢ lỗi
            kèm số dòng để sửa một lần.
    """
    csv_path = Path(path)
    if not csv_path.is_file():
        raise ResourceNotFoundError(
            f"Không tìm thấy file tài sản: {csv_path}.",
            [{"field": "path", "record_id": str(csv_path)}],
        )
    return parse_asset_inventory_bytes(csv_path.read_bytes())


def parse_asset_inventory_bytes(data: bytes) -> AssetInventory:
    """Giống `load_asset_inventory` nhưng nhận nội dung CSV dạng bytes."""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ContractError(
            "File tài sản phải được lưu bằng UTF-8.", [{"field": "<csv>", "record_id": ""}]
        ) from exc

    reader = csv.DictReader(io.StringIO(text, newline=""), delimiter=_detect_delimiter(text))
    header = [(name or "").strip().lower() for name in (reader.fieldnames or [])]
    if not header:
        raise ContractError("File tài sản rỗng.", [{"field": "<csv>", "record_id": ""}])
    missing = [c for c in REQUIRED_COLUMNS if c not in header]
    if missing:
        raise ContractError(
            f"File tài sản thiếu cột bắt buộc: {', '.join(missing)}.",
            [{"field": column, "record_id": "", "row": 1} for column in missing],
        )
    reader.fieldnames = header

    errors: list[dict[str, Any]] = []
    assets: list[Asset] = []
    address_to_asset_id: dict[str, str] = {}
    id_rows: dict[str, int] = {}
    address_owner: dict[str, tuple[str, int]] = {}

    for row_number, row in enumerate(reader, start=2):
        if None not in row and not any((v or "").strip() for v in row.values()):
            continue  # dòng trống
        if None in row:
            errors.append(_error("<row>", "", row_number, "dòng có nhiều ô hơn dòng tiêu đề"))
            continue
        parsed = _parse_row(row_number, row, errors)
        if parsed is None:
            continue
        asset, addresses = parsed
        if asset.asset_id in id_rows:
            reason = f"asset_id trùng với dòng {id_rows[asset.asset_id]}"
            errors.append(_error("asset_id", asset.asset_id, row_number, reason))
            continue
        id_rows[asset.asset_id] = row_number
        for address in addresses:
            if address in address_owner:
                other_id, other_row = address_owner[address]
                reason = f"địa chỉ {address} trùng với {other_id} (dòng {other_row})"
                errors.append(_error("addresses", asset.asset_id, row_number, reason))
            else:
                address_owner[address] = (asset.asset_id, row_number)
                address_to_asset_id[address] = asset.asset_id
        assets.append(asset)

    if errors:
        raise ContractError(f"File tài sản có {len(errors)} lỗi.", errors)

    warnings: list[str] = []
    ignored = [c for c in header if c and c not in KNOWN_COLUMNS]
    if ignored:
        warnings.append(f"Đã bỏ qua các cột chưa có trong hợp đồng: {', '.join(ignored)}.")
    owners = set(address_to_asset_id.values())
    without_address = [a.asset_id for a in assets if a.asset_id not in owners]
    if without_address:
        warnings.append(
            "Tài sản không có địa chỉ (không khớp được với kết quả quét): "
            + ", ".join(without_address)
            + "."
        )
    return AssetInventory(assets=assets, address_to_asset_id=address_to_asset_id, warnings=warnings)


def merge_assets(
    inventory_assets: Sequence[Asset], scanned_assets: Sequence[Asset]
) -> tuple[list[Asset], list[str]]:
    """Ghép tài sản từ inventory với tài sản từ kết quả quét, khớp theo asset_id.

    Inventory là nguồn chính cho name và các trường ngữ cảnh. Chỉ khi inventory để trống
    (None) mà kết quả quét có giá trị thì mới lấy giá trị của kết quả quét.
    Tài sản có trong kết quả quét nhưng chưa có trong inventory vẫn được giữ lại và có cảnh báo.
    """
    scanned = {a.asset_id: a for a in scanned_assets}
    merged: list[Asset] = []
    for inv in inventory_assets:
        scan = scanned.pop(inv.asset_id, None)
        if scan is None:
            merged.append(inv)
            continue
        merged.append(
            Asset(
                asset_id=inv.asset_id,
                name=inv.name,
                asset_type=inv.asset_type if inv.asset_type is not None else scan.asset_type,
                internet_facing=(
                    inv.internet_facing if inv.internet_facing is not None else scan.internet_facing
                ),
                criticality=inv.criticality if inv.criticality is not None else scan.criticality,
                sensitive_data=(
                    inv.sensitive_data if inv.sensitive_data is not None else scan.sensitive_data
                ),
            )
        )
    warnings: list[str] = []
    for leftover in scanned.values():
        warnings.append(
            f"Tài sản {leftover.asset_id} có trong kết quả quét nhưng chưa có trong inventory; "
            "các trường ngữ cảnh để null."
        )
        merged.append(leftover)
    return merged, warnings


def _parse_row(
    row_number: int, row: dict[str, str | None], errors: list[dict[str, Any]]
) -> tuple[Asset, list[str]] | None:
    problems: list[tuple[str, str]] = []
    asset_id = _cell(row, "asset_id")
    if not asset_id:
        problems.append(("asset_id", "bắt buộc"))
    elif asset_id == INTERNET_ID:
        problems.append(("asset_id", f"{INTERNET_ID} là ID dành riêng"))
    name = _cell(row, "name")
    if not name:
        problems.append(("name", "bắt buộc"))
    internet_facing = _parse_bool(_cell(row, "internet_facing"), "internet_facing", problems)
    sensitive_data = _parse_bool(_cell(row, "sensitive_data"), "sensitive_data", problems)
    criticality = _parse_criticality(_cell(row, "criticality"), problems)
    addresses = _parse_addresses(_cell(row, "addresses"), problems)

    if problems:
        errors.extend(_error(column, asset_id, row_number, reason) for column, reason in problems)
        return None
    asset = Asset(
        asset_id=asset_id,
        name=name,
        asset_type=_cell(row, "asset_type") or None,
        internet_facing=internet_facing,
        criticality=criticality,
        sensitive_data=sensitive_data,
    )
    return asset, addresses


def _parse_bool(value: str, column: str, problems: list[tuple[str, str]]) -> bool | None:
    if not value:
        return None
    lowered = value.lower()
    if lowered in _TRUE:
        return True
    if lowered in _FALSE:
        return False
    problems.append((column, f"giá trị {value!r} không phải true/false"))
    return None


def _parse_criticality(value: str, problems: list[tuple[str, str]]) -> int | None:
    if not value:
        return None
    try:
        number = int(value)
    except ValueError:
        problems.append(("criticality", f"giá trị {value!r} không phải số nguyên"))
        return None
    if not 1 <= number <= 5:
        problems.append(("criticality", f"giá trị {number} ngoài khoảng 1-5"))
        return None
    return number


def _parse_addresses(value: str, problems: list[tuple[str, str]]) -> list[str]:
    addresses: list[str] = []
    for part in _ADDRESS_SEPARATOR.split(value):
        if not part:
            continue
        try:
            addresses.append(str(ipaddress.ip_address(part)))
        except ValueError:
            problems.append(("addresses", f"{part!r} không phải địa chỉ IP hợp lệ"))
    return addresses


def _detect_delimiter(text: str) -> str:
    first_line = text.split("\n", 1)[0]
    for candidate in (",", ";", "\t"):
        if candidate in first_line:
            return candidate
    return ","


def _cell(row: dict[str, str | None], column: str) -> str:
    return (row.get(column) or "").strip()


def _error(column: str, record_id: str, row_number: int, reason: str) -> dict[str, Any]:
    return {"field": column, "record_id": record_id, "row": row_number, "reason": reason}
