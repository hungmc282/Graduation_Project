"""Đọc danh mục CISA Known Exploited Vulnerabilities (KEV), bản JSON.

JSON có phần đầu (title, catalogVersion, dateReleased, count) và mảng `vulnerabilities`, mỗi
phần tử có `cveID`, `dateAdded`... Module này chỉ PHÂN TÍCH dữ liệu đã có, không gọi mạng.
"""

import json
from dataclasses import dataclass
from typing import NoReturn

from common.errors import ContractError

# cisa.gov chặn nhiều mạng (HTTP 403 từ CDN), nên mặc định dùng bản sao do chính CISA duy
# trì trên GitHub (repo cisagov/kev-data, cùng nội dung, đồng bộ trong vài phút).
KEV_CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/refs/heads/develop/"
    "known_exploited_vulnerabilities.json"
)


@dataclass(frozen=True)
class KevEntry:
    date_added: str | None


@dataclass(frozen=True)
class KevCatalog:
    entries: dict[str, KevEntry]
    catalog_version: str | None
    date_released: str | None


def parse_kev(data: bytes) -> KevCatalog:
    """Phân tích nội dung JSON của KEV.

    Raises:
        ContractError: JSON hỏng, có NaN/Infinity, sai cấu trúc, hoặc danh mục rỗng. Danh mục
            rỗng bị từ chối vì nếu chấp nhận thì mọi CVE sẽ bị gắn nhầm là "không bị khai thác".
    """
    try:
        catalog = json.loads(data.decode("utf-8-sig"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(
            f"File KEV không phải JSON hợp lệ: {exc}.", [{"field": "<json>", "record_id": ""}]
        ) from exc
    vulnerabilities = catalog.get("vulnerabilities") if isinstance(catalog, dict) else None
    if not isinstance(vulnerabilities, list):
        raise ContractError(
            "File KEV thiếu mảng vulnerabilities.", [{"field": "vulnerabilities", "record_id": ""}]
        )

    entries: dict[str, KevEntry] = {}
    for item in vulnerabilities:
        cve = item.get("cveID") if isinstance(item, dict) else None
        if isinstance(cve, str) and cve.strip():
            added = item.get("dateAdded")
            entries[cve.strip().upper()] = KevEntry(added if isinstance(added, str) else None)
    if not entries:
        raise ContractError(
            "Danh mục KEV không có CVE nào.", [{"field": "vulnerabilities", "record_id": ""}]
        )
    return KevCatalog(
        entries=entries,
        catalog_version=_as_text(catalog.get("catalogVersion")),
        date_released=_as_text(catalog.get("dateReleased")),
    )


def _as_text(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _reject_constant(name: str) -> NoReturn:
    raise ContractError(
        "JSON chứa giá trị không hợp lệ (NaN/Infinity).",
        [{"field": "<json>", "record_id": name}],
    )
