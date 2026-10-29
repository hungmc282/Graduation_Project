"""Adapter Trivy JSON (`trivy image --format json`) -> Finding (ARCHITECTURE.md, mục 6.2).

Trivy quét IMAGE nên lỗ hổng thuộc về GÓI phần mềm, không thuộc về một cổng mạng. Vì vậy:
- Người gọi phải nói image này chạy trên asset nào (`asset_id`).
- `service_id` của Finding mặc định là None. Chỉ gắn vào Service khi người gọi khai báo
  rõ ràng qua `service_by_package` (ví dụ {"apache2": "WEB01:tcp/8080"}); adapter không đoán.
- Trivy không có EPSS, KEV: `epss_probability`, `is_kev`, `enriched_at` là None (chưa biết),
  bước enrichment sẽ điền sau.

Chính sách điểm CVSS (cần nhóm xác nhận): lấy điểm CVSS v3 của NVD; nếu NVD không có thì lấy
điểm v3 của nguồn khác (theo thứ tự chữ cái); KHÔNG dùng điểm v2; không có thì None, không bịa 0.
Nguồn điểm được ghi trong `evidence` ("cvss source: nvd v3") để không mất thông tin phiên bản.
"""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn

from pydantic import ValidationError

from common.errors import ContractError, ResourceNotFoundError, UnsupportedVersionError
from common.schemas import Finding

SUPPORTED_TRIVY_SCHEMA_VERSION = 2
_MAX_TITLE_LENGTH = 200
_FRACTION = re.compile(r"\.(\d+)")


@dataclass(frozen=True)
class TrivyScan:
    """Kết quả chuyển đổi một báo cáo Trivy."""

    findings: list[Finding]
    warnings: list[str] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)


def parse_trivy_json(
    path: Path,
    asset_id: str,
    service_by_package: Mapping[str, str] | None = None,
) -> TrivyScan:
    """Đọc báo cáo Trivy JSON và chuyển thành danh sách Finding.

    Args:
        path: file tạo bởi `trivy image --format json`.
        asset_id: asset mà image này đang chạy trên đó (ví dụ "WEB01").
        service_by_package: ánh xạ tên gói -> service_id, chỉ cho những gói người dùng chắc chắn
            là một dịch vụ đang mở cổng. Gói không có trong ánh xạ có service_id = None.

    Raises:
        ResourceNotFoundError: không có file.
        UnsupportedVersionError: SchemaVersion của báo cáo Trivy khác 2.
        ContractError: JSON hỏng, có NaN/Infinity, hoặc dữ liệu không đúng schema.
    """
    json_path = Path(path)
    if not json_path.is_file():
        raise ResourceNotFoundError(
            f"Không tìm thấy báo cáo Trivy: {json_path}.",
            [{"field": "path", "record_id": str(json_path)}],
        )
    return parse_trivy_json_bytes(json_path.read_bytes(), asset_id, service_by_package)


def parse_trivy_json_bytes(
    data: bytes,
    asset_id: str,
    service_by_package: Mapping[str, str] | None = None,
) -> TrivyScan:
    """Giống `parse_trivy_json` nhưng nhận nội dung JSON dạng bytes."""
    asset_id = asset_id.strip()
    if not asset_id:
        raise ContractError("asset_id không được rỗng.", [{"field": "asset_id", "record_id": ""}])

    report = _load_report(data)
    observed_at = _parse_timestamp(report.get("CreatedAt"))
    packages_to_services = service_by_package or {}

    stats = {
        "vulnerabilities_read": 0,
        "findings": 0,
        "duplicates_removed": 0,
        "skipped_no_id": 0,
        "without_cvss": 0,
        "invalid_cvss_ignored": 0,
        "secrets_skipped": 0,
    }
    findings: list[Finding] = []
    seen: set[str] = set()

    for result in report.get("Results") or []:
        stats["secrets_skipped"] += len(result.get("Secrets") or [])
        for vuln in result.get("Vulnerabilities") or []:
            stats["vulnerabilities_read"] += 1
            vulnerability_id = _text(vuln.get("VulnerabilityID"))
            if vulnerability_id is None:
                stats["skipped_no_id"] += 1
                continue

            pkg_name = _text(vuln.get("PkgName"))
            installed = _text(vuln.get("InstalledVersion"))
            pkg_id = _text(vuln.get("PkgID")) or f"{pkg_name or 'unknown'}@{installed or 'unknown'}"
            finding_id = f"{asset_id}:{vulnerability_id}:{pkg_id}"
            if finding_id in seen:
                stats["duplicates_removed"] += 1
                continue
            seen.add(finding_id)

            score, score_source, invalid = _pick_cvss(vuln.get("CVSS"))
            stats["invalid_cvss_ignored"] += invalid
            if score is None:
                stats["without_cvss"] += 1

            try:
                findings.append(
                    Finding(
                        finding_id=finding_id,
                        asset_id=asset_id,
                        service_id=packages_to_services.get(pkg_name) if pkg_name else None,
                        vulnerability_id=vulnerability_id,
                        cvss_score=score,
                        epss_probability=None,
                        is_kev=None,
                        source="scanner",
                        evidence=_evidence(vuln, score_source),
                        observed_at=observed_at,
                        enriched_at=None,
                    )
                )
            except ValidationError as exc:
                raise ContractError(
                    f"Lỗ hổng {vulnerability_id} của Trivy không đúng schema.",
                    [
                        {"field": ".".join(str(p) for p in e["loc"]), "record_id": finding_id}
                        for e in exc.errors()
                    ],
                ) from exc
            stats["findings"] += 1

    return TrivyScan(findings=findings, warnings=_summarize(stats), stats=stats)


def _load_report(data: bytes) -> dict[str, Any]:
    try:
        report = json.loads(data.decode("utf-8-sig"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(
            f"Báo cáo Trivy không phải JSON hợp lệ: {exc}.",
            [{"field": "<json>", "record_id": ""}],
        ) from exc
    if not isinstance(report, dict):
        raise ContractError("Báo cáo Trivy phải là một đối tượng JSON.", [])
    version = report.get("SchemaVersion")
    if version != SUPPORTED_TRIVY_SCHEMA_VERSION:
        raise UnsupportedVersionError(
            f"Trivy SchemaVersion {version!r} chưa được hỗ trợ "
            f"(cần {SUPPORTED_TRIVY_SCHEMA_VERSION}).",
            [{"field": "SchemaVersion", "record_id": str(version)}],
        )
    return report


def _pick_cvss(cvss: Any) -> tuple[float | None, str | None, int]:
    """Trả về (điểm, nguồn, số điểm không hợp lệ bị bỏ qua). Chỉ dùng CVSS v3."""
    if not isinstance(cvss, dict):
        return None, None, 0
    invalid = 0
    sources = (["nvd"] if "nvd" in cvss else []) + sorted(k for k in cvss if k != "nvd")
    for source in sources:
        entry = cvss[source]
        score = entry.get("V3Score") if isinstance(entry, dict) else None
        if isinstance(score, bool) or not isinstance(score, int | float):
            continue
        if 0 <= score <= 10:
            return float(score), f"{source} v3", invalid
        invalid += 1
    return None, None, invalid


def _evidence(vuln: dict[str, Any], score_source: str | None) -> list[str]:
    items: list[str] = []
    pkg = _text(vuln.get("PkgName"))
    installed = _text(vuln.get("InstalledVersion"))
    if pkg:
        items.append(f"package: {pkg} {installed}" if installed else f"package: {pkg}")
    for label, key in (
        ("fixed version", "FixedVersion"),
        ("status", "Status"),
        ("trivy severity", "Severity"),
    ):
        value = _text(vuln.get(key))
        if value:
            items.append(f"{label}: {value}")
    if score_source:
        items.append(f"cvss source: {score_source}")
    title = _text(vuln.get("Title"))
    if title:
        items.append(f"title: {title[:_MAX_TITLE_LENGTH]}")
    url = _text(vuln.get("PrimaryURL"))
    if url:
        items.append(f"reference: {url}")
    return items


def _summarize(stats: dict[str, int]) -> list[str]:
    messages = [
        (
            "duplicates_removed",
            "Đã loại {n} bản ghi trùng (cùng asset, CVE và gói).",
        ),
        ("skipped_no_id", "Đã bỏ qua {n} lỗ hổng không có VulnerabilityID."),
        ("without_cvss", "{n} finding không có điểm CVSS v3 (cvss_score = null)."),
        ("invalid_cvss_ignored", "Đã bỏ qua {n} điểm CVSS v3 ngoài khoảng 0-10."),
        ("secrets_skipped", "Đã bỏ qua {n} secret (không đưa vào dữ liệu chuẩn)."),
    ]
    return [text.format(n=stats[key]) for key, text in messages if stats[key]]


def _parse_timestamp(value: Any) -> datetime | None:
    text = _text(value)
    if text is None:
        return None
    text = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), text, count=1)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _reject_constant(name: str) -> NoReturn:
    raise ContractError(
        "JSON chứa giá trị không hợp lệ (NaN/Infinity).",
        [{"field": "<json>", "record_id": name}],
    )
