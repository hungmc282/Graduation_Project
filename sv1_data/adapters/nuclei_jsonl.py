"""Adapter Nuclei JSONL (`nuclei -jsonl`) -> Finding (ARCHITECTURE.md, mục 6.2).

Mỗi dòng của file là một phát hiện (hoặc cả file là một mảng JSON nếu dùng `-je`).

Quy tắc chuyển đổi:
- Người gọi khai báo `asset_id` (máy được quét) và, nếu muốn, `service_by_port` (cổng ->
  service_id). Cổng lấy từ chính bản ghi Nuclei; cổng không có trong bảng thì service_id là None.
- `vulnerability_id`: mã CVE từ `info.classification.cve-id` (mỗi CVE một finding); template
  không có CVE thì dùng `template-id` (ví dụ "cookies-without-secure"). Mã không phải CVE sẽ
  không được làm giàu EPSS/KEV (giữ null, tức chưa biết).
- `cvss_score`: chỉ lấy khi template có `cvss-score` hợp lệ (0-10); chỉ có vector thì là None
  (vector được ghi vào evidence). Không tự tính điểm, không bịa 0.
- BẢO MẬT: các trường `request`, `response`, `curl-command`, `extracted-results` có thể chứa
  cookie, phiên làm việc hoặc mật khẩu, nên KHÔNG BAO GIỜ được sao chép. Địa chỉ khớp
  (`matched-at`) chỉ giữ phần trước dấu `?` và `#`.
- `min_severity`: bỏ qua phát hiện có mức nghiêm trọng thấp hơn (mặc định "info" nghĩa là giữ
  tất cả). Mức không rõ luôn được giữ lại, vì "không rõ" không đồng nghĩa với "vô hại".
"""

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn

from pydantic import ValidationError

from common.errors import ContractError, ResourceNotFoundError
from common.schemas import Finding

SEVERITY_RANK = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_FRACTION = re.compile(r"\.(\d+)")
_MAX_TEXT = 200


@dataclass(frozen=True)
class NucleiScan:
    """Kết quả chuyển đổi một file Nuclei."""

    findings: list[Finding]
    warnings: list[str] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)


def parse_nuclei_jsonl(
    path: Path,
    asset_id: str,
    service_by_port: Mapping[int, str] | None = None,
    *,
    min_severity: str = "info",
) -> NucleiScan:
    """Đọc file kết quả Nuclei và chuyển thành danh sách Finding.

    Raises:
        ResourceNotFoundError: không có file.
        ContractError: asset_id rỗng, min_severity không hợp lệ, hoặc dữ liệu sai schema.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise ResourceNotFoundError(
            f"Không tìm thấy kết quả Nuclei: {file_path}.",
            [{"field": "path", "record_id": str(file_path)}],
        )
    return parse_nuclei_jsonl_bytes(
        file_path.read_bytes(), asset_id, service_by_port, min_severity=min_severity
    )


def parse_nuclei_jsonl_bytes(
    data: bytes,
    asset_id: str,
    service_by_port: Mapping[int, str] | None = None,
    *,
    min_severity: str = "info",
) -> NucleiScan:
    """Giống `parse_nuclei_jsonl` nhưng nhận nội dung dạng bytes."""
    asset_id = asset_id.strip()
    if not asset_id:
        raise ContractError("asset_id không được rỗng.", [{"field": "asset_id", "record_id": ""}])
    if min_severity not in SEVERITY_RANK:
        raise ContractError(
            f"min_severity phải thuộc {sorted(SEVERITY_RANK, key=SEVERITY_RANK.get)}.",
            [{"field": "min_severity", "record_id": min_severity}],
        )
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ContractError(
            "Kết quả Nuclei phải là UTF-8.", [{"field": "<jsonl>", "record_id": ""}]
        ) from exc

    records, invalid_lines = _read_records(text)
    services = service_by_port or {}
    stats = {
        "records_read": len(records),
        "invalid_lines": invalid_lines,
        "skipped_unmatched": 0,
        "skipped_no_template": 0,
        "below_min_severity": 0,
        "duplicates_removed": 0,
        "invalid_cvss_ignored": 0,
        "without_cvss": 0,
        "findings": 0,
        **{f"severity_{level}": 0 for level in (*SEVERITY_RANK, "unknown")},
    }
    findings: list[Finding] = []
    seen: set[str] = set()

    for record in records:
        if record.get("matcher-status") is False:
            stats["skipped_unmatched"] += 1
            continue
        template_id = _text(record.get("template-id"))
        if template_id is None:
            stats["skipped_no_template"] += 1
            continue
        info = record.get("info") if isinstance(record.get("info"), dict) else {}
        classification = (
            info.get("classification") if isinstance(info.get("classification"), dict) else {}
        )
        severity = (_text(info.get("severity")) or "unknown").lower()
        severity = severity if severity in SEVERITY_RANK else "unknown"
        stats[f"severity_{severity}"] += 1
        if severity != "unknown" and SEVERITY_RANK[severity] < SEVERITY_RANK[min_severity]:
            stats["below_min_severity"] += 1
            continue

        score, invalid_score = _cvss_score(classification.get("cvss-score"))
        stats["invalid_cvss_ignored"] += invalid_score
        port = _port(record.get("port"))
        matched_at = _strip_query(record.get("matched-at") or record.get("url"))
        matcher = _text(record.get("matcher-name"))
        observed_at = _parse_timestamp(record.get("timestamp"))
        evidence = _evidence(
            template_id, info, classification, severity, matched_at, matcher, score
        )

        for vulnerability_id in _cve_ids(classification.get("cve-id")) or [template_id]:
            key = f"{template_id}|{vulnerability_id}|{matcher or ''}|{matched_at or ''}"
            finding_id = f"{asset_id}:{vulnerability_id}:nuclei:{_digest(key)}"
            if finding_id in seen:
                stats["duplicates_removed"] += 1
                continue
            seen.add(finding_id)
            if score is None:
                stats["without_cvss"] += 1
            try:
                findings.append(
                    Finding(
                        finding_id=finding_id,
                        asset_id=asset_id,
                        service_id=services.get(port) if port is not None else None,
                        vulnerability_id=vulnerability_id,
                        cvss_score=score,
                        epss_probability=None,
                        is_kev=None,
                        source="scanner",
                        evidence=evidence,
                        observed_at=observed_at,
                        enriched_at=None,
                    )
                )
            except ValidationError as exc:
                raise ContractError(
                    f"Phát hiện {template_id} của Nuclei không đúng schema.",
                    [
                        {"field": ".".join(str(p) for p in e["loc"]), "record_id": finding_id}
                        for e in exc.errors()
                    ],
                ) from exc
            stats["findings"] += 1

    return NucleiScan(findings=findings, warnings=_summarize(stats), stats=stats)


def _read_records(text: str) -> tuple[list[dict[str, Any]], int]:
    """Đọc JSONL (mỗi dòng một đối tượng) hoặc một mảng JSON. Dòng hỏng được đếm, không dừng."""
    if text.lstrip().startswith("["):
        try:
            data = json.loads(text, parse_constant=_reject_constant)
        except (json.JSONDecodeError, ContractError) as exc:
            raise ContractError(
                "Kết quả Nuclei (mảng JSON) không hợp lệ.", [{"field": "<json>", "record_id": ""}]
            ) from exc
        records = [item for item in data if isinstance(item, dict)]
        return records, len(data) - len(records)

    records: list[dict[str, Any]] = []
    invalid = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line, parse_constant=_reject_constant)
        except (json.JSONDecodeError, ContractError):
            invalid += 1  # thường là dòng cuối bị cắt dở khi Nuclei bị ngắt
            continue
        if isinstance(item, dict):
            records.append(item)
        else:
            invalid += 1
    return records, invalid


def _evidence(
    template_id: str,
    info: dict[str, Any],
    classification: dict[str, Any],
    severity: str,
    matched_at: str | None,
    matcher: str | None,
    score: float | None,
) -> list[str]:
    items = ["scanner: nuclei", f"template: {template_id}"]
    name = _text(info.get("name"))
    if name:
        items.append(f"name: {name[:_MAX_TEXT]}")
    items.append(f"nuclei severity: {severity}")
    if matched_at:
        items.append(f"matched at: {matched_at}")
    if matcher:
        items.append(f"matcher: {matcher[:_MAX_TEXT]}")
    cwes = classification.get("cwe-id")
    if isinstance(cwes, list):
        cleaned = [c for c in (_text(x) for x in cwes) if c]
        if cleaned:
            items.append(f"cwe: {', '.join(cleaned)}"[:_MAX_TEXT])
    vector = _text(classification.get("cvss-metrics"))
    if vector:
        items.append(f"cvss vector: {vector[:_MAX_TEXT]}")
    if score is not None:
        items.append("cvss source: nuclei template")
    reference = info.get("reference")
    first = reference[0] if isinstance(reference, list) and reference else reference
    if _text(first):
        items.append(f"reference: {_text(first)[:_MAX_TEXT]}")
    return items


def _summarize(stats: dict[str, int]) -> list[str]:
    messages = [
        ("invalid_lines", "Đã bỏ qua {n} dòng không đọc được (JSON hỏng hoặc không phải object)."),
        ("skipped_unmatched", "Đã bỏ qua {n} bản ghi không khớp (matcher-status = false)."),
        ("skipped_no_template", "Đã bỏ qua {n} bản ghi không có template-id."),
        ("below_min_severity", "Đã bỏ qua {n} phát hiện thấp hơn mức tối thiểu."),
        ("duplicates_removed", "Đã loại {n} bản ghi trùng."),
        ("invalid_cvss_ignored", "Đã bỏ qua {n} điểm CVSS ngoài khoảng 0-10."),
        ("without_cvss", "{n} finding không có điểm CVSS (cvss_score = null)."),
    ]
    warnings = [text.format(n=stats[key]) for key, text in messages if stats[key]]
    if not stats["findings"]:
        warnings.append("Không có finding nào từ file Nuclei này.")
    return warnings


def _cve_ids(value: Any) -> list[str]:
    candidates = value if isinstance(value, list) else [value]
    result: list[str] = []
    for item in candidates:
        cve = (_text(item) or "").upper()
        if _CVE.match(cve) and cve not in result:
            result.append(cve)
    return result


def _cvss_score(value: Any) -> tuple[float | None, int]:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None, 0
    if 0 <= value <= 10:
        return float(value), 0
    return None, 1


def _port(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int | str):
        return None
    text = str(value).strip()
    if text.isdigit() and 1 <= int(text) <= 65535:
        return int(text)
    return None


def _strip_query(value: Any) -> str | None:
    text = _text(value)
    if text is None:
        return None
    return text.split("?", 1)[0].split("#", 1)[0][:_MAX_TEXT] or None


def _digest(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]


def _parse_timestamp(value: Any) -> datetime | None:
    text = _text(value)
    if text is None:
        return None
    # Nuclei ghi tới 9 chữ số thập phân; chuẩn hóa về đúng 6 chữ số để mọi bản Python đọc được.
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
