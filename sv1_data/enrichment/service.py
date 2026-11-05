"""Làm giàu Finding bằng EPSS và KEV (đề tài mục 5, module 4).

Quy tắc điền giá trị (ghi rõ để SV3 biết ý nghĩa của null):
- Chỉ xử lý finding có `vulnerability_id` dạng CVE-YYYY-NNNN. Mã khác (ví dụ mã synthetic) giữ
  nguyên, mọi trường là null (chưa biết).
- `epss_probability`: có trong file EPSS thì lấy giá trị; không có thì null (không phải 0).
- `is_kev`: danh mục KEV là danh sách đầy đủ, nên CVE có trong danh mục là True, không có là False.
- `enriched_at`: thời điểm chạy làm giàu. Nguồn và phiên bản dữ liệu được ghi vào `evidence`
  (dòng bắt đầu bằng "epss:" và "kev:"), chạy lại sẽ thay các dòng đó, không nhân đôi.
Việc tải dữ liệu từ mạng tách riêng khỏi việc tính (xem cache.py).
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from common.errors import ContractError
from common.schemas import DatasetSnapshot, Finding
from sv1_data.enrichment.cache import DEFAULT_MAX_AGE, fetch_cached
from sv1_data.enrichment.epss import EPSS_URL, EpssData, parse_epss
from sv1_data.enrichment.kev import KEV_URL, KevCatalog, parse_kev

EPSS_CACHE_NAME = "epss_scores-current.csv.gz"
KEV_CACHE_NAME = "known_exploited_vulnerabilities.json"
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_OWN_EVIDENCE_PREFIXES = ("epss:", "kev:")


@dataclass(frozen=True)
class EnrichmentResult:
    findings: list[Finding]
    warnings: list[str] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)


def enrich_findings(
    findings: Sequence[Finding], epss: EpssData, kev: KevCatalog, *, now: datetime
) -> EnrichmentResult:
    """Điền epss_probability, is_kev, enriched_at. Không gọi mạng, không sửa đối tượng gốc."""
    if now.tzinfo is None:
        raise ContractError("`now` phải có timezone (UTC).", [{"field": "now", "record_id": ""}])
    stats = {
        "findings": len(findings),
        "enriched": 0,
        "non_cve_skipped": 0,
        "epss_found": 0,
        "epss_missing": 0,
        "kev_listed": 0,
    }
    result: list[Finding] = []
    for finding in findings:
        cve = finding.vulnerability_id.strip().upper()
        if not _CVE.match(cve):
            stats["non_cve_skipped"] += 1
            result.append(finding)
            continue

        score = epss.scores.get(cve)
        entry = kev.entries.get(cve)
        stats["epss_found" if score else "epss_missing"] += 1
        stats["kev_listed"] += 1 if entry else 0
        stats["enriched"] += 1

        evidence = [e for e in finding.evidence if not e.startswith(_OWN_EVIDENCE_PREFIXES)]
        if score:
            percentile = f"{score.percentile:.5f}" if score.percentile is not None else "n/a"
            evidence.append(
                f"epss: {score.probability:.5f} (percentile {percentile}, "
                f"model {epss.model_version or 'n/a'}, score date {epss.score_date or 'n/a'})"
            )
        if entry:
            evidence.append(
                f"kev: listed in CISA KEV (catalog {kev.catalog_version or 'n/a'}, "
                f"added {entry.date_added or 'n/a'})"
            )
        else:
            evidence.append(f"kev: not listed (catalog {kev.catalog_version or 'n/a'})")

        updated: dict[str, Any] = {
            **finding.model_dump(),
            "epss_probability": score.probability if score else None,
            "is_kev": entry is not None,
            "evidence": evidence,
            "enriched_at": now,
        }
        result.append(Finding.model_validate(updated))

    warnings: list[str] = []
    if stats["non_cve_skipped"]:
        warnings.append(f"{stats['non_cve_skipped']} finding không có mã CVE nên không làm giàu.")
    if stats["epss_missing"]:
        warnings.append(
            f"{stats['epss_missing']} CVE không có trong dữ liệu EPSS (epss_probability = null)."
        )
    if epss.skipped_rows:
        warnings.append(f"Đã bỏ qua {epss.skipped_rows} dòng EPSS không hợp lệ.")
    return EnrichmentResult(findings=result, warnings=warnings, stats=stats)


def load_threat_data(
    cache_dir: Path,
    *,
    now: datetime | None = None,
    client: httpx.Client | None = None,
    max_age: timedelta = DEFAULT_MAX_AGE,
) -> tuple[EpssData, KevCatalog, list[str]]:
    """Lấy EPSS và KEV (từ cache hoặc mạng) rồi phân tích. Trả về cả cảnh báo về cache."""
    directory = Path(cache_dir)
    epss_bytes, epss_warnings = fetch_cached(
        EPSS_URL, directory / EPSS_CACHE_NAME, max_age=max_age, client=client, now=now
    )
    kev_bytes, kev_warnings = fetch_cached(
        KEV_URL, directory / KEV_CACHE_NAME, max_age=max_age, client=client, now=now
    )
    return parse_epss(epss_bytes), parse_kev(kev_bytes), epss_warnings + kev_warnings


def enrich_dataset(
    dataset: DatasetSnapshot,
    cache_dir: Path,
    *,
    now: datetime,
    client: httpx.Client | None = None,
    max_age: timedelta = DEFAULT_MAX_AGE,
) -> tuple[DatasetSnapshot, EnrichmentResult]:
    """Làm giàu toàn bộ finding của snapshot, trả về snapshot mới (không sửa bản gốc)."""
    epss, kev, cache_warnings = load_threat_data(cache_dir, now=now, client=client, max_age=max_age)
    result = enrich_findings(dataset.findings, epss, kev, now=now)
    enriched = dataset.model_copy(update={"findings": result.findings})
    return enriched, EnrichmentResult(
        findings=result.findings, warnings=cache_warnings + result.warnings, stats=result.stats
    )
