"""Đọc dữ liệu EPSS của FIRST (file CSV nén gzip tải về hằng ngày).

Định dạng: dòng đầu là chú thích `#model_version:v...,score_date:YYYY-MM-DDT...`, tiếp theo là
tiêu đề `cve,epss,percentile`. EPSS là xác suất 0-1 bị khai thác trong 30 ngày tới.
Module này chỉ PHÂN TÍCH dữ liệu đã có, không gọi mạng (xem cache.py).
"""

import csv
import gzip
import io
import math
import re
from dataclasses import dataclass

from common.errors import ContractError

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
_GZIP_MAGIC = b"\x1f\x8b"
_MODEL = re.compile(r"model_version:([^,\s]+)")
_DATE = re.compile(r"score_date:(\d{4}-\d{2}-\d{2})")


@dataclass(frozen=True)
class EpssScore:
    probability: float
    percentile: float | None


@dataclass(frozen=True)
class EpssData:
    scores: dict[str, EpssScore]
    model_version: str | None
    score_date: str | None  # YYYY-MM-DD
    skipped_rows: int


def parse_epss(data: bytes) -> EpssData:
    """Phân tích nội dung file EPSS (nén gzip hoặc CSV thường).

    Dòng có điểm không hợp lệ (không phải số, ngoài 0-1, NaN/Infinity) bị bỏ qua và được đếm
    trong `skipped_rows`.

    Raises:
        ContractError: gzip hỏng, thiếu cột `cve`/`epss`, hoặc không có dòng hợp lệ nào.
    """
    if data[:2] == _GZIP_MAGIC:
        try:
            data = gzip.decompress(data)
        except (OSError, EOFError) as exc:
            raise ContractError(
                f"File EPSS nén gzip bị hỏng: {exc}.", [{"field": "<gzip>", "record_id": ""}]
            ) from exc
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ContractError(
            "File EPSS phải là UTF-8.", [{"field": "<csv>", "record_id": ""}]
        ) from exc

    comments = [line for line in text.splitlines() if line.startswith("#")]
    body = "\n".join(line for line in text.splitlines() if not line.startswith("#"))
    model = next((m.group(1) for c in comments if (m := _MODEL.search(c))), None)
    date = next((m.group(1) for c in comments if (m := _DATE.search(c))), None)

    reader = csv.DictReader(io.StringIO(body, newline=""))
    header = [(name or "").strip().lower() for name in (reader.fieldnames or [])]
    if "cve" not in header or "epss" not in header:
        raise ContractError(
            "File EPSS thiếu cột bắt buộc cve hoặc epss.", [{"field": "<csv>", "record_id": ""}]
        )
    reader.fieldnames = header

    scores: dict[str, EpssScore] = {}
    skipped = 0
    for row in reader:
        cve = (row.get("cve") or "").strip().upper()
        probability = _probability(row.get("epss"))
        if not cve or probability is None:
            skipped += 1
            continue
        scores[cve] = EpssScore(probability, _probability(row.get("percentile")))
    if not scores:
        raise ContractError(
            "File EPSS không có dòng hợp lệ nào.", [{"field": "<csv>", "record_id": ""}]
        )
    return EpssData(scores=scores, model_version=model, score_date=date, skipped_rows=skipped)


def _probability(value: str | None) -> float | None:
    try:
        number = float((value or "").strip())
    except ValueError:
        return None
    return number if math.isfinite(number) and 0 <= number <= 1 else None
