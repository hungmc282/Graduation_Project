"""Tải dữ liệu từ mạng có cache trên đĩa, để chạy được cả khi mất mạng.

Quy tắc: cache còn mới (trong `max_age`) thì dùng luôn, không gọi mạng. Cache cũ thì thử tải lại;
nếu tải lỗi mà còn cache cũ thì dùng cache cũ và trả về cảnh báo; không có cache thì báo lỗi.
Có thể tự tải file về đặt vào đúng đường dẫn cache; file mới sẽ được dùng ngay.
"""

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from common.errors import ResourceNotFoundError

DEFAULT_MAX_AGE = timedelta(hours=24)
_TIMEOUT_SECONDS = 60.0


def fetch_cached(
    url: str,
    cache_path: Path,
    *,
    max_age: timedelta = DEFAULT_MAX_AGE,
    client: httpx.Client | None = None,
    now: datetime | None = None,
) -> tuple[bytes, list[str]]:
    """Trả về (nội dung, cảnh báo). `client` và `now` cho phép kiểm thử không cần mạng."""
    current = now or datetime.now(UTC)
    cache_path = Path(cache_path)
    cached_at = _cached_at(cache_path)
    if cached_at is not None and current - cached_at <= max_age:
        return cache_path.read_bytes(), []
    try:
        data = _download(url, client)
    except httpx.HTTPError as exc:
        if cached_at is None:
            raise ResourceNotFoundError(
                f"Không tải được {url} ({type(exc).__name__}) và chưa có bản cache.",
                [{"field": "url", "record_id": url}],
            ) from exc
        warning = (
            f"Không tải được {url} ({type(exc).__name__}); dùng bản cache cũ "
            f"tải lúc {cached_at.isoformat()}."
        )
        return cache_path.read_bytes(), [warning]
    _write_atomic(cache_path, data)
    return data, []


def _cached_at(cache_path: Path) -> datetime | None:
    if not cache_path.is_file():
        return None
    return datetime.fromtimestamp(cache_path.stat().st_mtime, UTC)


def _download(url: str, client: httpx.Client | None) -> bytes:
    if client is not None:
        response = client.get(url)
        response.raise_for_status()
        return response.content
    with httpx.Client(timeout=_TIMEOUT_SECONDS, follow_redirects=True) as own_client:
        response = own_client.get(url)
        response.raise_for_status()
        return response.content


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_bytes(data)
    os.replace(temp, path)
