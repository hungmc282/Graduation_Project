"""Exception dùng chung (ARCHITECTURE.md, mục 8).

Mỗi lỗi có `code` ổn định và `details` dạng [{"field": ..., "record_id": ...}] để API
chuyển thẳng sang envelope lỗi mà không phải đoán.
"""

from typing import Any


class AppError(Exception):
    """Lỗi gốc của dự án."""

    code = "APP_ERROR"

    def __init__(self, message: str, details: list[dict[str, Any]] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or []


class ContractError(AppError):
    """Dữ liệu hoặc lời gọi vi phạm hợp đồng (HTTP 422)."""

    code = "CONTRACT_VIOLATION"


class InvalidReferenceError(ContractError):
    """Tham chiếu tới ID không tồn tại hoặc sai quan hệ (HTTP 422)."""

    code = "INVALID_REFERENCE"


class UnsupportedVersionError(AppError):
    """schema_version hoặc model_version chưa được hỗ trợ (HTTP 409)."""

    code = "UNSUPPORTED_VERSION"


class ResourceNotFoundError(AppError):
    """Không tìm thấy tài nguyên được yêu cầu (HTTP 404)."""

    code = "RESOURCE_NOT_FOUND"
