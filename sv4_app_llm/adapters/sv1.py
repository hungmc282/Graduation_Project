"""SV1 public facade adapter; uploaded files are validated in a temporary folder."""
from pathlib import Path
from tempfile import TemporaryDirectory

from sv4_app_llm.config import PROJECT_ROOT


class DatasetInputError(ValueError):
    def __init__(self, message, details=None):
        super().__init__(message)
        self.details = details or []


def load_sv1_snapshot(content=None):
    try:
        from common.errors import AppError
        from sv1_data.service import load_dataset
    except ImportError as error:
        raise DatasetInputError(
            "Chưa cài package dữ liệu chung. Xem bước cài đặt trong README.md."
        ) from error
    try:
        if content is None:
            snapshot = load_dataset(PROJECT_ROOT / "data" / "samples" / "demo_lab_v1")
        else:
            if not isinstance(content, bytes) or len(content) > 5 * 1024 * 1024:
                raise DatasetInputError("File phải là JSON và không vượt quá 5 MB.")
            # Never use the uploaded filename as a filesystem path.
            with TemporaryDirectory(prefix="sv4-dataset-") as folder:
                (Path(folder) / "dataset.json").write_bytes(content)
                snapshot = load_dataset(Path(folder))
    except AppError as error:
        raise DatasetInputError(error.message, error.details) from error
    except UnicodeError as error:
        raise DatasetInputError("File phải có mã hóa UTF-8.") from error
    return snapshot.model_dump(mode="json")
