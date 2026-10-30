"""Kết nối CSDL và chạy migration (ARCHITECTURE.md, mục 2 và 9).

    python -m sv1_data.db migrate     # áp các file migrations/NNNN_*.sql chưa chạy
    python -m sv1_data.db status      # xem file nào đã và chưa áp

Địa chỉ CSDL lấy từ biến môi trường APP_DATABASE_URL, ví dụ:
    postgresql+psycopg2://nguoidung:matkhau@localhost:5432/vulnintel
Thông tin kết nối không bao giờ được đưa vào mã nguồn hay commit.

Migration là các file SQL đánh số, chạy theo thứ tự, mỗi file một giao dịch, và được ghi vào
bảng `schema_migrations`. Chương trình chỉ chạy migration khi người vận hành yêu cầu; không
có chỗ nào khác trong SV1 tự tạo hoặc sửa bảng.
"""

import argparse
import os
import re
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.exc import SQLAlchemyError

from common.errors import AppError, ContractError, ResourceNotFoundError

DATABASE_URL_ENV = "APP_DATABASE_URL"
MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "migrations"
_MIGRATION_NAME = re.compile(r"^\d{4}_[A-Za-z0-9_\-]+\.sql$")

_CREATE_TRACKING_TABLE = (
    "CREATE TABLE IF NOT EXISTS schema_migrations ("
    "version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL)"
)


class DatabaseError(AppError):
    """Không kết nối được hoặc câu lệnh SQL thất bại."""

    code = "DATABASE_ERROR"


def database_url_from_env(environ: Mapping[str, str] | None = None) -> str:
    url = (environ if environ is not None else os.environ).get(DATABASE_URL_ENV, "").strip()
    if not url:
        raise ContractError(
            f"Chưa đặt biến môi trường {DATABASE_URL_ENV}.",
            [{"field": DATABASE_URL_ENV, "record_id": ""}],
        )
    return url


def create_db_engine(url: str) -> Engine:
    """Tạo engine. Với SQLite (dùng khi kiểm thử) bật kiểm tra khóa ngoại như PostgreSQL."""
    engine = create_engine(url)
    if engine.dialect.name == "sqlite":

        @event.listens_for(engine, "connect")
        def _enable_foreign_keys(dbapi_connection, _record) -> None:  # type: ignore[no-untyped-def]
            dbapi_connection.execute("PRAGMA foreign_keys=ON")

    return engine


def split_statements(sql: str) -> list[str]:
    """Tách file SQL thành từng câu lệnh (bỏ dòng chú thích `--`, tách theo dấu `;`)."""
    lines = [line for line in sql.splitlines() if not line.strip().startswith("--")]
    return [statement.strip() for statement in "\n".join(lines).split(";") if statement.strip()]


def list_migration_files(directory: Path = MIGRATIONS_DIR) -> list[Path]:
    folder = Path(directory)
    if not folder.is_dir():
        raise ResourceNotFoundError(
            f"Không tìm thấy thư mục migration: {folder}.",
            [{"field": "migrations_dir", "record_id": str(folder)}],
        )
    return sorted(p for p in folder.iterdir() if p.is_file() and _MIGRATION_NAME.match(p.name))


def applied_versions(engine: Engine) -> set[str]:
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(_CREATE_TRACKING_TABLE)
            rows = connection.execute(text("SELECT version FROM schema_migrations")).fetchall()
    except SQLAlchemyError as exc:
        raise DatabaseError(f"Không đọc được trạng thái migration: {exc}", []) from exc
    return {row[0] for row in rows}


def apply_migrations(
    engine: Engine, directory: Path = MIGRATIONS_DIR, *, now: datetime | None = None
) -> list[str]:
    """Áp các migration chưa chạy theo thứ tự tên file. Trả về danh sách vừa áp."""
    done = applied_versions(engine)
    applied: list[str] = []
    stamp = (now or datetime.now(UTC)).astimezone(UTC).isoformat()
    for path in list_migration_files(directory):
        if path.name in done:
            continue
        statements = split_statements(path.read_text(encoding="utf-8"))
        try:
            with engine.begin() as connection:
                for statement in statements:
                    connection.exec_driver_sql(statement)
                connection.execute(
                    text("INSERT INTO schema_migrations (version, applied_at) VALUES (:v, :t)"),
                    {"v": path.name, "t": stamp},
                )
        except SQLAlchemyError as exc:
            raise DatabaseError(
                f"Migration {path.name} thất bại: {exc}",
                [{"field": "migration", "record_id": path.name}],
            ) from exc
        applied.append(path.name)
    return applied


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m sv1_data.db", description="Quản lý migration của CSDL."
    )
    parser.add_argument("command", choices=["migrate", "status"])
    args = parser.parse_args(argv)
    try:
        engine = create_db_engine(database_url_from_env())
        if args.command == "migrate":
            applied = apply_migrations(engine)
            print("Đã áp: " + ", ".join(applied) if applied else "Không có migration mới.")
        else:
            done = applied_versions(engine)
            for path in list_migration_files():
                print(f"{'đã áp   ' if path.name in done else 'chưa áp '} {path.name}")
    except AppError as exc:
        print(f"LỖI [{exc.code}]: {exc.message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
