"""Kiểm tra kết nối CSDL và migration (SQLite trong thư mục tạm, không cần Docker)."""

from pathlib import Path

import pytest
from sqlalchemy import Engine, inspect
from sqlalchemy.exc import IntegrityError

from common.errors import ContractError, ResourceNotFoundError
from sv1_data.db import (
    DATABASE_URL_ENV,
    DatabaseError,
    applied_versions,
    apply_migrations,
    create_db_engine,
    database_url_from_env,
    list_migration_files,
    main,
    split_statements,
)

EXPECTED_TABLES = {
    "datasets",
    "assets",
    "services",
    "findings",
    "connections",
    "exploit_rules",
    "schema_migrations",
}


@pytest.fixture
def engine(tmp_path: Path) -> Engine:
    return create_db_engine(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")


def write_migration(directory: Path, name: str, sql: str) -> None:
    directory.mkdir(exist_ok=True)
    (directory / name).write_text(sql, encoding="utf-8")


def test_split_statements_ignores_comments_blank_lines_and_trailing_semicolon() -> None:
    sql = "-- chú thích\nCREATE TABLE a (x INTEGER);\n\n-- khác\nCREATE TABLE b (\n  y TEXT\n);\n"
    assert split_statements(sql) == ["CREATE TABLE a (x INTEGER)", "CREATE TABLE b (\n  y TEXT\n)"]


def test_only_numbered_sql_files_are_listed_in_order(tmp_path: Path) -> None:
    for name in ("0002_b.sql", "0001_a.sql", "notes.txt", "1_bad.sql", "0003_x.SQL"):
        write_migration(tmp_path, name, "SELECT 1;")
    assert [p.name for p in list_migration_files(tmp_path)] == ["0001_a.sql", "0002_b.sql"]


def test_missing_migration_directory_is_reported(tmp_path: Path) -> None:
    with pytest.raises(ResourceNotFoundError):
        list_migration_files(tmp_path / "nope")


def test_the_repository_ships_the_first_migration() -> None:
    assert "0001_sv1_source_data.sql" in [p.name for p in list_migration_files()]


def test_migrations_create_every_table(engine: Engine) -> None:
    assert apply_migrations(engine) == ["0001_sv1_source_data.sql"]
    assert EXPECTED_TABLES <= set(inspect(engine).get_table_names())


def test_applying_twice_does_nothing_the_second_time(engine: Engine) -> None:
    apply_migrations(engine)
    assert apply_migrations(engine) == []
    assert applied_versions(engine) == {"0001_sv1_source_data.sql"}


def test_only_new_files_are_applied_later(engine: Engine, tmp_path: Path) -> None:
    folder = tmp_path / "migs"
    write_migration(folder, "0001_first.sql", "CREATE TABLE one (x INTEGER);")
    assert apply_migrations(engine, folder) == ["0001_first.sql"]
    write_migration(folder, "0002_second.sql", "CREATE TABLE two (x INTEGER);")
    assert apply_migrations(engine, folder) == ["0002_second.sql"]
    assert {"one", "two"} <= set(inspect(engine).get_table_names())


def test_a_failing_migration_is_reported_and_not_recorded(engine: Engine, tmp_path: Path) -> None:
    folder = tmp_path / "migs"
    write_migration(folder, "0001_bad.sql", "CREATE TABLE ok (x INTEGER);\nTHIS IS NOT SQL;")
    with pytest.raises(DatabaseError):
        apply_migrations(engine, folder)
    assert "0001_bad.sql" not in applied_versions(engine)


def test_database_url_comes_from_the_environment() -> None:
    assert database_url_from_env({DATABASE_URL_ENV: " sqlite:///x.db "}) == "sqlite:///x.db"
    with pytest.raises(ContractError):
        database_url_from_env({})
    with pytest.raises(ContractError):
        database_url_from_env({DATABASE_URL_ENV: "   "})


def test_sqlite_engine_enforces_foreign_keys_like_postgresql(engine: Engine) -> None:
    apply_migrations(engine)
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.exec_driver_sql(
            "INSERT INTO services VALUES ('d', 0, 'S1', 'MISSING', 'tcp', 22, NULL, NULL)"
        )


def test_check_constraints_reject_out_of_range_values(engine: Engine) -> None:
    apply_migrations(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "INSERT INTO datasets VALUES ('d', '1.0.0', '2026-01-01T00:00:00+00:00', "
            "'synthetic', 'x', '2026-01-01T00:00:00+00:00')"
        )
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.exec_driver_sql(
            "INSERT INTO assets VALUES ('d', 0, 'A', 'n', NULL, NULL, 9, NULL)"
        )


def test_command_line_migrate_and_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(DATABASE_URL_ENV, f"sqlite:///{(tmp_path / 'cli.db').as_posix()}")
    assert main(["status"]) == 0
    assert "chưa áp" in capsys.readouterr().out
    assert main(["migrate"]) == 0
    assert "0001_sv1_source_data.sql" in capsys.readouterr().out
    assert main(["migrate"]) == 0
    assert "Không có migration mới" in capsys.readouterr().out
    assert main(["status"]) == 0
    assert "đã áp" in capsys.readouterr().out


def test_command_line_without_the_url_variable_fails_cleanly(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv(DATABASE_URL_ENV, raising=False)
    assert main(["migrate"]) == 1
    assert DATABASE_URL_ENV in capsys.readouterr().err
