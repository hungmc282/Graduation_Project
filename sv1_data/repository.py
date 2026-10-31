"""Kho lưu DatasetSnapshot trong CSDL quan hệ (ARCHITECTURE.md, mục 2, 4 và 6.4).

    python -m sv1_data.repository save   <thư mục chứa dataset.json>
    python -m sv1_data.repository list
    python -m sv1_data.repository export <dataset_id> <thư mục đích>

Quy tắc:
- Snapshot bất biến. Lưu lại cùng `dataset_id` với CÙNG nội dung thì không làm gì (trả về False).
  Cùng `dataset_id` mà nội dung khác thì từ chối, không bao giờ ghi đè hay tái sử dụng ID.
  "Cùng nội dung" so bằng `content_hash` (xem identity.py), bỏ qua created_at và enriched_at.
- Bảng được tạo bằng migration (python -m sv1_data.db migrate); nơi này không tự tạo bảng.
- Mỗi lần lưu là một giao dịch: hoặc ghi đủ mọi bảng, hoặc không ghi gì.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError

from common.errors import AppError, ContractError, ResourceNotFoundError
from common.schemas import Asset, Connection, DatasetSnapshot, ExploitRule, Finding, Service
from sv1_data.db import DatabaseError, create_db_engine, database_url_from_env
from sv1_data.identity import content_hash
from sv1_data.service import load_dataset, save_dataset, validate_dataset

_SELECT_HASH = "SELECT content_sha256 FROM datasets WHERE dataset_id = :id"
_SELECT_DATASET = "SELECT schema_version, created_at, source FROM datasets WHERE dataset_id = :id"
_SELECT_LIST = (
    "SELECT dataset_id, created_at, source, content_sha256, recorded_at "
    "FROM datasets ORDER BY recorded_at, dataset_id"
)
_INSERT_DATASET = (
    "INSERT INTO datasets (dataset_id, schema_version, created_at, source, content_sha256, "
    "recorded_at) VALUES (:dataset_id, :schema_version, :created_at, :source, :content_sha256, "
    ":recorded_at)"
)
_INSERT_ASSET = (
    "INSERT INTO assets (dataset_id, row_order, asset_id, name, asset_type, internet_facing, "
    "criticality, sensitive_data) VALUES (:dataset_id, :row_order, :asset_id, :name, "
    ":asset_type, :internet_facing, :criticality, :sensitive_data)"
)
_INSERT_SERVICE = (
    "INSERT INTO services (dataset_id, row_order, service_id, asset_id, protocol, port, "
    "product, product_version) VALUES (:dataset_id, :row_order, :service_id, :asset_id, "
    ":protocol, :port, :product, :product_version)"
)
_INSERT_FINDING = (
    "INSERT INTO findings (dataset_id, row_order, finding_id, asset_id, service_id, "
    "vulnerability_id, cvss_score, epss_probability, is_kev, source, evidence, observed_at, "
    "enriched_at) VALUES (:dataset_id, :row_order, :finding_id, :asset_id, :service_id, "
    ":vulnerability_id, :cvss_score, :epss_probability, :is_kev, :source, :evidence, "
    ":observed_at, :enriched_at)"
)
_INSERT_CONNECTION = (
    "INSERT INTO connections (dataset_id, row_order, connection_id, source_asset_id, "
    "target_asset_id, target_service_id, allowed, evidence) VALUES (:dataset_id, :row_order, "
    ":connection_id, :source_asset_id, :target_asset_id, :target_service_id, :allowed, "
    ":evidence)"
)
_INSERT_RULE = (
    "INSERT INTO exploit_rules (dataset_id, row_order, rule_id, source_asset_id, "
    "target_asset_id, required_finding_id, required_state, resulting_state, rule_type, "
    "evidence) VALUES (:dataset_id, :row_order, :rule_id, :source_asset_id, :target_asset_id, "
    ":required_finding_id, :required_state, :resulting_state, :rule_type, :evidence)"
)
_SELECT_ASSETS = (
    "SELECT asset_id, name, asset_type, internet_facing, criticality, sensitive_data "
    "FROM assets WHERE dataset_id = :id ORDER BY row_order"
)
_SELECT_SERVICES = (
    "SELECT service_id, asset_id, protocol, port, product, product_version "
    "FROM services WHERE dataset_id = :id ORDER BY row_order"
)
_SELECT_FINDINGS = (
    "SELECT finding_id, asset_id, service_id, vulnerability_id, cvss_score, epss_probability, "
    "is_kev, source, evidence, observed_at, enriched_at "
    "FROM findings WHERE dataset_id = :id ORDER BY row_order"
)
_SELECT_CONNECTIONS = (
    "SELECT connection_id, source_asset_id, target_asset_id, target_service_id, allowed, "
    "evidence FROM connections WHERE dataset_id = :id ORDER BY row_order"
)
_SELECT_RULES = (
    "SELECT rule_id, source_asset_id, target_asset_id, required_finding_id, required_state, "
    "resulting_state, rule_type, evidence FROM exploit_rules WHERE dataset_id = :id "
    "ORDER BY row_order"
)


@dataclass(frozen=True)
class DatasetRecord:
    dataset_id: str
    created_at: datetime
    source: str
    content_sha256: str
    recorded_at: datetime


class DatasetRepository:
    """Lưu và đọc DatasetSnapshot. Cần bảng đã được tạo bằng migration."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def save(self, dataset: DatasetSnapshot, *, now: datetime | None = None) -> bool:
        """Lưu snapshot. Trả về True nếu vừa ghi mới, False nếu đã có nội dung giống hệt.

        Raises:
            InvalidReferenceError / ContractError: snapshot không hợp lệ (kiểm tra trước khi ghi).
            ContractError: `dataset_id` đã dùng cho nội dung khác.
            DatabaseError: lỗi CSDL (ví dụ chưa chạy migration).
        """
        validate_dataset(dataset)
        digest = content_hash(dataset)
        recorded_at = _iso(now or datetime.now(UTC))
        try:
            with self._engine.begin() as connection:
                existing = connection.execute(
                    text(_SELECT_HASH), {"id": dataset.dataset_id}
                ).first()
                if existing is not None:
                    if existing[0] == digest:
                        return False
                    raise ContractError(
                        f"dataset_id {dataset.dataset_id!r} đã được dùng cho nội dung khác.",
                        [{"field": "dataset_id", "record_id": dataset.dataset_id}],
                    )
                connection.execute(
                    text(_INSERT_DATASET),
                    {
                        "dataset_id": dataset.dataset_id,
                        "schema_version": dataset.schema_version,
                        "created_at": _iso(dataset.created_at),
                        "source": dataset.source,
                        "content_sha256": digest,
                        "recorded_at": recorded_at,
                    },
                )
                self._insert_children(connection, dataset)
        except SQLAlchemyError as exc:
            raise _database_error(exc) from exc
        return True

    def load(self, dataset_id: str) -> DatasetSnapshot:
        """Đọc lại snapshot đã lưu (đúng thứ tự bản ghi) và kiểm tra lại hợp đồng."""
        params = {"id": dataset_id}
        try:
            with self._engine.begin() as connection:
                head = connection.execute(text(_SELECT_DATASET), params).first()
                if head is None:
                    raise ResourceNotFoundError(
                        f"Không có dataset {dataset_id!r} trong CSDL.",
                        [{"field": "dataset_id", "record_id": dataset_id}],
                    )
                assets = connection.execute(text(_SELECT_ASSETS), params).fetchall()
                services = connection.execute(text(_SELECT_SERVICES), params).fetchall()
                findings = connection.execute(text(_SELECT_FINDINGS), params).fetchall()
                connections = connection.execute(text(_SELECT_CONNECTIONS), params).fetchall()
                rules = connection.execute(text(_SELECT_RULES), params).fetchall()
        except SQLAlchemyError as exc:
            raise _database_error(exc) from exc

        dataset = DatasetSnapshot(
            schema_version=head[0],
            dataset_id=dataset_id,
            created_at=_to_datetime(head[1]),
            source=head[2],
            assets=[
                Asset(
                    asset_id=r[0],
                    name=r[1],
                    asset_type=r[2],
                    internet_facing=_to_bool(r[3]),
                    criticality=r[4],
                    sensitive_data=_to_bool(r[5]),
                )
                for r in assets
            ],
            services=[
                Service(
                    service_id=r[0],
                    asset_id=r[1],
                    protocol=r[2],
                    port=r[3],
                    product=r[4],
                    product_version=r[5],
                )
                for r in services
            ],
            findings=[
                Finding(
                    finding_id=r[0],
                    asset_id=r[1],
                    service_id=r[2],
                    vulnerability_id=r[3],
                    cvss_score=r[4],
                    epss_probability=r[5],
                    is_kev=_to_bool(r[6]),
                    source=r[7],
                    evidence=json.loads(r[8]),
                    observed_at=_to_datetime(r[9]),
                    enriched_at=_to_datetime(r[10]),
                )
                for r in findings
            ],
            connections=[
                Connection(
                    connection_id=r[0],
                    source_asset_id=r[1],
                    target_asset_id=r[2],
                    target_service_id=r[3],
                    allowed=bool(r[4]),
                    evidence=json.loads(r[5]),
                )
                for r in connections
            ],
            exploit_rules=[
                ExploitRule(
                    rule_id=r[0],
                    source_asset_id=r[1],
                    target_asset_id=r[2],
                    required_finding_id=r[3],
                    required_state=r[4],
                    resulting_state=r[5],
                    rule_type=r[6],
                    evidence=json.loads(r[7]),
                )
                for r in rules
            ],
        )
        validate_dataset(dataset)
        return dataset

    def exists(self, dataset_id: str) -> bool:
        try:
            with self._engine.begin() as connection:
                row = connection.execute(text(_SELECT_HASH), {"id": dataset_id}).first()
                return row is not None
        except SQLAlchemyError as exc:
            raise _database_error(exc) from exc

    def list_datasets(self) -> list[DatasetRecord]:
        try:
            with self._engine.begin() as connection:
                rows = connection.execute(text(_SELECT_LIST)).fetchall()
        except SQLAlchemyError as exc:
            raise _database_error(exc) from exc
        return [
            DatasetRecord(
                dataset_id=r[0],
                created_at=_to_datetime(r[1]),  # type: ignore[arg-type]
                source=r[2],
                content_sha256=r[3],
                recorded_at=_to_datetime(r[4]),  # type: ignore[arg-type]
            )
            for r in rows
        ]

    @staticmethod
    def _insert_children(connection: Any, dataset: DatasetSnapshot) -> None:
        did = dataset.dataset_id
        groups = (
            (_INSERT_ASSET, dataset.assets, _asset_row),
            (_INSERT_SERVICE, dataset.services, _service_row),
            (_INSERT_FINDING, dataset.findings, _finding_row),
            (_INSERT_CONNECTION, dataset.connections, _connection_row),
            (_INSERT_RULE, dataset.exploit_rules, _rule_row),
        )
        for statement, items, to_row in groups:  # đúng thứ tự phụ thuộc khóa ngoại
            if items:
                connection.execute(
                    text(statement), [to_row(did, i, item) for i, item in enumerate(items)]
                )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m sv1_data.repository", description="Lưu và đọc dataset trong CSDL."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    save_parser = commands.add_parser("save", help="lưu dataset.json trong một thư mục")
    save_parser.add_argument("directory")
    commands.add_parser("list", help="liệt kê dataset đã lưu")
    export_parser = commands.add_parser("export", help="ghi một dataset ra thư mục")
    export_parser.add_argument("dataset_id")
    export_parser.add_argument("directory")
    args = parser.parse_args(argv)

    try:
        repository = DatasetRepository(create_db_engine(database_url_from_env()))
        if args.command == "save":
            dataset = load_dataset(Path(args.directory))
            saved = repository.save(dataset)
            print(("Đã lưu " if saved else "Đã có sẵn, không ghi lại: ") + dataset.dataset_id)
        elif args.command == "list":
            for record in repository.list_datasets():
                print(f"{record.dataset_id}  {record.source}  {record.created_at.isoformat()}")
        else:
            path = save_dataset(repository.load(args.dataset_id), Path(args.directory))
            print(f"Đã ghi {path}")
    except AppError as exc:
        print(f"LỖI [{exc.code}]: {exc.message}", file=sys.stderr)
        return 1
    return 0


def _asset_row(dataset_id: str, order: int, a: Asset) -> dict[str, Any]:
    return {
        "dataset_id": dataset_id,
        "row_order": order,
        "asset_id": a.asset_id,
        "name": a.name,
        "asset_type": a.asset_type,
        "internet_facing": a.internet_facing,
        "criticality": a.criticality,
        "sensitive_data": a.sensitive_data,
    }


def _service_row(dataset_id: str, order: int, s: Service) -> dict[str, Any]:
    return {
        "dataset_id": dataset_id,
        "row_order": order,
        "service_id": s.service_id,
        "asset_id": s.asset_id,
        "protocol": s.protocol,
        "port": s.port,
        "product": s.product,
        "product_version": s.product_version,
    }


def _finding_row(dataset_id: str, order: int, f: Finding) -> dict[str, Any]:
    return {
        "dataset_id": dataset_id,
        "row_order": order,
        "finding_id": f.finding_id,
        "asset_id": f.asset_id,
        "service_id": f.service_id,
        "vulnerability_id": f.vulnerability_id,
        "cvss_score": f.cvss_score,
        "epss_probability": f.epss_probability,
        "is_kev": f.is_kev,
        "source": f.source,
        "evidence": json.dumps(f.evidence, ensure_ascii=False),
        "observed_at": _iso(f.observed_at),
        "enriched_at": _iso(f.enriched_at),
    }


def _connection_row(dataset_id: str, order: int, c: Connection) -> dict[str, Any]:
    return {
        "dataset_id": dataset_id,
        "row_order": order,
        "connection_id": c.connection_id,
        "source_asset_id": c.source_asset_id,
        "target_asset_id": c.target_asset_id,
        "target_service_id": c.target_service_id,
        "allowed": c.allowed,
        "evidence": json.dumps(c.evidence, ensure_ascii=False),
    }


def _rule_row(dataset_id: str, order: int, r: ExploitRule) -> dict[str, Any]:
    return {
        "dataset_id": dataset_id,
        "row_order": order,
        "rule_id": r.rule_id,
        "source_asset_id": r.source_asset_id,
        "target_asset_id": r.target_asset_id,
        "required_finding_id": r.required_finding_id,
        "required_state": r.required_state,
        "resulting_state": r.resulting_state,
        "rule_type": r.rule_type,
        "evidence": json.dumps(r.evidence, ensure_ascii=False),
    }


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.astimezone(UTC).isoformat()


def _to_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _to_bool(value: Any) -> bool | None:
    return None if value is None else bool(value)


def _database_error(exc: SQLAlchemyError) -> DatabaseError:
    return DatabaseError(
        f"Lỗi CSDL: {exc}. Nếu bảng chưa tồn tại, chạy: python -m sv1_data.db migrate", []
    )


if __name__ == "__main__":
    sys.exit(main())
