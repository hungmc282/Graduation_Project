"""Quy trình một lệnh của SV1: đọc inventory và kết quả quét, chuẩn hóa, làm giàu, ghi dataset.

    python -m sv1_data.pipeline cau_hinh.json

File cấu hình JSON (đường dẫn tương đối được tính từ thư mục chứa file cấu hình):

    {
      "dataset_id": "dvwa-lab-v1",
      "output_dir": "out/dvwa-lab-v1",
      "inventory_csv": "assets_lab.csv",
      "nmap_xml": ["nmap_dvwa.xml"],
      "trivy": [
        {
          "path": "trivy_dvwa.json",
          "asset_id": "WEB01",
          "service_by_package": {"apache2": "WEB01:tcp/8080"}
        }
      ],
      "topology_json": "topology.json",
      "enrich": true,
      "cache_dir": "cache"
    }

`inventory_csv`, `nmap_xml`, `trivy`, `topology_json` đều tuỳ chọn nhưng phải có ít nhất một
nguồn. `topology_json` do SV2 cung cấp: {"connections": [...], "exploit_rules": [...]}.
Kết quả: `<output_dir>/dataset.json` (DatasetSnapshot hợp lệ) và `<output_dir>/report.json`
(số lượng, thời gian từng bước, mã băm file đầu vào, phiên bản EPSS/KEV, cảnh báo).
Cùng đầu vào và cùng thời điểm `now` cho ra cùng một dataset.json.
"""

import argparse
import hashlib
import json
import sys
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError

from common.errors import AppError, ContractError, ResourceNotFoundError
from common.schemas import (
    SCHEMA_VERSION,
    Asset,
    Connection,
    DatasetSnapshot,
    ExploitRule,
    Finding,
    Service,
)
from sv1_data.adapters.nmap_xml import parse_nmap_xml
from sv1_data.adapters.trivy_json import parse_trivy_json
from sv1_data.enrichment.service import enrich_findings, load_threat_data
from sv1_data.inventory import load_asset_inventory, merge_assets
from sv1_data.service import save_dataset

REPORT_FILENAME = "report.json"


class TrivyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    asset_id: str
    service_by_package: dict[str, str] = {}


class PipelineConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dataset_id: str
    output_dir: str
    inventory_csv: str | None = None
    nmap_xml: list[str] = []
    trivy: list[TrivyInput] = []
    topology_json: str | None = None
    enrich: bool = True
    cache_dir: str | None = None


class _Topology(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    connections: list[Connection]
    exploit_rules: list[ExploitRule]


@dataclass(frozen=True)
class PipelineResult:
    dataset: DatasetSnapshot
    report: dict[str, Any]
    dataset_path: Path
    report_path: Path


def load_config(path: Path) -> tuple[PipelineConfig, Path]:
    """Đọc file cấu hình; trả về (cấu hình, thư mục gốc để tính đường dẫn tương đối)."""
    config_path = Path(path)
    if not config_path.is_file():
        raise ResourceNotFoundError(
            f"Không tìm thấy file cấu hình: {config_path}.",
            [{"field": "config", "record_id": str(config_path)}],
        )
    try:
        config = PipelineConfig.model_validate_json(config_path.read_text(encoding="utf-8-sig"))
    except ValidationError as exc:
        raise ContractError(
            "File cấu hình không hợp lệ.",
            [
                {"field": ".".join(str(p) for p in e["loc"]), "record_id": "", "reason": e["msg"]}
                for e in exc.errors()
            ],
        ) from exc
    return config, config_path.resolve().parent


def run_pipeline_from_file(
    config_path: Path, *, now: datetime | None = None, client: httpx.Client | None = None
) -> PipelineResult:
    config, base_dir = load_config(config_path)
    return run_pipeline(config, base_dir, now=now, client=client)


def run_pipeline(
    config: PipelineConfig,
    base_dir: Path,
    *,
    now: datetime | None = None,
    client: httpx.Client | None = None,
) -> PipelineResult:
    """Chạy toàn bộ quy trình và ghi dataset.json cùng report.json vào `output_dir`.

    Raises:
        ContractError: cấu hình thiếu nguồn, hoặc dữ liệu đầu vào sai hợp đồng.
        ResourceNotFoundError: thiếu file đầu vào hoặc không tải được dữ liệu EPSS/KEV.
        InvalidReferenceError: tham chiếu giữa các bản ghi không hợp lệ (không ghi file nào).
    """
    created_at = now or datetime.now(UTC)
    if not (config.inventory_csv or config.nmap_xml or config.trivy or config.topology_json):
        raise ContractError(
            "Cần ít nhất một nguồn: inventory_csv, nmap_xml, trivy hoặc topology_json.",
            [{"field": "config", "record_id": ""}],
        )
    if config.enrich and config.trivy and not config.cache_dir:
        raise ContractError(
            "enrich = true cần khai báo cache_dir (hoặc đặt enrich = false).",
            [{"field": "cache_dir", "record_id": ""}],
        )

    timings: dict[str, float] = {}
    warnings: list[str] = []
    inputs: list[dict[str, str]] = []
    total_start = time.perf_counter()

    inventory_assets: list[Asset] = []
    address_map: dict[str, str] = {}
    with _stage(timings, "inventory"):
        if config.inventory_csv:
            path = _input(base_dir, config.inventory_csv, "inventory", inputs)
            inventory = load_asset_inventory(path)
            inventory_assets, address_map = inventory.assets, inventory.address_to_asset_id
            warnings += inventory.warnings

    scanned_assets: dict[str, Asset] = {}
    services: dict[str, Service] = {}
    with _stage(timings, "nmap"):
        for name in config.nmap_xml:
            scan = parse_nmap_xml(_input(base_dir, name, "nmap", inputs), address_map)
            for asset in scan.assets:
                scanned_assets.setdefault(asset.asset_id, asset)
            for service in scan.services:
                services.setdefault(service.service_id, service)
            warnings += scan.warnings

    findings: dict[str, Finding] = {}
    trivy_stats: dict[str, int] = {}
    with _stage(timings, "trivy"):
        for item in config.trivy:
            path = _input(base_dir, item.path, "trivy", inputs)
            trivy_scan = parse_trivy_json(path, item.asset_id, item.service_by_package)
            for finding in trivy_scan.findings:
                findings.setdefault(finding.finding_id, finding)
            warnings += [f"{path.name}: {w}" for w in trivy_scan.warnings]
            for key, value in trivy_scan.stats.items():
                trivy_stats[key] = trivy_stats.get(key, 0) + value

    with _stage(timings, "merge"):
        assets, merge_warnings = merge_assets(inventory_assets, list(scanned_assets.values()))
        warnings += merge_warnings

    final_findings = list(findings.values())
    threat_data: dict[str, Any] | None = None
    enrichment_stats: dict[str, int] | None = None
    with _stage(timings, "enrichment"):
        if config.enrich and final_findings:
            epss, kev, cache_warnings = load_threat_data(
                _resolve(base_dir, config.cache_dir or ""), now=created_at, client=client
            )
            enriched = enrich_findings(final_findings, epss, kev, now=created_at)
            final_findings = enriched.findings
            enrichment_stats = enriched.stats
            warnings += cache_warnings + enriched.warnings
            threat_data = {
                "epss_model_version": epss.model_version,
                "epss_score_date": epss.score_date,
                "kev_catalog_version": kev.catalog_version,
                "kev_entries": len(kev.entries),
            }

    connections: list[Connection] = []
    exploit_rules: list[ExploitRule] = []
    if config.topology_json:
        topology_path = _input(base_dir, config.topology_json, "topology", inputs)
        try:
            topology = _Topology.model_validate_json(topology_path.read_text(encoding="utf-8-sig"))
        except ValidationError as exc:
            raise ContractError(
                "File topology không đúng hợp đồng.",
                [
                    {
                        "field": ".".join(str(p) for p in e["loc"]),
                        "record_id": "",
                        "reason": e["msg"],
                    }
                    for e in exc.errors()
                ],
            ) from exc
        connections, exploit_rules = topology.connections, topology.exploit_rules

    kinds: set[str] = set()
    if config.inventory_csv or config.topology_json:
        kinds.add("manual")
    if config.nmap_xml or config.trivy:
        kinds.add("scanner")
    source = next(iter(kinds)) if len(kinds) == 1 else "mixed"

    dataset = DatasetSnapshot(
        schema_version=SCHEMA_VERSION,
        dataset_id=config.dataset_id,
        created_at=created_at,
        source=source,  # type: ignore[arg-type]
        assets=assets,
        services=list(services.values()),
        findings=final_findings,
        connections=connections,
        exploit_rules=exploit_rules,
    )

    output_dir = _resolve(base_dir, config.output_dir)
    with _stage(timings, "validate_and_save"):
        dataset_path = save_dataset(dataset, output_dir)  # kiểm tra hợp đồng trước khi ghi

    timings["total"] = round(time.perf_counter() - total_start, 6)
    report: dict[str, Any] = {
        "dataset_id": dataset.dataset_id,
        "schema_version": dataset.schema_version,
        "created_at": created_at.isoformat(),
        "source": dataset.source,
        "counts": {
            "assets": len(dataset.assets),
            "services": len(dataset.services),
            "findings": len(dataset.findings),
            "connections": len(dataset.connections),
            "exploit_rules": len(dataset.exploit_rules),
        },
        "inputs": inputs,
        "trivy_stats": trivy_stats or None,
        "threat_data": threat_data,
        "enrichment_stats": enrichment_stats,
        "timings_seconds": timings,
        "warnings": warnings,
    }
    report_path = output_dir / REPORT_FILENAME
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return PipelineResult(dataset, report, dataset_path, report_path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m sv1_data.pipeline",
        description="Đọc inventory và kết quả quét, làm giàu EPSS/KEV, ghi dataset.json.",
    )
    parser.add_argument("config", help="đường dẫn file cấu hình JSON")
    args = parser.parse_args(argv)
    try:
        result = run_pipeline_from_file(Path(args.config))
    except AppError as exc:
        print(f"LỖI [{exc.code}]: {exc.message}", file=sys.stderr)
        for detail in exc.details[:20]:
            print(f"  - {detail}", file=sys.stderr)
        return 1

    counts = result.report["counts"]
    print(f"Đã ghi {result.dataset_path}")
    print(
        f"  {counts['assets']} asset, {counts['services']} service, "
        f"{counts['findings']} finding, {counts['connections']} connection"
    )
    print(f"  Thời gian: {result.report['timings_seconds']['total']} giây")
    for warning in result.report["warnings"]:
        print(f"  Cảnh báo: {warning}")
    print(f"Báo cáo: {result.report_path}")
    return 0


@contextmanager
def _stage(timings: dict[str, float], name: str) -> Iterator[None]:
    start = time.perf_counter()
    try:
        yield
    finally:
        timings[name] = round(time.perf_counter() - start, 6)


def _resolve(base_dir: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else base_dir / path


def _input(base_dir: Path, value: str, kind: str, inputs: list[dict[str, str]]) -> Path:
    path = _resolve(base_dir, value)
    if not path.is_file():
        raise ResourceNotFoundError(
            f"Không tìm thấy file đầu vào ({kind}): {path}.",
            [{"field": kind, "record_id": str(path)}],
        )
    inputs.append(
        {"kind": kind, "file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    )
    return path


if __name__ == "__main__":
    sys.exit(main())
