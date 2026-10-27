"""Bộ sinh dữ liệu GIẢ LẬP có hạt giống cố định, phục vụ thực nghiệm (đề tài, đầu ra số 12).

    python -m sv1_data.synthetic --out data/samples/synthetic --seed 42

Cùng `seed` và cùng tham số cho ra cùng một dataset.json (từng byte). Mọi bản ghi mang
`source = "synthetic"`, mã lỗ hổng dạng `SYN-NNNNN`, nên không thể nhầm với dữ liệu quét thật.

Mô hình:
- Bốn tầng: web (hướng Internet), app, db (chứa dữ liệu nhạy cảm), other (máy phụ, máy thử).
  Kết nối: INTERNET -> web -> app -> db; một số máy `other` chỉ với tới được từ web/app
  (ngõ cụt) và số còn lại không có kết nối nào.
- Điểm CVSS, EPSS và cờ KEV là thuộc tính của LỖ HỔNG (không phải của tài sản): một danh mục
  lỗ hổng được sinh trước, rồi mỗi tài sản lấy ngẫu nhiên các lỗ hổng từ đó.
- Hiệu chỉnh theo MỘT báo cáo Trivy thật (image DVWA, 1575 finding): CVSS theo bốn mức
  (thấp 7%, trung bình 41%, cao 35%, nghiêm trọng 17%), KEV khoảng 1,4% và phần lớn KEV có
  CVSS từ 9, khoảng 8% lỗ hổng không phải KEV vẫn có EPSS từ 0,5, khoảng 0,8% thiếu điểm
  (cvss, epss, is_kev đều null). Đây chỉ là mô phỏng gần đúng, không đại diện cho mọi hệ thống.
- `exploit_rules` để rỗng: luật khai thác thuộc SV2.
"""

import argparse
import json
import random
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from common.errors import AppError, ContractError
from common.schemas import (
    INTERNET_ID,
    SCHEMA_VERSION,
    Asset,
    Connection,
    DatasetSnapshot,
    Finding,
    Service,
)
from sv1_data.service import save_dataset

GENERATOR_VERSION = "1.0"
DEFAULT_SIZES = (10, 50, 200)
DEFAULT_CREATED_AT = datetime(2026, 10, 1, tzinfo=UTC)
MANIFEST_FILENAME = "scenarios.json"

_SEVERITY_RANGES = ((0.1, 3.9), (4.0, 6.9), (7.0, 8.9), (9.0, 10.0))
_SEVERITY_WEIGHTS = (0.07, 0.41, 0.35, 0.17)
_KEV_RATE = 0.014
_KEV_HIGH_CVSS_SHARE = 0.73
_HIGH_EPSS_RATE = 0.08
_MISSING_RATE = 0.008
_BLOCKED_CONNECTION_RATE = 0.03
_UNKNOWN_CRITICALITY_RATE = 0.05

# Mỗi tầng: tiền tố asset_id, loại tài sản, cổng, sản phẩm, các phiên bản, khoảng số finding
_TIERS: dict[str, dict[str, Any]] = {
    "web": {
        "prefix": "WEB",
        "type": "web_server",
        "port": 443,
        "product": "nginx",
        "versions": ("1.14.0", "1.18.0", "1.22.1"),
        "findings": (4, 12),
    },
    "app": {
        "prefix": "APP",
        "type": "application_server",
        "port": 8080,
        "product": "tomcat",
        "versions": ("8.5.50", "9.0.30", "9.0.65"),
        "findings": (4, 12),
    },
    "db": {
        "prefix": "DB",
        "type": "database_server",
        "port": 5432,
        "product": "postgresql",
        "versions": ("11.5", "12.2", "13.4"),
        "findings": (3, 10),
    },
    "other": {
        "prefix": "OTH",
        "type": "other_server",
        "port": 22,
        "product": "openssh",
        "versions": ("7.4", "8.0", "8.9"),
        "findings": (1, 6),
    },
}


@dataclass(frozen=True)
class _Vuln:
    vuln_id: str
    cvss: float | None
    epss: float | None
    kev: bool | None


def generate_dataset(
    *,
    seed: int,
    n_assets: int,
    created_at: datetime = DEFAULT_CREATED_AT,
    dataset_id: str | None = None,
) -> DatasetSnapshot:
    """Sinh một DatasetSnapshot giả lập hợp lệ gồm `n_assets` tài sản (tối thiểu 4)."""
    if n_assets < 4:
        raise ContractError(
            "n_assets phải từ 4 trở lên (cần ít nhất một máy mỗi tầng).",
            [{"field": "n_assets", "record_id": str(n_assets)}],
        )
    if created_at.tzinfo is None:
        raise ContractError(
            "created_at phải có timezone.", [{"field": "created_at", "record_id": ""}]
        )

    rng = random.Random(seed)
    counts = _tier_counts(n_assets)
    width = 3 if n_assets > 99 else 2
    ids = {
        tier: [f"{_TIERS[tier]['prefix']}{i:0{width}d}" for i in range(1, counts[tier] + 1)]
        for tier in _TIERS
    }
    catalog = _make_catalog(rng, max(30, n_assets * 4))

    assets: list[Asset] = []
    services: list[Service] = []
    service_of: dict[str, str] = {}
    for tier, spec in _TIERS.items():
        for asset_id in ids[tier]:
            assets.append(_make_asset(rng, tier, asset_id))
            service = Service(
                service_id=f"{asset_id}:tcp/{spec['port']}",
                asset_id=asset_id,
                protocol="tcp",
                port=spec["port"],
                product=spec["product"],
                product_version=rng.choice(spec["versions"]),
            )
            services.append(service)
            service_of[asset_id] = service.service_id

    findings: list[Finding] = []
    for tier, spec in _TIERS.items():
        low, high = spec["findings"]
        for asset_id in ids[tier]:
            for index in rng.sample(range(len(catalog)), rng.randint(low, high)):
                vuln = catalog[index]
                findings.append(
                    Finding(
                        finding_id=f"{asset_id}:{vuln.vuln_id}",
                        asset_id=asset_id,
                        service_id=service_of[asset_id] if rng.random() < 0.85 else None,
                        vulnerability_id=vuln.vuln_id,
                        cvss_score=vuln.cvss,
                        epss_probability=vuln.epss,
                        is_kev=vuln.kev,
                        source="synthetic",
                        evidence=["synthetic fixture, not a real scan"],
                        observed_at=created_at,
                        enriched_at=created_at,
                    )
                )

    return DatasetSnapshot(
        schema_version=SCHEMA_VERSION,
        dataset_id=dataset_id or f"synthetic-{n_assets}-seed{seed}",
        created_at=created_at,
        source="synthetic",
        assets=assets,
        services=services,
        findings=findings,
        connections=_make_connections(rng, ids, service_of),
        exploit_rules=[],
    )


def generate_scenarios(
    output_dir: Path, *, seed: int = 42, sizes: Sequence[int] = DEFAULT_SIZES
) -> list[dict[str, Any]]:
    """Sinh nhiều quy mô vào `<output_dir>/synthetic_<n>/` kèm file tổng hợp `scenarios.json`."""
    root = Path(output_dir)
    manifest: list[dict[str, Any]] = []
    for size in sizes:
        dataset = generate_dataset(seed=seed, n_assets=size)
        directory = f"synthetic_{size}"
        save_dataset(dataset, root / directory)
        manifest.append(
            {
                "dataset_id": dataset.dataset_id,
                "directory": directory,
                "seed": seed,
                "assets": len(dataset.assets),
                "services": len(dataset.services),
                "findings": len(dataset.findings),
                "connections": len(dataset.connections),
                "kev_findings": sum(1 for f in dataset.findings if f.is_kev),
            }
        )
    payload = {"generator_version": GENERATOR_VERSION, "seed": seed, "scenarios": manifest}
    (root / MANIFEST_FILENAME).write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m sv1_data.synthetic",
        description="Sinh bộ dữ liệu giả lập tái lập được (cùng seed cho cùng kết quả).",
    )
    parser.add_argument("--out", required=True, help="thư mục đầu ra")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--sizes", type=int, nargs="+", default=list(DEFAULT_SIZES))
    args = parser.parse_args(argv)
    try:
        manifest = generate_scenarios(Path(args.out), seed=args.seed, sizes=args.sizes)
    except AppError as exc:
        print(f"LỖI [{exc.code}]: {exc.message}", file=sys.stderr)
        return 1
    for item in manifest:
        print(
            f"{item['directory']}: {item['assets']} asset, {item['services']} service, "
            f"{item['findings']} finding ({item['kev_findings']} KEV), "
            f"{item['connections']} connection"
        )
    print(f"Đã ghi vào {args.out} (seed {args.seed})")
    return 0


def _tier_counts(n_assets: int) -> dict[str, int]:
    web = max(1, round(n_assets * 0.15))
    app = max(1, round(n_assets * 0.30))
    db = max(1, round(n_assets * 0.15))
    while n_assets - web - app - db < 1:
        app -= 1
    return {"web": web, "app": app, "db": db, "other": n_assets - web - app - db}


def _make_catalog(rng: random.Random, size: int) -> list[_Vuln]:
    catalog: list[_Vuln] = []
    for number in range(1, size + 1):
        vuln_id = f"SYN-{number:05d}"
        if rng.random() < _MISSING_RATE:
            catalog.append(_Vuln(vuln_id, None, None, None))
            continue
        if rng.random() < _KEV_RATE:
            low, high = (9.0, 10.0) if rng.random() < _KEV_HIGH_CVSS_SHARE else (5.0, 8.9)
            cvss, epss, kev = rng.uniform(low, high), rng.uniform(0.5, 1.0), True
        else:
            low, high = rng.choices(_SEVERITY_RANGES, weights=_SEVERITY_WEIGHTS)[0]
            cvss = rng.uniform(low, high)
            if rng.random() < _HIGH_EPSS_RATE:
                epss = rng.uniform(0.5, 0.99)
            else:
                epss = rng.random() ** 3 * 0.5
            kev = False
        catalog.append(_Vuln(vuln_id, round(cvss, 1), round(epss, 5), kev))
    return catalog


def _make_asset(rng: random.Random, tier: str, asset_id: str) -> Asset:
    if tier == "web":
        criticality, sensitive = rng.randint(2, 3), False
    elif tier == "app":
        criticality, sensitive = rng.randint(3, 4), False
    elif tier == "db":
        criticality, sensitive = rng.randint(4, 5), True
    else:
        criticality, sensitive = rng.randint(1, 2), False
    unknown = rng.random() < _UNKNOWN_CRITICALITY_RATE
    return Asset(
        asset_id=asset_id,
        name=f"{_TIERS[tier]['type'].replace('_', ' ').title()} {asset_id}",
        asset_type=_TIERS[tier]["type"],
        internet_facing=tier == "web",
        criticality=None if unknown else criticality,
        sensitive_data=sensitive,
    )


def _make_connections(
    rng: random.Random, ids: dict[str, list[str]], service_of: dict[str, str]
) -> list[Connection]:
    connections: list[Connection] = []
    seen: set[tuple[str, str]] = set()

    def add(source: str, target: str) -> None:
        if (source, target) in seen:
            return
        seen.add((source, target))
        connections.append(
            Connection(
                connection_id=f"C-{source}-{target}",
                source_asset_id=source,
                target_asset_id=target,
                target_service_id=service_of[target],
                allowed=rng.random() >= _BLOCKED_CONNECTION_RATE,
                evidence=["synthetic topology"],
            )
        )

    webs, apps, dbs, others = ids["web"], ids["app"], ids["db"], ids["other"]
    for web in webs:
        add(INTERNET_ID, web)
    for app in apps:
        for parent in _pick_parents(rng, webs):
            add(parent, app)
    for db in dbs:
        for parent in _pick_parents(rng, apps):
            add(parent, db)
    for other in others:
        if rng.random() < 0.5:
            add(rng.choice(webs + apps), other)
    return connections


def _pick_parents(rng: random.Random, candidates: list[str]) -> list[str]:
    """Một cha chính cộng tối đa hai cha phụ, để số kết nối tăng theo tuyến tính với quy mô."""
    extra = rng.randint(0, min(2, len(candidates)))
    return sorted({rng.choice(candidates), *rng.sample(candidates, extra)})


if __name__ == "__main__":
    sys.exit(main())
