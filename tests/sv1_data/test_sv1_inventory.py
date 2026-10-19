"""Kiểm tra Asset Inventory (nhập CSV và ghép với kết quả quét)."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from common.errors import ContractError, ResourceNotFoundError
from common.schemas import Asset, DatasetSnapshot
from sv1_data.adapters.nmap_xml import parse_nmap_xml_bytes
from sv1_data.inventory import (
    AssetInventory,
    load_asset_inventory,
    merge_assets,
    parse_asset_inventory_bytes,
)
from sv1_data.service import load_dataset, validate_dataset

SAMPLE_DIR = Path(__file__).resolve().parents[2] / "data" / "samples" / "demo_lab_v1"

HEADER = "asset_id,name,asset_type,internet_facing,criticality,sensitive_data,addresses\n"

NMAP_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.80">
<host><status state="up"/><address addr="10.0.1.10" addrtype="ipv4"/>
<hostnames><hostname name="web.lab" type="user"/></hostnames>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="https" product="nginx" version="1.18.0"/></port></ports></host>
</nmaprun>
"""


def parse(csv_text: str) -> AssetInventory:
    return parse_asset_inventory_bytes(csv_text.encode("utf-8"))


def details_of(csv_text: str) -> list[dict]:
    with pytest.raises(ContractError) as info:
        parse(csv_text)
    return info.value.details


def test_sample_csv_matches_sample_dataset_assets() -> None:
    inventory = load_asset_inventory(SAMPLE_DIR / "assets.csv")
    assert inventory.assets == load_dataset(SAMPLE_DIR).assets


def test_sample_csv_address_mapping_and_ignored_column_warning() -> None:
    inventory = load_asset_inventory(SAMPLE_DIR / "assets.csv")
    assert inventory.address_to_asset_id["10.0.1.10"] == "WEB01"
    assert inventory.address_to_asset_id["10.0.3.10"] == "DB01"
    assert any("subnet" in w for w in inventory.warnings)


def test_boolean_variants_and_blank_means_unknown() -> None:
    inventory = parse(
        HEADER + "A1,Alpha,server,TRUE,1,no,\n" + "A2,Beta,server,0,2,Yes,\n" + "A3,Gamma,,,,,\n"
    )
    a1, a2, a3 = inventory.assets
    assert (a1.internet_facing, a1.sensitive_data, a1.criticality) == (True, False, 1)
    assert (a2.internet_facing, a2.sensitive_data, a2.criticality) == (False, True, 2)
    assert (a3.asset_type, a3.internet_facing, a3.criticality, a3.sensitive_data) == (
        None,
        None,
        None,
        None,
    )


def test_optional_columns_may_be_absent() -> None:
    inventory = parse("asset_id,name\nA1,Alpha\n")
    asset = inventory.assets[0]
    assert (asset.asset_type, asset.internet_facing, asset.criticality) == (None, None, None)


def test_bom_and_semicolon_delimiter_from_excel() -> None:
    data = b"\xef\xbb\xbf" + b"asset_id;name;criticality\nA1;Alpha;3\n"
    inventory = parse_asset_inventory_bytes(data)
    assert inventory.assets[0].criticality == 3


def test_multiple_addresses_and_ipv6_normalised() -> None:
    inventory = parse(HEADER + 'A1,Alpha,,,,,"10.0.0.1|10.0.0.2 fe80:0:0:0:0:0:0:1"\n')
    assert inventory.address_to_asset_id == {
        "10.0.0.1": "A1",
        "10.0.0.2": "A1",
        "fe80::1": "A1",
    }


def test_blank_rows_are_skipped() -> None:
    inventory = parse(HEADER + "A1,Alpha,,,,,\n,,,,,,\n\nA2,Beta,,,,,\n")
    assert [a.asset_id for a in inventory.assets] == ["A1", "A2"]


def test_asset_without_address_gets_warning() -> None:
    inventory = parse(HEADER + "A1,Alpha,,,,,10.0.0.1\nA2,Beta,,,,,\n")
    assert any("A2" in w for w in inventory.warnings)
    assert not any("A1" in w for w in inventory.warnings)


@pytest.mark.parametrize("value", ["0", "6", "high", "2.5"])
def test_invalid_criticality_reports_row(value: str) -> None:
    errors = details_of(HEADER + f"A1,Alpha,,,{value},,\n")
    assert errors[0]["field"] == "criticality"
    assert errors[0]["row"] == 2
    assert errors[0]["record_id"] == "A1"


def test_invalid_boolean_rejected() -> None:
    errors = details_of(HEADER + "A1,Alpha,,maybe,,,\n")
    assert errors[0]["field"] == "internet_facing"


def test_invalid_address_rejected() -> None:
    errors = details_of(HEADER + "A1,Alpha,,,,,999.1.1.1\n")
    assert errors[0]["field"] == "addresses"


def test_duplicate_asset_id_rejected() -> None:
    errors = details_of(HEADER + "A1,Alpha,,,,,\nA1,Again,,,,,\n")
    assert errors[0]["row"] == 3
    assert "dòng 2" in errors[0]["reason"]


def test_ids_keep_case_so_a1_and_a1_lowercase_are_different() -> None:
    inventory = parse(HEADER + "A1,Alpha,,,,,\na1,Beta,,,,,\n")
    assert [a.asset_id for a in inventory.assets] == ["A1", "a1"]


def test_duplicate_address_across_assets_rejected() -> None:
    errors = details_of(HEADER + "A1,Alpha,,,,,10.0.0.1\nA2,Beta,,,,,10.0.0.1\n")
    assert errors[0]["field"] == "addresses"
    assert errors[0]["record_id"] == "A2"


def test_internet_id_is_reserved() -> None:
    errors = details_of(HEADER + "INTERNET,Net,,,,,\n")
    assert errors[0]["field"] == "asset_id"


def test_empty_name_rejected() -> None:
    errors = details_of(HEADER + "A1,,,,,,\n")
    assert errors[0]["field"] == "name"


def test_missing_required_column_rejected() -> None:
    with pytest.raises(ContractError):
        parse("asset_id,criticality\nA1,3\n")


def test_empty_file_rejected() -> None:
    with pytest.raises(ContractError):
        parse_asset_inventory_bytes(b"")


def test_row_with_extra_cells_rejected() -> None:
    errors = details_of("asset_id,name\nA1,Alpha,unexpected\n")
    assert errors[0]["row"] == 2


def test_all_errors_are_reported_together() -> None:
    errors = details_of(HEADER + "A1,Alpha,,,9,,\nA2,Beta,,maybe,,,\n")
    assert len(errors) == 2
    assert {e["row"] for e in errors} == {2, 3}


def test_missing_file_raises_not_found(tmp_path: Path) -> None:
    with pytest.raises(ResourceNotFoundError):
        load_asset_inventory(tmp_path / "nope.csv")


def make_asset(asset_id: str, **override: object) -> Asset:
    data: dict[str, object] = {
        "asset_id": asset_id,
        "name": asset_id,
        "asset_type": None,
        "internet_facing": None,
        "criticality": None,
        "sensitive_data": None,
    }
    data.update(override)
    return Asset(**data)  # type: ignore[arg-type]


def test_merge_inventory_wins_over_scan() -> None:
    inventory = [make_asset("WEB01", name="Web Server", criticality=3)]
    scanned = [make_asset("WEB01", name="web.lab", criticality=5)]
    merged, warnings = merge_assets(inventory, scanned)
    assert merged[0].name == "Web Server"
    assert merged[0].criticality == 3
    assert warnings == []


def test_merge_fills_blanks_from_scan() -> None:
    inventory = [make_asset("WEB01", criticality=3)]
    scanned = [make_asset("WEB01", asset_type="web_server", internet_facing=True)]
    merged, _ = merge_assets(inventory, scanned)
    assert merged[0].asset_type == "web_server"
    assert merged[0].internet_facing is True
    assert merged[0].criticality == 3


def test_merge_keeps_scan_only_assets_with_warning() -> None:
    merged, warnings = merge_assets([make_asset("WEB01")], [make_asset("NEW01")])
    assert [a.asset_id for a in merged] == ["WEB01", "NEW01"]
    assert len(warnings) == 1
    assert "NEW01" in warnings[0]


def test_merge_keeps_inventory_assets_that_were_not_scanned() -> None:
    merged, warnings = merge_assets([make_asset("WEB01"), make_asset("DB01")], [])
    assert [a.asset_id for a in merged] == ["WEB01", "DB01"]
    assert warnings == []


def test_inventory_drives_nmap_adapter_into_a_valid_snapshot() -> None:
    inventory = parse(HEADER + "WEB01,Web Server,web_server,true,3,false,10.0.1.10\n")
    scan = parse_nmap_xml_bytes(NMAP_XML, inventory.address_to_asset_id)
    assert scan.assets[0].asset_id == "WEB01"
    assert scan.services[0].service_id == "WEB01:tcp/443"

    assets, warnings = merge_assets(inventory.assets, scan.assets)
    assert warnings == []
    assert assets[0].criticality == 3
    assert assets[0].internet_facing is True

    snapshot = DatasetSnapshot(
        schema_version="1.0.0",
        dataset_id="inventory-nmap-test",
        created_at=datetime(2026, 10, 19, tzinfo=UTC),
        source="scanner",
        assets=assets,
        services=scan.services,
        findings=[],
        connections=[],
        exploit_rules=[],
    )
    validate_dataset(snapshot)
