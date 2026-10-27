"""Kiểm tra adapter Nmap XML."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from common.errors import ContractError, ResourceNotFoundError
from common.schemas import DatasetSnapshot
from sv1_data.adapters.nmap_xml import parse_nmap_xml, parse_nmap_xml_bytes
from sv1_data.service import validate_dataset

# Kết quả thật khi quét container DVWA của chính nhóm (đã bỏ đường dẫn cá nhân).
DVWA_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -sV -Pn -p 8080 127.0.0.1" version="7.80">
<host><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
<hostname name="kubernetes.docker.internal" type="PTR"/>
</hostnames>
<ports><port protocol="tcp" portid="8080"><state state="open" reason="syn-ack" reason_ttl="0"/>\
<service name="http" product="Apache httpd" version="2.4.25" extrainfo="(Debian)" \
method="probed" conf="10"><cpe>cpe:/a:apache:http_server:2.4.25</cpe></service></port>
</ports>
</host>
</nmaprun>
"""

MIXED_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.80">
<host><status state="up"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
<hostnames><hostname name="ptr.lab" type="PTR"/><hostname name="web01.lab" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="80"><state state="filtered"/><service name="http"/></port>
<port protocol="tcp" portid="443"><state state="closed"/></port>
<port protocol="udp" portid="53"><state state="open"/>\
<service name="domain" product="dnsmasq" version="2.80"/></port>
<port protocol="udp" portid="161"><state state="open|filtered"/></port>
<port protocol="sctp" portid="5000"><state state="open"/></port>
</ports></host>
<host><status state="down"/><address addr="10.0.0.6" addrtype="ipv4"/></host>
<host><status state="up"/><address addr="fe80::1" addrtype="ipv6"/><hostnames/><ports/></host>
</nmaprun>
"""


def test_parse_real_dvwa_scan() -> None:
    scan = parse_nmap_xml_bytes(DVWA_XML)
    assert len(scan.assets) == 1
    asset = scan.assets[0]
    assert asset.asset_id == "127.0.0.1"
    assert asset.name == "kubernetes.docker.internal"
    assert asset.asset_type is None
    assert asset.internet_facing is None
    assert asset.criticality is None
    assert asset.sensitive_data is None

    assert len(scan.services) == 1
    service = scan.services[0]
    assert service.service_id == "127.0.0.1:tcp/8080"
    assert service.asset_id == "127.0.0.1"
    assert service.protocol == "tcp"
    assert service.port == 8080
    assert service.product == "Apache httpd"
    assert service.product_version == "2.4.25"
    assert scan.warnings == []


def test_asset_id_mapping_is_applied_to_asset_and_service() -> None:
    scan = parse_nmap_xml_bytes(DVWA_XML, {"127.0.0.1": "WEB01"})
    assert scan.assets[0].asset_id == "WEB01"
    assert scan.services[0].asset_id == "WEB01"
    assert scan.services[0].service_id == "WEB01:tcp/8080"


def test_only_open_tcp_udp_ports_become_services() -> None:
    scan = parse_nmap_xml_bytes(MIXED_XML)
    assert [s.service_id for s in scan.services] == ["10.0.0.5:tcp/22", "10.0.0.5:udp/53"]


def test_missing_product_and_version_are_none() -> None:
    scan = parse_nmap_xml_bytes(MIXED_XML)
    ssh = scan.services[0]
    assert ssh.product is None
    assert ssh.product_version is None
    dns = scan.services[1]
    assert (dns.product, dns.product_version) == ("dnsmasq", "2.80")


def test_unsupported_protocol_gives_warning_not_service() -> None:
    scan = parse_nmap_xml_bytes(MIXED_XML)
    assert len(scan.warnings) == 1
    assert "sctp" in scan.warnings[0]


def test_down_host_is_skipped() -> None:
    scan = parse_nmap_xml_bytes(MIXED_XML)
    assert "10.0.0.6" not in {a.asset_id for a in scan.assets}


def test_ipv4_preferred_over_mac_and_user_hostname_preferred_over_ptr() -> None:
    scan = parse_nmap_xml_bytes(MIXED_XML)
    asset = scan.assets[0]
    assert asset.asset_id == "10.0.0.5"
    assert asset.name == "web01.lab"


def test_ipv6_host_without_hostname_uses_address_as_name() -> None:
    scan = parse_nmap_xml_bytes(MIXED_XML)
    asset = scan.assets[1]
    assert (asset.asset_id, asset.name) == ("fe80::1", "fe80::1")


def test_parse_from_file(tmp_path: Path) -> None:
    path = tmp_path / "scan.xml"
    path.write_bytes(DVWA_XML)
    scan = parse_nmap_xml(path)
    assert scan.services[0].port == 8080


def test_missing_file_raises_not_found(tmp_path: Path) -> None:
    with pytest.raises(ResourceNotFoundError):
        parse_nmap_xml(tmp_path / "nope.xml")


def test_broken_xml_raises_contract_error() -> None:
    with pytest.raises(ContractError):
        parse_nmap_xml_bytes(b"<nmaprun><host>")


def test_wrong_root_raises_contract_error() -> None:
    with pytest.raises(ContractError):
        parse_nmap_xml_bytes(b"<other/>")


def test_scan_output_is_a_valid_snapshot_part() -> None:
    scan = parse_nmap_xml_bytes(DVWA_XML, {"127.0.0.1": "WEB01"})
    snapshot = DatasetSnapshot(
        schema_version="1.0.0",
        dataset_id="nmap-dvwa-test",
        created_at=datetime(2026, 10, 17, tzinfo=UTC),
        source="scanner",
        assets=scan.assets,
        services=scan.services,
        findings=[],
        connections=[],
        exploit_rules=[],
    )
    validate_dataset(snapshot)
