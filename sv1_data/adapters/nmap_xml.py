"""Adapter Nmap XML (`nmap -oX`) -> Asset, Service (ARCHITECTURE.md, mục 1 điều 4).

Nmap chỉ cho biết host, cổng mở và dịch vụ. Nmap KHÔNG cho biết lỗ hổng, criticality,
internet_facing, sensitive_data hay asset_type, nên các trường đó là None (chưa biết).
Finding đến từ scanner lỗ hổng (Nuclei, Trivy...), không đến từ Nmap.

Ghi chú bảo mật: dùng xml.etree của thư viện chuẩn, chỉ nên đọc file do chính mình quét.
Không dùng để phân tích file XML không tin cậy từ bên ngoài.
"""

import xml.etree.ElementTree as ET
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from common.errors import ContractError, ResourceNotFoundError
from common.schemas import Asset, Service


@dataclass(frozen=True)
class NmapScan:
    """Kết quả chuyển đổi một file Nmap XML."""

    assets: list[Asset]
    services: list[Service]
    warnings: list[str] = field(default_factory=list)


def parse_nmap_xml(path: Path, asset_ids: Mapping[str, str] | None = None) -> NmapScan:
    """Đọc file Nmap XML và chuyển thành Asset, Service.

    Args:
        path: đường dẫn file tạo bởi `nmap -oX`.
        asset_ids: ánh xạ địa chỉ IP -> asset_id chuẩn của nhóm (ví dụ "10.0.0.5" -> "WEB01").
            Địa chỉ không có trong ánh xạ dùng chính địa chỉ làm asset_id.

    Raises:
        ResourceNotFoundError: không có file.
        ContractError: XML hỏng, sai gốc `nmaprun`, hoặc dữ liệu không đúng schema.
    """
    xml_path = Path(path)
    if not xml_path.is_file():
        raise ResourceNotFoundError(
            f"Không tìm thấy file Nmap XML: {xml_path}.",
            [{"field": "path", "record_id": str(xml_path)}],
        )
    return parse_nmap_xml_bytes(xml_path.read_bytes(), asset_ids)


def parse_nmap_xml_bytes(data: bytes, asset_ids: Mapping[str, str] | None = None) -> NmapScan:
    """Giống `parse_nmap_xml` nhưng nhận nội dung XML dạng bytes."""
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ContractError(
            f"File Nmap XML không hợp lệ: {exc}.", [{"field": "<xml>", "record_id": ""}]
        ) from exc
    if root.tag != "nmaprun":
        raise ContractError(
            "File không phải kết quả Nmap (thiếu thẻ gốc nmaprun).",
            [{"field": "<xml>", "record_id": root.tag}],
        )

    id_map = asset_ids or {}
    assets: list[Asset] = []
    services: list[Service] = []
    warnings: list[str] = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        address = _pick_address(host)
        if address is None:
            warnings.append("Bỏ qua một host không có địa chỉ IP.")
            continue
        asset_id = id_map.get(address, address).strip()
        try:
            assets.append(
                Asset(
                    asset_id=asset_id,
                    name=_pick_hostname(host) or address,
                    asset_type=None,
                    internet_facing=None,
                    criticality=None,
                    sensitive_data=None,
                )
            )
            services.extend(_parse_ports(host, asset_id, warnings))
        except ValidationError as exc:
            raise ContractError(
                f"Dữ liệu Nmap của host {address} không đúng schema.",
                [
                    {"field": ".".join(str(p) for p in e["loc"]), "record_id": address}
                    for e in exc.errors()
                ],
            ) from exc

    return NmapScan(assets=assets, services=services, warnings=warnings)


def _parse_ports(host: ET.Element, asset_id: str, warnings: list[str]) -> list[Service]:
    result: list[Service] = []
    for port in host.findall("ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue  # filtered, closed, open|filtered... không coi là dịch vụ đang mở
        protocol = port.get("protocol")
        port_number = port.get("portid", "")
        if protocol not in ("tcp", "udp"):
            warnings.append(
                f"Bỏ qua cổng {port_number}/{protocol} của {asset_id}: giao thức "
                "chưa được hợp đồng hỗ trợ."
            )
            continue
        service = port.find("service")
        result.append(
            Service(
                service_id=f"{asset_id}:{protocol}/{port_number}",
                asset_id=asset_id,
                protocol=protocol,
                port=int(port_number),
                product=_clean(service.get("product")) if service is not None else None,
                product_version=_clean(service.get("version")) if service is not None else None,
            )
        )
    return result


def _pick_address(host: ET.Element) -> str | None:
    by_type = {a.get("addrtype"): a.get("addr") for a in host.findall("address")}
    return _clean(by_type.get("ipv4")) or _clean(by_type.get("ipv6"))


def _pick_hostname(host: ET.Element) -> str | None:
    names = {h.get("type"): h.get("name") for h in host.findall("hostnames/hostname")}
    for kind in ("user", "PTR"):
        if _clean(names.get(kind)):
            return _clean(names.get(kind))
    return next((c for c in (_clean(n) for n in names.values()) if c), None)


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None
