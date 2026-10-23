"""Hợp đồng dữ liệu chung, Pydantic v2 (ARCHITECTURE.md, mục 6).

Nguồn kiểu thực thi duy nhất của dự án. Phần của SV1: Asset, Service, Finding.
Connection và ExploitRule thuộc SV2 (mục 6.3); được khai báo ở đây chỉ để
DatasetSnapshot (mục 6.4) đầy đủ, SV2 là người duyệt và có thể sửa.

Quy ước: trường nullable vẫn BẮT BUỘC có mặt (không đặt default), null nghĩa là chưa biết.
"""

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1.0.0"
INTERNET_ID = "INTERNET"  # điểm vào đặc biệt, không phải asset

FindingSource = Literal["synthetic", "scanner", "manual"]
DatasetSource = Literal["synthetic", "scanner", "manual", "mixed"]


class _CanonicalModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Asset(_CanonicalModel):
    asset_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    asset_type: str | None
    internet_facing: bool | None
    criticality: int | None = Field(ge=1, le=5)
    sensitive_data: bool | None


class Service(_CanonicalModel):
    service_id: str = Field(min_length=1)
    asset_id: str = Field(min_length=1)
    protocol: Literal["tcp", "udp"]
    port: int = Field(ge=1, le=65535)
    product: str | None
    product_version: str | None


class Finding(_CanonicalModel):
    finding_id: str = Field(min_length=1)
    asset_id: str = Field(min_length=1)
    service_id: str | None
    vulnerability_id: str = Field(min_length=1)
    cvss_score: float | None = Field(ge=0, le=10)
    epss_probability: float | None = Field(ge=0, le=1)
    is_kev: bool | None
    source: FindingSource
    evidence: list[str]
    observed_at: AwareDatetime | None
    enriched_at: AwareDatetime | None


class Connection(_CanonicalModel):
    """SV2 sở hữu (mục 6.3). Có hướng; source có thể là INTERNET_ID."""

    connection_id: str = Field(min_length=1)
    source_asset_id: str = Field(min_length=1)
    target_asset_id: str = Field(min_length=1)
    target_service_id: str | None
    allowed: bool
    evidence: list[str]


class ExploitRule(_CanonicalModel):
    """SV2 sở hữu (mục 6.3)."""

    rule_id: str = Field(min_length=1)
    source_asset_id: str = Field(min_length=1)
    target_asset_id: str = Field(min_length=1)
    required_finding_id: str | None
    required_state: str = Field(min_length=1)
    resulting_state: str = Field(min_length=1)
    rule_type: Literal["exploit", "trust"]
    evidence: list[str]


class DatasetSnapshot(_CanonicalModel):
    schema_version: str
    dataset_id: str = Field(min_length=1)
    created_at: AwareDatetime
    source: DatasetSource
    assets: list[Asset]
    services: list[Service]
    findings: list[Finding]
    connections: list[Connection]
    exploit_rules: list[ExploitRule]
