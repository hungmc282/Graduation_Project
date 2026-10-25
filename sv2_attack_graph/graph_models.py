"""Provisional SV2 graph output/config models until approved in common.schemas.

These types do NOT duplicate any existing canonical model. See ARCHITECTURE.md 6.5.
"""
from pydantic import BaseModel, ConfigDict, Field

class _GraphModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

class GraphConfig(_GraphModel):
    model_version: str = Field(min_length=1)
    entry_point_ids: list[str]
    target_asset_ids: list[str]
    max_depth: int = Field(gt=0)
    max_paths: int = Field(gt=0)

class AttackPath(_GraphModel):
    path_id: str = Field(min_length=1)
    target_asset_id: str = Field(min_length=1)
    asset_ids: list[str]
    rule_ids: list[str]
    finding_ids: list[str]

class GraphResult(_GraphModel):
    schema_version: str
    dataset_id: str
    graph_model_version: str
    patched_finding_ids: list[str]
    entry_point_ids: list[str]
    target_asset_ids: list[str]
    paths: list[AttackPath]
    search_complete: bool
    warnings: list[str]
