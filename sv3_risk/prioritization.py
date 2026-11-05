"""Pure ranking functions; no graph mutation, network I/O, or LLM calls."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING

from .errors import RiskContractError

if TYPE_CHECKING:
    from common.schemas import Finding


def rank_cvss(findings: Iterable[Finding]) -> list[str]:
    """Return IDs by descending CVSS; missing values last, ID for stable display.

    An ID ordering inside equal CVSS values does not imply a business tie-break.
    """
    return [
        item.finding_id
        for item in sorted(
            findings,
            key=lambda item: (
                item.cvss_score is None,
                -(item.cvss_score if item.cvss_score is not None else 0.0),
                item.finding_id,
            ),
        )
    ]


def blocked_path_ids(before: Iterable[str], after: Iterable[str]) -> list[str]:
    """Return removed path IDs, rejecting new paths in a removal-only model."""
    before_ids, after_ids = set(before), set(after)
    unexpected = after_ids - before_ids
    if unexpected:
        raise RiskContractError(
            f"Patch unexpectedly added or renamed paths: {sorted(unexpected)}"
        )
    return sorted(before_ids - after_ids)


def dense_ranks(impacts: Mapping[str, int]) -> dict[str, int]:
    """Assign 1,1,2 for impacts 1,1,0; never use CVSS to break ties."""
    if any(type(value) is not int or value < 0 for value in impacts.values()):
        raise RiskContractError("Impacts must be non-negative integers")
    value_ranks = {
        value: rank
        for rank, value in enumerate(sorted(set(impacts.values()), reverse=True), 1)
    }
    return {finding_id: value_ranks[value] for finding_id, value in impacts.items()}
