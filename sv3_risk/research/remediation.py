"""Explicit finding/CVE group action scope, avoiding double-counted impact."""

from sv3_risk.errors import RiskContractError
from sv3_risk.research.service import analyze_detailed


def finding_ids_for_vulnerability(
    dataset, vulnerability_id: str, asset_ids=None
) -> list[str]:
    """Resolve an explicit CVE/demo ID to occurrences; no implicit global patch."""
    assets = {asset.asset_id for asset in dataset.assets}
    if asset_ids is not None and not set(asset_ids) <= assets:
        raise RiskContractError("Unknown asset in remediation scope")
    result = sorted(
        finding.finding_id
        for finding in dataset.findings
        if finding.vulnerability_id == vulnerability_id
        and (asset_ids is None or finding.asset_id in asset_ids)
    )
    if not result:
        raise RiskContractError("No matching findings in requested remediation scope")
    return result


def simulate_patch_group(
    dataset, patched_finding_ids, additional_finding_ids, graph_config, risk_config
):
    """Recompute the union action; impact is NOT sum of independent finding RIs."""
    if (
        type(additional_finding_ids) is not list
        or any(type(fid) is not str for fid in additional_finding_ids)
        or len(additional_finding_ids) != len(set(additional_finding_ids))
    ):
        raise RiskContractError("Additional finding IDs must be a unique list[str]")
    known = {finding.finding_id for finding in dataset.findings}
    if not set(additional_finding_ids) <= known:
        raise RiskContractError("Unknown finding in group action")
    before = analyze_detailed(dataset, patched_finding_ids, graph_config, risk_config)
    union = sorted(set(patched_finding_ids) | set(additional_finding_ids))
    after = analyze_detailed(dataset, union, graph_config, risk_config)
    before_ids = {path["path_id"] for path in before.detail["before"]["path_details"]}
    after_ids = {path["path_id"] for path in after.detail["before"]["path_details"]}
    return {
        "action_unit": "explicit finding_id union",
        "dataset_id": dataset.dataset_id,
        "before_analysis_id": before.analysis.analysis_id,
        "after_analysis_id": after.analysis.analysis_id,
        "previous_patched_finding_ids": sorted(patched_finding_ids),
        "requested_finding_ids": sorted(additional_finding_ids),
        "patched_finding_ids": union,
        "risk_before": before.analysis.risk_before,
        "risk_after": after.analysis.risk_before,
        "remediation_impact": before.analysis.risk_before - after.analysis.risk_before,
        "blocked_path_ids": sorted(before_ids - after_ids),
    }
