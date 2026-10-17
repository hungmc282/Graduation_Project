"""Local core errors until the team's common.errors contract is implemented."""


class RiskContractError(ValueError):
    """Invalid input or inconsistent upstream graph result."""


class UnsupportedRiskModelError(RiskContractError):
    """Requested risk model, metric, or parameters are unsupported."""


class IncompletePathSearchError(RiskContractError):
    """Exact ranking cannot be computed from an incomplete path search."""
