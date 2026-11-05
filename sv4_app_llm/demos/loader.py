"""Read saved demo reports, independently of the live engine contracts."""

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = ("before-F01", "after-F01")


def load_demo_report(scenario: str) -> dict:
    if scenario not in SCENARIOS:
        raise ValueError("Kịch bản không hợp lệ.")
    folder = PROJECT_ROOT / "data" / "demo_reports" / scenario
    report = {}
    for key in ("analysis", "details"):
        with (folder / f"{key}.json").open(encoding="utf-8-sig") as source:
            report[key] = json.load(source)
    analysis, details = report["analysis"], report["details"]
    if analysis["schema_version"] != "1.0.0" or details["report_schema_version"] != "1.0.0":
        raise ValueError("Phiên bản báo cáo chưa được hỗ trợ.")
    if analysis["analysis_id"] != details["analysis_id"]:
        raise ValueError("Hai file không thuộc cùng một lần phân tích.")
    if analysis["risk_before"] != details["before"]["system_risk"]:
        raise ValueError("Điểm tổng hợp và chi tiết không khớp.")
    return report
