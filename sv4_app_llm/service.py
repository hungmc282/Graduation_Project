"""UI orchestration. Connect future SV1–SV3 adapters here, not in the UI."""
import copy
from datetime import datetime, timezone

from sv4_app_llm.demos.loader import SCENARIOS, load_demo_report
from sv4_app_llm.llm.ollama import PROMPT_VERSION, explain_demo
from sv4_app_llm.storage.repository import get_record, list_records, save_record

ASSET_FIELDS = {
    "asset_id", "name", "asset_type", "internet_facing", "criticality", "sensitive_data"
}


def validate_assets(assets):
    """SV4 draft validation only; SV1 must validate the eventual canonical dataset."""
    if not isinstance(assets, list) or not assets:
        raise ValueError("Cần ít nhất một tài sản.")
    cleaned, seen = [], set()
    for asset in assets:
        if not isinstance(asset, dict) or set(asset) != ASSET_FIELDS:
            raise ValueError("Tài sản phải có đúng các trường của mẫu nhập liệu.")
        item = dict(asset)
        for key in ("asset_id", "name"):
            if not isinstance(item[key], str) or not item[key].strip():
                raise ValueError(f"{key} không được trống.")
            item[key] = item[key].strip()
        if item["asset_id"] in seen:
            raise ValueError("ID tài sản bị trùng: " + item["asset_id"])
        seen.add(item["asset_id"])
        if item["asset_type"] is not None:
            if not isinstance(item["asset_type"], str):
                raise ValueError("Loại tài sản phải là chuỗi hoặc null.")
            item["asset_type"] = item["asset_type"].strip() or None
        for key in ("internet_facing", "sensitive_data"):
            if item[key] is not None and type(item[key]) is not bool:
                raise ValueError(f"{key} phải là boolean hoặc null.")
        value = item["criticality"]
        if value is not None and (type(value) is not int or not 1 <= value <= 5):
            raise ValueError("Mức quan trọng phải là số nguyên 1–5 hoặc null.")
        cleaned.append(item)
    return cleaned


def save_asset_draft(title, assets):
    if not title.strip():
        raise ValueError("Hãy đặt tên bản nháp.")
    return save_record("draft", title.strip(), {
        "draft_schema_version": "sv4-draft-1", "status": "draft",
        "assets": validate_assets(assets),
        "missing_sections": ["services", "findings", "connections", "exploit_rules"],
    })


def run_analysis(mode, scenario=None, draft_id=None, patched_finding_ids=None):
    if mode == "demo":
        if scenario not in SCENARIOS:
            raise ValueError("Kịch bản không hợp lệ.")
        if draft_id or patched_finding_ids:
            raise ValueError("Demo không phân tích bản nháp hoặc phương án vá tùy ý.")
        report = load_demo_report(scenario)
        return {"source": "demo", "scenario": scenario, "report": report}
    if mode == "integrated":
        # Future adapter: SV1 validates draft -> snapshot; SV3 analyze() calls SV2.
        # Return the same UI envelope, with the real report and its provenance.
        raise NotImplementedError(
            "Chưa kết nối SV1–SV3. Bản nháp tài sản chưa đủ để dựng đường tấn công."
        )
    raise ValueError("Chế độ không hợp lệ.")


def save_analysis(envelope):
    return save_record("analysis", "Báo cáo " + envelope.get("scenario", "phân tích"), envelope)


def explain_report(envelope, question, compare=False):
    if not question.strip():
        raise ValueError("Câu hỏi không được trống.")
    reports = {"current": copy.deepcopy(envelope["report"])}
    if compare:
        if envelope["source"] != "demo":
            raise ValueError("So sánh này chỉ dành cho bộ demo.")
        reports = {name: load_demo_report(name) for name in SCENARIOS}
        before, after = (reports[name] for name in SCENARIOS)
        if (before["details"]["dataset_hash"] != after["details"]["dataset_hash"]
                or before["analysis"]["config_hash"] != after["analysis"]["config_hash"]):
            raise ValueError("Hai báo cáo không cùng dữ liệu và cấu hình.")
    text, model = explain_demo(reports, question)
    return {
        "text": text, "model_id": model, "prompt_version": PROMPT_VERSION,
        "analysis_ids": [r["analysis"]["analysis_id"] for r in reports.values()],
        "question": question, "created_at": datetime.now(timezone.utc).isoformat(),
        "validation_status": "not_verified",
    }


def save_explanation(envelope, explanation):
    if envelope["report"]["analysis"]["analysis_id"] not in explanation["analysis_ids"]:
        raise ValueError("Giải thích không thuộc báo cáo này.")
    return save_record("explanation", explanation["question"], {
        "envelope": copy.deepcopy(envelope), "explanation": explanation,
    })


def inspect_sv1_dataset(content=None):
    """Validate via SV1 and return input data, never a fabricated analysis report."""
    from sv4_app_llm.adapters.sv1 import load_sv1_snapshot
    dataset = load_sv1_snapshot(content)
    return {
        "dataset": dataset,
        "counts": {name: len(dataset[name]) for name in
                   ("assets", "services", "findings", "connections", "exploit_rules")},
        "analysis_status": "not_connected",
    }


def dataset_fingerprint(dataset):
    import hashlib
    import json
    return hashlib.sha256(json.dumps(dataset, sort_keys=True, ensure_ascii=False,
                                     allow_nan=False).encode()).hexdigest()


def explain_sv1_dataset(dataset, question):
    """Revalidate the input through SV1 before passing it to the model."""
    import json
    from sv4_app_llm.llm.dataset import DATASET_PROMPT_VERSION, explain_dataset_input
    if not question.strip():
        raise ValueError("Câu hỏi không được trống.")
    validated = inspect_sv1_dataset(json.dumps(dataset, allow_nan=False).encode())["dataset"]
    text, model = explain_dataset_input(validated, question)
    return {
        "text": text, "model_id": model, "prompt_version": DATASET_PROMPT_VERSION,
        "dataset_id": validated["dataset_id"], "dataset_hash": dataset_fingerprint(validated),
        "question": question, "created_at": datetime.now(timezone.utc).isoformat(),
        "scope": "input_only", "validation_status": "not_verified",
    }


def save_dataset_explanation(dataset, explanation):
    if (explanation["dataset_id"] != dataset["dataset_id"]
            or explanation["dataset_hash"] != dataset_fingerprint(dataset)):
        raise ValueError("Giải thích không thuộc đúng phiên bản dataset.")
    return save_record("dataset_explanation", explanation["question"], {
        "dataset": copy.deepcopy(dataset), "explanation": explanation,
    })
