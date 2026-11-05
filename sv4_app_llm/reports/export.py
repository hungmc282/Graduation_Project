"""Export saved evidence; never recalculate engine scores."""
import json


def export_json(envelope, explanation=None):
    if explanation and envelope["report"]["analysis"]["analysis_id"] not in explanation["analysis_ids"]:
        raise ValueError("Giải thích không thuộc báo cáo.")
    return json.dumps({"envelope": envelope, "explanation": explanation},
                      ensure_ascii=False, indent=2, allow_nan=False).encode("utf-8")


def export_markdown(envelope, explanation=None):
    report = envelope["report"]
    a = report["analysis"]
    lines = ["# Báo cáo ưu tiên xử lý lỗ hổng", "",
             f"- Nguồn: {envelope['source']}",
             f"- Analysis ID: {a['analysis_id']}",
             f"- Dataset: {a['dataset_id']}",
             f"- Thời điểm phân tích: {a['created_at']}",
             f"- Graph model: {a['graph_model_version']}",
             f"- Risk model: {a['risk_model_version']}",
             f"- Tài sản đích: {', '.join(a['target_asset_ids'])}",
             f"- Đã vá: {', '.join(a['patched_finding_ids']) or 'Không'}",
             f"- Điểm rủi ro: {a['risk_before']}", "",
             "| Finding | Tài sản | CVSS | Mức giảm rủi ro | Hạng |",
             "|---|---|---:|---:|---:|"]
    for r in a["results"]:
        lines.append(f"| {r['finding_id']} | {r['asset_id']} | {r['cvss_score']} | "
                     f"{r['remediation_impact']} | {r['priority_rank']} |")
    lines += ["", "## Cảnh báo", ""] + ["- " + w for w in a["warnings"]]
    lines += ["", "## Giả định", ""] + ["- " + s for s in report["details"]["assumptions"]]
    if explanation:
        if a["analysis_id"] not in explanation["analysis_ids"]:
            raise ValueError("Giải thích không thuộc báo cáo.")
        lines += ["", "## AI giải thích — chưa kiểm chứng nội dung", "",
                  f"Model: {explanation['model_id']}; prompt: {explanation['prompt_version']}",
                  f"Thời điểm: {explanation['created_at']}",
                  "Câu hỏi: " + explanation["question"], "", explanation["text"]]
    return "\n".join(lines).encode("utf-8")
