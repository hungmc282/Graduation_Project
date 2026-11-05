"""Engine-derived facts: patch effect is distinct from additional candidate impact."""

import math

from sv4_app_llm.services.analysis import analyze_dataset


def number(value):
    return f"{value:.4f}".rstrip("0").rstrip(".").replace(".", ",")


def analysis_facts(workspace, envelope, baseline=None):
    report = envelope["report"]
    current = report["analysis"]
    config = report["details"]["graph_config"]
    if baseline is None:
        baseline = (
            envelope
            if not current["patched_finding_ids"]
            else analyze_dataset(
                workspace["dataset"],
                current["target_asset_ids"],
                max_depth=config["max_depth"],
                max_paths=config["max_paths"],
            )
        )
    original = baseline["report"]["analysis"]
    if (
        original["patched_finding_ids"]
        or original["config_hash"] != current["config_hash"]
        or original["target_asset_ids"] != current["target_asset_ids"]
        or baseline["report"]["details"]["dataset_hash"]
        != report["details"]["dataset_hash"]
    ):
        raise ValueError(
            "Không thể so sánh: dữ liệu hoặc cấu hình trước–sau không khớp."
        )
    before_graph, after_graph = baseline["report"]["graph"], report["graph"]
    for analysis, graph in [(original, before_graph), (current, after_graph)]:
        if (
            not graph["search_complete"]
            or analysis["risk_score_status"] != "complete"
            or graph["dataset_id"] != analysis["dataset_id"]
            or set(graph["patched_finding_ids"]) != set(analysis["patched_finding_ids"])
        ):
            raise ValueError(
                "Kết quả đồ thị và rủi ro không đủ nhất quán để giải thích."
            )
    risk_before, risk_after = original["risk_before"], current["risk_before"]
    if any(
        not isinstance(v, (int, float)) or not math.isfinite(v)
        for v in (risk_before, risk_after)
    ):
        raise ValueError("Chưa có điểm rủi ro hợp lệ để so sánh.")
    before_ids = {p["path_id"] for p in before_graph["paths"]}
    after_ids = {p["path_id"] for p in after_graph["paths"]}
    if not after_ids <= before_ids or risk_after > risk_before + 1e-9:
        raise ValueError("Kết quả trước–sau không phù hợp mô hình mô phỏng vá.")
    targets = ", ".join(current["target_asset_ids"])
    patched = current["patched_finding_ids"]
    reduction = max(0.0, risk_before - risk_after)
    comparison = {
        "targets": current["target_asset_ids"],
        "patched_finding_ids": patched,
        "before_patching": {"risk": risk_before, "target_path_count": len(before_ids)},
        "after_current_patch": {
            "risk": risk_after,
            "target_path_count": len(after_ids),
        },
        "risk_reduction_from_current_patch": reduction,
        "paths_blocked_by_current_patch": len(before_ids - after_ids),
        "all_target_paths_blocked": bool(before_ids) and not after_ids,
    }
    facts = {
        "current_state": f"Hiện còn {len(after_ids)} đường tấn công tới {targets}; điểm rủi ro theo mô hình là {number(risk_after)}.",
        "scope": f"Kết luận chỉ áp dụng cho {targets} và các điều kiện trong mô hình; mô phỏng không phải cài bản vá thật hay xác nhận toàn hệ thống an toàn.",
    }
    if patched:
        facts["patch_effect"] = (
            f"Mô phỏng vá {', '.join(patched)} làm số đường tới {targets} thay đổi từ {len(before_ids)} xuống {len(after_ids)}, "
            f"rủi ro từ {number(risk_before)} xuống {number(risk_after)}, giảm {number(reduction)} điểm."
        )
        if comparison["all_target_paths_blocked"]:
            facts["patch_effect"] += (
                " Phương án này đã chặn toàn bộ đường tới đích được tìm thấy trong mô hình."
            )
        if (
            all(row["remediation_impact"] == 0 for row in current["results"])
            and current["results"]
        ):
            facts["additional_actions"] = (
                "Các finding chưa vá có mức giảm thêm bằng 0 ở trạng thái hiện tại. "
                "NO_ADDITIONAL_RISK_REDUCTION nói về việc vá thêm các finding đó, không phủ nhận hiệu quả của phương án đã chọn."
            )
    for row in current["results"]:
        fid = row["finding_id"]
        if row["remediation_impact"] == 0:
            facts["candidate:" + fid] = (
                f"Ở trạng thái hiện tại, vá thêm {fid} không giảm thêm rủi ro tới {targets}; điều đó không có nghĩa finding này an toàn."
            )
        else:
            peers = sum(
                r["priority_rank"] == row["priority_rank"] for r in current["results"]
            )
            rank = ("đồng hạng " if peers > 1 else "hạng ") + str(row["priority_rank"])
            facts["candidate:" + fid] = (
                f"{fid} trên {row['asset_id']} được xếp {rank}; thử vá riêng từ trạng thái hiện tại "
                f"giảm {number(row['remediation_impact'])} điểm và chặn {row['paths_blocked']} đường tới đích."
            )
    facts["cvss_baseline"] = (
        "Thứ tự chỉ theo CVSS của các finding chưa vá là "
        + (" → ".join(current["baseline_cvss_order"]) or "không còn finding")
        + "; đây là cách xếp khác với mức giảm rủi ro."
    )
    return {"comparison": comparison, "facts": facts}


def render_fact_selection(raw, evidence):
    import json

    try:
        result = json.loads(raw)
    except (ValueError, TypeError) as error:
        raise ValueError(
            "AI trả nội dung chưa kiểm chứng được nên không hiển thị. Xem kết quả engine ở trên hoặc thử lại."
        ) from error
    if not isinstance(result, dict) or set(result) != {"fact_ids"}:
        raise ValueError(
            "AI trả nội dung ngoài bằng chứng cho phép; câu trả lời đã bị chặn."
        )
    selected = result["fact_ids"]
    facts = evidence["facts"]
    if (
        not isinstance(selected, list)
        or not selected
        or len(selected) > 8
        or any(not isinstance(x, str) or x not in facts for x in selected)
        or len(selected) != len(set(selected))
    ):
        raise ValueError("AI viện dẫn bằng chứng không hợp lệ; câu trả lời đã bị chặn.")
    # Always anchor patch explanations in verified before/after values.
    required = (
        ["patch_effect", "current_state"]
        if "patch_effect" in facts
        else ["current_state"]
    )
    order = list(
        dict.fromkeys([x for x in required if x in facts] + selected + ["scope"])
    )
    return "\n\n".join(facts[x] for x in order), order
