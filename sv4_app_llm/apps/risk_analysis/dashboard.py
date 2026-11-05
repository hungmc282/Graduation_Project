"""Màn hình phân tích dữ liệu và mô phỏng vá của ứng dụng chính."""

import json
from pathlib import Path

import streamlit as st

from common.errors import ContractError
from sv1_data.service import load_dataset
from sv3_risk.errors import RiskContractError
from sv4_app_llm.apps.risk_analysis.service import PROJECT_ROOT, run_analysis


def render_dashboard() -> None:
    """Render the live SV1–SV3 analysis workflow."""
    st.set_page_config(page_title="Ưu tiên xử lý lỗ hổng", layout="wide")
    st.title("Ưu tiên xử lý lỗ hổng")
    st.caption(
        "SV1: dữ liệu → SV2: đường tấn công → SV3: rủi ro và ưu tiên → SV4: giao diện"
    )
    choices = {
        "Dữ liệu SV2": PROJECT_ROOT / "sv2_attack_graph/fixtures",
        "Dữ liệu SV1": PROJECT_ROOT / "data/samples/demo_lab_v1",
        **{
            f"Kịch bản {name}": PROJECT_ROOT / "sv3_risk/data/scenarios" / name
            for name in ("chain", "diamond", "multi-target")
        },
    }
    source = st.selectbox("Bộ dữ liệu", list(choices))
    custom = st.text_input("Hoặc thư mục chứa dataset.json", "")
    folder = Path(custom).expanduser() if custom.strip() else choices[source]
    try:
        dataset = load_dataset(folder)
        if not dataset.exploit_rules:
            st.warning(
                "Bộ dữ liệu chưa có exploit rules. Cần bổ sung topology/rules từ SV2 trước khi kết luận về rủi ro."
            )
        st.caption(
            f"{dataset.dataset_id} • Nguồn: {dataset.source} • "
            f"{len(dataset.assets)} tài sản • {len(dataset.findings)} findings"
        )
        targets = st.multiselect(
            "Tài sản đích",
            [a.asset_id for a in dataset.assets],
            default=[a.asset_id for a in dataset.assets if a.criticality == 5],
        )
        patched = st.multiselect(
            "Mô phỏng vá findings (tính lại cả nhóm)",
            [f.finding_id for f in dataset.findings],
        )
        with st.expander("Giới hạn tìm đường"):
            depth = st.number_input(
                "Số bước tối đa", min_value=1, max_value=100, value=12
            )
            budget = st.number_input(
                "Số đường tối đa", min_value=1, max_value=100000, value=10000
            )
        if not targets:
            st.info("Chọn ít nhất một tài sản đích để phân tích.")
            st.stop()
        with st.spinner("Đang dựng đồ thị và tính rủi ro…"):
            before = run_analysis(
                folder, [], targets, max_depth=depth, max_paths=budget
            )
            current = (
                run_analysis(
                    folder, patched, targets, max_depth=depth, max_paths=budget
                )
                if patched
                else before
            )
    except (ContractError, RiskContractError, ValueError, OSError) as error:
        st.error(f"Không thể tính kết quả: {error}")
        st.stop()

    analysis, graph = current["analysis"], current["graph"]
    a, b, c = st.columns(3)
    a.metric("Rủi ro hiện tại", f"{analysis['risk_before']:.4f}")
    b.metric("Đường đến đích", len(graph["paths"]))
    c.metric("Findings đã vá", len(patched))
    st.info("Điểm heuristic trong phạm vi mô hình, không phải xác suất tấn công.")
    for warning in analysis["warnings"]:
        st.warning(warning)
    st.subheader("Ưu tiên xử lý tiếp theo")
    st.dataframe(analysis["results"], hide_index=True, width="stretch")
    st.subheader("So sánh phương án vá")
    st.dataframe(
        [
            {
                "Trạng thái": label,
                "Rủi ro": report["analysis"]["risk_before"],
                "Đường đến đích": len(report["graph"]["paths"]),
            }
            for label, report in (("Chưa vá", before), ("Phương án hiện tại", current))
        ],
        hide_index=True,
        width="stretch",
    )
    st.subheader("Đường tấn công còn lại")
    for path in graph["paths"]:
        with st.expander(" → ".join(path["asset_ids"])):
            st.json(path)
    if not graph["paths"]:
        st.write("Không có đường đến đích trong phạm vi mô hình đang xét.")
    st.download_button(
        "Tải kết quả JSON",
        json.dumps(current, ensure_ascii=False, indent=2),
        file_name="analysis.json",
        mime="application/json",
    )
    with st.expander("Dữ liệu và kết quả đầy đủ"):
        st.json(current)
    st.caption(
        "Demo AI từ báo cáo lưu sẵn có hướng dẫn chạy riêng trong README của SV4."
    )
