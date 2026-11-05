"""Report display shared by current analyses and historical snapshots."""

import streamlit as st
from sv4_app_llm.reports.export import export_json, export_markdown
from sv4_app_llm.service import explain_report, save_explanation


def render_report(envelope, key, saved_explanation=None):
    report = envelope["report"]
    a, d = report["analysis"], report["details"]
    if envelope["source"] == "demo":
        st.info("Kết quả minh họa cho hệ thống mẫu. Không đánh giá website của bạn.")
    st.subheader("Những vấn đề được ưu tiên trong báo cáo")
    for row in sorted(
        a["results"], key=lambda r: (r["priority_rank"], r["finding_id"])
    ):
        with st.container(border=True):
            st.markdown(
                f"### Hạng {row['priority_rank']}: xem xét vấn đề trên {row['asset_id']}"
            )
            if row["remediation_impact"] > 0:
                st.write(
                    f"**Vì sao:** trong mô hình, khắc phục vấn đề này giảm "
                    f"{row['remediation_impact']:.2f} điểm và chặn {row['paths_blocked']} đường đến đích."
                )
            else:
                st.write(
                    "**Vì sao:** báo cáo chưa ghi nhận mức giảm điểm khi khắc phục riêng vấn đề này. "
                    "Điều đó không xác nhận vấn đề an toàn hoặc không cần xử lý."
                )
            st.write(
                "**Bạn nên làm gì:** nhờ người quản trị xác nhận sản phẩm, phiên bản và hướng dẫn "
                "khắc phục từ nhà cung cấp. Báo cáo này chưa có nguồn để chỉ định bản vá cụ thể."
            )
            st.caption("Mã tham chiếu cho người kỹ thuật: " + row["finding_id"])
    with st.expander("Chi tiết kỹ thuật và bằng chứng"):
        st.caption(f"Nguồn: {envelope['source']} · Analysis ID: {a['analysis_id']}")
        cols = st.columns(3)
        risk = a["risk_before"]
        cols[0].metric(
            "Điểm theo mô hình", "Chưa tính" if risk is None else f"{risk:.4f}"
        )
        cols[1].metric("Đường đến đích", len(d["before"]["path_details"]))
        cols[2].metric("Tài sản đích", ", ".join(a["target_asset_ids"]))
        st.caption(
            "Điểm heuristic không phải xác suất; điểm 0 không có nghĩa toàn hệ thống an toàn."
        )
        st.dataframe(a["results"], hide_index=True, width="stretch")
        selected = st.selectbox(
            "Chọn mã vấn đề",
            [r["finding_id"] for r in a["results"]],
            key=key + "finding",
        )
        if selected:
            st.json(d["candidate_details"][selected])
            for path in d["before"]["path_details"]:
                if selected in path["finding_ids"]:
                    st.json(path)
    explanation = saved_explanation
    if saved_explanation is None:
        prompts = [
            "Giải thích báo cáo này dễ hiểu hơn.",
            "Vì sao tôi nên xử lý vấn đề được xếp đầu trước?",
            "Tôi cần nhờ người kỹ thuật làm gì?",
            "Thông tin nào còn thiếu?",
            "Tự nhập câu hỏi",
        ]
        preset = st.selectbox("Bạn muốn hiểu điều gì?", prompts, key=key + "preset")
        with st.form(key + "ai"):
            question = st.text_input(
                "Câu hỏi cho trợ lý",
                "" if preset == "Tự nhập câu hỏi" else preset,
                key=key + "question-" + str(prompts.index(preset)),
            )
            compare = st.checkbox(
                "Đối chiếu cả hai báo cáo demo", disabled=envelope["source"] != "demo"
            )
            submitted = st.form_submit_button("AI giải thích và lưu")
        if submitted:
            st.session_state.pop(key + "answer", None)
            if not question.strip():
                st.warning("Hãy nhập câu hỏi.")
            else:
                try:
                    with st.spinner("Ollama đang giải thích…"):
                        answer = explain_report(envelope, question, compare)
                    save_explanation(envelope, answer)
                    st.session_state[key + "answer"] = answer
                    st.success("Đã lưu câu trả lời cùng bản sao báo cáo.")
                except Exception:
                    st.error(
                        "Không tạo hoặc lưu được giải thích. Kiểm tra Ollama, model và thư mục lưu dữ liệu."
                    )
        explanation = st.session_state.get(key + "answer")
    if explanation:
        st.markdown(explanation["text"])
        st.caption(
            f"AI chưa được kiểm chứng nội dung · {explanation['model_id']} · "
            f"{explanation['prompt_version']} · {explanation['created_at']}"
        )
    st.download_button(
        "Xuất JSON",
        export_json(envelope, explanation),
        "report.json",
        "application/json",
        key=key + "json",
    )
    st.download_button(
        "Xuất báo cáo Markdown",
        export_markdown(envelope, explanation),
        "report.md",
        "text/markdown",
        key=key + "md",
    )
    with st.expander("Báo cáo gốc và cảnh báo"):
        st.json(report)
