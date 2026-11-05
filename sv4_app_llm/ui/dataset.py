"""Inspect canonical input independently of saved demo analysis results."""

import hashlib
import json
import streamlit as st

from sv4_app_llm.service import inspect_sv1_dataset
from sv4_app_llm.adapters.sv1 import DatasetInputError


def render_dataset():
    st.subheader("Dataset SV1 — nạp và kiểm tra")
    source = st.radio(
        "Nguồn dữ liệu SV1",
        ["sample", "upload"],
        horizontal=True,
        format_func=lambda x: (
            "Dataset mẫu SV1" if x == "sample" else "Tải dataset.json"
        ),
    )
    content = None
    if source == "upload":
        uploaded = st.file_uploader(
            "Dataset đầy đủ, không phải bản nháp tài sản", type="json", key="sv1_upload"
        )
        if uploaded is None:
            st.info("Chọn file dataset.json theo schema SV1.")
            return
        content = uploaded.getvalue()
    token = source + (
        hashlib.sha256(content).hexdigest() if content is not None else ""
    )
    if source == "sample" or st.button("Kiểm tra dataset SV1"):
        # Discard the old successful result before checking a replacement file.
        st.session_state.pop("sv1_inspection", None)
        try:
            result = inspect_sv1_dataset(content)
            st.session_state["sv1_inspection"] = (token, result)
        except DatasetInputError as error:
            st.error(str(error))
            if error.details:
                st.dataframe(error.details, hide_index=True, width="stretch")
    saved = st.session_state.get("sv1_inspection")
    if not saved or saved[0] != token:
        return
    result = saved[1]
    dataset = result["dataset"]
    st.success("Đã nạp và kiểm tra schema/tham chiếu bằng module SV1.")
    st.caption(
        f"Dataset: {dataset['dataset_id']} · schema {dataset['schema_version']} · "
        f"nguồn {dataset['source']} · {dataset['created_at']}"
    )
    labels = {
        "assets": "Tài sản",
        "services": "Dịch vụ",
        "findings": "Finding",
        "connections": "Kết nối",
        "exploit_rules": "Luật khai thác",
    }
    for col, (name, label) in zip(st.columns(5), labels.items()):
        col.metric(label, result["counts"][name])
    st.warning(
        "Chưa kết nối engine SV2–SV3: chưa xác định đường tấn công khả thi, "
        "điểm rủi ro hoặc hiệu quả vá cho dataset này. Kết nối không đồng nghĩa khai thác được."
    )
    if not dataset["exploit_rules"]:
        st.info(
            "Danh sách luật khai thác rỗng; cần SV2 bổ sung điều kiện và trạng thái khai thác."
        )
    for name, label in labels.items():
        with st.expander(label, expanded=name == "assets"):
            if dataset[name]:
                st.dataframe(dataset[name], hide_index=True, width="stretch")
            else:
                st.caption("Chưa có dữ liệu.")
    st.download_button(
        "Tải dataset đã kiểm tra",
        json.dumps(dataset, ensure_ascii=False, indent=2),
        "dataset.json",
        "application/json",
        key="sv1_download",
    )
    render_dataset_ai(dataset)


def render_dataset_ai(dataset):
    from sv4_app_llm.service import (
        dataset_fingerprint,
        explain_sv1_dataset,
        save_dataset_explanation,
    )

    fingerprint = dataset_fingerprint(dataset)
    st.subheader("AI giải thích dữ liệu SV1")
    st.caption(
        "AI đọc dataset đã kiểm tra. Chưa có kết quả tính đường tấn công hoặc ưu tiên vá. "
        "Chỉ gửi dữ liệu đến Ollama đã cấu hình khi bạn bấm nút."
    )
    prompts = [
        "Giải thích dữ liệu này dễ hiểu hơn.",
        "Tôi cần nhờ người kỹ thuật làm gì?",
        "Thông tin nào còn thiếu để đánh giá rủi ro?",
        "Tự nhập câu hỏi",
    ]
    preset = st.selectbox("Bạn muốn hỏi trợ lý điều gì?", prompts, key="sv1_ai_preset")
    with st.form("sv1_ai_form"):
        question = st.text_input(
            "Bạn muốn hiểu gì về dữ liệu này?",
            "" if preset == "Tự nhập câu hỏi" else preset,
            key="sv1-question-" + str(prompts.index(preset)),
        )
        submitted = st.form_submit_button("Hỏi AI về dữ liệu SV1")
    if submitted:
        st.session_state.pop("sv1_ai_answer", None)
        try:
            with st.spinner("Ollama đang đọc dữ liệu SV1…"):
                answer = explain_sv1_dataset(dataset, question)
            st.session_state["sv1_ai_answer"] = answer
        except Exception:
            st.error(
                "Chưa lấy được giải thích. Kiểm tra câu hỏi, Ollama, model và cấu hình kết nối."
            )
    answer = st.session_state.get("sv1_ai_answer")
    if not answer or answer["dataset_hash"] != fingerprint:
        return
    st.markdown(answer["text"])
    st.caption(
        f"Nội dung AI chưa được kiểm chứng · {answer['model_id']} · "
        f"{answer['prompt_version']} · {answer['created_at']}"
    )
    if st.button("Lưu giải thích SV1 vào lịch sử"):
        save_dataset_explanation(dataset, answer)
        st.success("Đã lưu giải thích kèm bản sao dataset.")
    st.download_button(
        "Tải giải thích SV1",
        json.dumps(
            {"dataset": dataset, "explanation": answer}, ensure_ascii=False, indent=2
        ),
        "sv1-explanation.json",
        "application/json",
    )
