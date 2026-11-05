"""An on-demand assistant rail tied to the active dataset and patch state."""

import html
import os

import streamlit as st

from sv4_app_llm.llm.ollama import base_url, list_models
from sv4_app_llm.services.assistant import context_id, explain_context
from sv4_app_llm.services.assistant_facts import analysis_facts
from sv4_app_llm.storage.repository import save_record


@st.cache_data(ttl=15, show_spinner=False)
def available_models():
    return list_models()


def render_assistant(workspace, envelope, baseline=None):
    with st.container(key="rd_ai_panel"):
        st.subheader("Trợ lý AI", anchor=False)
        analysis = envelope["report"]["analysis"] if envelope else None
        if envelope:
            facts = analysis_facts(workspace, envelope, baseline)
            note = (
                facts["facts"]["patch_effect"]
                if analysis["patched_finding_ids"]
                else facts["facts"]["current_state"]
            )
            if not analysis["patched_finding_ids"]:
                best = [
                    row["finding_id"]
                    for row in analysis["results"]
                    if row["priority_rank"] == 1 and row["remediation_impact"] > 0
                ]
                if best:
                    note = (
                        "Ưu tiên xem "
                        + " hoặc ".join(best)
                        + " theo mức giảm rủi ro tính được trong mô hình này."
                    )
            st.markdown(
                '<div class="rd-engine-note">' + html.escape(note) + "</div>",
                unsafe_allow_html=True,
            )
        if envelope and analysis["patched_finding_ids"]:
            evidence = analysis_facts(workspace, envelope, baseline)
            st.caption("Kết quả engine đã kiểm tra")
            st.success(evidence["facts"]["patch_effect"])
        st.caption("Bạn có thể hỏi thêm:")
        suggestions = (
            [
                "Vì sao nên ưu tiên các lỗi đứng đầu?",
                "Phương án vá hiện tại thay đổi gì?",
                "Vì sao F03 có CVSS cao nhưng ưu tiên thấp?",
                "Giải thích đường tấn công đang hiển thị?",
                "Các giới hạn của kết quả phân tích này là gì?",
            ]
            if envelope
            else ["Dữ liệu này có những gì?", "Còn thiếu gì để phân tích rủi ro?"]
        )
        for index, prompt in enumerate(suggestions):
            if st.button(prompt, key=f"rd_ai_suggest_{index}", width="stretch"):
                st.session_state["rd_ai_preset"] = prompt
                st.rerun()
        with st.expander("Phạm vi và kết nối AI"):
            st.caption("Phạm vi: " + workspace["source_label"])
            if analysis:
                st.caption("Đích: " + ", ".join(analysis["target_asset_ids"]))
                st.caption(
                    "Mô phỏng vá: "
                    + (", ".join(analysis["patched_finding_ids"]) or "Chưa vá")
                )
        try:
            models = available_models()
        except ValueError as error:
            with st.expander("Kết nối Ollama · Chưa sẵn sàng"):
                st.warning(str(error))
                if st.button("Kiểm tra lại Ollama", key="rd_retry_ollama"):
                    available_models.clear()
                    st.rerun()
                st.caption("Kết nối: " + base_url())
            return
        if not models:
            st.info("Ollama đang chạy nhưng chưa có model. Chọn model đã cài trên máy.")
            return
        configured = os.environ.get("APP_OLLAMA_MODEL", "qwen3.5:35b")
        selected = st.session_state.get("rd_model", configured)
        if selected not in models:
            st.session_state["rd_model"] = models[0]
        model = st.selectbox("Model trên máy", models, key="rd_model")
        prompts = [*suggestions, "Tự nhập câu hỏi"]
        preset = st.selectbox("Bạn muốn hiểu điều gì?", prompts, key="rd_ai_preset")
        with st.form("rd_ai_form"):
            question = st.text_area(
                "Câu hỏi của bạn",
                "" if preset == "Tự nhập câu hỏi" else preset,
                key="rd_question_" + str(prompts.index(preset)),
                height=95,
            )
            submitted = st.form_submit_button(
                "Gọi AI giải thích", type="primary", width="stretch"
            )
        if submitted:
            st.session_state.pop("rd_ai_answer", None)
            try:
                with st.spinner("Ollama đang trả lời… lần đầu cần nạp model."):
                    answer = explain_context(
                        workspace, question, envelope, model=model, baseline=baseline
                    )
                st.session_state["rd_ai_answer"] = answer
            except (ValueError, OSError, KeyError, TypeError) as error:
                st.error(str(error))
        answer = st.session_state.get("rd_ai_answer")
        if answer and answer["context_id"] == context_id(workspace, envelope, model):
            st.divider()
            st.caption("Câu hỏi: " + answer["question"])
            st.markdown(answer["text"])
            st.caption(
                "Các ý phân tích được chọn từ bằng chứng engine và kiểm tra trước khi hiển thị."
                if answer.get("validation_status") == "fact_ids_checked"
                else "Nội dung giải thích đầu vào của AI cần đối chiếu bằng chứng."
            )
            if st.button("Lưu giải thích", key="rd_save_ai"):
                save_record(
                    "dashboard_explanation",
                    answer["question"],
                    {
                        "workspace": workspace,
                        "envelope": envelope,
                        "explanation": answer,
                    },
                )
                st.success("Đã lưu câu trả lời cùng dữ liệu tham chiếu.")
        elif answer:
            st.caption(
                "Dữ liệu, phương án hoặc model đã thay đổi. Hỏi lại để có giải thích đúng ngữ cảnh."
            )
        with st.expander("Kết nối AI"):
            st.caption(base_url())
            st.caption(
                "Chỉ gửi dữ liệu tới Ollama khi bấm Gọi AI. Không có câu trả lời mẫu thay thế."
            )
