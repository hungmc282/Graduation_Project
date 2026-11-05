import streamlit as st
from sv4_app_llm.storage.repository import get_record, list_records
from sv4_app_llm.ui.reports import render_report


def render_history():
    st.subheader("Lịch sử lưu trên máy")
    kind = st.radio(
        "Loại lịch sử",
        [
            "enterprise_activity",
            "analysis",
            "explanation",
            "dataset_explanation",
            "website_activity",
        ],
        horizontal=True,
        format_func=lambda x: {
            "enterprise_activity": "Tài sản và dữ liệu đầu vào",
            "website_activity": "Hoạt động website cũ",
            "analysis": "Báo cáo",
            "explanation": "AI giải thích báo cáo",
            "dataset_explanation": "AI dữ liệu SV1",
        }[x],
    )
    if kind == "enterprise_activity":
        rows = []
        for record_kind, label in (
            ("enterprise_asset", "Hồ sơ tài sản"),
            ("enterprise_connection", "Kết nối khai báo"),
            ("input_dataset", "Snapshot dữ liệu đầu vào"),
        ):
            for item in list_records(record_kind):
                rows.append(
                    {
                        "Thời điểm lưu ban đầu": item["created_at"],
                        "Loại": label,
                        "Tên": item["title"],
                        "ID bản ghi": item["id"],
                    }
                )
        if rows:
            st.dataframe(
                sorted(rows, key=lambda r: r["Thời điểm lưu ban đầu"], reverse=True),
                hide_index=True,
                width="stretch",
            )
            st.caption(
                "Hồ sơ tài sản hiển thị thông tin hiện tại; chưa có nhật ký mọi lần chỉnh sửa."
            )
        else:
            st.info("Chưa có hồ sơ hoặc dataset doanh nghiệp được lưu.")
        return
    if kind == "website_activity":
        from sv4_app_llm.ui.legacy.websites import choose_website

        website_id = choose_website("history-website")
        if not website_id:
            return
        items = []
        for record_kind in ("website_action", "website_evidence"):
            for item in list_records(record_kind):
                record = get_record(item["id"])
                payload = record["payload"]
                if payload["website_id"] == website_id:
                    items.append(
                        {
                            "Thời điểm": record["created_at"],
                            "Hoạt động": "Cung cấp báo cáo kiểm tra"
                            if record_kind == "website_evidence"
                            else "Cập nhật công việc: " + payload["action_id"],
                            "Trạng thái": "Đầu vào, chưa phân tích"
                            if record_kind == "website_evidence"
                            else payload["status"],
                            "Ghi chú": payload.get("note", ""),
                        }
                    )
        if items:
            st.dataframe(
                sorted(items, key=lambda r: r["Thời điểm"], reverse=True),
                hide_index=True,
                width="stretch",
            )
        else:
            st.info(
                "Chưa có hoạt động bổ sung. Hồ sơ website đã được lưu trong Tài sản của tôi."
            )
        return
    records = list_records(kind)
    if not records:
        st.info("Chưa có bản ghi. Hãy lưu báo cáo hoặc tạo giải thích AI.")
        return
    selected = st.selectbox(
        "Chọn bản ghi",
        records,
        format_func=lambda r: r["title"] + " · " + r["created_at"],
    )
    payload = get_record(selected["id"])["payload"]
    if kind == "dataset_explanation":
        import json

        answer = payload["explanation"]
        st.caption(f"Dataset: {answer['dataset_id']} · {answer['dataset_hash']}")
        st.markdown(answer["text"])
        st.caption(
            f"AI giải thích đầu vào, chưa kiểm chứng nội dung · {answer['model_id']} · "
            f"{answer['prompt_version']} · {answer['created_at']}"
        )
        st.write("Câu hỏi: " + answer["question"])
        st.download_button(
            "Tải giải thích SV1 đã lưu",
            json.dumps(payload, ensure_ascii=False, indent=2),
            "sv1-explanation.json",
            "application/json",
            key="history-sv1-download",
        )
        with st.expander("Dataset gốc của câu trả lời"):
            st.json(payload["dataset"])
    elif kind == "analysis":
        render_report(payload, "history-" + selected["id"])
    else:
        render_report(
            payload["envelope"], "history-" + selected["id"], payload["explanation"]
        )
