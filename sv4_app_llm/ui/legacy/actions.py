"""Next actions for the selected website, distinct from synthetic demo results."""

import json
import streamlit as st
from sv4_app_llm.ui.legacy.websites import choose_website
from sv4_app_llm.ui.dataset import render_dataset_ai
from sv4_app_llm.services.websites import (
    get_website,
    preparation_steps,
    website_evidence,
    action_status,
    set_action_status,
    STATUSES,
    website_summary,
)


def render_actions():
    st.header("Việc cần xử lý")
    website_id = choose_website("actions-selected-website")
    if not website_id:
        return
    website = get_website(website_id)["payload"]
    st.subheader(website["name"])
    st.warning(
        "Chưa có đánh giá rủi ro cho website này. Các việc bên dưới giúp chuẩn bị dữ liệu, "
        "chưa phải danh sách lỗ hổng được xếp hạng."
    )
    for step in preparation_steps(website_id):
        with st.container(border=True):
            st.markdown("### " + step["title"])
            st.write("**Vì sao cần làm:** " + step["why"])
            st.write("**Bước tiếp theo:** " + step["action"])
            if step["id"] != "analysis":
                saved = action_status(website_id, step["id"])
                with st.form("action-" + website_id + step["id"]):
                    status = st.selectbox(
                        "Tiến độ của bạn",
                        STATUSES,
                        index=STATUSES.index(saved["status"]),
                    )
                    note = st.text_input("Ghi chú (không nhập mật khẩu)", saved["note"])
                    if st.form_submit_button("Lưu tiến độ"):
                        set_action_status(website_id, step["id"], status, note)
                        st.success(
                            "Đã lưu tiến độ do bạn khai báo; chưa xác minh khắc phục."
                        )
    st.caption(
        "Đánh dấu ‘Tôi đã xử lý’ không xác nhận website an toàn. "
        "Kiểm tra lại sau khắc phục sẽ được nối khi có công cụ hỗ trợ."
    )
    st.download_button(
        "Tải bản tóm tắt để gửi người kỹ thuật",
        website_summary(website_id),
        "website-support.md",
        "text/markdown",
    )
    evidence = website_evidence(website_id)
    if evidence:
        item = evidence[0]["payload"]
        dataset = item["dataset"]
        st.subheader("Thông tin từ báo cáo bạn cung cấp")
        st.caption(
            "Liên kết với website do bạn xác nhận; hệ thống chưa tự kiểm chứng quyền sở hữu hoặc quét website."
        )
        selected_findings = [
            f for f in dataset["findings"] if f["asset_id"] == item["asset_id"]
        ]
        st.write(f"Báo cáo có {len(selected_findings)} phát hiện cho tài sản đã chọn.")
        st.caption(
            "Số phát hiện không phải mức rủi ro; chưa tìm thấy trong dữ liệu không đồng nghĩa không có lỗ hổng."
        )
        with st.expander("Chi tiết kỹ thuật của báo cáo"):
            st.json(dataset)
        st.caption(
            "Trợ lý đọc toàn bộ báo cáo bên dưới, có thể gồm nhiều tài sản; "
            "không coi mọi finding trong báo cáo là finding của website đã chọn."
        )
        render_dataset_ai(dataset)
        st.download_button(
            "Tải lại dữ liệu đã cung cấp",
            json.dumps(dataset, ensure_ascii=False, indent=2),
            "website-dataset.json",
            "application/json",
        )
