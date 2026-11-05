"""Plain-language website intake and evidence collection."""

import hashlib
import streamlit as st

from sv4_app_llm.storage.repository import list_records
from sv4_app_llm.service import inspect_sv1_dataset
from sv4_app_llm.adapters.sv1 import DatasetInputError
from sv4_app_llm.services.websites import (
    PURPOSES,
    IMPACTS,
    get_website,
    save_website,
    website_evidence,
    attach_website_dataset,
)


def choose_website(key):
    websites = list_records("website")
    if not websites:
        st.info("Bạn chưa thêm website. Hãy vào Tài sản của tôi để bắt đầu.")
        return None
    return st.selectbox(
        "Website của bạn",
        [r["id"] for r in websites],
        key=key,
        format_func=lambda value: next(
            r["title"] for r in websites if r["id"] == value
        ),
    )


def website_form(record=None):
    old = record["payload"] if record else {}
    key = record["id"] if record else "new"
    with st.form("website-" + key):
        name = st.text_input(
            "Bạn muốn gọi website này là gì?",
            old.get("name", ""),
            placeholder="Ví dụ: Cửa hàng của tôi",
        )
        address = st.text_input(
            "Địa chỉ website",
            old.get("address", ""),
            placeholder="Ví dụ: https://cuahang.vn",
            disabled=bool(record),
        )
        st.caption(
            "Chỉ lưu địa chỉ website, không lưu đường dẫn, mã truy cập hoặc tham số trong liên kết."
        )
        purpose = st.selectbox(
            "Bạn dùng website để làm gì?",
            PURPOSES,
            index=PURPOSES.index(old.get("purpose", PURPOSES[0])),
        )
        impact = st.selectbox(
            "Nếu website ngừng hoạt động, công việc bị ảnh hưởng thế nào?",
            IMPACTS,
            index=IMPACTS.index(old.get("impact", IMPACTS[0])),
        )
        sensitive = st.selectbox(
            "Website có lưu thông tin khách hàng, tài chính hoặc dữ liệu quan trọng không?",
            [None, True, False],
            index=[None, True, False].index(old.get("sensitive_data")),
            format_func=lambda x: {None: "Tôi không biết", True: "Có", False: "Không"}[
                x
            ],
        )
        platform = st.text_input(
            "Bạn có biết nền tảng website không? (có thể để trống)",
            old.get("platform") or "",
            placeholder="Ví dụ: WordPress, Shopify hoặc chưa biết",
        )
        st.caption(
            "Chưa biết thông số cũng có thể lưu. Các câu trả lời này chưa tạo thành kết quả đánh giá rủi ro."
        )
        if st.form_submit_button(
            "Lưu thay đổi" if record else "Thêm website", type="primary"
        ):
            try:
                save_website(
                    name,
                    address,
                    purpose,
                    impact,
                    sensitive,
                    platform,
                    website_id=record["id"] if record else None,
                )
                st.session_state["website_notice"] = (
                    "Đã lưu website. Bước tiếp theo là chuẩn bị thông tin kiểm tra."
                )
                st.rerun()
            except ValueError as error:
                st.error(str(error))


def render_collection(website_id):
    st.subheader("Chuẩn bị thông tin kiểm tra")
    st.write(
        "Nhờ người quản trị website cung cấp báo cáo kiểm tra. Phiên bản này chưa tự quét "
        "website; thông tin tên và địa chỉ chưa đủ để tìm lỗ hổng."
    )
    with st.expander("Tôi đã có báo cáo từ người kỹ thuật"):
        st.caption(
            "Hiện hỗ trợ file dataset.json theo định dạng SV1. PDF, ảnh chụp hoặc báo cáo scanner "
            "khác cần được chuyển đổi trước; không đổi đuôi file để tải lên."
        )
        uploaded = st.file_uploader(
            "Chọn báo cáo dữ liệu", type="json", key="website-upload-" + website_id
        )
        if uploaded is not None:
            try:
                content = uploaded.getvalue()
                inspected = inspect_sv1_dataset(content)
                assets = inspected["dataset"]["assets"]
                if not assets:
                    st.warning("Báo cáo chưa có tài sản để liên kết.")
                    return
                upload_key = hashlib.sha256(content).hexdigest()
                asset_id = st.selectbox(
                    "Nhờ người kỹ thuật xác nhận tài sản nào thuộc website này",
                    [a["asset_id"] for a in assets],
                    key="attach-asset-" + website_id + upload_key,
                    format_func=lambda value: next(
                        a["name"] + " (" + value + ")"
                        for a in assets
                        if a["asset_id"] == value
                    ),
                )
                confirmed = st.checkbox(
                    "Tôi xác nhận báo cáo và tài sản đã chọn thuộc website này",
                    key="attach-confirm-" + website_id + upload_key + asset_id,
                )
                if st.button(
                    "Lưu báo cáo cho website",
                    disabled=not confirmed,
                    key="attach-save-" + website_id,
                ):
                    attach_website_dataset(website_id, content, asset_id, confirmed)
                    st.success(
                        "Đã lưu dữ liệu đầu vào. Chưa có kết quả phân tích đường tấn công hoặc rủi ro."
                    )
            except DatasetInputError as error:
                st.error("Báo cáo chưa hợp lệ: " + str(error))
                if error.details:
                    st.dataframe(error.details, hide_index=True, width="stretch")


def render_websites():
    st.header("Tài sản của tôi")
    st.write(
        "Bắt đầu với website bạn muốn bảo vệ. Bạn có thể chọn ‘Tôi không biết’ khi chưa rõ thông tin."
    )
    if "website_notice" in st.session_state:
        st.success(st.session_state.pop("website_notice"))
    with st.expander("Thêm website", expanded=not list_records("website")):
        website_form()
    website_id = choose_website("assets-selected-website")
    if website_id:
        record = get_website(website_id)
        st.subheader(record["title"])
        st.write(record["payload"]["address"])
        evidence = website_evidence(website_id)
        st.info(
            "Đã có dữ liệu kiểm tra; đang chờ bộ phân tích."
            if evidence
            else "Chưa đánh giá — cần thêm dữ liệu kiểm tra website."
        )
        with st.expander("Chỉnh sửa thông tin website"):
            website_form(record)
        render_collection(website_id)
