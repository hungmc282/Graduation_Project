"""Asset draft entry. No assumptions about unknown attributes."""

import json
import streamlit as st
from sv4_app_llm.service import (
    get_record,
    list_records,
    save_asset_draft,
    validate_assets,
)


def render_assets():
    st.subheader("Nhập tài sản — bản nháp")
    st.info(
        "Chỉ nhập tài sản chưa đủ để phân tích. Cần thêm dịch vụ, finding, "
        "kết nối và điều kiện khai thác từ SV1–SV2."
    )
    assets = st.session_state.setdefault("draft_assets", [])
    with st.form("asset_form", clear_on_submit=True):
        asset_id = st.text_input("ID tài sản")
        name = st.text_input("Tên tài sản")
        asset_type = st.text_input("Loại tài sản (có thể để trống)")
        criticality = st.selectbox(
            "Mức quan trọng",
            [None, 1, 2, 3, 4, 5],
            format_func=lambda x: "Chưa biết" if x is None else str(x),
        )
        internet = st.selectbox(
            "Tiếp xúc Internet",
            [None, True, False],
            format_func=lambda x: {None: "Chưa biết", True: "Có", False: "Không"}[x],
        )
        sensitive = st.selectbox(
            "Có dữ liệu nhạy cảm",
            [None, True, False],
            format_func=lambda x: {None: "Chưa biết", True: "Có", False: "Không"}[x],
        )
        if st.form_submit_button("Thêm / cập nhật tài sản"):
            item = {
                "asset_id": asset_id,
                "name": name,
                "asset_type": asset_type or None,
                "criticality": criticality,
                "internet_facing": internet,
                "sensitive_data": sensitive,
            }
            try:
                item = validate_assets([item])[0]
                updated = [a for a in assets if a["asset_id"] != item["asset_id"]] + [
                    item
                ]
                st.session_state["draft_assets"] = validate_assets(updated)
                st.rerun()
            except ValueError as error:
                st.error(str(error))
    assets = st.session_state["draft_assets"]
    if assets:
        st.dataframe(assets, hide_index=True, width="stretch")
        remove = st.selectbox("Chọn tài sản cần xóa", [a["asset_id"] for a in assets])
        if st.button("Xóa khỏi bản nháp"):
            st.session_state["draft_assets"] = [
                a for a in assets if a["asset_id"] != remove
            ]
            st.rerun()
    title = st.text_input("Tên bản nháp", "Tài sản của tôi")
    if st.button("Lưu bản nháp", disabled=not assets):
        try:
            record_id = save_asset_draft(title, assets)
            st.success("Đã lưu bản nháp: " + record_id)
        except ValueError as error:
            st.error(str(error))
    st.download_button(
        "Tải bản nháp JSON",
        json.dumps(
            {
                "draft_schema_version": "sv4-draft-1",
                "status": "draft",
                "assets": assets,
            },
            ensure_ascii=False,
            indent=2,
        ),
        "asset-draft.json",
        "application/json",
    )
    uploaded = st.file_uploader("Nạp bản nháp JSON đã xuất", type="json")
    if st.button("Đọc file bản nháp", disabled=uploaded is None):
        try:
            draft = json.loads(uploaded.getvalue().decode("utf-8-sig"))
            if draft.get("draft_schema_version") != "sv4-draft-1":
                raise ValueError("Phiên bản bản nháp không hỗ trợ.")
            st.session_state["draft_assets"] = validate_assets(draft["assets"])
            st.rerun()
        except (ValueError, KeyError, TypeError, AttributeError) as error:
            st.error("Không nạp được bản nháp: " + str(error))
    drafts = list_records("draft")
    if drafts:
        selected = st.selectbox(
            "Bản nháp đã lưu",
            drafts,
            format_func=lambda r: r["title"] + " · " + r["created_at"],
        )
        if st.button("Mở bản nháp đã lưu"):
            st.session_state["draft_assets"] = get_record(selected["id"])["payload"][
                "assets"
            ]
            st.rerun()
