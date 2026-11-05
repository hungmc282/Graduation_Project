"""Enterprise-wide UI. Unimplemented capabilities stay explicit, disabled sections."""

import json
import streamlit as st
from sv4_app_llm.services.enterprise import (
    ASSET_TYPES,
    records_of,
    save_enterprise_asset,
    save_declared_connection,
    store_input_dataset,
)
from sv4_app_llm.service import inspect_sv1_dataset
from sv4_app_llm.adapters.sv1 import DatasetInputError
from sv4_app_llm.ui.dataset import render_dataset_ai
from sv4_app_llm.ui.legacy.assets import render_assets
from sv4_app_llm.ui.history import render_history
from sv4_app_llm.ui.legacy.websites import render_websites
from sv4_app_llm.ui.legacy.actions import render_actions


def pending(title, description):
    with st.container(border=True):
        st.subheader(title)
        st.caption("Chưa triển khai / chờ tích hợp")
        st.write(description)


def scope_note(workspace):
    st.caption("Phạm vi: " + workspace["source_label"])
    if workspace["source"] == "synthetic":
        st.info(
            "Đây là dữ liệu mô phỏng, không phải kết quả kiểm tra hạ tầng thực tế của doanh nghiệp."
        )


def render_overview(workspace):
    st.header("Tổng quan doanh nghiệp")
    scope_note(workspace)
    for col, key, label in zip(
        st.columns(4),
        ("assets", "services", "findings", "connections"),
        ("Tài sản", "Dịch vụ đã ghi nhận", "Phát hiện đã ghi nhận", "Kết nối khai báo"),
    ):
        col.metric(label, len(workspace[key]))
    st.warning(
        "Chưa có đánh giá rủi ro cho phạm vi này. Số phát hiện bằng 0 có thể do thiếu dữ liệu, "
        "không xác nhận hệ thống an toàn."
    )
    st.subheader("Mức sẵn sàng dữ liệu")
    st.dataframe(
        [
            {
                "Thành phần": label,
                "Trạng thái": "Có dữ liệu đầu vào"
                if workspace[key]
                else "Chưa có dữ liệu",
            }
            for key, label in (
                ("assets", "Danh mục tài sản"),
                ("services", "Dịch vụ"),
                ("findings", "Kết quả kiểm tra"),
                ("connections", "Kết nối"),
                ("exploit_rules", "Luật khai thác"),
            )
        ],
        hide_index=True,
        width="stretch",
    )
    st.caption(
        "Có dữ liệu không chứng minh dữ liệu đầy đủ; bộ phân tích cần xác nhận phạm vi và các giới hạn."
    )
    for title, description in (
        (
            "Tài sản và đường tấn công rủi ro cao",
            "Chờ GraphResult và AnalysisResult từ SV2–SV3.",
        ),
        (
            "Xu hướng rủi ro và cảnh báo",
            "Chờ các lần phân tích có cùng thang điểm, phạm vi và cấu hình phù hợp để so sánh.",
        ),
    ):
        pending(title, description)


def asset_form(record=None):
    asset = record["payload"]["asset"] if record else {}
    context = record["payload"]["context"] if record else {}
    with st.form(
        "enterprise-asset-" + (record["id"] if record else "new"),
        clear_on_submit=record is None,
    ):
        name = st.text_input(
            "Tên tài sản",
            asset.get("name", ""),
            placeholder="Ví dụ: Database khách hàng",
        )
        options = list(ASSET_TYPES)
        kind = st.selectbox(
            "Loại tài sản",
            options,
            index=options.index(asset.get("asset_type", options[0])),
            format_func=lambda x: ASSET_TYPES[x],
        )
        address = st.text_input(
            "Địa chỉ IP / tên máy / tên miền (nếu biết)", context.get("address") or ""
        )
        system = st.text_input(
            "Thuộc hệ thống hoặc phòng ban nào?",
            context.get("system") or "",
            placeholder="Ví dụ: Hệ thống bán hàng",
        )
        purpose = st.text_input(
            "Tài sản này dùng để làm gì?", context.get("purpose") or ""
        )
        owner = st.text_input(
            "Bộ phận hoặc người phụ trách (nếu biết)", context.get("owner") or ""
        )
        levels = [None, 1, 2, 3, 4, 5]
        criticality = st.selectbox(
            "Mức ảnh hưởng nếu tài sản ngừng hoạt động",
            levels,
            index=levels.index(asset.get("criticality")),
            format_func=lambda x: {
                None: "Tôi chưa biết",
                1: "1 — Rất ít ảnh hưởng",
                2: "2 — Ảnh hưởng nhỏ",
                3: "3 — Ảnh hưởng đáng kể",
                4: "4 — Ảnh hưởng lớn",
                5: "5 — Gián đoạn hoạt động trọng yếu",
            }[x],
        )
        choices = [None, True, False]
        internet = st.selectbox(
            "Có thể truy cập trực tiếp từ Internet không?",
            choices,
            index=choices.index(asset.get("internet_facing")),
            format_func=lambda x: {None: "Tôi không biết", True: "Có", False: "Không"}[
                x
            ],
        )
        sensitive = st.selectbox(
            "Có lưu dữ liệu nhạy cảm hoặc quan trọng không?",
            choices,
            index=choices.index(asset.get("sensitive_data")),
            format_func=lambda x: {None: "Tôi không biết", True: "Có", False: "Không"}[
                x
            ],
        )
        with st.expander("Thông tin mạng bổ sung (có thể để trống)"):
            subnet = st.text_input("Subnet / vùng mạng", context.get("subnet") or "")
            vlan = st.text_input("VLAN", context.get("vlan") or "")
            st.caption(
                "Đây là thông tin mô tả bản nháp; chưa dùng để tự suy ra khả năng kết nối hoặc đường tấn công."
            )
        if st.form_submit_button(
            "Lưu thay đổi tài sản" if record else "Thêm tài sản", type="primary"
        ):
            try:
                save_enterprise_asset(
                    name,
                    kind,
                    address,
                    system,
                    subnet,
                    vlan,
                    owner,
                    purpose,
                    criticality,
                    internet,
                    sensitive,
                    record["id"] if record else None,
                )
                st.session_state["enterprise-notice"] = (
                    "Đã lưu tài sản. Chưa tự quét hoặc tính rủi ro."
                )
                st.rerun()
            except ValueError as error:
                st.error(str(error))


def render_inventory(workspace, workspace_id):
    st.header("Tài sản và hệ thống")
    scope_note(workspace)
    if "enterprise-notice" in st.session_state:
        st.success(st.session_state.pop("enterprise-notice"))
    if workspace_id == "manual":
        with st.expander("Thêm tài sản doanh nghiệp", expanded=not workspace["assets"]):
            asset_form()
    else:
        st.caption(
            "Đang xem snapshot đã nhập, không sửa trực tiếp. Chuyển phạm vi sang tài sản tự khai báo để thêm tài sản."
        )
    if workspace["assets"]:
        rows = []
        for asset in workspace["assets"]:
            context = workspace["contexts"].get(asset["asset_id"], {})
            rows.append(
                {
                    "Tên": asset["name"],
                    "Loại": ASSET_TYPES.get(asset["asset_type"], asset["asset_type"]),
                    "Hệ thống": context.get("system"),
                    "Mức quan trọng (1–5)": asset["criticality"],
                    "Địa chỉ": context.get("address"),
                    "ID kỹ thuật": asset["asset_id"],
                }
            )
        st.dataframe(rows, hide_index=True, width="stretch")
        if workspace_id == "manual":
            records = records_of("enterprise_asset")
            chosen = st.selectbox(
                "Tài sản cần chỉnh sửa",
                [r["id"] for r in records],
                format_func=lambda x: next(r["title"] for r in records if r["id"] == x),
            )
            with st.expander("Chỉnh sửa tài sản đã chọn"):
                asset_form(next(r for r in records if r["id"] == chosen))
    else:
        st.info(
            "Thêm máy chủ, cơ sở dữ liệu, máy trạm, ứng dụng và các tài sản khác của doanh nghiệp."
        )
    with st.expander("Dịch vụ đã ghi nhận trên tài sản"):
        if workspace["services"]:
            st.dataframe(workspace["services"], hide_index=True, width="stretch")
        else:
            st.caption("Chưa có dữ liệu dịch vụ trong phạm vi này.")
        pending(
            "Bổ sung / cập nhật dịch vụ",
            "Chờ giao diện dịch vụ và adapter SV1. Hiện có thể đọc dịch vụ từ dataset SV1.",
        )
    with st.expander("Nhập CSV danh mục tài sản"):
        pending("Nhập CSV", "Chờ chốt định dạng và adapter chuẩn hóa với SV1.")
    with st.expander("Xuất bản nháp tài sản và kết nối"):
        st.download_button(
            "Tải bản nháp doanh nghiệp",
            json.dumps(workspace, ensure_ascii=False, indent=2),
            "enterprise-inventory-draft.json",
            "application/json",
        )
        st.caption(
            "Bản nháp này không phải dataset.json canonical để đưa trực tiếp vào engine."
        )


def render_data(workspace):
    st.header("Dữ liệu kiểm tra và lỗ hổng")
    scope_note(workspace)
    st.write("Nhập dữ liệu kiểm tra tài sản và kết nối theo định dạng SV1 đã hỗ trợ.")
    source = st.radio(
        "Nguồn nhập",
        ["upload", "sample"],
        horizontal=True,
        format_func=lambda x: (
            "Dataset doanh nghiệp (JSON)" if x == "upload" else "Dataset mô phỏng SV1"
        ),
    )
    content = None
    if source == "upload":
        uploaded = st.file_uploader(
            "Chọn dataset.json", type="json", key="enterprise-upload"
        )
        if uploaded is not None:
            content = uploaded.getvalue()
    if st.button(
        "Kiểm tra và lưu dataset"
        if source == "upload"
        else "Lưu dataset mẫu để trải nghiệm",
        disabled=source == "upload" and content is None,
    ):
        try:
            record_id = store_input_dataset(content)
            st.session_state["dataset-saved-notice"] = (
                "Đã lưu dataset. Chọn dataset vừa lưu tại Phạm vi dữ liệu ở thanh bên."
            )
            st.rerun()
        except DatasetInputError as error:
            st.error(str(error))
            if error.details:
                st.dataframe(error.details, hide_index=True, width="stretch")
    st.subheader("Các phát hiện trong phạm vi đang chọn")
    if workspace["findings"]:
        st.dataframe(workspace["findings"], hide_index=True, width="stretch")
    else:
        st.info(
            "Chưa có kết quả kiểm tra trong dữ liệu đang chọn. Không có nghĩa là không có lỗ hổng."
        )
    if workspace["dataset"]:
        render_dataset_ai(workspace["dataset"])
        with st.expander("Dataset và bằng chứng kỹ thuật"):
            st.json(workspace["dataset"])
    pending(
        "Kết nối công cụ quét",
        "Chờ tích hợp adapter ít nhất hai nguồn scanner với SV1. Chưa có nút tự quét hoạt động.",
    )
    pending(
        "Làm giàu CVE / EPSS / KEV",
        "Hiện đọc được giá trị có trong dataset; chưa có luồng cập nhật, cache và lịch sử enrichment trên giao diện.",
    )


def render_legacy():
    with st.expander("Dữ liệu website và bản nháp của phiên bản cũ", expanded=True):
        old = st.radio(
            "Loại dữ liệu cũ",
            ["Website", "Tiến độ website", "Bản nháp tài sản"],
            horizontal=True,
        )
        if old == "Website":
            render_websites()
        elif old == "Tiến độ website":
            render_actions()
        else:
            render_assets()


def render_network(workspace, workspace_id):
    st.header("Sơ đồ hạ tầng và đường tấn công")
    scope_note(workspace)
    st.subheader("Kết nối mạng đã khai báo")
    st.caption(
        "Sơ đồ dưới đây chỉ biểu diễn quan hệ kết nối. Mũi tên không khẳng định có thể khai thác."
    )
    if workspace["assets"]:
        nodes = {a["asset_id"]: a["name"] for a in workspace["assets"]}
        nodes["INTERNET"] = "Internet / điểm vào bên ngoài"
        lines = ["digraph infrastructure { rankdir=LR;"]
        for node_id, name in nodes.items():
            lines.append(
                json.dumps(node_id)
                + " [label="
                + json.dumps(name, ensure_ascii=False)
                + "];"
            )
        for c in workspace["connections"]:
            label = "Cho phép" if c["allowed"] else "Chặn"
            style = "solid" if c["allowed"] else "dashed"
            lines.append(
                json.dumps(c["source_asset_id"])
                + " -> "
                + json.dumps(c["target_asset_id"])
                + " [label="
                + json.dumps(label, ensure_ascii=False)
                + ", style="
                + style
                + "];"
            )
        st.graphviz_chart("\n".join(lines) + "}", width="stretch")
    else:
        st.info("Chưa có tài sản để hiển thị sơ đồ.")
    if workspace["connections"]:
        with st.expander("Kết nối và bằng chứng"):
            st.dataframe(workspace["connections"], hide_index=True, width="stretch")
    if workspace_id == "manual" and workspace["assets"]:
        with st.expander("Khai báo kết nối giữa các tài sản"):
            names = {a["asset_id"]: a["name"] for a in workspace["assets"]}
            with st.form("enterprise-connection"):
                source = st.selectbox(
                    "Từ tài sản",
                    ["INTERNET"] + list(names),
                    format_func=lambda x: "Internet" if x == "INTERNET" else names[x],
                )
                target = st.selectbox(
                    "Đến tài sản", list(names), format_func=lambda x: names[x]
                )
                allowed = st.selectbox(
                    "Quyền kết nối",
                    [True, False],
                    format_func=lambda x: "Cho phép" if x else "Chặn",
                )
                evidence = st.text_input(
                    "Nguồn xác nhận kết nối",
                    placeholder="Ví dụ: cấu hình firewall do quản trị viên xác nhận",
                )
                if st.form_submit_button("Lưu kết nối khai báo"):
                    try:
                        save_declared_connection(source, target, allowed, evidence)
                        st.rerun()
                    except ValueError as error:
                        st.error(str(error))
    pending(
        "Chọn điểm vào và tài sản đích",
        "Chờ kết nối cấu hình graph với SV2; sẽ hỗ trợ Internet hoặc tài sản đã bị xâm nhập làm điểm vào.",
    )
    pending(
        "Đường tấn công khả thi",
        "Chờ engine kiểm tra điều kiện khai thác, quyền và trust; hiển thị đường, finding và bằng chứng từ SV2.",
    )
    pending(
        "Đường quan trọng và giới hạn tìm kiếm",
        "Chờ dữ liệu đánh dấu đường quan trọng, độ đầy đủ và cảnh báo từ GraphResult.",
    )
    st.button("Phân tích đường tấn công", disabled=True)


def render_priorities(workspace):
    st.header("Ưu tiên khắc phục")
    scope_note(workspace)
    st.info(
        "Chưa có kết quả Risk Engine cho phạm vi đang chọn. Không dùng điểm hoặc thứ hạng của dataset mẫu khác."
    )
    pending(
        "Điểm rủi ro tài sản / đường / hệ thống",
        "Chờ SV3 cung cấp thang điểm, phiên bản mô hình và kết quả tính có thể tái lập.",
    )
    pending(
        "Hàng đợi khắc phục",
        "Sẽ hiển thị lỗ hổng cần xử lý trước, lý do, tài sản liên quan và mức giảm rủi ro dự kiến.",
    )
    pending(
        "Mô phỏng vá một hoặc nhiều lỗ hổng",
        "Chờ SV2–SV3 tính lại graph, Remediation Impact và thứ hạng; không tự sửa báo cáo lưu sẵn.",
    )
    st.button("Mô phỏng phương án khắc phục", disabled=True)
    pending(
        "Hướng dẫn khắc phục và kiểm tra lại",
        "Chờ nguồn hướng dẫn theo sản phẩm/phiên bản; phân biệt mô phỏng với kết quả đã khắc phục được xác minh.",
    )
    pending(
        "So sánh các phương pháp ưu tiên",
        "Dự kiến CVSS-only, EPSS-only, CVSS+KEV và weighted scoring không xét graph; chờ kết quả SV3 trên cùng dataset.",
    )


def render_reports():
    st.header("Báo cáo và lịch sử")
    mode = st.radio(
        "Nội dung",
        ["history", "demo", "legacy"],
        horizontal=True,
        format_func=lambda x: {
            "history": "Lịch sử đã lưu",
            "demo": "Báo cáo minh họa",
            "legacy": "Dữ liệu phiên bản cũ",
        }[x],
    )
    if mode == "history":
        render_history()
    elif mode == "legacy":
        render_legacy()
    else:
        from sv4_app_llm.service import run_analysis, save_analysis
        from sv4_app_llm.ui.reports import render_report

        st.warning(
            "Tình huống mô phỏng diamond-v1; không thuộc phạm vi doanh nghiệp đang chọn."
        )
        scenario = st.radio(
            "Tình huống mẫu",
            ["before-F01", "after-F01"],
            horizontal=True,
            format_func=lambda x: (
                "Trước khắc phục"
                if x == "before-F01"
                else "Sau khắc phục F01 (lưu sẵn)"
            ),
        )
        envelope = run_analysis("demo", scenario=scenario)
        if st.button("Lưu báo cáo mẫu vào lịch sử"):
            save_analysis(envelope)
            st.success("Đã lưu báo cáo mẫu.")
        render_report(envelope, "enterprise-demo-" + scenario)
        st.subheader("So sánh trước–sau trên cùng kịch bản mẫu")
        st.dataframe(
            [
                {
                    "Tình huống": name,
                    "Điểm theo mô hình": run_analysis("demo", scenario=name)["report"][
                        "analysis"
                    ]["risk_before"],
                    "Số đường": len(
                        run_analysis("demo", scenario=name)["report"]["details"][
                            "before"
                        ]["path_details"]
                    ),
                }
                for name in ("before-F01", "after-F01")
            ],
            hide_index=True,
            width="stretch",
        )
    pending(
        "Báo cáo quản trị / kỹ thuật PDF và CSV",
        "Hiện báo cáo mẫu có xuất JSON/Markdown; PDF/CSV theo yêu cầu đề tài sẽ bổ sung sau.",
    )
    pending(
        "Cảnh báo và thông báo",
        "Chờ dữ liệu engine và quy tắc cảnh báo; hiện chưa gửi thông báo bên ngoài.",
    )
    with st.expander("Triển khai và kiểm thử toàn hệ thống"):
        pending(
            "Triển khai tái lập và kiểm thử end-to-end",
            "Chờ tích hợp đầy đủ pipeline, cấu hình triển khai và thực nghiệm. Lưu trữ hiện tại dùng SQLite cho bản local.",
        )
