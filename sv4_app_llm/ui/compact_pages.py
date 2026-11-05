"""Five task-oriented pages for the compact dashboard."""

import html
import json

import streamlit as st

from sv4_app_llm.reports.export import export_json, export_markdown
from sv4_app_llm.services.enterprise import (
    records_of,
    save_declared_connection,
    store_input_dataset,
)
from sv4_app_llm.storage.repository import get_record, list_records, save_record
from sv4_app_llm.ui.graph_view import render_graph
from sv4_app_llm.ui.workspace import asset_form, render_legacy


def set_patch(finding):
    st.session_state["rd_patch_ids"] = [finding] if finding else []
    st.session_state["rd_patch_widget"] = list(st.session_state["rd_patch_ids"])


def go(page):
    st.session_state["rd_page"] = page


def path_view(envelope):
    if not envelope:
        return
    graph = envelope["report"]["graph"]
    if not graph["paths"]:
        st.info("Không còn đường tới đích trong phạm vi mô hình đang xét.")
    for path in graph["paths"]:
        label = " → ".join(html.escape(x) for x in path["asset_ids"])
        st.markdown(f'<div class="rd-path">{label}</div>', unsafe_allow_html=True)
        with st.expander("Điều kiện và bằng chứng · " + path["path_id"]):
            st.caption("Findings: " + ", ".join(path["finding_ids"]))
            st.json(path)


def ranking(envelope, prefix, workspace=None):
    analysis = envelope["report"]["analysis"]
    rows = analysis["results"]
    if not rows:
        st.info("Không còn finding chưa vá trong bộ dữ liệu này.")
        return
    assets = {a["asset_id"]: a for a in (workspace or {}).get("assets", [])}
    widths = [0.65, 1.5, 1, 1.15, 1.1, 0.85]
    for col, label in zip(
        st.columns(widths),
        [
            "Lỗ hổng",
            "Tài sản liên quan",
            "Mức độ",
            "Giảm rủi ro",
            "Ưu tiên",
            "Hành động",
        ],
    ):
        col.caption(label)
    for row in rows:
        with st.container(key=prefix + "_row_" + row["finding_id"]):
            cols = st.columns(widths, vertical_alignment="center")
            cols[0].markdown(
                '<span class="rd-finding">'
                + html.escape(row["finding_id"])
                + "</span>",
                unsafe_allow_html=True,
            )
            asset = assets.get(row["asset_id"], {})
            name = asset.get("name", row["asset_id"])
            if name == row["asset_id"]:
                name = {
                    "web": "Máy chủ web",
                    "application": "Máy ứng dụng",
                    "database": "Cơ sở dữ liệu",
                }.get(asset.get("asset_type"), name)
            cols[1].write(name)
            cvss = row["cvss_score"]
            severity = (
                "Chưa rõ"
                if cvss is None
                else "Nghiêm trọng"
                if cvss >= 9
                else "Cao"
                if cvss >= 7
                else "Trung bình"
                if cvss >= 4
                else "Thấp"
            )
            cols[2].markdown(
                '<span class="rd-severity">' + severity + "</span>",
                unsafe_allow_html=True,
            )
            cols[2].caption("CVSS " + ("—" if cvss is None else f"{cvss:.1f}"))
            cols[3].write(f"{row['remediation_impact']:.4f}")
            peers = sum(x["priority_rank"] == row["priority_rank"] for x in rows)
            label = (
                "Không giảm thêm"
                if row["remediation_impact"] == 0
                else ("Đồng hạng " if peers > 1 else "Hạng ")
                + str(row["priority_rank"])
            )
            cols[4].write(label)
            cols[5].button(
                "Thử vá",
                key=prefix + "_patch_" + row["finding_id"],
                on_click=set_patch,
                args=(row["finding_id"],),
            )
    st.caption("Thử vá là mô phỏng trên dữ liệu, chưa cài bản vá lên máy thật.")


def overview(workspace, envelope, reason, before=None):
    cols = st.columns(3)
    cols[0].metric("Tài sản", len(workspace["assets"]))
    cols[1].metric("Phát hiện lỗ hổng", len(workspace["findings"]))
    cols[2].metric(
        "Đường tới tài sản đích",
        len(envelope["report"]["graph"]["paths"]) if envelope else "Chưa tính",
    )
    st.write("")
    with st.container(border=True):
        left, right = st.columns([3, 1])
        left.subheader("Việc nên xem trước", anchor=False)
        right.button(
            "Mở phân tích →", on_click=go, args=("Phân tích",), width="stretch"
        )
        if envelope:
            ranking(envelope, "overview", workspace)
        else:
            st.info(reason)
            st.button("Chuẩn bị dữ liệu", on_click=go, args=("Dữ liệu",))
    if envelope:
        with st.container(border=True):
            st.subheader("Sơ đồ đường tấn công", anchor=False)
            render_graph(workspace, envelope, before, compact=True)
            with st.expander("Danh sách đường và bằng chứng"):
                path_view(envelope)
        st.caption(
            "Dữ liệu giả lập được ghi rõ. Điểm 0 không xác nhận toàn hệ thống an toàn."
        )
    else:
        with st.expander("Dữ liệu cần có để phân tích"):
            for key, label in [
                ("assets", "Tài sản"),
                ("services", "Dịch vụ"),
                ("findings", "Phát hiện"),
                ("connections", "Kết nối"),
                ("exploit_rules", "Điều kiện khai thác"),
            ]:
                st.write(f"{label}: {len(workspace[key])} bản ghi")


def inventory(workspace, scope_id):
    if scope_id == "manual":
        with st.expander("Thêm tài sản", expanded=not workspace["assets"]):
            asset_form()
    else:
        st.caption(
            "Snapshot đang xem chỉ đọc. Chọn Hồ sơ của tôi ở thanh bên để thêm hoặc sửa tài sản."
        )
    if st.session_state.get("enterprise-notice"):
        st.success(st.session_state.pop("enterprise-notice"))
    if workspace["assets"]:
        st.dataframe(
            [
                {
                    "Tài sản": a["asset_id"],
                    "Tên": a["name"],
                    "Loại": a["asset_type"],
                    "Quan trọng / 5": a["criticality"],
                    "Mở Internet": a["internet_facing"],
                    "Dữ liệu nhạy cảm": a["sensitive_data"],
                }
                for a in workspace["assets"]
            ],
            hide_index=True,
            width="stretch",
        )
        if scope_id == "manual":
            records = records_of("enterprise_asset")
            chosen = st.selectbox(
                "Tài sản cần chỉnh sửa", records, format_func=lambda r: r["title"]
            )
            with st.expander("Chỉnh sửa tài sản đã chọn"):
                asset_form(chosen)
    else:
        st.info("Chưa có tài sản trong hồ sơ. Bắt đầu bằng Thêm tài sản.")
    with st.expander("Dịch vụ và kết nối"):
        if workspace["services"]:
            st.dataframe(workspace["services"], hide_index=True, width="stretch")
        if workspace["connections"]:
            st.dataframe(workspace["connections"], hide_index=True, width="stretch")
        if scope_id == "manual" and workspace["assets"]:
            names = {a["asset_id"]: a["name"] for a in workspace["assets"]}
            with st.form("rd_connection"):
                source = st.selectbox(
                    "Từ",
                    ["INTERNET", *names],
                    format_func=lambda x: names.get(x, "Internet"),
                )
                target = st.selectbox("Đến", list(names), format_func=names.get)
                allowed = st.selectbox(
                    "Quyền kết nối",
                    [True, False],
                    format_func=lambda x: "Cho phép" if x else "Chặn",
                )
                evidence = st.text_input(
                    "Nguồn xác nhận",
                    placeholder="Cấu hình firewall / quản trị viên xác nhận",
                )
                if st.form_submit_button("Lưu kết nối"):
                    try:
                        save_declared_connection(source, target, allowed, evidence)
                        st.rerun()
                    except ValueError as error:
                        st.error(str(error))
        st.caption(
            "Kết nối mạng không đồng nghĩa có thể khai thác. Điều kiện tấn công được kiểm tra riêng."
        )
    with st.expander("Tải bản nháp tài sản"):
        st.download_button(
            "Tải JSON bản nháp",
            json.dumps(workspace, ensure_ascii=False, indent=2),
            "asset-draft.json",
            "application/json",
        )


def data_page(workspace):
    with st.container(border=True):
        st.subheader("Nhập bộ dữ liệu", anchor=False)
        uploaded = st.file_uploader("Chọn dataset.json", type="json", key="rd_upload")
        st.caption(
            "Dữ liệu được SV1 kiểm tra cấu trúc và liên kết trước khi lưu. Không tự chạy scanner."
        )
        if st.button(
            "Kiểm tra và lưu dataset", disabled=uploaded is None, type="primary"
        ):
            try:
                record_id = store_input_dataset(uploaded.getvalue())
                st.session_state["rd_next_scope"] = record_id
                st.session_state["rd_notice"] = (
                    "Đã kiểm tra và lưu dataset. Đang xem đúng bộ dữ liệu vừa nhập."
                )
                st.rerun()
            except ValueError as error:
                st.error(str(error))
        if st.button("Lưu dataset mẫu SV1"):
            st.session_state["rd_next_scope"] = store_input_dataset()
            st.rerun()
    if workspace["dataset"]:
        st.subheader("Dữ liệu đang xem", anchor=False)
        st.caption(workspace["dataset"]["dataset_id"])
        if workspace["findings"]:
            st.dataframe(
                [
                    {
                        k: f[k]
                        for k in [
                            "finding_id",
                            "asset_id",
                            "vulnerability_id",
                            "cvss_score",
                            "epss_probability",
                            "is_kev",
                        ]
                    }
                    for f in workspace["findings"]
                ],
                hide_index=True,
                width="stretch",
            )
        st.download_button(
            "Tải dataset đã kiểm tra",
            json.dumps(workspace["dataset"], ensure_ascii=False, indent=2),
            "dataset.json",
            "application/json",
        )
        with st.expander("Xem dữ liệu gốc và bằng chứng"):
            st.json(workspace["dataset"])
    else:
        st.info(
            "Hồ sơ thủ công chưa có kết quả quét. Nhập dataset đầy đủ hoặc chọn một kịch bản mẫu ở thanh bên."
        )


def analysis_page(workspace, envelope, reason, before):
    dataset = workspace.get("dataset")
    if not dataset:
        st.info(reason)
        render_graph(workspace)
        return
    targets = st.session_state.get(
        "rd_targets_" + workspace["fingerprint"], workspace["default_targets"]
    )
    selected = st.session_state.get("rd_patch_ids", [])
    if targets != workspace["active_targets"] or selected != st.session_state.get(
        "rd_patch_ids", []
    ):
        st.rerun()
    if st.session_state.get("rd_patch_ids"):
        st.button("Bỏ mô phỏng", on_click=set_patch, args=(None,))
    if not envelope:
        st.info(reason)
        render_graph(workspace)
        return
    analysis = envelope["report"]["analysis"]
    cols = st.columns(4)
    cols[0].metric("Tài sản", len(workspace["assets"]))
    cols[1].metric("Lỗ hổng", len(workspace["findings"]))
    cols[2].metric("Đường tới đích", len(envelope["report"]["graph"]["paths"]))
    cols[3].metric("Điểm rủi ro", f"{analysis['risk_before']:.2f}".replace(".", ","))
    with st.container(border=True, key="rd_graph_panel"):
        st.subheader("Đường tấn công", anchor=False)
        render_graph(workspace, envelope, before)
    with st.container(border=True, key="rd_ranking_panel"):
        st.subheader("Ưu tiên khắc phục", anchor=False)
        ranking(envelope, "analysis", workspace)
    with st.expander("Chọn tài sản đích và mô phỏng vá", expanded=False):
        targets = st.multiselect(
            "Tài sản cần bảo vệ",
            [a["asset_id"] for a in workspace["assets"]],
            default=workspace["default_targets"],
            key="rd_targets_" + workspace["fingerprint"],
        )

        def update_patches():
            st.session_state["rd_patch_ids"] = list(st.session_state["rd_patch_widget"])

        selected = st.multiselect(
            "Mô phỏng vá một hoặc nhiều findings",
            [f["finding_id"] for f in workspace["findings"]],
            default=st.session_state.get("rd_patch_ids", []),
            key="rd_patch_widget",
            on_change=update_patches,
        )
    with st.container(border=True):
        st.subheader("Đường tới tài sản đích", anchor=False)
        path_view(envelope)
    with st.expander("So sánh phương án và cách xếp hạng"):
        st.dataframe(
            [
                {
                    "Trạng thái": label,
                    "Rủi ro": env["report"]["analysis"]["risk_before"],
                    "Đường tới đích": len(env["report"]["graph"]["paths"]),
                }
                for label, env in [
                    ("Chưa vá", before),
                    ("Phương án hiện tại", envelope),
                ]
            ],
            hide_index=True,
            width="stretch",
        )
        st.caption("Theo CVSS: " + " → ".join(analysis["baseline_cvss_order"]))
        st.json(envelope["report"]["details"]["baselines"])
    with st.expander("Giả định, giới hạn và bằng chứng kỹ thuật"):
        st.write(envelope["report"]["details"]["assumptions"])
        st.write(analysis["warnings"])
        st.json(envelope["report"]["graph"])


def reports_page(envelope):
    if envelope:
        with st.container(border=True):
            st.subheader("Báo cáo đang xem", anchor=False)
            analysis = envelope["report"]["analysis"]
            st.caption(
                f"{analysis['dataset_id']} · Đích: {', '.join(analysis['target_asset_ids'])}"
            )
            cols = st.columns(3)
            if cols[0].button("Lưu báo cáo", type="primary"):
                save_record("analysis", "Phân tích " + analysis["dataset_id"], envelope)
                st.success("Đã lưu kết quả và bằng chứng của phương án này.")
            cols[1].download_button(
                "Xuất JSON", export_json(envelope), "analysis.json", "application/json"
            )
            cols[2].download_button(
                "Xuất Markdown",
                export_markdown(envelope),
                "analysis.md",
                "text/markdown",
            )
    else:
        st.info(
            "Chưa có kết quả phân tích cho phạm vi hiện tại. Lịch sử đã lưu vẫn xem được bên dưới."
        )
    st.subheader("Lịch sử đã lưu", anchor=False)
    kind = st.selectbox(
        "Loại bản ghi",
        [
            "analysis",
            "dashboard_explanation",
            "input_dataset",
            "explanation",
            "dataset_explanation",
        ],
        format_func=lambda x: {
            "analysis": "Báo cáo phân tích",
            "dashboard_explanation": "AI trên dashboard",
            "input_dataset": "Dataset đã nhập",
            "explanation": "Giải thích báo cáo cũ",
            "dataset_explanation": "Giải thích dữ liệu SV1",
        }[x],
    )
    rows = list_records(kind)
    if rows:
        chosen = st.selectbox(
            "Chọn bản ghi",
            rows,
            format_func=lambda r: r["title"] + " · " + r["created_at"],
        )
        payload = get_record(chosen["id"])["payload"]
        if kind == "dashboard_explanation":
            st.markdown(payload["explanation"]["text"])
            st.caption("Model: " + payload["explanation"]["model_id"])
        with st.expander("Nội dung bản ghi", expanded=kind != "dashboard_explanation"):
            st.json(payload)
    else:
        st.caption("Chưa có bản ghi thuộc loại này.")
    with st.expander("Dữ liệu website và bản nháp phiên bản cũ"):
        render_legacy()
