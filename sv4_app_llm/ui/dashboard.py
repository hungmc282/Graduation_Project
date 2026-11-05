"""Compact workspace dashboard: inventory, data, real analysis, reports and local AI."""

import hashlib
import json
import sqlite3

import streamlit as st

from common.errors import AppError
from sv1_data.service import load_dataset
from sv3_risk.errors import RiskContractError
from sv4_app_llm.config import PROJECT_ROOT
from sv4_app_llm.services.analysis import analyze_dataset
from sv4_app_llm.services.enterprise import load_workspace, records_of
from sv4_app_llm.ui.assistant import render_assistant
from sv4_app_llm.ui.compact_pages import (
    analysis_page,
    data_page,
    inventory,
    overview,
    reports_page,
)
from sv4_app_llm.ui.theme import apply_theme

PAGES = ["Tổng quan", "Tài sản", "Dữ liệu", "Phân tích", "Báo cáo"]
SAMPLES = {
    "sample-chain": ("Mẫu · Một đường tới DB", "chain"),
    "sample-diamond": ("Mẫu · Hai đường tới DB", "diamond"),
    "sample-multi-target": ("Mẫu · Nhiều tài sản đích", "multi-target"),
}


@st.cache_data(show_spinner=False, max_entries=32)
def cached_analysis(payload, targets, patched):
    return analyze_dataset(json.loads(payload), targets, patched)


def get_workspace(scope):
    if scope in SAMPLES:
        folder = PROJECT_ROOT / "sv3_risk/data/scenarios" / SAMPLES[scope][1]
        dataset = load_dataset(folder).model_dump(mode="json")
        config = json.loads((folder / "config.json").read_text())
        workspace = {
            "source_label": dataset["dataset_id"],
            "source": dataset["source"],
            "dataset": dataset,
            "contexts": {},
            **{
                key: dataset[key]
                for key in (
                    "assets",
                    "services",
                    "findings",
                    "connections",
                    "exploit_rules",
                )
            },
            "default_targets": config["graph_config"]["target_asset_ids"],
        }
    else:
        workspace = load_workspace(scope)
        workspace["default_targets"] = [
            a["asset_id"] for a in workspace["assets"] if a["criticality"] == 5
        ]
    workspace["fingerprint"] = hashlib.sha256(
        json.dumps(workspace, sort_keys=True).encode()
    ).hexdigest()[:16]
    return workspace


def main():
    st.set_page_config(
        page_title="RiskDesk · Ưu tiên khắc phục", page_icon="🛡️", layout="wide"
    )
    apply_theme()
    st.session_state.setdefault("rd_ai_open", True)
    scope_bar = st.container(key="rd_scope_bar")
    with st.sidebar:
        st.markdown(
            '<div class="rd-brand"><span>R</span>RiskDesk</div>', unsafe_allow_html=True
        )
        labels = {
            **{key: value[0] for key, value in SAMPLES.items()},
            "manual": "Hồ sơ của tôi",
        }
        labels.update({r["id"]: r["title"] for r in records_of("input_dataset")})
        if "rd_next_scope" in st.session_state:
            st.session_state["rd_scope"] = st.session_state.pop("rd_next_scope")
        if st.session_state.get("rd_scope") not in labels:
            st.session_state["rd_scope"] = "sample-chain"
        with scope_bar:
            scope = st.selectbox(
                "Bộ dữ liệu",
                list(labels),
                format_func=labels.get,
                key="rd_scope",
                label_visibility="collapsed",
            )
        st.caption("KHÔNG GIAN LÀM VIỆC")
        page = st.radio("Chức năng", PAGES, key="rd_page", label_visibility="collapsed")
        st.divider()
        st.caption("Mẫu là dữ liệu giả lập. Hồ sơ của bạn được lưu riêng trên máy.")
    try:
        workspace = get_workspace(scope)
        token = scope + workspace["fingerprint"]
        if st.session_state.get("rd_scope_token") != token:
            st.session_state["rd_scope_token"] = token
            st.session_state["rd_patch_ids"] = []
            st.session_state.pop("rd_patch_widget", None)
        title = {
            "Tổng quan": "Tổng quan",
            "Tài sản": "Tài sản",
            "Dữ liệu": "Dữ liệu đầu vào",
            "Phân tích": "Phân tích rủi ro",
            "Báo cáo": "Báo cáo & lịch sử",
        }[page]
        heading, ai_button = st.columns([5, 1], vertical_alignment="center")
        with heading:
            st.title(title)

        if ai_button.button(
            "✦ Hỏi AI",
            width="stretch",
            key="rd_ai_toggle",
        ):
            st.session_state["rd_ai_open"] = not st.session_state.get(
                "rd_ai_open", False
            )
            st.rerun()
        source = (
            "Dữ liệu giả lập"
            if workspace["source"] == "synthetic"
            else "Hồ sơ tự khai báo"
            if scope == "manual"
            else "Dataset đã nhập"
        )
        st.markdown(
            '<span class="rd-source">' + source + "</span>", unsafe_allow_html=True
        )

        if st.session_state.get("rd_notice"):
            st.success(st.session_state.pop("rd_notice"))
        key = "rd_targets_" + workspace["fingerprint"]
        targets = st.session_state.get(key, workspace["default_targets"])
        workspace["active_targets"] = list(targets)
        envelope = before = None
        reason = "Hồ sơ thủ công chưa có kết quả quét và điều kiện khai thác. Nhập dataset đầy đủ hoặc chọn mẫu để thử."
        if workspace.get("dataset"):
            if not targets:
                reason = "Chọn ít nhất một tài sản cần bảo vệ trong Phân tích."
            else:
                try:
                    payload = json.dumps(workspace["dataset"], sort_keys=True)
                    before = cached_analysis(payload, tuple(targets), ())
                    patches = tuple(sorted(st.session_state.get("rd_patch_ids", [])))
                    envelope = (
                        cached_analysis(payload, tuple(targets), patches)
                        if patches
                        else before
                    )
                except (AppError, RiskContractError, ValueError) as error:
                    reason = "Chưa phân tích được bộ dữ liệu này: " + str(error)
        if st.session_state.get("rd_patch_ids"):
            st.caption(
                "Đang mô phỏng vá: "
                + ", ".join(st.session_state["rd_patch_ids"])
                + " · Dữ liệu gốc được giữ nguyên."
            )
        if st.session_state.get("rd_ai_open"):
            content, assistant = st.columns([3.3, 1.05], gap="medium")
        else:
            content = st.container()
            assistant = None
        with content:
            if page == "Tổng quan":
                overview(workspace, envelope, reason, before)
            elif page == "Tài sản":
                inventory(workspace, scope)
            elif page == "Dữ liệu":
                data_page(workspace)
            elif page == "Phân tích":
                analysis_page(workspace, envelope, reason, before)
            else:
                reports_page(envelope)
        if assistant is not None:
            with assistant:
                render_assistant(workspace, envelope, before)
    except (AppError, RiskContractError, ValueError, OSError, sqlite3.Error) as error:
        st.error("Không thể đọc hoặc xử lý dữ liệu: " + str(error))


if __name__ == "__main__":
    main()
