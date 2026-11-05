"""Compact UI, real risk calculations, and correctly scoped AI without network."""

import copy
from unittest.mock import patch

import pytest
from streamlit.testing.v1 import AppTest

from sv1_data.service import load_dataset
from sv4_app_llm.config import PROJECT_ROOT
from sv4_app_llm.services.analysis import analyze_dataset
from sv4_app_llm.services.assistant import context_id, explain_context
from sv4_app_llm.storage import repository


def workspace():
    dataset = load_dataset(PROJECT_ROOT / "sv3_risk/data/scenarios/chain").model_dump(
        mode="json"
    )
    return {
        "dataset": dataset,
        "source": dataset["source"],
        "assets": dataset["assets"],
        "connections": dataset["connections"],
        "contexts": {},
    }


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    original = repository.connection
    monkeypatch.setattr(
        repository, "connection", lambda path=None: original(tmp_path / "store.sqlite3")
    )


def test_live_json_snapshot_ranking_patch_and_no_mutation():
    w = workspace()
    original = copy.deepcopy(w["dataset"])
    before = analyze_dataset(w["dataset"], ["DB01"])
    after = analyze_dataset(w["dataset"], ["DB01"], ["F01"])
    assert before["report"]["analysis"]["risk_before"] == pytest.approx(41.2825)
    assert [r["priority_rank"] for r in before["report"]["analysis"]["results"]] == [
        1,
        1,
        2,
    ]
    assert after["report"]["analysis"]["risk_before"] == 0
    assert after["report"]["graph"]["paths"] == []
    assert w["dataset"] == original


def test_missing_exploit_rules_not_reported_as_safe():
    data = workspace()["dataset"]
    data["exploit_rules"] = []
    with pytest.raises(ValueError, match="Chưa có điều kiện"):
        analyze_dataset(data, ["DB01"])


def test_ai_receives_exact_current_analysis_and_invalidates_previous_context():
    w = workspace()
    before = analyze_dataset(w["dataset"], ["DB01"])
    after = analyze_dataset(w["dataset"], ["DB01"], ["F02"])
    with patch(
        "sv4_app_llm.services.assistant.ask_ollama",
        return_value=('{"fact_ids":["patch_effect","current_state"]}', "local-test"),
    ) as call:
        answer = explain_context(w, "Sau vá thay đổi gì?", after, model="local-test")
    sent = call.call_args.args[1]
    assert sent["comparison"]["patched_finding_ids"] == ["F02"]
    assert sent["comparison"]["after_current_patch"]["risk"] == 0
    assert answer["analysis_ids"] == [after["report"]["analysis"]["analysis_id"]]
    assert context_id(w, before, "local-test") != answer["context_id"]
    assert context_id(w, after, "other-model") != answer["context_id"]


def test_input_only_ai_never_receives_demo_analysis():
    w = workspace()
    with patch(
        "sv4_app_llm.services.assistant.ask_ollama",
        return_value=("Thông tin thiếu", "test"),
    ) as call:
        answer = explain_context(w, "Thiếu gì?", model="test")
    assert call.call_args.args[1]["analysis"] is None
    assert call.call_args.args[1]["analysis_status"] == "not_run"
    assert answer["scope"] == "input_only"
    with pytest.raises(ValueError):
        explain_context(w, " ", model="test")


def test_compact_app_patch_scope_change_and_all_pages(isolated_db):
    app = AppTest.from_file(
        str(PROJECT_ROOT / "sv4_app_llm/app.py"), default_timeout=20
    ).run()
    assert not app.exception and not app.error
    assert app.metric[2].value == "1"
    app.button(key="overview_patch_F01").click().run()
    assert not app.exception
    assert app.metric[2].value == "0"
    app.radio(key="rd_page").set_value("Phân tích").run()
    assert not app.exception and not app.error
    assert app.metric[3].value == "0,00"
    assert app.multiselect(key="rd_patch_widget").value == ["F01"]
    app.multiselect(key="rd_patch_widget").set_value(["F03"]).run()
    assert not app.exception
    assert app.metric[3].value == "41,28"
    app.selectbox(key="rd_scope").set_value("sample-diamond").run()
    assert not app.exception
    assert app.multiselect(key="rd_patch_widget").value == []
    assert app.metric[2].value == "2"
    for page in ["Tài sản", "Dữ liệu", "Báo cáo", "Tổng quan"]:
        app.radio(key="rd_page").set_value(page).run()
        assert not app.exception and not app.error
    app.selectbox(key="rd_scope").set_value("manual").run()
    assert not app.exception
    assert app.metric[2].value == "Chưa tính"


def test_ai_only_calls_when_submitted_and_clears_stale_answer(isolated_db):
    with (
        patch("sv4_app_llm.ui.assistant.available_models", return_value=["test-model"]),
        patch(
            "sv4_app_llm.services.assistant.ask_ollama",
            return_value=(
                '{"fact_ids":["candidate:F01","candidate:F02"]}',
                "test-model",
            ),
        ) as call,
    ):
        app = AppTest.from_file(
            str(PROJECT_ROOT / "sv4_app_llm/app.py"), default_timeout=20
        ).run()
        if not app.session_state["rd_ai_open"]:
            app.button(key="rd_ai_toggle").click().run()
        assert not app.exception
        call.assert_not_called()
        next(b for b in app.button if b.label == "Gọi AI giải thích").click().run()
        assert not app.exception and not app.error
        assert call.call_count == 1
        assert any(
            "F01 trên WEB01 được xếp đồng hạng 1" in m.value for m in app.markdown
        )
        app.button(key="overview_patch_F01").click().run()
        assert not app.exception
        assert not any(
            "F01 trên WEB01 được xếp đồng hạng 1" in m.value for m in app.markdown
        )
        assert call.call_count == 1
        app.selectbox(key="rd_scope").set_value("manual").run()
        assert not app.exception
