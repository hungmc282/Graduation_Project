"""Regression: additional impact zero must never negate the effect of F01."""

import copy
import json
from unittest.mock import patch

import pytest

from sv1_data.service import load_dataset
from sv4_app_llm.config import PROJECT_ROOT
from sv4_app_llm.services.analysis import analyze_dataset
from sv4_app_llm.services.assistant import explain_context
from sv4_app_llm.services.assistant_facts import analysis_facts, render_fact_selection


def setup_case(name="chain", patched=("F01",)):
    data = load_dataset(PROJECT_ROOT / "sv3_risk/data/scenarios" / name).model_dump(
        mode="json"
    )
    workspace = {
        "dataset": data,
        "source": data["source"],
        "assets": data["assets"],
        "connections": data["connections"],
        "contexts": {},
    }
    before = analyze_dataset(data, ["DB01"])
    after = analyze_dataset(data, ["DB01"], patched)
    return workspace, before, after


@pytest.mark.parametrize("patched", [("F01",), ("F02",), ("F01", "F02")])
def test_patch_effect_is_separate_from_zero_additional_impact(patched):
    w, before, after = setup_case(patched=patched)
    evidence = analysis_facts(w, after, before)
    c = evidence["comparison"]
    assert c["before_patching"] == {
        "risk": pytest.approx(41.2825),
        "target_path_count": 1,
    }
    assert c["after_current_patch"] == {"risk": 0, "target_path_count": 0}
    assert c["risk_reduction_from_current_patch"] == pytest.approx(41.2825)
    assert c["paths_blocked_by_current_patch"] == 1
    assert c["all_target_paths_blocked"] is True
    # Even when AI selects only the zero-additional-impact fact, the actual patch result comes first.
    text, order = render_fact_selection('{"fact_ids":["additional_actions"]}', evidence)
    assert order[:2] == ["patch_effect", "current_state"]
    assert "từ 1 xuống 0" in text
    assert "giảm 41,2825 điểm" in text
    assert "không phủ nhận hiệu quả" in text


def test_patching_f03_does_not_falsely_claim_db_protection():
    w, before, after = setup_case(patched=("F03",))
    c = analysis_facts(w, after, before)["comparison"]
    assert c["after_current_patch"]["target_path_count"] == 1
    assert c["risk_reduction_from_current_patch"] == 0
    assert c["all_target_paths_blocked"] is False


def test_diamond_partial_patch_reports_remaining_path():
    w, before, after = setup_case("diamond", ("F02",))
    evidence = analysis_facts(w, after, before)
    c = evidence["comparison"]
    assert c["before_patching"]["target_path_count"] == 2
    assert c["after_current_patch"]["target_path_count"] == 1
    assert c["after_current_patch"]["risk"] == pytest.approx(23.59)
    assert c["all_target_paths_blocked"] is False
    assert "chặn toàn bộ" not in evidence["facts"]["patch_effect"]


@pytest.mark.parametrize(
    "raw",
    [
        "Vá F01 không làm giảm rủi ro vì F02 và F03 vẫn chưa được xử lý.",
        '{"fact_ids":["fabricated_path"]}',
        '{"fact_ids":["patch_effect"],"text":"Vẫn còn đường tới DB"}',
        '{"fact_ids":[]}',
        '{"fact_ids":["patch_effect","patch_effect"]}',
    ],
)
def test_unverified_model_claims_are_rejected(raw):
    w, before, after = setup_case()
    with pytest.raises(ValueError):
        render_fact_selection(raw, analysis_facts(w, after, before))


def test_wrong_baseline_is_not_compared():
    w, before, after = setup_case()
    wrong = copy.deepcopy(before)
    wrong["report"]["analysis"]["config_hash"] = "different"
    with pytest.raises(ValueError, match="không khớp"):
        analysis_facts(w, after, wrong)


def test_real_context_auto_reconstructs_unpatched_baseline():
    w, _, after = setup_case()
    with patch(
        "sv4_app_llm.services.assistant.ask_ollama",
        return_value=(
            json.dumps({"fact_ids": ["patch_effect", "additional_actions"]}),
            "test-model",
        ),
    ) as call:
        answer = explain_context(
            w, "Phương án vá hiện tại thay đổi gì?", after, model="test-model"
        )
    assert answer["validation_status"] == "fact_ids_checked"
    assert answer["comparison"]["paths_blocked_by_current_patch"] == 1
    assert "giảm 41,2825 điểm" in answer["text"]
    assert call.call_args.kwargs["response_schema"]["additionalProperties"] is False
    assert (
        "analysis" not in call.call_args.args[1]
    )  # No ambiguous risk_before / reason-code dump.
