import pytest
from streamlit.testing.v1 import AppTest

from sv3_risk.errors import IncompletePathSearchError
from sv4_app_llm.apps.risk_analysis.service import PROJECT_ROOT, run_analysis


def test_real_sv2_risk_group_patch_and_no_input_mutation():
    folder = PROJECT_ROOT / "sv3_risk/data/scenarios/diamond"
    original = (folder / "dataset.json").read_bytes()
    before = run_analysis(folder, [], ["DB01"])
    after = run_analysis(folder, ["F01"], ["DB01"])
    assert len(before["graph"]["paths"]) == 2
    assert before["analysis"]["risk_before"] == pytest.approx(41.2825)
    assert after["analysis"]["risk_before"] == 0
    assert after["graph"]["paths"] == []
    assert "F01" not in [r["finding_id"] for r in after["analysis"]["results"]]
    assert (folder / "dataset.json").read_bytes() == original


def test_incomplete_graph_is_not_displayed_as_zero_risk():
    with pytest.raises(IncompletePathSearchError):
        run_analysis(
            PROJECT_ROOT / "sv3_risk/data/scenarios/diamond", [], ["DB01"], max_paths=1
        )


def test_streamlit_real_pipeline_and_patch_selection():
    app = AppTest.from_file(
        str(PROJECT_ROOT / "sv4_app_llm/apps/risk_analysis/app.py"), default_timeout=20
    ).run()
    assert not app.exception
    app.selectbox[0].select("Kịch bản diamond").run()
    assert not app.exception
    assert app.metric[0].value == "41.2825"
    app.multiselect[1].select("F01").run()
    assert not app.exception
    assert app.metric[0].value == "0.0000"
    assert app.metric[1].value == "0"


