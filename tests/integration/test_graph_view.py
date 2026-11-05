"""Graph drawing must reflect actual engine paths, not infer exploits from connectivity."""

import copy

import pytest
from streamlit.testing.v1 import AppTest

from sv1_data.service import load_dataset
from sv4_app_llm.config import PROJECT_ROOT
from sv4_app_llm.services.analysis import analyze_dataset
from sv4_app_llm.storage import repository
from sv4_app_llm.ui.graph_view import asset_labels, attack_dot, topology_dot


def case(name="chain", patched=()):
    data = load_dataset(PROJECT_ROOT / "sv3_risk/data/scenarios" / name).model_dump(
        mode="json"
    )
    before = analyze_dataset(data, ["DB01"])["report"]["graph"]
    after = analyze_dataset(data, ["DB01"], patched)["report"]["graph"]
    return data, before, after


def test_attack_graph_only_draws_target_path_rules():
    data, before, _ = case()
    dot = attack_dot(data, before)
    assert "rule-R01" in dot and "rule-R02" in dot and "rule-R03" in dot
    assert "rule-R04" not in dot  # Test machine is not a target-reaching attack path.
    assert "asset-TEST01" in dot
    assert "TÀI SẢN ĐÍCH" in dot


def test_after_f01_graph_marks_cut_and_unreachable_downstream():
    data, before, after = case(patched=("F01",))
    original = copy.deepcopy(data)
    dot = attack_dot(data, after, before)
    assert after["paths"] == []
    cut = next(line for line in dot.splitlines() if "rule-R01" in line)
    downstream = next(line for line in dot.splitlines() if "rule-R02" in line)
    assert "Đã chặn do mô phỏng vá" in cut and 'style="dashed"' in cut
    assert "Không còn trên đường tới đích" in downstream
    assert data == original


def test_diamond_remaining_route_stays_active():
    data, before, after = case("diamond", ("F02",))
    dot = attack_dot(data, after, before)
    assert len(after["paths"]) == 1
    alternate = next(line for line in dot.splitlines() if "rule-R05" in line)
    assert 'style="solid"' in alternate
    direct = next(line for line in dot.splitlines() if "rule-R02" in line)
    assert "Đã chặn do mô phỏng vá" in direct


def test_topology_does_not_invent_attack_rules_and_escapes_labels():
    data, _, _ = case()
    data["assets"][0]["name"] = 'Web "special"\nserver'
    data["connections"][0]["allowed"] = False
    dot = topology_dot(data)
    assert 'label="Chặn"' in dot and 'style="dashed"' in dot
    assert '\\"special\\"' in dot
    assert "rule-R01" not in dot


def test_mismatched_target_scope_is_rejected():
    data, before, after = case()
    after["target_asset_ids"] = ["TEST01"]
    with pytest.raises(ValueError, match="phạm vi"):
        attack_dot(data, after, before)


def test_graph_is_present_in_both_dashboard_and_analysis(tmp_path, monkeypatch):
    connection = repository.connection
    monkeypatch.setattr(
        repository,
        "connection",
        lambda path=None: connection(tmp_path / "store.sqlite3"),
    )
    app = AppTest.from_file(
        str(PROJECT_ROOT / "sv4_app_llm/app.py"), default_timeout=20
    ).run()
    assert not app.exception
    assert len(app.get("graphviz_chart")) == 1
    app.button(key="overview_patch_F01").click().run()
    assert not app.exception
    assert "Đã chặn do mô phỏng vá" in app.get("graphviz_chart")[0].proto.spec
    app.radio(key="rd_page").set_value("Phân tích").run()
    assert not app.exception
    assert len(app.get("graphviz_chart")) == 1
    app.radio(key="rd_graph_mode").set_value("Kết nối mạng").run()
    assert not app.exception
    assert 'label="Cho phép"' in app.get("graphviz_chart")[0].proto.spec
    assert "rule-R01" not in app.get("graphviz_chart")[0].proto.spec


def test_compact_labels_keep_identifiers_out_of_visible_labels():
    data, before, _ = case()
    original = copy.deepcopy(data)
    dot = topology_dot(data)
    assert 'tooltip="C01"' in dot
    assert 'label="C01' not in dot
    assert 'tooltip="WEB01"' in dot
    assert "\\nWEB01" not in dot
    attack = attack_dot(data, before)
    assert ">F01</FONT>" in attack
    assert 'HEIGHT="18"' in attack
    assert 'label="R01' not in attack
    assert data == original


def test_duplicate_names_use_address_or_stable_numbers():
    workspace = {
        "assets": [
            {"asset_id": "ASSET-b", "name": "Máy chủ"},
            {"asset_id": "ASSET-a", "name": "Máy chủ"},
        ],
        "contexts": {
            "ASSET-a": {"address": "192.168.1.10"},
            "ASSET-b": {"address": "192.168.1.11"},
        },
    }
    assert asset_labels(workspace) == {
        "ASSET-a": "Máy chủ · 192.168.1.10",
        "ASSET-b": "Máy chủ · 192.168.1.11",
    }
    workspace["contexts"] = {}
    assert asset_labels(workspace) == {
        "ASSET-a": "Máy chủ · 1",
        "ASSET-b": "Máy chủ · 2",
    }


def test_theme_preserves_original_graph_node_shapes():
    data, before, _ = case()
    dot = attack_dot(data, before)
    nodes = {
        aid: next(line for line in dot.splitlines() if f'id="asset-{aid}"' in line)
        for aid in ("INTERNET", "WEB01", "APP01", "DB01")
    }
    assert "shape=oval" in nodes["INTERNET"]
    assert "shape=box" in nodes["WEB01"]
    assert "shape=box" in nodes["APP01"]
    assert "shape=doubleoctagon" in nodes["DB01"]
