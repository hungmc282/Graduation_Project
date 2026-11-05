"""Glass presentation must preserve supplied nodes, edges and hostile text safely."""

from sv4_app_llm.ui.glass_graph import glass_svg


def test_glass_graph_has_only_supplied_edges_and_rounded_badges():
    assets = [{"asset_id": "WEB", "name": "Web", "asset_type": "web_server"}]
    edges = [
        {
            "id": "R1",
            "source": "INTERNET",
            "target": "WEB",
            "label": "F01",
            "finding": True,
        }
    ]
    svg = glass_svg(assets, edges, entries=["INTERNET"])
    assert svg.count("data-edge=") == 1
    assert 'data-edge="R1"' in svg and 'data-asset="WEB"' in svg
    assert 'rx="12.5"' in svg and ">F01</text>" in svg
    assert 'rx="23"' in svg


def test_glass_graph_handles_cycles_disconnected_assets_and_escapes_text():
    assets = [
        {"asset_id": aid, "name": '<script>alert("x")</script>', "asset_type": "server"}
        for aid in ["A", "B", "C"]
    ]
    edges = [
        {"id": str(i), "source": a, "target": b, "label": "<unsafe>", "blocked": True}
        for i, (a, b) in enumerate([("A", "B"), ("B", "A")])
    ]
    svg = glass_svg(assets, edges)
    assert svg.count("data-asset=") == 3
    assert svg.count("data-edge=") == 2
    assert "<script>" not in svg and "&lt;unsafe&gt;" in svg
    assert 'stroke-dasharray="6 5"' in svg
