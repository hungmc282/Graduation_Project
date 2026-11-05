"""Draw engine-returned target paths separately from declared network connections."""

import base64
import html
import json

import streamlit as st

from sv4_app_llm.ui.glass_graph import glass_svg


def quoted(value):
    return json.dumps(str(value), ensure_ascii=False)


def edge_label(text, finding=False):
    """Reserve space below the badge so it cannot touch the edge arrow."""
    rows = text.split("\n")
    color = "#ffe4e7" if finding else "#d8f8f4"
    cells = f'<TR><TD BGCOLOR="{color}" CELLPADDING="7"><FONT COLOR="#9f3046" POINT-SIZE="11">{html.escape(rows[0])}</FONT></TD></TR>'
    for row in rows[1:]:
        cells += f'<TR><TD><FONT POINT-SIZE="10">{html.escape(row)}</FONT></TD></TR>'
    return (
        '<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0">'
        + cells
        + '<TR><TD HEIGHT="18"> </TD></TR></TABLE>>'
    )


def palette(dark=False):
    return (
        {
            "text": "#e2e8f0",
            "line": "#8fa6b8",
            "surface": "#202c38",
            "active": "#75ddc6",
            "blocked": "#f49b90",
            "target": "#18483b",
        }
        if dark
        else {
            "text": "#243746",
            "line": "#687d8e",
            "surface": "#f3f7fa",
            "active": "#087e70",
            "blocked": "#b73e34",
            "target": "#def4e9",
        }
    )


def asset_labels(dataset):
    """Readable names; duplicate names use addresses, then stable short numbers."""
    assets = sorted(dataset["assets"], key=lambda asset: asset["asset_id"])
    contexts = dataset.get("contexts", {})
    names = {a["asset_id"]: a["name"].strip() or "Tài sản" for a in assets}
    labels = {}
    for asset in assets:
        aid = asset["asset_id"]
        name = names[aid]
        duplicates = [
            a for a in assets if names[a["asset_id"]].casefold() == name.casefold()
        ]
        if len(duplicates) == 1:
            labels[aid] = name
            continue
        address = (contexts.get(aid, {}).get("address") or "").strip()
        same_address = [
            a
            for a in duplicates
            if (contexts.get(a["asset_id"], {}).get("address") or "").strip() == address
        ]
        suffix = address if address else ""
        if not address or len(same_address) > 1:
            suffix += (" · " if suffix else "") + str(same_address.index(asset) + 1)
        labels[aid] = name + " · " + suffix
    return labels


def start_dot(dataset, entries, targets, patched, colors):
    lines = [
        "digraph riskdesk {",
        'graph [rankdir=LR, bgcolor="transparent", pad="0.3", nodesep="0.5", ranksep="0.8"];',
        f'node [shape=box, style="rounded,filled", fontname="Arial", fontsize=13, margin="0.18,0.12", color="{colors["line"]}", fillcolor="{colors["surface"]}", fontcolor="{colors["text"]}"];',
        f'edge [fontname="Arial", fontsize=11, arrowsize=0.8, fontcolor="{colors["text"]}"];',
    ]
    assets = {a["asset_id"]: a for a in dataset["assets"]}
    findings = {f["finding_id"]: f for f in dataset.get("findings", [])}
    labels = asset_labels(dataset)
    nodes = sorted(set(assets) | set(entries))
    for aid in nodes:
        label = labels.get(aid, aid)
        if aid in entries:
            label += "\nĐiểm bắt đầu"
        if aid in targets:
            label += "\nTÀI SẢN ĐÍCH"
        changed = [
            fid for fid in patched if findings.get(fid, {}).get("asset_id") == aid
        ]
        if changed:
            label += "\nMô phỏng vá: " + ", ".join(changed)
        fill = colors["target"] if aid in targets else colors["surface"]
        shape = (
            "doubleoctagon" if aid in targets else "oval" if aid in entries else "box"
        )
        lines.append(
            f"{quoted(aid)} [id={quoted('asset-' + aid)}, label={quoted(label)}, tooltip={quoted(aid)}, shape={shape}, fillcolor={quoted(fill)}];"
        )
    return lines


def attack_dot(dataset, graph, baseline=None, *, dark=False):
    """Colors are derived solely from returned current/baseline target paths."""
    baseline = baseline or graph
    if (
        graph["dataset_id"] != baseline["dataset_id"]
        or graph["graph_model_version"] != baseline["graph_model_version"]
        or graph["target_asset_ids"] != baseline["target_asset_ids"]
        or graph["entry_point_ids"] != baseline["entry_point_ids"]
    ):
        raise ValueError("Không thể vẽ hai đồ thị có dữ liệu hoặc phạm vi khác nhau.")
    colors = palette(dark)
    patched = set(graph["patched_finding_ids"])
    active_ids = {r for p in graph["paths"] for r in p["rule_ids"]}
    original_ids = {r for p in baseline["paths"] for r in p["rule_ids"]}
    rules = {r["rule_id"]: r for r in dataset["exploit_rules"]}
    if not (active_ids | original_ids) <= set(rules):
        raise ValueError("Đường tấn công tham chiếu điều kiện không có trong dataset.")
    lines = start_dot(
        dataset, graph["entry_point_ids"], graph["target_asset_ids"], patched, colors
    )
    for rid in sorted(active_ids | original_ids):
        rule = rules[rid]
        finding = rule["required_finding_id"]
        label = finding or "Quyền truy cập"
        if rid in active_ids:
            color, style, width = colors["active"], "solid", 2.5
        elif finding in patched:
            color, style, width = colors["blocked"], "dashed", 2.5
            label += "\nĐã chặn do mô phỏng vá"
        else:
            color, style, width = colors["line"], "dashed", 1.2
            label += "\nKhông còn trên đường tới đích"
        lines.append(
            f"{quoted(rule['source_asset_id'])} -> {quoted(rule['target_asset_id'])} [id={quoted('rule-' + rid)}, label={edge_label(label, bool(finding))}, tooltip={quoted(rid)}, color={quoted(color)}, style={quoted(style)}, penwidth={width}];"
        )
    lines.append("}")
    return "\n".join(lines)


def topology_dot(workspace, *, dark=False):
    """Declared connectivity is not interpreted as exploit feasibility."""
    colors = palette(dark)
    entries = sorted(
        {
            c["source_asset_id"]
            for c in workspace["connections"]
            if c["source_asset_id"] == "INTERNET"
        }
    )
    lines = start_dot(workspace, entries, [], [], colors)
    for connection in workspace["connections"]:
        allowed = connection["allowed"]
        label = "Cho phép" if allowed else "Chặn"
        lines.append(
            f"{quoted(connection['source_asset_id'])} -> {quoted(connection['target_asset_id'])} [label={quoted(label)}, tooltip={quoted(connection['connection_id'])}, color={quoted(colors['line'] if allowed else colors['blocked'])}, style={quoted('solid' if allowed else 'dashed')}];"
        )
    lines.append("}")
    return "\n".join(lines)


def render_glass(markup):
    # st.html sanitizes inline SVG; an SVG image preserves the safe static drawing.
    svg = markup[markup.index("<svg") : markup.rindex("</svg>") + 6]
    encoded = base64.b64encode(svg.encode()).decode()
    st.html(
        '<div class="rd-glass-graph"><img alt="Sơ đồ tài sản và đường nối từ dữ liệu hiện tại" src="data:image/svg+xml;base64,'
        + encoded
        + '" style="width:100%;height:auto;display:block;min-width:640px"></div>'
    )


def entries_for(workspace):
    return (
        ["INTERNET"]
        if any(c["source_asset_id"] == "INTERNET" for c in workspace["connections"])
        else []
    )


def render_graph(workspace, envelope=None, baseline=None, *, compact=False):
    mode = "Đường tấn công"
    if not compact and envelope:
        mode = st.radio(
            "Loại sơ đồ",
            ["Đường tấn công", "Kết nối mạng"],
            horizontal=True,
            key="rd_graph_mode",
        )
    dark = False  # The selected glass theme uses light graph surfaces consistently.
    if envelope and mode == "Đường tấn công":
        graph = envelope["report"]["graph"]
        original = baseline["report"]["graph"] if baseline else graph
        dataset = {**workspace["dataset"], "contexts": workspace.get("contexts", {})}
        dot = attack_dot(dataset, graph, original, dark=dark)
        label = f"Sơ đồ đường tấn công: còn {len(graph['paths'])} đường tới {', '.join(graph['target_asset_ids'])}."
        active_ids = {rid for path in graph["paths"] for rid in path["rule_ids"]}
        original_ids = {rid for path in original["paths"] for rid in path["rule_ids"]}
        rules = {r["rule_id"]: r for r in dataset["exploit_rules"]}
        visible = set(graph["entry_point_ids"]) | set(graph["target_asset_ids"])
        edges = []
        for rid in sorted(active_ids | original_ids):
            rule = rules[rid]
            visible.update([rule["source_asset_id"], rule["target_asset_id"]])
            finding = rule["required_finding_id"]
            edges.append(
                {
                    "id": rid,
                    "source": rule["source_asset_id"],
                    "target": rule["target_asset_id"],
                    "label": finding or "Quyền truy cập",
                    "finding": bool(finding),
                    "blocked": finding in graph["patched_finding_ids"],
                    "inactive": rid not in active_ids,
                }
            )
        render_glass(
            glass_svg(
                [a for a in dataset["assets"] if a["asset_id"] in visible],
                edges,
                entries=graph["entry_point_ids"],
                targets=graph["target_asset_ids"],
                names=asset_labels(dataset),
            )
        )
        details = st.expander("Chi tiết graph, tài sản và bằng chứng")
        with details:
            st.graphviz_chart(dot, width="stretch", height=320, alt=label)
            st.caption(
                "Nét liền: còn đường tới đích · Nét đứt đỏ: bị chặn do vá · Nét đứt xám: không còn trên đường tới đích. Tài sản ngoài đường tới đích không đồng nghĩa an toàn."
            )
    elif workspace["assets"]:
        render_glass(
            glass_svg(
                workspace["assets"],
                [
                    {
                        "id": c["connection_id"],
                        "source": c["source_asset_id"],
                        "target": c["target_asset_id"],
                        "label": "Cho phép" if c["allowed"] else "Chặn",
                        "blocked": not c["allowed"],
                    }
                    for c in workspace["connections"]
                ],
                entries=entries_for(workspace),
                names=asset_labels(workspace),
            )
        )
        details = st.expander("Chi tiết graph, tài sản và bằng chứng")
        with details:
            st.graphviz_chart(
                topology_dot(workspace, dark=dark),
                width="stretch",
                height=360,
                alt="Sơ đồ các kết nối mạng do người dùng hoặc dataset khai báo.",
            )
        st.caption(
            "Đây là kết nối mạng đã khai báo, không khẳng định có thể tấn công qua các kết nối này."
        )
    else:
        st.info("Thêm tài sản và khai báo kết nối để xem sơ đồ.")

    if workspace["assets"]:
        with details:
            labels = asset_labels(workspace)
            st.dataframe(
                [
                    {
                        "Tên trên sơ đồ": labels[a["asset_id"]],
                        "Mã tài sản": a["asset_id"],
                    }
                    for a in workspace["assets"]
                ],
                hide_index=True,
                width="stretch",
            )
            if workspace["connections"]:
                st.dataframe(
                    [
                        {
                            "Mã kết nối": c["connection_id"],
                            "Từ": labels.get(
                                c["source_asset_id"], c["source_asset_id"]
                            ),
                            "Đến": labels.get(
                                c["target_asset_id"], c["target_asset_id"]
                            ),
                            "Trạng thái": "Cho phép" if c["allowed"] else "Chặn",
                        }
                        for c in workspace["connections"]
                    ],
                    hide_index=True,
                    width="stretch",
                )
