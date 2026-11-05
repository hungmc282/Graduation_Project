"""Glass SVG view of supplied engine edges; no attack inference in this module."""

from html import escape

import networkx as nx

ICONS = {
    "internet": '<circle cx="24" cy="24" r="18"/><ellipse cx="24" cy="24" rx="8" ry="18"/><path d="M6 24h36M10 13h28M10 35h28"/>',
    "server": '<rect x="8" y="7" width="32" height="10" rx="3"/><rect x="8" y="19" width="32" height="10" rx="3"/><rect x="8" y="31" width="32" height="10" rx="3"/><path d="M13 12h1m-1 12h1m-1 12h1M21 12h13M21 24h13M21 36h13"/>',
    "database": '<ellipse cx="24" cy="10" rx="16" ry="6"/><path d="M8 10v26c0 8 32 8 32 0V10M8 23c0 8 32 8 32 0"/>',
    "workstation": '<rect x="5" y="7" width="38" height="27" rx="4"/><path d="M24 34v8M15 42h18"/>',
}


def glass_svg(assets, edges, *, entries=(), targets=(), names=None):
    """Lay out arbitrary directed graphs, including cycles, without adding edges."""
    names = names or {}
    by_id = {a["asset_id"]: a for a in assets}
    ids = set(by_id) | set(entries)
    graph = nx.DiGraph()
    graph.add_nodes_from(ids)
    graph.add_edges_from((e["source"], e["target"]) for e in edges)
    condensation = nx.condensation(graph)
    levels = {}
    for group in nx.topological_sort(condensation):
        levels[group] = max(
            (levels[p] + 1 for p in condensation.predecessors(group)), default=0
        )
    columns = {}
    for aid in sorted(graph):
        level = levels[condensation.graph["mapping"][aid]]
        columns.setdefault(level, []).append(aid)
    height = max(180, max((len(v) for v in columns.values()), default=1) * 145 + 30)
    if any(
        levels[condensation.graph["mapping"][e["source"]]]
        >= levels[condensation.graph["mapping"][e["target"]]]
        for e in edges
    ):
        height += 90
    width = max(900, len(columns) * 250 - 70)
    pos = {}
    for level, members in columns.items():
        for index, aid in enumerate(members):
            pos[aid] = (
                24 + level * 250,
                (height - len(members) * 145) / 2 + index * 145 + 22,
            )
    out = [
        f'<div class="rd-glass-graph"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" font-family="Arial, sans-serif" role="img" aria-label="Sơ đồ tài sản và đường nối từ dữ liệu đang xem"><defs><linearGradient id="nodeGlass" x2="1" y2="1"><stop stop-color="#ffffff" stop-opacity=".94"/><stop offset="1" stop-color="#edf5ff" stop-opacity=".65"/></linearGradient><linearGradient id="targetGlass" x2="1" y2="1"><stop stop-color="#f1fffd"/><stop offset="1" stop-color="#c7f9f1"/></linearGradient><filter id="glassShadow" x="-30%" y="-30%" width="160%" height="180%"><feDropShadow dx="0" dy="7" stdDeviation="8" flood-color="#8db5d4" flood-opacity=".22"/></filter></defs>'
    ]
    for index, edge in enumerate(edges):
        x, y = pos[edge["source"]]
        tx, ty = pos[edge["target"]]
        reverse = tx <= x
        sx, sy = x + 144, y + 68
        ex, ey = tx - 7, ty + 68
        color = (
            "#df8e9c"
            if edge.get("blocked")
            else "#a9b6c9"
            if edge.get("inactive")
            else "#529fbe"
        )
        dash = (
            'stroke-dasharray="6 5"'
            if edge.get("blocked") or edge.get("inactive")
            else ""
        )
        path = f"M{sx},{sy} C{sx + 50},{sy} {ex - 50},{ey} {ex},{ey}"
        if reverse:
            sy = y + 120
            ey = ty + 120
            sx = x + 72
            ex = tx + 72
            path = f"M{sx},{sy} C{sx},{sy + 50} {ex},{ey + 50} {ex},{ey}"
        label = edge["label"]
        badge_w = max(45, min(240, len(label) * 7 + 22))
        bx = (sx + ex) / 2 - badge_w / 2
        by = (sy + ey) / 2 - 37 if not reverse else max(sy, ey) + 18
        bg = "#ffe2e8" if edge.get("finding") else "#d6faf5"
        out.append(
            f'<g data-edge="{escape(edge["id"], quote=True)}"><title>{escape(edge["id"])}</title><path d="{path}" fill="none" stroke="{color}" stroke-width="2.6" {dash}/><path d="M{ex - 7},{ey - 5} L{ex},{ey} L{ex - 7},{ey + 5}" fill="none" stroke="{color}" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/><rect x="{bx}" y="{by}" width="{badge_w}" height="25" rx="12.5" fill="{bg}"/><text x="{bx + badge_w / 2}" y="{by + 17}" text-anchor="middle" fill="#9c3653" font-size="12">{escape(label)}</text></g>'
        )
    for aid, (x, y) in pos.items():
        asset = by_id.get(aid, {})
        kind = asset.get("asset_type", "")
        icon = (
            "internet"
            if aid in entries
            else "database"
            if "database" in kind
            else "workstation"
            if kind == "workstation"
            else "server"
        )
        color = (
            "#078d91"
            if aid in targets
            else "#7569bd"
            if "application" in kind
            else "#236aaa"
        )
        name = names.get(aid, asset.get("name", aid))
        if name == aid and asset:
            name = {
                "web": "Máy chủ web",
                "application": "Máy ứng dụng",
                "database": "Cơ sở dữ liệu",
                "web_server": "Máy chủ web",
                "application_server": "Máy ứng dụng",
                "database_server": "Cơ sở dữ liệu",
                "workstation": "Máy trạm",
            }.get(kind, name)
        words = name.split()
        lines = []
        line = ""
        for word in words:
            if len(line + " " + word) > 19 and line:
                lines.append(line)
                line = word
            else:
                line = (line + " " + word).strip()
        lines.append(line)
        fill = "targetGlass" if aid in targets else "nodeGlass"
        out.append(
            f'<g data-asset="{escape(aid, quote=True)}"><title>{escape(name)} · {escape(aid)}</title><rect x="{x}" y="{y}" width="144" height="126" rx="23" fill="url(#{fill})" stroke="white" stroke-width="1.6" filter="url(#glassShadow)"/><svg x="{x + 50}" y="{y + 20}" width="44" height="44" viewBox="0 0 48 48" fill="none" stroke="{color}" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round">{ICONS[icon]}</svg>'
        )
        for index, line in enumerate(lines):
            out.append(
                f'<text x="{x + 72}" y="{y + 90 + index * 16}" text-anchor="middle" font-size="13" font-weight="600" fill="#19294a">{escape(line)}</text>'
            )
        out.append("</g>")
    out.append("</svg></div>")
    return "".join(out)
