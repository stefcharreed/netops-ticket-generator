"""NETWORK.md + topology.png: the network as documented (which may differ from the gear in one place, on purpose).

Built only from `topology` (with its `documented` overrides) and `meta.mac_table`: never from events, telemetry or
the answer, so the docs can't give the fault away. Nothing marks which value is the documented override.
"""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # headless; must precede pyplot import
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.offsetbox import AnnotationBbox, OffsetImage  # noqa: E402
from matplotlib.patches import FancyArrowPatch  # noqa: E402

from packetgen.icons import draw_builtin, load_icon  # noqa: E402
from packetgen.topology import device_kind, doc_rows, entity_kind, link_ends, mac_rows, short_if, slug  # noqa: E402

__all__ = ["layout", "render_network", "short_if"]

TIER = {"cloud": 0, "firewall": 1, "router": 2, "l3switch": 3, "wlc": 3, "switch": 4}   # anything else: 5
GAP_X, GAP_Y, HOST_GAP = 3.4, 2.6, 2.4
HEADER = "**Documentation may be out of date. Verify against the logs and configs.** Cite a row as `doc:<Ref>`."


def _spread(items: list[tuple[str, float]], gap: float) -> dict[str, float]:
    """Place ids near their wanted x, in order, at least `gap` apart, keeping the group's centre."""
    items = sorted(items, key=lambda t: (t[1], t[0]))
    xs: list[float] = []
    for _, want in items:
        xs.append(want if not xs else max(want, xs[-1] + gap))
    shift = (sum(w for _, w in items) - sum(xs)) / len(xs) if xs else 0.0
    return {i: x + shift for (i, _), x in zip(items, xs)}


def layout(spec: dict) -> dict:
    """Pure: nodes (id, kind, tier, x, y, label) and edges (a, b, a_label, b_label, rad). Tests pin this."""
    topo = spec["topology"]
    rows = {r["id"]: r for r in doc_rows(spec)}
    hosts = {d["hostname"]: d for d in topo["devices"]}
    kind = {h: device_kind(d) for h, d in hosts.items()}
    label = {h: f"{h}\n{rows[f'doc:{slug(h)}-mgmt']['ip']}" for h in hosts}
    attached, side = {}, []
    for name, e in sorted(topo["entities"].items()):
        kind[name] = entity_kind(name, e)
        r = rows.get(f"doc:{slug(name)}")
        att = e.get("attached")
        label[name] = name + (f"\n{r['ip']}" if r else "") + (f"\nVLAN {att['vlan']}" if att and att.get("vlan") else "")
        if att and att["device"] in hosts:
            attached[name] = att
        else:
            side.append(name)

    ends = [(a, ia, b, ib) for a, ia, b, ib in link_ends(spec) if a in kind and b in kind]
    nbrs: dict[str, set[str]] = {n: set() for n in kind}
    for a, _, b, _ in ends:
        nbrs[a].add(b)
        nbrs[b].add(a)
    for name, att in attached.items():
        nbrs[name].add(att["device"])

    tier_of = {h: TIER.get(k, 5) for h, k in kind.items() if h in hosts}
    tier_of |= {n: 5 for n in attached}
    x: dict[str, float] = {}
    for t in sorted(set(tier_of.values())):
        members = sorted(n for n, tt in tier_of.items() if tt == t)
        def want(n: str) -> float:
            placed = [x[m] for m in nbrs[n] if m in x]
            return sum(placed) / len(placed) if placed else 0.0
        if t < 5:   # infrastructure: order by upstream position, then centre the row
            order = sorted(members, key=lambda n: (want(n), n))
            x |= {n: (i - (len(order) - 1) / 2) * GAP_X for i, n in enumerate(order)}
        else:       # hosts: under whatever they plug into
            x |= _spread([(n, want(n)) for n in members], HOST_GAP)
    levels = sorted(set(tier_of.values()))
    y = {n: -levels.index(t) * GAP_Y for n, t in tier_of.items()}

    right = max(x.values(), default=0.0) + GAP_X
    nodes = [{"id": n, "kind": kind[n], "tier": tier_of[n], "x": x[n], "y": y[n], "label": label[n]}
             for n in sorted(tier_of, key=lambda n: (tier_of[n], x[n]))]
    nodes += [{"id": n, "kind": kind[n], "tier": "side", "x": right, "y": -i * GAP_Y * 0.7, "label": label[n]}
              for i, n in enumerate(side)]

    seen: dict[frozenset, int] = {}
    edges = []
    for a, ia, b, ib in ends:
        k = seen.get(frozenset((a, b)), 0)
        seen[frozenset((a, b))] = k + 1
        rad = 0.0 if k == 0 else (0.25 if k % 2 else -0.25) * ((k + 1) // 2)
        edges.append({"a": a, "b": b, "a_label": short_if(ia), "b_label": short_if(ib), "rad": rad})
    edges += [{"a": att["device"], "b": n, "a_label": short_if(att.get("interface")), "b_label": "", "rad": 0.0}
              for n, att in attached.items()]
    return {"nodes": nodes, "edges": edges}


def _draw(lay: dict, path: Path, icons: Path) -> None:
    pos = {n["id"]: (n["x"], n["y"]) for n in lay["nodes"]}
    xs, ys = [p[0] for p in pos.values()] or [0.0], [p[1] for p in pos.values()] or [0.0]
    w = min(18.0, max(6.0, (max(xs) - min(xs) + 4) * 0.95))
    h = min(14.0, max(4.0, (max(ys) - min(ys) + 3.5) * 0.95))
    fig, ax = plt.subplots(figsize=(w, h))
    ax.set_xlim(min(xs) - 1.5, max(xs) + 2.8)
    ax.set_ylim(min(ys) - 1.8, max(ys) + 1.2)
    ax.set_aspect("equal")
    ax.axis("off")
    for e in lay["edges"]:
        (xa, ya), (xb, yb) = pos[e["a"]], pos[e["b"]]
        ax.add_patch(FancyArrowPatch((xa, ya), (xb, yb), arrowstyle="-", connectionstyle=f"arc3,rad={e['rad']}",
                                     color="#5B6878", lw=1.4, zorder=1))
        for lab, (x0, y0), (x1, y1) in ((e["a_label"], (xa, ya), (xb, yb)), (e["b_label"], (xb, yb), (xa, ya))):
            if lab:
                ax.text(x0 + (x1 - x0) * 0.27, y0 + (y1 - y0) * 0.27, lab, ha="center", va="center", fontsize=7,
                        color="#15202B", zorder=8, bbox={"fc": "white", "ec": "none", "pad": 0.6})
    for n in lay["nodes"]:
        img = load_icon(n["kind"], icons)
        if img is not None:
            zoom = 52 / max(img.shape[1], 1)
            ax.add_artist(AnnotationBbox(OffsetImage(img, zoom=zoom), (n["x"], n["y"]), frameon=False, zorder=5))
        else:
            draw_builtin(ax, n["kind"], n["x"], n["y"], 0.5)
        # Label right of the icon and just below its centre line: vertical links leave above and below it, and a
        # horizontal link to a neighbour in the same tier runs along the centre line, above the text.
        ax.text(n["x"] + 0.62, n["y"] - 0.12, n["label"], ha="left", va="top", fontsize=8, color="#15202B", zorder=7)
    ax.set_title("Documented topology (may be out of date)", fontsize=10, color="#5B6878")
    fig.savefig(path, dpi=110, bbox_inches="tight")
    plt.close(fig)


def _cell(v) -> str:
    return "" if v is None else str(v)


def render_network(spec: dict, out: Path, icons: Path) -> dict:
    """Write NETWORK.md and topology.png; return the manifest of citable doc row ids."""
    out.mkdir(parents=True, exist_ok=True)
    lay = layout(spec)
    _draw(lay, out / "topology.png", icons)
    rows, macs = doc_rows(spec), (mac_rows(spec) if spec["meta"].get("mac_table") else [])
    links = [f"- {e['a']}{' ' + e['a_label'] if e['a_label'] else ''} ↔ {e['b']}{' ' + e['b_label'] if e['b_label'] else ''}"
             for e in lay["edges"]]
    text = ["# Network documentation", "", HEADER, "", "![Documented topology](topology.png)", "",
            "## Links", *(links or ["- none documented"]), "",
            "## Documented addressing", "| Ref | Device | Interface | IP | VLAN |", "| --- | --- | --- | --- | --- |",
            *(f"| {r['id'][4:]} | {r['device']} | {_cell(r['interface'])} | {_cell(r['ip'])} | {_cell(r['vlan'])} |"
              for r in rows)]
    if macs:
        text += ["", "## Documented MAC table", "| Ref | MAC | IP | Switch | Port | VLAN |",
                 "| --- | --- | --- | --- | --- | --- |",
                 *(f"| {m['id'][4:]} | {m['mac']} | {_cell(m['ip'])} | {m['switch']} | {short_if(m['port'])} | "
                   f"{_cell(m['vlan'])} |" for m in macs)]
    (out / "NETWORK.md").write_text("\n".join(text) + "\n")
    return {"NETWORK.md": [r["id"] for r in rows + macs], "topology.png": []}
