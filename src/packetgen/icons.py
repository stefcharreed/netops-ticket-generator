"""Device icons for topology.png.

Built-in icons are drawn in code in the familiar Cisco style. If a local folder holds Cisco's official topology
icons (default ~/.config/packetgen/icons, or $PACKETGEN_ICONS), those are used instead, one icon at a time, with
the built-in drawing as the fallback for anything missing or unreadable. Cisco's icons are never part of this
repo, and the terms ("You may use them freely, but you may not alter them") mean they are only scaled here.
"""
from __future__ import annotations

import os
from pathlib import Path

import matplotlib.image as mpimg
from matplotlib.axes import Axes
from matplotlib.patches import Circle, Ellipse, FancyBboxPatch, Polygon, Rectangle

# File names in Cisco's "PMS 3015 JPG" pack (first one found wins).
CISCO_FILES: dict[str, tuple[str, ...]] = {
    "cloud": ("cloud.jpg",),
    "firewall": ("firewall.jpg", "cisco asa 5500.jpg"),
    "router": ("router.jpg",),
    "l3switch": ("layer 3 switch.jpg",),
    "switch": ("workgroup switch.jpg",),
    "wlc": ("wlan controller.jpg",),
    "ap": ("lightweight ap.jpg", "accesspoint.jpg"),
    "server": ("file server.jpg", "www server.jpg"),
    "aaa": ("ACS.jpg",),
    "pc": ("pc.jpg", "workstation.jpg"),
    "printer": ("printer.jpg",),
    "phone": ("ip phone.jpg", "phone.jpg"),
    "host": ("standard host.jpg", "host.jpg"),
}
BLUE, DARK, BRICK = "#0072B8", "#0B3C5D", "#B5523B"


def icons_dir() -> Path:
    return Path(os.environ.get("PACKETGEN_ICONS") or Path.home() / ".config" / "packetgen" / "icons")


def icon_source(kind: str, folder: Path) -> Path | None:
    return next((folder / n for n in CISCO_FILES.get(kind, ()) if (folder / n).is_file()), None)


def load_icon(kind: str, folder: Path):
    """The Cisco icon as an image array, or None (missing or unreadable -> use the built-in drawing)."""
    src = icon_source(kind, folder)
    if src is None:
        return None
    try:
        return mpimg.imread(src)
    except Exception:  # noqa: BLE001  a corrupt file must not stop the build
        return None


def icon_report(folder: Path) -> dict[str, str]:
    """Which file each kind will use: its Cisco file name, or "built-in"."""
    out = {}
    for kind in CISCO_FILES:
        src = icon_source(kind, folder)
        out[kind] = src.name if src is not None and load_icon(kind, folder) is not None else "built-in"
    return out


def _arrows(ax: Axes, x: float, y: float, r: float, color: str = "white") -> None:
    for dx, dy in ((1, 1), (-1, -1), (1, -1), (-1, 1)):
        ax.annotate("", xy=(x + dx * r, y + dy * r * 0.55), xytext=(x + dx * r * 0.25, y + dy * r * 0.14),
                    arrowprops={"arrowstyle": "-|>", "color": color, "lw": 1.2}, zorder=6)


def draw_builtin(ax: Axes, kind: str, x: float, y: float, s: float = 0.5) -> None:
    """Draw a Cisco-style icon of width ~2s centred on (x, y)."""
    z = 5
    if kind == "router":
        ax.add_patch(Ellipse((x, y), 2 * s, 1.2 * s, fc=BLUE, ec=DARK, lw=1.2, zorder=z))
        _arrows(ax, x, y, s * 0.75)
    elif kind in ("l3switch", "switch", "wlc"):
        h = 1.3 * s if kind == "l3switch" else 0.8 * s
        ax.add_patch(FancyBboxPatch((x - s, y - h / 2), 2 * s, h, boxstyle="round,pad=0.02", fc=BLUE, ec=DARK,
                                    lw=1.2, zorder=z))
        if kind == "l3switch":
            _arrows(ax, x, y, s * 0.6)
        else:
            for d in (-1, 1):
                ax.annotate("", xy=(x + d * s * 0.85, y + d * h * 0.18), xytext=(x - d * s * 0.85, y + d * h * 0.18),
                            arrowprops={"arrowstyle": "-|>", "color": "white", "lw": 1.2}, zorder=6)
        if kind == "wlc":
            ax.text(x, y - h * 0.05, "WLC", ha="center", va="center", color="white", fontsize=7, zorder=6)
    elif kind == "firewall":
        w, h = 1.6 * s, 1.1 * s
        ax.add_patch(Rectangle((x - w / 2, y - h / 2), w, h, fc=BRICK, ec=DARK, lw=1.2, zorder=z))
        for i in range(1, 4):
            yy = y - h / 2 + i * h / 4
            ax.plot([x - w / 2, x + w / 2], [yy, yy], color="white", lw=0.8, zorder=6)
        for i in range(4):
            off = (w / 4) * (0.5 if i % 2 else 0)
            for j in range(1, 4):
                xx = x - w / 2 + off + j * w / 4
                if xx < x + w / 2:
                    yy = y - h / 2 + i * h / 4
                    ax.plot([xx, xx], [yy, yy + h / 4], color="white", lw=0.8, zorder=6)
    elif kind == "ap":
        ax.add_patch(Circle((x, y), 0.45 * s, fc=BLUE, ec=DARK, lw=1.2, zorder=z))
        for rr in (0.7, 0.95):
            ax.add_patch(Ellipse((x, y), 2 * rr * s, 2 * rr * s, fc="none", ec=BLUE, lw=1, zorder=z))
    elif kind in ("server", "aaa"):
        w, h = 0.9 * s, 1.6 * s
        ax.add_patch(Rectangle((x - w / 2, y - h / 2), w, h, fc=BLUE, ec=DARK, lw=1.2, zorder=z))
        for i in range(1, 4):
            yy = y + h / 2 - i * h / 5
            ax.plot([x - w / 3, x + w / 3], [yy, yy], color="white", lw=1, zorder=6)
        if kind == "aaa":
            ax.text(x, y - h * 0.3, "AAA", ha="center", va="center", color="white", fontsize=6, zorder=6)
    elif kind == "pc":
        ax.add_patch(Rectangle((x - 0.8 * s, y - 0.2 * s), 1.6 * s, 1.0 * s, fc=BLUE, ec=DARK, lw=1.2, zorder=z))
        ax.add_patch(Rectangle((x - 0.6 * s, y - 0.05 * s), 1.2 * s, 0.7 * s, fc="#DCEBF5", ec="none", zorder=6))
        ax.add_patch(Polygon([(x - 0.5 * s, y - 0.65 * s), (x + 0.5 * s, y - 0.65 * s), (x + 0.3 * s, y - 0.2 * s),
                              (x - 0.3 * s, y - 0.2 * s)], fc=DARK, zorder=z))
    elif kind == "printer":
        ax.add_patch(Rectangle((x - 0.8 * s, y - 0.4 * s), 1.6 * s, 0.7 * s, fc=BLUE, ec=DARK, lw=1.2, zorder=z))
        ax.add_patch(Rectangle((x - 0.5 * s, y + 0.3 * s), 1.0 * s, 0.4 * s, fc="white", ec=DARK, lw=1, zorder=z))
    elif kind == "phone":
        ax.add_patch(FancyBboxPatch((x - 0.6 * s, y - 0.4 * s), 1.2 * s, 0.8 * s, boxstyle="round,pad=0.05",
                                    fc=BLUE, ec=DARK, lw=1.2, zorder=z))
        ax.add_patch(Rectangle((x - 0.7 * s, y + 0.35 * s), 1.4 * s, 0.25 * s, fc=DARK, zorder=z))
    elif kind == "cloud":
        for dx, dy, rr in ((-0.5, 0, 0.5), (0.1, 0.25, 0.6), (0.6, 0, 0.45), (0, -0.2, 0.5)):
            ax.add_patch(Circle((x + dx * s, y + dy * s), rr * s, fc="#E8F1F8", ec=BLUE, lw=1, zorder=z))
    else:  # host
        ax.add_patch(FancyBboxPatch((x - 0.7 * s, y - 0.5 * s), 1.4 * s, 1.0 * s, boxstyle="round,pad=0.05",
                                    fc="#E8F1F8", ec=BLUE, lw=1.2, zorder=z))
