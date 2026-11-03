"""telemetry_<device>.png: one chart per device, every series for that device on it."""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # headless; must precede pyplot import
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.dates as mdates  # noqa: E402

from packetgen.timebase import parse_utc  # noqa: E402


def render_telemetry(spec: dict, out: Path) -> dict[str, str]:
    out.mkdir(parents=True, exist_ok=True)
    window = spec["meta"]["window"]
    minutes = round((parse_utc(window["end"]) - parse_utc(window["start"])).total_seconds() / 60)
    by_device: dict[str, list[dict]] = {}
    for s in spec["telemetry"]:
        by_device.setdefault(s["device"], []).append(s)
    manifest = {}
    for device, series in by_device.items():
        name = f"telemetry_{device}.png"
        fig, ax = plt.subplots(figsize=(10, 5))
        for s in series:
            xs = mdates.date2num([parse_utc(t).replace(tzinfo=None) for t, _ in s["points"]])
            ax.plot(xs, [v for _, v in s["points"]], marker="o", label=f"{s['metric']} ({s['unit']})")
            manifest[s["id"]] = name
        ax.xaxis_date()
        ax.set_title(f"{device} telemetry ({minutes}-minute window)")
        ax.set_xlabel("time (UTC)")
        ax.grid(True, linestyle="--", alpha=0.5)
        ax.legend()
        fig.autofmt_xdate()
        fig.savefig(out / name, dpi=110)
        plt.close(fig)
    return manifest
