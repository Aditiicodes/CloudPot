#!/usr/bin/env python3
"""Render the four standard CloudPot figures from Cowrie JSON logs.

Produces, into --out-dir:

  attempts_per_day.png      login attempts per calendar day (UTC)
  top_credentials.png       most-tried username/password pairs
  hourly_distribution.png   login attempts by hour of day (UTC)
  source_country_bar.png    attempts by source country - requires --geo

Log reading is shared with parse_cowrie.py rather than reimplemented, so the
two scripts can never disagree about what counts as an event.

No figure is ever drawn from invented data. If a chart has no input - most
often source_country_bar, which needs an IP-to-country mapping this script
deliberately does not fetch - it is skipped with a message saying why.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from collections import Counter
from typing import Dict, List, Optional, Sequence, Tuple

# parse_cowrie.py lives beside this file and is standard-library only.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse_cowrie import LOGIN_EVENTS, iter_events, iter_log_files  # noqa: E402

try:
    import matplotlib
except ImportError:  # pragma: no cover - dependency guidance, not logic
    sys.exit(
        "matplotlib is not installed.\n"
        "  python3 -m venv .venv && . .venv/bin/activate\n"
        "  pip install -r analysis/requirements.txt"
    )

# Agg: render to file, never try to open a window. This script runs over SSH
# and in CI as often as it runs on a laptop.
matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import PathPatch  # noqa: E402
from matplotlib.path import Path  # noqa: E402

# ---------------------------------------------------------------------------
# Theme
#
# One hue for everything. Every figure here is a single series answering a
# magnitude question - "how many attempts" - so there is no identity to encode
# and nothing for a second colour to mean. A rainbow across the bars of a
# single-series chart is decoration that implies a distinction the data does
# not contain, and it is the most common way a security report's charts stop
# being readable.
#
# Values are the validated defaults from the project's chart palette: one blue
# that clears the 3:1 contrast floor against its own surface in both modes,
# with recessive grey chrome so the data is the only thing with weight.
# ---------------------------------------------------------------------------


class Theme:
    def __init__(self, mode: str) -> None:
        dark = mode == "dark"
        self.mode = mode
        self.surface = "#1a1a19" if dark else "#fcfcfb"
        self.series = "#3987e5" if dark else "#2a78d6"
        self.ink = "#ffffff" if dark else "#0b0b0b"
        self.ink_secondary = "#c3c2b7" if dark else "#52514e"
        self.muted = "#898781"
        self.grid = "#2c2c2a" if dark else "#e1e0d9"
        self.baseline = "#383835" if dark else "#c3c2b7"


def apply_rc(theme: Theme) -> None:
    plt.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.sans-serif": ["Helvetica Neue", "Helvetica", "Arial", "DejaVu Sans"],
            "figure.facecolor": theme.surface,
            "axes.facecolor": theme.surface,
            "savefig.facecolor": theme.surface,
            "text.color": theme.ink,
            "axes.labelcolor": theme.ink_secondary,
            "xtick.color": theme.muted,
            "ytick.color": theme.muted,
            "axes.edgecolor": theme.baseline,
            "axes.titlesize": 13,
            "axes.titleweight": "semibold",
            "axes.labelsize": 10,
            "xtick.labelsize": 9,
            "ytick.labelsize": 9,
            "figure.autolayout": False,
        }
    )


def style_axes(ax, theme: Theme, orientation: str) -> None:
    """Strip the chart down to a baseline and one recessive grid direction."""
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(theme.baseline)
    ax.spines["bottom"].set_linewidth(1.0)

    if orientation == "vertical":
        ax.grid(axis="y", color=theme.grid, linewidth=1.0, zorder=0)
        ax.set_axisbelow(True)
        ax.tick_params(axis="both", length=0)
    else:
        # Horizontal bars read against a value axis along the bottom, and the
        # category labels are the y axis - so the grid runs vertically and the
        # baseline is the left edge.
        ax.grid(axis="x", color=theme.grid, linewidth=1.0, zorder=0)
        ax.set_axisbelow(True)
        ax.spines["bottom"].set_visible(False)
        ax.spines["left"].set_visible(True)
        ax.spines["left"].set_color(theme.baseline)
        ax.tick_params(axis="both", length=0)


def _rounded_bar_path(
    x0: float, x1: float, y0: float, y1: float, rx: float, ry: float, orientation: str
) -> Path:
    """Build one bar as a path whose DATA end is rounded and whose baseline end is square.

    The radius is passed as a separate rx and ry because a bar chart's two
    axes are in wildly different units - bar index against event count - and a
    single radius expressed in data units produces a corner that is circular in
    neither. Callers convert a pixel radius into rx and ry independently, so
    what is elliptical in data space renders as a circle on screen.

    (The obvious shortcut, FancyBboxPatch with boxstyle="round", does not work
    here for exactly that reason: its rounding_size is one number applied in
    data space, so on a chart whose y axis runs to a few thousand it draws a
    corner hundreds of bar-widths wide.)
    """
    if orientation == "vertical":
        verts = [
            (x0, y0),
            (x0, y1 - ry),
            (x0, y1), (x0 + rx, y1),      # quadratic corner, control then end
            (x1 - rx, y1),
            (x1, y1), (x1, y1 - ry),      # quadratic corner
            (x1, y0),
            (x0, y0),
        ]
    else:
        verts = [
            (x0, y0),
            (x1 - rx, y0),
            (x1, y0), (x1, y0 + ry),
            (x1, y1 - ry),
            (x1, y1), (x1 - rx, y1),
            (x0, y1),
            (x0, y0),
        ]
    codes = [
        Path.MOVETO,
        Path.LINETO,
        Path.CURVE3, Path.CURVE3,
        Path.LINETO,
        Path.CURVE3, Path.CURVE3,
        Path.LINETO,
        Path.CLOSEPOLY,
    ]
    return Path(verts, codes)


def rounded_bars(
    ax,
    fig,
    values: Sequence[float],
    theme: Theme,
    orientation: str = "vertical",
    thickness: float = 0.62,
    corner_px: float = 4.0,
) -> None:
    """Draw bars with a 4px rounded data end, anchored square to the baseline.

    Axis limits are set here, before the radii are computed, because the
    pixels-per-data-unit conversion depends on them.
    """
    if not values:
        return

    span = max(values) or 1.0
    count = len(values)

    if orientation == "vertical":
        ax.set_xlim(-0.6, count - 0.4)
        ax.set_ylim(0, span * 1.15)
    else:
        ax.set_ylim(-0.6, count - 0.4)
        ax.set_xlim(0, span * 1.18)

    # Axes size in pixels, from the figure geometry - available without a draw
    # pass, and stable under bbox_inches="tight" because tight cropping trims
    # the margin rather than rescaling the axes.
    position = ax.get_position()
    width_px = fig.get_figwidth() * position.width * fig.dpi
    height_px = fig.get_figheight() * position.height * fig.dpi

    xmin, xmax = ax.get_xlim()
    ymin, ymax = ax.get_ylim()
    rx = corner_px * (xmax - xmin) / max(width_px, 1.0)
    ry = corner_px * (ymax - ymin) / max(height_px, 1.0)

    for index, value in enumerate(values):
        if orientation == "vertical":
            # A bar shorter than the corner radius would invert the path.
            capped_ry = min(ry, max(value, 0.0))
            path = _rounded_bar_path(
                index - thickness / 2.0, index + thickness / 2.0, 0.0, value,
                min(rx, thickness / 2.0), capped_ry, orientation,
            )
        else:
            capped_rx = min(rx, max(value, 0.0))
            path = _rounded_bar_path(
                0.0, value, index - thickness / 2.0, index + thickness / 2.0,
                capped_rx, min(ry, thickness / 2.0), orientation,
            )
        ax.add_patch(PathPatch(path, facecolor=theme.series, linewidth=0, zorder=3))


def save(fig, out_dir: str, name: str, dpi: int) -> str:
    path = os.path.join(out_dir, name)
    fig.savefig(path, dpi=dpi, bbox_inches="tight", pad_inches=0.3)
    plt.close(fig)
    return path


# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------


def plot_attempts_per_day(days: Counter, theme: Theme, out_dir: str, dpi: int) -> Optional[str]:
    if not days:
        print("skip attempts_per_day.png - no login events in the input")
        return None

    labels = sorted(days)
    values = [days[d] for d in labels]

    fig, ax = plt.subplots(figsize=(9, 4.5))
    rounded_bars(ax, fig, values, theme, "vertical")
    style_axes(ax, theme, "vertical")

    ax.set_xticks(range(len(labels)))
    # Day-month is enough once the year is stated in the title; the full ISO
    # date on seven ticks forces a rotation that costs more than it explains.
    ax.set_xticklabels([lbl[5:] for lbl in labels])
    ax.set_ylabel("Login attempts")
    ax.set_title(
        "SSH login attempts per day\n{} to {} (UTC)".format(labels[0], labels[-1]),
        loc="left",
        color=theme.ink,
    )

    # Direct labels rather than dense y ticks: seven bars is few enough that
    # every value can be read off the chart without a lookup.
    span = max(values)
    for idx, value in enumerate(values):
        ax.text(
            idx,
            value + span * 0.04,
            "{:,}".format(value),
            ha="center",
            va="bottom",
            fontsize=9,
            color=theme.ink_secondary,
        )
    ax.set_yticks([])

    return save(fig, out_dir, "attempts_per_day.png", dpi)


def plot_top_credentials(
    credentials: Counter, top: int, theme: Theme, out_dir: str, dpi: int
) -> Optional[str]:
    if not credentials:
        print("skip top_credentials.png - no login events in the input")
        return None

    pairs = credentials.most_common(top)
    # Largest at the top: a horizontal ranking is read downward, so the
    # matplotlib default of index 0 at the bottom is backwards here.
    pairs.reverse()
    labels = [p[0] for p in pairs]
    values = [p[1] for p in pairs]

    fig, ax = plt.subplots(figsize=(9, max(3.0, 0.42 * len(values) + 1.4)))
    rounded_bars(ax, fig, values, theme, "horizontal")
    style_axes(ax, theme, "horizontal")

    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=9, color=theme.ink_secondary)
    ax.set_xlabel("Attempts")
    ax.set_title(
        "Most-attempted credentials (username / password)\ntop {} of {:,} distinct pairs".format(
            len(values), len(credentials)
        ),
        loc="left",
        color=theme.ink,
    )

    span = max(values)
    for idx, value in enumerate(values):
        ax.text(
            value + span * 0.015,
            idx,
            "{:,}".format(value),
            ha="left",
            va="center",
            fontsize=9,
            color=theme.ink_secondary,
        )
    ax.set_xticks([])

    return save(fig, out_dir, "top_credentials.png", dpi)


def plot_hourly_distribution(
    hours: Counter, theme: Theme, out_dir: str, dpi: int
) -> Optional[str]:
    if not hours:
        print("skip hourly_distribution.png - no timestamped login events in the input")
        return None

    # All 24 bins, including the empty ones. Dropping a quiet hour would
    # compress the axis and imply activity was more evenly spread than it was.
    values = [hours.get(h, 0) for h in range(24)]

    fig, ax = plt.subplots(figsize=(10, 4.2))
    rounded_bars(ax, fig, values, theme, "vertical", thickness=0.68)
    style_axes(ax, theme, "vertical")

    ax.set_xticks(range(0, 24, 2))
    ax.set_xticklabels(["{:02d}".format(h) for h in range(0, 24, 2)])
    ax.set_xlabel("Hour of day (UTC)")
    ax.set_ylabel("Login attempts")
    ax.set_title(
        "Login attempts by hour of day (UTC)\n"
        "aggregated across the whole run; sources span many local timezones",
        loc="left",
        color=theme.ink,
    )
    # 24 bars is past the point where a number on every one is readable, so
    # this chart keeps its value axis instead of direct labels.
    ax.tick_params(axis="y", labelcolor=theme.muted)

    return save(fig, out_dir, "hourly_distribution.png", dpi)


def load_geo(path: str) -> Dict[str, str]:
    """Load an IP-to-country mapping from a two-column CSV.

    Expected columns: ip, country. A header row is optional and detected.

    This script does no geolocation of its own, and that is deliberate rather
    than lazy. Resolving addresses would mean either bundling a licensed
    database or sending every attacker IP to a third-party API - which is a
    network dependency, a rate limit, a licence question, and a disclosure of
    the sensor's observations to someone else. Producing the mapping is the
    operator's step, with whatever source they are entitled to use.
    """
    mapping: Dict[str, str] = {}
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        for row in reader:
            if len(row) < 2:
                continue
            ip, country = row[0].strip(), row[1].strip()
            if not ip or not country:
                continue
            if ip.lower() in ("ip", "src_ip", "address"):
                continue  # header
            mapping[ip] = country
    return mapping


def plot_source_country(
    ip_counts: Counter, geo_path: Optional[str], top: int, theme: Theme, out_dir: str, dpi: int
) -> Optional[str]:
    if not geo_path:
        print(
            "skip source_country_bar.png - no --geo mapping supplied.\n"
            "  This script will not guess or fetch geolocation. Build a CSV of\n"
            "  ip,country from a source you are licensed to use, then re-run:\n"
            "    python3 analysis/plots.py --input findings/raw/ --geo findings/geo.csv"
        )
        return None

    if not os.path.isfile(geo_path):
        print("skip source_country_bar.png - no such file: {}".format(geo_path))
        return None

    mapping = load_geo(geo_path)
    if not mapping:
        print("skip source_country_bar.png - {} contained no usable ip,country rows".format(geo_path))
        return None

    countries: Counter = Counter()
    unresolved = 0
    for ip, count in ip_counts.items():
        country = mapping.get(ip)
        if country:
            countries[country] += count
        else:
            unresolved += count

    if not countries:
        print(
            "skip source_country_bar.png - none of the {:,} observed source IPs "
            "appear in {}".format(len(ip_counts), geo_path)
        )
        return None

    pairs = countries.most_common(top)
    pairs.reverse()
    labels = [p[0] for p in pairs]
    values = [p[1] for p in pairs]

    fig, ax = plt.subplots(figsize=(9, max(3.0, 0.42 * len(values) + 1.6)))
    rounded_bars(ax, fig, values, theme, "horizontal")
    style_axes(ax, theme, "horizontal")

    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=9, color=theme.ink_secondary)
    ax.set_xlabel("Events from source addresses in this country")

    # The unresolved count belongs on the chart, not in a footnote nobody
    # reads. A country ranking that quietly drops a third of the traffic is
    # worse than no ranking at all.
    subtitle = "top {} by event volume".format(len(values))
    if unresolved:
        subtitle += "  |  {:,} events from unmapped addresses excluded".format(unresolved)
    ax.set_title(
        "Source country by event volume\n" + subtitle,
        loc="left",
        color=theme.ink,
    )

    span = max(values)
    for idx, value in enumerate(values):
        ax.text(
            value + span * 0.015,
            idx,
            "{:,}".format(value),
            ha="left",
            va="center",
            fontsize=9,
            color=theme.ink_secondary,
        )
    ax.set_xticks([])

    # Geolocation is an inference, not an observation. Saying so on the figure
    # keeps the caveat attached when the image is pasted into a slide.
    fig.text(
        0.0,
        -0.02,
        "Country is inferred from IP registration and is not attribution: "
        "proxies, VPNs and cloud egress all misattribute.",
        fontsize=8,
        color=theme.muted,
        ha="left",
    )

    return save(fig, out_dir, "source_country_bar.png", dpi)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render the standard CloudPot figures from Cowrie JSON logs.",
    )
    parser.add_argument("--input", nargs="+", required=True, metavar="PATH",
                        help="Cowrie JSON files or directories. .gz is handled transparently.")
    parser.add_argument("--out-dir", default="analysis/figures", metavar="DIR",
                        help="Where to write the PNGs (default: analysis/figures).")
    parser.add_argument("--geo", default=None, metavar="CSV",
                        help="Optional ip,country CSV. Without it, source_country_bar.png is skipped.")
    parser.add_argument("--top", type=int, default=15, metavar="N",
                        help="Bars in the ranked charts (default: 15).")
    parser.add_argument("--theme", choices=("light", "dark"), default="light",
                        help="Figure theme (default: light).")
    parser.add_argument("--dpi", type=int, default=160, help="Output resolution (default: 160).")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    files = list(iter_log_files(args.input))
    if not files:
        print(
            "No Cowrie log files found under: {}\n"
            "No figures were written. Fetch logs first:\n"
            "  aws s3 sync s3://<telemetry-bucket>/cowrie/ findings/raw/".format(
                ", ".join(args.input)
            )
        )
        return 0

    stats: Counter = Counter()
    days: Counter = Counter()
    hours: Counter = Counter()
    credentials: Counter = Counter()
    ip_counts: Counter = Counter()

    for event in iter_events(files, stats):
        eventid = str(event.get("eventid"))
        src_ip = event.get("src_ip")
        if src_ip:
            ip_counts[str(src_ip)] += 1

        if eventid not in LOGIN_EVENTS:
            continue

        timestamp = event.get("timestamp")
        if isinstance(timestamp, str) and len(timestamp) >= 13:
            days[timestamp[:10]] += 1
            hour = timestamp[11:13]
            if hour.isdigit():
                hours[int(hour)] += 1

        username, password = event.get("username"), event.get("password")
        if username is not None and password is not None:
            credentials["{} / {}".format(username, password)] += 1

    if stats["events_parsed"] == 0:
        print(
            "Read {} line(s) across {} file(s) but found no valid Cowrie events.\n"
            "No figures were written.".format(stats["lines_read"], stats["files_read"])
        )
        return 0

    os.makedirs(args.out_dir, exist_ok=True)
    theme = Theme(args.theme)
    apply_rc(theme)

    written = [
        plot_attempts_per_day(days, theme, args.out_dir, args.dpi),
        plot_top_credentials(credentials, args.top, theme, args.out_dir, args.dpi),
        plot_hourly_distribution(hours, theme, args.out_dir, args.dpi),
        plot_source_country(ip_counts, args.geo, args.top, theme, args.out_dir, args.dpi),
    ]

    produced = [p for p in written if p]
    for path in produced:
        print("wrote {}".format(path))
    print(
        "{} of 4 figures written from {:,} events".format(len(produced), stats["events_parsed"])
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
