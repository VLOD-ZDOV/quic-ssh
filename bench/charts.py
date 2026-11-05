#!/usr/bin/env python3
"""Draws the README benchmark charts (assets/*.svg) from the numbers below.

Update the numbers after a new bench.py run, then: python3 bench/charts.py
"""

from pathlib import Path

FONT = "system-ui, -apple-system, 'Segoe UI', sans-serif"
THEMES = {
    "light": dict(bg="#fcfcfb", ink="#0b0b0b", ink2="#52514e", muted="#898781",
                  grid="#e1e0d9", axis="#c3c2b7",
                  series=["#eb6834", "#2a78d6", "#1baf7a"]),
    "dark": dict(bg="#1a1a19", ink="#ffffff", ink2="#c3c2b7", muted="#898781",
                 grid="#2c2c2a", axis="#383835",
                 series=["#d95926", "#3987e5", "#199e70"]),
}

# Each value is a number or (low, high): a range drawn as a whisker, the bar at its middle.
CHARTS = [
    dict(
        name="connect",
        title="Connect and run true (ms), lower is better",
        series=["ssh", "qsh (QUIC)", "qsh (TCP fallback)"],
        groups=[
            ("loopback", [87, 37, 15]),
            ("RTT 50 ms, 100 Mbit/s", [631, 188, 217]),
            ("RTT 100 ms, 1% loss", [1183, 343, 420]),
            ("real server, internet", [1000, 309, 337]),
        ],
    ),
    dict(
        name="transfer",
        title="File transfer (Mbit/s), higher is better",
        series=["scp", "qsh cp (QUIC)", "qsh cp (TCP fallback)"],
        groups=[
            ("upload, RTT 50 ms", [66.2, 85.2, 79.2]),
            ("upload, RTT 100 ms, 1% loss", [10.4, 16.3, 14.1]),
            ("upload, internet", [53, 70, 107]),
            ("download, internet", [53, 107, 94]),
        ],
    ),
    dict(
        name="memory",
        title="Memory, RSS (MB), lower is better",
        series=["OpenSSH", "qsh / qshd"],
        groups=[
            ("server, idle", [8.6, 7.5]),
            ("server, per session", [23, (3, 5)]),
            ("client, in a session", [(11, 13), 9]),
            ("client, sending 1 GiB", [11, 17]),
        ],
    ),
]

W, H = 760, 400
LEFT, RIGHT, TOP, BOTTOM = 64, 736, 92, 330


def nice_max(v):
    for exp in range(-1, 6):
        for step in (1, 2, 2.5, 5):
            m = step * 10**exp * 4
            if m >= v * 1.12:
                return m, m / 4
    return v, v / 4


def fmt(v):
    if isinstance(v, tuple):
        return f"{fmt(v[0])}–{fmt(v[1])}"
    return f"{v:g}"


def text(x, y, s, size, fill, anchor="start", weight=None):
    w = f' font-weight="{weight}"' if weight else ""
    return (f'<text x="{x:.2f}" y="{y:.2f}" font-family="{FONT}" font-size="{size}"{w} '
            f'fill="{fill}" text-anchor="{anchor}">{s}</text>')


def bar(x, y, w, base, fill):
    r = min(4, (base - y) / 2)
    return (f'<path d="M {x:.2f} {base:.2f} L {x:.2f} {y + r:.2f} Q {x:.2f} {y:.2f} {x + r:.2f} {y:.2f} '
            f'L {x + w - r:.2f} {y:.2f} Q {x + w:.2f} {y:.2f} {x + w:.2f} {y + r:.2f} '
            f'L {x + w:.2f} {base:.2f} Z" fill="{fill}"/>')


def draw(chart, t):
    hi = max(v[1] if isinstance(v, tuple) else v for _, vals in chart["groups"] for v in vals)
    top, step = nice_max(hi)
    y_of = lambda v: BOTTOM - (BOTTOM - TOP) * v / top
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
           f'role="img" aria-label="{chart["title"]}">',
           f'<rect width="{W}" height="{H}" fill="{t["bg"]}" rx="8"/>',
           text(24, 34, chart["title"], 17, t["ink"], weight=600)]
    lx = 24
    for name, color in zip(chart["series"], t["series"]):
        out.append(f'<rect x="{lx}" y="52" width="12" height="12" rx="3" fill="{color}"/>')
        out.append(text(lx + 18, 62, name, 12.5, t["ink2"]))
        lx += 18 + len(name) * 7.2 + 28
    for i in range(5):
        v = step * i
        y = y_of(v)
        if i:
            out.append(f'<line x1="{LEFT}" y1="{y:.2f}" x2="{RIGHT}" y2="{y:.2f}" stroke="{t["grid"]}" stroke-width="1"/>')
        out.append(text(LEFT - 10, y + 4, fmt(v), 11, t["muted"], "end"))
    out.append(f'<line x1="{LEFT}" y1="{BOTTOM}" x2="{RIGHT}" y2="{BOTTOM}" stroke="{t["axis"]}" stroke-width="1"/>')

    n = len(chart["series"])
    gw = (RIGHT - LEFT) / len(chart["groups"])
    bw, gap = 44, 2
    for gi, (label, vals) in enumerate(chart["groups"]):
        cx = LEFT + gw * (gi + 0.5)
        x0 = cx - (n * bw + (n - 1) * gap) / 2
        for si, v in enumerate(vals):
            x = x0 + si * (bw + gap)
            mid = sum(v) / 2 if isinstance(v, tuple) else v
            y = y_of(mid)
            out.append(bar(x, y, bw, BOTTOM, t["series"][si]))
            label_y = y
            if isinstance(v, tuple):
                ylo, yhi = y_of(v[0]), y_of(v[1])
                xm = x + bw / 2
                out.append(f'<line x1="{xm:.2f}" y1="{ylo:.2f}" x2="{xm:.2f}" y2="{yhi:.2f}" stroke="{t["ink2"]}" stroke-width="1.5"/>')
                for yy in (ylo, yhi):
                    out.append(f'<line x1="{xm - 5:.2f}" y1="{yy:.2f}" x2="{xm + 5:.2f}" y2="{yy:.2f}" stroke="{t["ink2"]}" stroke-width="1.5"/>')
                label_y = yhi
            out.append(text(x + bw / 2, label_y - 8, fmt(v), 12, t["ink"], "middle", 600))
        out.append(text(cx, BOTTOM + 22, label, 12, t["ink2"], "middle"))
    out.append("</svg>\n")
    return "\n".join(out)


def main():
    assets = Path(__file__).resolve().parent.parent / "assets"
    assets.mkdir(exist_ok=True)
    for chart in CHARTS:
        for theme, t in THEMES.items():
            (assets / f"bench-{chart['name']}-{theme}.svg").write_text(draw(chart, t))


if __name__ == "__main__":
    main()
