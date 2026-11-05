#!/usr/bin/env python3
"""Draw the README banner (banner.svg) and the link-preview card (card.svg).

Both say API KEY CRAWLER over a dim code page: two crawlers made of dots and
hairlines reach out to masked keys in neon boxes, between purple neon strips.
The banner loops in 8 s and holds still under prefers-reduced-motion; the card
is the same scene, still, at 1280x640 for GitHub's social preview.

Run it with no arguments; the files land in docs/assets. Deterministic: the
same run writes the same bytes. card.png comes from card.svg:

  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new \
    --use-mock-keychain --password-store=basic --user-data-dir="$(mktemp -d)" \
    --hide-scrollbars --window-size=1280,640 --screenshot=docs/assets/card.png \
    "file://$PWD/docs/assets/card.svg"
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "docs", "assets")

PAGE = "#000000"
DIM = "#3b4680"
ICE = "#e8f0ff"
WIRE = "#9fb3ff"
MAGENTA = "#ff2bd6"
VIOLET = "#8a3dff"
BLUE = "#3d7bff"
SKY = "#5fb4ff"
AMBER = "#ffc23d"
MINT = "#3dffa0"
MONO = 'ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace'
ADV = 0.6  # monospace advance in em; textLength pins every real font to it
BUL = chr(0x2022)
T = 8.0

NAME = "API KEY CRAWLER"
TAGLINE = "Your keys never reach GitHub."

# Shapes only: a prefix, four bullets, the last four. No value is ever whole.
KEYS = [
    ("sk_live_", "a1B2", MAGENTA, 0.5),
    ("AIza", "xR0s", MINT, 2.0),
    ("ghp_", "9F3K", AMBER, 3.5),
    ("xoxb-", "7Hq2", SKY, 5.0),
    ("AKIA", "Q7XZ", BLUE, 6.5),
]
# Where each key box sits, as a share of the width and height.
SPOTS = [(0.045, 0.17), (0.44, 0.07), (0.85, 0.15), (0.83, 0.75), (0.055, 0.75)]

CODE = [
    "// config/clients.js: created once at boot",
    "export const stripe = { secret: 'sk_live_" + BUL * 4 + "a1B2', retries: RETRIES };",
    "export const aws = { accessKeyId: 'AKIA" + BUL * 4 + "Q7XZ', region: 'us-east-1' };",
    "export const github = { token: 'ghp_" + BUL * 4 + "9F3K' };",
    "export const slack = { token: 'xoxb-" + BUL * 4 + "7Hq2', channel: '#deploys' };",
    "export const google = { apiKey: 'AIza" + BUL * 4 + "xR0s' };",
    "9752a3e  add billing config        2 hours ago",
    "c58e610  move secrets to vault     3 days ago",
    "a8b5e43  bump deps                 last week",
]

# One crawler: a hub and seven nodes, in px at scale 1.
NODES = [(0, 0), (-40, -32), (35, -38), (62, 10), (28, 55), (-30, 46), (-60, 10), (-2, 30)]
EDGES = [(0, i) for i in range(1, 8)] + [(1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 1), (7, 4), (7, 5)]


def n(x):
    return ("%.2f" % x).rstrip("0").rstrip(".")


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39;")


def pct(t):
    return n(100.0 * t / T) + "%"


def text(x, y, s, size, fill, extra=""):
    width = len(s) * ADV * size
    return ('<text x="%s" y="%s" font-family=\'%s\' font-size="%s" fill="%s" textLength="%s" '
            'lengthAdjust="spacingAndGlyphs"%s>%s</text>' % (n(x), n(y), MONO, n(size), fill, n(width), extra, esc(s)))


def scene(w, h, animated):
    s = h / 320.0 if h <= 320 else 1.6
    fs = min(0.27 * h, 1000.0 / (len(NAME) * ADV))
    base = h * 0.5 + fs * 0.3
    out = []
    add = out.append
    add('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" '
        'aria-label="%s. %s">' % (w, h, w, h, NAME, TAGLINE))
    add("<defs>")
    add('<linearGradient id="strip" x1="0" x2="1"><stop offset="0" stop-color="%s"/>'
        '<stop offset=".5" stop-color="%s"/><stop offset="1" stop-color="%s"/></linearGradient>' % (VIOLET, MAGENTA, VIOLET))
    add('<linearGradient id="beam" x1="0" x2="1"><stop offset="0" stop-color="%s" stop-opacity="0"/>'
        '<stop offset=".5" stop-color="%s" stop-opacity=".9"/><stop offset="1" stop-color="%s" stop-opacity="0"/>'
        '</linearGradient>' % (MAGENTA, MAGENTA, MAGENTA))
    add('<filter id="glow" x="-20%" y="-60%" width="140%" height="220%"><feGaussianBlur stdDeviation="4" result="b"/>'
        '<feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>')
    add("</defs>")
    if animated:
        css = []
        css.append(".drift-l{animation:drl %ss ease-in-out infinite}.drift-r{animation:drr %ss ease-in-out infinite}"
                   % (n(T), n(T)))
        css.append("@keyframes drl{0%,100%{transform:translate(0,0)}50%{transform:translate(10px,-7px)}}")
        css.append("@keyframes drr{0%,100%{transform:translate(0,0)}50%{transform:translate(-10px,7px)}}")
        for i, (_, _, _, t0) in enumerate(KEYS):
            css.append(".hot%d{animation:hot%d %ss linear infinite}" % (i, i, n(T)))
            css.append("@keyframes hot%d{0%%,%s{opacity:.28}%s,%s{opacity:1}%s,100%%{opacity:.28}}"
                       % (i, pct(t0 - 0.05), pct(t0 + 0.08), pct(t0 + 0.9), pct(t0 + 1.8)))
        css.append(".gm{animation:gm %ss linear infinite}.gc{animation:gc %ss linear infinite}" % (n(T), n(T)))
        css.append("@keyframes gm{0%%,%s,%s,%s,%s,100%%{transform:translate(-2px,0)}%s,%s{transform:translate(-7px,-2px)}"
                   "%s,%s{transform:translate(4px,1px)}}"
                   % (pct(2.0), pct(2.18), pct(6.0), pct(6.14), pct(2.02), pct(2.16), pct(6.02), pct(6.12)))
        css.append("@keyframes gc{0%%,%s,%s,%s,%s,100%%{transform:translate(2px,0)}%s,%s{transform:translate(7px,2px)}"
                   "%s,%s{transform:translate(-4px,-1px)}}"
                   % (pct(2.0), pct(2.18), pct(6.0), pct(6.14), pct(2.02), pct(2.16), pct(6.02), pct(6.12)))
        css.append(".sweep{animation:sw %ss linear infinite}" % n(T))
        css.append("@keyframes sw{0%%,%s{transform:translate(-%dpx,0);opacity:0}%s{opacity:1}%s{opacity:1}"
                   "%s,100%%{transform:translate(%dpx,0);opacity:0}}"
                   % (pct(3.0), w, pct(3.08), pct(3.9), pct(4.0), w + 400))
        css.append("@media (prefers-reduced-motion:reduce){*{animation:none!important}"
                   ".hot0,.hot1,.hot2,.hot3,.hot4{opacity:1}.sweep{opacity:0}}")
        add("<style>%s</style>" % "".join(css))
    add('<rect width="%d" height="%d" fill="%s"/>' % (w, h, PAGE))

    # The dim page the crawlers climb.
    row = 34
    for i in range(int(h // row) + 1):
        line = CODE[i % len(CODE)] + "    " + CODE[(i + 4) % len(CODE)]
        add(text(18 + (i % 3) * 22, 26 + i * row, line, 12, DIM, ' opacity=".55"'))

    # The beam, under the name so the name stays readable.
    bx = -0.1 * w
    beam = ('<rect x="%s" y="%s" width="%s" height="%s" fill="url(#beam)" transform="rotate(-28 %s %s)" '
            'filter="url(#glow)"/>' % (n(bx), n(-0.5 * h), n(0.09 * w), n(2 * h), n(bx), n(h / 2)))
    if animated:
        add('<g class="sweep" opacity="0">%s</g>' % beam)
    else:
        add('<g transform="translate(%s,0)">%s</g>' % (n(0.36 * w), beam))

    # Key boxes, then the crawlers that reach them.
    boxes = []
    cfs = 15 * min(s, 1.25)
    for (prefix, tail, color, _), (fx, fy) in zip(KEYS, SPOTS):
        label = prefix + BUL * 4 + tail
        bw = len(label) * ADV * cfs + 2 * 0.8 * cfs
        bh = cfs * 1.9
        boxes.append((fx * w, fy * h, bw, bh, label, color))
    hubs = [(0.135 * w, 0.5 * h, 1, "drift-l"), (0.865 * w, 0.5 * h, -1, "drift-r")]
    points = []
    for hx, hy, flip, cls in hubs:
        points.append([(hx + flip * dx * s, hy + dy * s) for dx, dy in NODES])

    for i, (x, y, bw, bh, label, color) in enumerate(boxes):
        cx, cy = x + bw / 2, y + bh / 2
        best = min(((px - cx) ** 2 + (py - cy) ** 2, k, j) for k, pts in enumerate(points)
                   for j, (px, py) in enumerate(pts))
        _, k, j = best
        px, py = points[k][j]
        ey = y + bh if cy < py else y
        cls = (' class="hot%d"' % i) if animated else ""
        add('<line x1="%s" y1="%s" x2="%s" y2="%s" stroke="%s" stroke-width="1" opacity=".35"/>'
            % (n(px), n(py), n(cx), n(ey), WIRE))
        add('<g%s>' % cls)
        add('<line x1="%s" y1="%s" x2="%s" y2="%s" stroke="%s" stroke-width="1.4" filter="url(#glow)"/>'
            % (n(px), n(py), n(cx), n(ey), color))
        add('<rect x="%s" y="%s" width="%s" height="%s" rx="4" fill="%s" stroke="%s" stroke-width="2" '
            'filter="url(#glow)"/>' % (n(x), n(y), n(bw), n(bh), PAGE, color))
        add(text(x + 0.8 * cfs, y + bh * 0.68, label, cfs, ICE))
        add("</g>")

    for (hx, hy, flip, cls), pts in zip(hubs, points):
        add('<g%s>' % ((' class="%s"' % cls) if animated else ""))
        for a, b in EDGES:
            add('<line x1="%s" y1="%s" x2="%s" y2="%s" stroke="%s" stroke-width="1" opacity=".7"/>'
                % (n(pts[a][0]), n(pts[a][1]), n(pts[b][0]), n(pts[b][1]), WIRE))
        for j, (px, py) in enumerate(pts):
            r = 4.2 if j == 0 else 2.6
            add('<circle cx="%s" cy="%s" r="%s" fill="%s" filter="url(#glow)"/>' % (n(px), n(py), n(r * s), ICE))
        add("</g>")

    # The name, with a magenta and a sky copy split off it like a glitch.
    for cls, color, dx in (("gm", MAGENTA, -2), ("gc", SKY, 2)):
        attr = (' class="%s" opacity=".6"' % cls) if animated else (' opacity=".6" transform="translate(%d,0)"' % dx)
        add('<g%s>%s</g>' % (attr, text(w / 2, base, NAME, fs, color, ' text-anchor="middle" font-weight="800"')))
    add('<g filter="url(#glow)">%s</g>'
        % text(w / 2, base, NAME, fs, "#ffffff", ' text-anchor="middle" font-weight="800"'))
    add(text(w / 2, base + fs * 0.62, TAGLINE, fs * 0.29, ICE, ' text-anchor="middle"'))

    # Purple neon strips along the top and bottom edges.
    sh = 4 * min(s, 1.5)
    for y in (0, h - sh):
        add('<rect x="0" y="%s" width="%d" height="%s" fill="url(#strip)" filter="url(#glow)"/>' % (n(y), w, n(sh)))
    add("</svg>")
    return "\n".join(out) + "\n"


def main():
    for name, w, h, animated in (("banner.svg", 1280, 320, True), ("card.svg", 1280, 640, False)):
        with open(os.path.join(OUT, name), "w", encoding="utf-8") as f:
            f.write(scene(w, h, animated))
        print(os.path.join(OUT, name))


if __name__ == "__main__":
    main()
