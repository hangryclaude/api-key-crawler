#!/usr/bin/env python3
"""Render the README hero (hero.svg) and its still (social-card.svg).

Deterministic: every random choice comes from random.Random(SEED), so a re-run writes
byte-identical files. System python3 (3.9), standard library only. social-card.svg is the
same scene as a still, with the wordmark and tagline set large enough to read at thumbnail
size (the repo's social preview is its PNG).

The scene: a GitHub repo page in dark mode, drawn only in the two dim navy tokens, so it is
texture and not text to read. A repo header (owner / name, tabs, a branch pill), a file tree,
one open code file with line numbers, and a strip of commits down the right. A lime
centipede is the one thing that moves through it, on one closed route at one speed. The
route is a figure eight: it crosses the open file from the commit side to the file tree, curls
round the tree, crosses the file again and curls round the history on the right, so the
crawler makes two passes through the code per lap and climbs the tree and the history between
them. A soft glow trails it, and the dim words it passes brighten for a moment, as if the page
were being read. A small ice crawler reads the commit history the same way.

Finding a key is the only event. The open file holds masked API keys (constant prefix, a run
of bullets, the last four characters), six per lap, three on each pass. Every key wears a quiet
mark all the time: a thin outline at about a third of its strength, its text a little dimmed.
When the head comes within reach of one, that key lights up in place: the outline and a glow in
one palette colour, held for about a second, then back to the quiet mark as the crawler moves on.
Only one or two keys glow at once, and the first and last frame of the loop are the same, so the
loop has no seam. The only words besides the dim page are the wordmark and the tagline, small,
in ice white, in the top left corner the route never enters. Two violet neon tubes light the
page along the top and bottom edge.

hero-narrow.svg is the same scene for a phone: a 640 px wide canvas, so GitHub's 358 px column
shows it at 56 %, with the type, the crawler and the keys drawn about twice as large, and
only four keys (with three, the figure eight left a 4 s gap between finds). The README
serves it with <picture> below 600 px.

One 8 s loop, CSS @keyframes only (transforms, opacity). With prefers-reduced-motion the
keyframes are switched off and the base styles show the final frame: the crawler at rest, every
found key carrying its quiet mark.

Every key here is a mask. No string in this file is long enough to look like a real key, and
there is no private-key header at all.
Note that betterleaks, gitleaks and trufflehog all skip a plain .svg by type (checked
2026-11-03: "scanned ~0 bytes"), so scan a copy with a line of text in front of it to get
real coverage.

Usage: render_hero.py [out_dir] [--png]
  out_dir  default: ../docs/assets next to this script
  writes   hero.svg (1280x560), hero-narrow.svg (640x560, for phones), social-card.svg (1280x640)
  --png    also write social-card.png (1280x640) with headless Google Chrome
"""
import bisect
import math
import os
import random
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(os.path.dirname(HERE), "docs", "assets")
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

SEED = 11
T = 8.0  # loop length in seconds

# ---- palette (the only colors used) -------------------------------------------------
PAGE = "#000000"
PANEL = "#05060b"
DIM = "#3b4680"
DIM2 = "#59649e"
ICE = "#e8f0ff"
WIRE = "#9fb3ff"
MAGENTA = "#ff2bd6"
VIOLET = "#8a3dff"
BLUE = "#3d7bff"
SKY = "#5fb4ff"
AMBER = "#ffc23d"
MINT = "#3dffa0"
RED = "#ff3b5c"
LIME = "#d4ff3d"
WHITE = "#ffffff"
PALETTE = (PAGE, PANEL, DIM, DIM2, ICE, WIRE, MAGENTA, VIOLET, BLUE, SKY, AMBER, MINT, RED, LIME, WHITE)

MONO = 'ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace'
SANS = '-apple-system,"Segoe UI",Helvetica,Arial,sans-serif'
ADV = 0.6  # monospace advance in em; textLength pins every real font to it
UI_ADV = 0.53  # average UI-font advance in em; sizes boxes only, never places text
BUL = chr(0x2022)
NBSP = chr(0xA0)


# ---- small helpers -------------------------------------------------------------------
def n(x):
    s = ("%.2f" % x).rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _lin(c):
    c = c / 255.0
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def lum(h):
    r, g, b = int(h[1:3], 16), int(h[3:5], 16), int(h[5:7], 16)
    return 0.2126 * _lin(r) + 0.7152 * _lin(g) + 0.0722 * _lin(b)


def contrast(a, b):
    la, lb = lum(a), lum(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


def blend(fg, bg, a):
    f = [int(fg[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(bg[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(int(round(f[i] * a + b[i] * (1 - a))) for i in range(3))


# ---- the keys (all masks) ------------------------------------------------------------
def mask(prefix, bullets, tail):
    return prefix + BUL * bullets + tail


# id -> (masked key, outline colour). Mixed providers (Stripe, Slack, GitHub, AWS, OpenAI,
# Google). Two colours repeat, never on keys found one after the other.
KEYS = {
    "stripe": (mask("sk_live_", 8, "a1B2"), MAGENTA),
    "slack": (mask("xoxb-", 8, "7Hq2"), SKY),
    "github": (mask("ghp_", 8, "9f3K"), VIOLET),
    "aws": (mask("AKIA", 8, "Q7XZ"), AMBER),
    "openai": (mask("sk-proj-", 8, "w3Rt"), BLUE),
    "gcp": (mask("AIza", 8, "xR0s"), MAGENTA),
}

KEYWORDS = {"import", "export", "const", "from", "new", "async", "await", "function", "return", "default", "let", "if", "else"}

# ---- scene specs ---------------------------------------------------------------------
# Code lines: <<id>> is a masked key. The open file is an excerpt (first_line says where it
# starts), the middle of one config object, so no line needs an opening or a closing brace and
# the keys can sit wherever the route passes: short property names put a key at the left of the
# panel, a one-line nested object puts it at the right. Six keys, one on each of six lines.
HERO_CODE = [
    "  retries: RETRIES,",
    "  timeout: TIMEOUT,",
    "  region: REGION,",
    '  gcp: { project: PROJECT, apiKey: "<<gcp>>" },',
    '  stripe: "<<stripe>>",',
    "  webhook: WEBHOOK,",
    "  poolSize: 4,",
    "  debug: false,",
    "  tls: true,",
    "  owner: OWNER,",
    '  slack: "<<slack>>",',
    "  proxy: PROXY,",
    '  github: { host: HOST, token: "<<github>>" },',
    '  llm: "<<openai>>",',
    '  aws: { region: REGION, pool: 4, accessKeyId: "<<aws>>" },',
]


def eight(cx, cy, a, b, count=56, wobble=(9, 6)):
    """Waypoints of a figure eight (a lemniscate of Bernoulli, a wide, b tall, nudged a little so it
    does not look drawn with a compass). It starts at the right-hand tip, runs along the bottom of
    the right loop, crosses itself at the centre, and goes on over the top of the left loop."""
    pts = []
    for k in range(count):
        t = 2 * math.pi * k / count
        d = 1 + math.sin(t) ** 2
        pts.append((
            cx + a * math.cos(t) / d + wobble[0] * math.sin(3 * t + 0.7),
            cy + b * math.sin(t) * math.cos(t) / d + wobble[1] * math.sin(2 * t + 1.3),
        ))
    return pts


HERO = {
    "name": "hero",
    "W": 1280,
    "H": 560,
    "animated": True,
    "title": "keyguard: your keys never reach GitHub",
    "desc": (
        "A lime centipede crawler climbs through a dim GitHub repository page in a figure eight: up and down the file "
        "tree, across the lines of one open file, up and down the commit history, and across the file again. Six masked "
        "API keys sit in the code. Each one lights up in place with a thin neon outline as the crawler reaches it, then "
        "settles to a quiet mark. The keyguard wordmark and the line Your keys never reach GitHub. sit in the top left "
        "corner. Violet neon tubes glow along the top and bottom edge."
    ),
    "brand": {"x": 40, "mark_y": 72, "mark": 34, "tag_y": 98, "tag": 16, "keepout": (24, 36, 300, 72)},
    "header": {"x": 368, "y": 62},
    "tree": {
        "x": 28, "y": 112, "w": 224, "h": 378, "row0": 138, "step": 22,
        "rows": [
            (0, "d", ".github"), (1, "d", "workflows"), (2, "f", "ci.yml"), (0, "d", "config"), (1, "s", "clients.js"),
            (1, "f", "defaults.json"), (0, "c", "src"), (0, "c", "tests"), (0, "c", "scripts"), (0, "f", ".env.example"),
            (0, "f", ".gitignore"), (0, "f", "package.json"), (0, "f", "README.md"),
        ],
    },
    "code": {"x": 272, "y": 112, "w": 648, "h": 378, "font": 14, "step": 22, "line0": 166, "lines": HERO_CODE, "first_line": 21, "file": "config / clients.js"},
    "commits": {"dir": "v", "x": 936, "y": 112, "w": 316, "h": 378},
    # a figure eight over the page: the right loop curls round the history, the left loop round the
    # file tree, and both cross the open file. The head reaches the six keys in two bursts of three,
    # one on each pass through the code, with a quiet climb up the tree and the history between.
    "route": eight(612, 340, 462, 380),
    "centipede": {"n": 15, "spacing": 23, "glow_tail": 12},
    "spider": (1200, 190, 430),
    "t_rest": 3.9,
}

# The still for the repo's social preview. Same scene, no motion: the crawler at rest and a
# few lit keys; the wordmark and tagline are set big enough to read at thumbnail size.
CARD_CODE = [
    "// config/clients.js",
    "export const stripe = {",
    '  secret: "<<stripe>>",',
    "  retries: RETRIES,",
    "};",
    'export const github = { token: "<<github>>" };',
    "export const slack = new WebClient(",
    '  "<<slack>>",',
    ");",
    "",
    "export default { stripe, github, slack };",
]


CARD = {
    "name": "social-card",
    "W": 1280,
    "H": 640,
    "animated": False,
    "title": "keyguard: your keys never reach GitHub",
    "desc": (
        "The keyguard wordmark and the line Your keys never reach GitHub. in the top left corner. Behind them a dim "
        "GitHub repository page: a file tree and one open file. A lime centipede crawler rests across the file and "
        "three masked API keys it found are lit with thin neon outlines. Violet neon tubes glow along the top and "
        "bottom edge."
    ),
    "brand": {"x": 64, "mark_y": 174, "mark": 92, "tag_y": 228, "tag": 32, "keepout": (40, 92, 520, 160)},
    "header": None,
    "tree": {
        "x": 40, "y": 300, "w": 224, "h": 276, "row0": 326, "step": 24,
        "rows": [
            (0, "d", ".github"), (0, "d", "config"), (1, "s", "clients.js"), (1, "f", "defaults.json"), (0, "c", "src"),
            (0, "c", "tests"), (0, "f", ".gitignore"), (0, "f", "package.json"), (0, "f", "README.md"),
        ],
    },
    "code": {"x": 560, "y": 56, "w": 680, "h": 520, "font": 17, "step": 28, "line0": 130, "lines": CARD_CODE, "file": "config / clients.js"},
    "commits": {"dir": "h", "y": 606, "x0": 40, "x1": 1240},
    # an S across the empty lower half of the file, the head up at the right; the rest of the
    # loop is only there to close the curve
    "route": [(720, 498), (790, 462), (860, 448), (930, 462), (1000, 490), (1070, 492), (1130, 462), (1166, 416), (1196, 372), (1196, 520), (1100, 556), (940, 556), (800, 540)],
    "head_at": 7,
    "lit": ("stripe", "github", "slack"),  # the still shows its three keys fully lit
    "centipede": {"n": 16, "spacing": 26, "glow_tail": 6},
    "spider": None,
    "t_rest": 0.0,
}


# The phone variant of the hero: a 640 px canvas that GitHub's 358 px column shows at 56 %, so the
# wordmark, the tagline, the crawler and the keys are drawn about twice as large as in the wide
# image, and the page is cut down to the open file with four keys. The same figure eight, one
# pass through the code per half lap.
NARROW_CODE = [
    "  retries: RETRIES,",
    "  keys: [",
    '    "<<stripe>>",',
    '    { project: PROJECT, key: "<<gcp>>" },',
    "  ],",
    "  poolSize: 4,",
    "  more: [",
    '    { host: HOST, id: ID, token: "<<github>>" },',
    '    "<<slack>>",',
]

NARROW = {
    "name": "hero-narrow",
    "W": 640,
    "H": 560,
    "animated": True,
    "title": "keyguard: your keys never reach GitHub",
    "desc": (
        "The phone-sized version of the keyguard hero. The keyguard wordmark and the line Your keys never reach GitHub. "
        "sit at the top left. Below them a dim GitHub code file. A large lime centipede crawler climbs through it in a "
        "figure eight, and each of the four masked API keys in the file lights up with a thin neon outline as the crawler "
        "reaches it, then settles to a quiet mark. Violet neon tubes glow along the top and bottom edge."
    ),
    "brand": {"x": 32, "mark_y": 104, "mark": 62, "tag_y": 140, "tag": 23, "keepout": (24, 56, 340, 100)},
    "header": None,
    "tree": None,
    "code": {"x": 24, "y": 190, "w": 592, "h": 336, "font": 16, "step": 30, "line0": 244, "lines": NARROW_CODE, "first_line": 21, "file": "config / clients.js"},
    "commits": None,
    "route": eight(340, 392, 270, 344, wobble=(7, 5)),
    "reach": 100,  # the larger crawler's long spokes reach about 96 px
    "centipede": {"n": 13, "spacing": 30, "glow_tail": 10, "sz": 1.25},
    "spider": None,
    "t_rest": 4.0,
}


# ---- the route -----------------------------------------------------------------------
def lerp2(a, b, t):
    return (a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t)


def spline(pts, per=40):
    """Closed centripetal Catmull-Rom curve through pts, as a dense polyline."""
    m = len(pts)
    out = []
    for i in range(m):
        p0, p1, p2, p3 = pts[(i - 1) % m], pts[i], pts[(i + 1) % m], pts[(i + 2) % m]
        t0 = 0.0
        t1 = t0 + math.hypot(p1[0] - p0[0], p1[1] - p0[1]) ** 0.5
        t2 = t1 + math.hypot(p2[0] - p1[0], p2[1] - p1[1]) ** 0.5
        t3 = t2 + math.hypot(p3[0] - p2[0], p3[1] - p2[1]) ** 0.5
        for k in range(per):
            t = t1 + (t2 - t1) * k / per
            a1 = lerp2(p0, p1, (t - t0) / (t1 - t0))
            a2 = lerp2(p1, p2, (t - t1) / (t2 - t1))
            a3 = lerp2(p2, p3, (t - t2) / (t3 - t2))
            b1 = lerp2(a1, a2, (t - t0) / (t2 - t0))
            b2 = lerp2(a2, a3, (t - t1) / (t3 - t1))
            out.append(lerp2(b1, b2, (t - t1) / (t2 - t1)))
    return out


class Route:
    """The closed path the crawler walks, by arc length s in [0, L). The head moves at one
    speed, so the loop time of a point is s / L * T."""

    def __init__(self, pts):
        dense = spline(pts)
        self.cum = [0.0]
        for a, b in zip(dense, dense[1:] + dense[:1]):
            self.cum.append(self.cum[-1] + math.hypot(b[0] - a[0], b[1] - a[1]))
        self.L = self.cum[-1]
        self.pts = dense + dense[:1]

    def at(self, s):
        s %= self.L
        i = min(bisect.bisect_right(self.cum, s) - 1, len(self.pts) - 2)
        seg = self.cum[i + 1] - self.cum[i]
        f = (s - self.cum[i]) / seg if seg > 0 else 0.0
        return lerp2(self.pts[i], self.pts[i + 1], f)

    def heading(self, s):
        a, b = self.at(s - 3.0), self.at(s + 3.0)
        return math.atan2(b[1] - a[1], b[0] - a[0])

    def time(self, s):
        return (s % self.L) / self.L * T


def rect_dist(p, r):
    """Distance from point p to rect r = (x, y, w, h); 0 inside."""
    dx = max(r[0] - p[0], 0.0, p[0] - (r[0] + r[2]))
    dy = max(r[1] - p[1], 0.0, p[1] - (r[1] + r[3]))
    return math.hypot(dx, dy)


def visits(route, rect, near, gap=1.6, step=4.0):
    """Loop-time intervals (t_in, t_out, closest) in which the head is within `near` px of
    rect; visits less than `gap` seconds apart are one visit."""
    m = int(route.L / step)
    d = [rect_dist(route.at(k * route.L / m), rect) for k in range(m)]
    if min(d) > near:
        return []
    flag = [x <= near for x in d]
    if all(flag):
        return [(0.0, T, min(d))]
    k0 = flag.index(False)
    runs = []
    cur = None
    for j in range(m):
        k = (k0 + j) % m
        if flag[k] and cur is None:
            cur = [k0 + j, k0 + j, d[k]]
        elif flag[k]:
            cur[1] = k0 + j
            cur[2] = min(cur[2], d[k])
        elif cur is not None:
            runs.append(cur)
            cur = None
    if cur is not None:
        runs.append(cur)
    per = T / m
    out = []
    for a, b, dm in runs:
        t_in, t_out = a * per, (b + 1) * per
        if out and t_in - out[-1][1] < gap:
            out[-1] = (out[-1][0], t_out, min(out[-1][2], dm))
        else:
            out.append((t_in, t_out, dm))
    if len(out) > 1 and out[0][0] + T - out[-1][1] < gap:  # the last visit runs into the first one
        out[0] = (out[-1][0], out[0][1] + T, min(out[0][2], out[-1][2]))
        out.pop()
    return [(t_in % T, t_out, dm) for t_in, t_out, dm in out]


# ---- CSS keyframes -------------------------------------------------------------------
class Css:
    """Collects @keyframes. Every timeline starts and ends in the same state, so the loop
    has no seam."""

    def __init__(self, animated):
        self.animated = animated
        self.rules = []

    def frames(self, name, frames, seam=True):
        """frames: [(t_seconds, 'css declarations')]; first at 0, last at T. With seam the two
        must be the same state; the crawl turns a whole lap past its start, which looks the same."""
        assert abs(frames[0][0]) < 1e-9 and abs(frames[-1][0] - T) < 1e-9, name
        assert not seam or frames[0][1] == frames[-1][1], "loop seam in %s" % name
        body = []
        for t, decl in frames:
            pct = ("%.3f" % (t / T * 100.0)).rstrip("0").rstrip(".")
            body.append("%s%%{%s}" % (pct, decl))
        self.rules.append("@keyframes %s{%s}" % (name, "".join(body)))


def delay(t_start):
    """animation-delay that puts frame 0 of an infinite T-long animation at loop time t_start."""
    return "animation-delay:%ss" % n((t_start % T) - T)


# ---- the dim repo page ---------------------------------------------------------------
COMMITS = [
    ("e3a91f7", "wip: checkout"), ("b21c04d", "fix webhook retries"), ("7d9f3a2", "add .env.example"),
    ("c58e610", "move secrets to vault"), ("a09b4e3", "bump deps"), ("2c7a5f1", "initial import"),
]
TABS = ["Code", "Issues", "Pull requests", "Actions", "Security", "Insights"]


class Page:
    """The dim page: svg parts in paint order, plus every word on it as a token (a box the
    crawler can light up) and the position of every key."""

    def __init__(self):
        self.parts = []
        self.tokens = []
        self.keys = []

    def add(self, s):
        self.parts.append(s)

    def word(self, fam, size, x, y, text, tone, weight=None):
        """One dim word. It is drawn here and kept as a token, so a bright copy can be laid
        over it when the crawler passes."""
        w = len(text) * size * (ADV if fam == "m" else UI_ADV)
        self.tokens.append({"fam": fam, "size": size, "x": x, "y": y, "w": w, "text": text, "weight": weight})
        wt = ' font-weight="%s"' % weight if weight else ""
        self.add('<text class="%s %s" x="%s" y="%s" font-size="%s"%s>%s</text>' % (fam, tone, n(x), n(y), n(size), wt, esc(text)))
        return w


def panel_rect(P, x, y, w, h):
    P.add('<rect x="%s" y="%s" width="%s" height="%s" rx="8" fill="%s" stroke="%s" stroke-opacity=".5"/>' % (n(x), n(y), n(w), n(h), PANEL, DIM))


def header(P, h):
    x, y = h["x"], h["y"]
    P.add('<circle cx="%s" cy="%s" r="11" fill="%s" fill-opacity=".45"/>' % (n(x + 11), n(y), DIM))
    P.add('<circle cx="%s" cy="%s" r="3.8" fill="%s"/>' % (n(x + 11), n(y - 2.5), DIM2))
    P.add('<path d="M%s %sq6.5 -7 13 0" fill="%s"/>' % (n(x + 4.5), n(y + 8), DIM2))
    cx = x + 30
    cx += P.word("s", 16, cx, y + 5, "acme-labs", "d1") + 7
    cx += P.word("s", 16, cx, y + 5, "/", "d1") + 7
    P.word("s", 16, cx, y + 5, "checkout-api", "d2", weight=700)
    tx = x
    for i, label in enumerate(TABS):
        w = P.word("s", 13, tx, y + 36, label, "d2" if i == 0 else "d1")
        if i == 0:
            P.add('<rect x="%s" y="%s" width="%s" height="2" rx="1" fill="%s"/>' % (n(tx), n(y + 44), n(w), DIM2))
        tx += w + 22
    # branch pill, top right of the header
    bx = 1040
    P.add('<rect x="%s" y="%s" width="104" height="26" rx="13" fill="%s" stroke="%s" stroke-opacity=".7"/>' % (n(bx), n(y - 14), PANEL, DIM2))
    P.add(
        '<g fill="none" stroke="%s" stroke-width="1.4" stroke-linecap="round"><circle cx="%s" cy="%s" r="2.2"/><circle cx="%s" cy="%s" r="2.2"/>'
        '<circle cx="%s" cy="%s" r="2.2"/><path d="M%s %sv5.6M%s %sq0 4 -4 4"/></g>'
        % (DIM2, n(bx + 17), n(y - 5), n(bx + 17), n(y + 7), n(bx + 25), n(y - 1), n(bx + 17), n(y - 3), n(bx + 25), n(y + 1))
    )
    P.word("s", 13, bx + 36, y + 3, "main", "d2", weight=600)
    P.add('<path d="M%s %sl4 4 4 -4" fill="none" stroke="%s" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>' % (n(bx + 81), n(y - 2), DIM2))


def tree(P, t):
    x0, y0, w, h = t["x"], t["y"], t["w"], t["h"]
    panel_rect(P, x0, y0, w, h)
    rows = t["rows"]
    ys = [t["row0"] + r * t["step"] for r in range(len(rows))]
    for r, (ind, kind, label) in enumerate(rows):
        if kind == "d":  # an open folder: a guide runs down its children
            last = r
            while last + 1 < len(rows) and rows[last + 1][0] > ind:
                last += 1
            if last > r:
                gx = x0 + 20 + ind * 16
                P.add('<path d="M%s %sV%s" stroke="%s" stroke-opacity=".45"/>' % (n(gx), n(ys[r] + 9), n(ys[last] + 3), DIM))
    for r, (ind, kind, label) in enumerate(rows):
        cy = ys[r]
        bx = x0 + 16 + ind * 16
        if kind == "s":
            P.add('<rect x="%s" y="%s" width="%s" height="%s" rx="5" fill="%s" fill-opacity=".24"/>' % (n(x0 + 5), n(cy - 11), n(w - 10), n(t["step"] - 1), DIM))
            P.add('<rect x="%s" y="%s" width="2.5" height="14" rx="1.2" fill="%s"/>' % (n(x0 + 5), n(cy - 7), DIM2))
        if kind in "dc":
            d = "M%s %sl4 4 -4 4" % (n(bx), n(cy - 4)) if kind == "c" else "M%s %sl4 4 4 -4" % (n(bx - 1), n(cy - 2))
            P.add('<path d="%s" fill="none" stroke="%s" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>' % (d, DIM2))
            P.add('<path d="M%s %sh4.4l1.8 2H%sv7.4H%sz" fill="%s" fill-opacity=".6"/>' % (n(bx + 12), n(cy - 6.6), n(bx + 25), n(bx + 12), DIM))
        else:
            P.add('<path d="M%s %sh6l3.6 3.6v7.2h-9.6z" fill="%s" fill-opacity=".3" stroke="%s" stroke-width="1" stroke-linejoin="round"/>' % (n(bx + 12), n(cy - 6.6), DIM, DIM))
        P.word("s", 13, bx + 32, cy + 4.5, label, "d2" if kind == "s" else "d1", weight=600 if kind == "s" else None)


def code(P, c):
    x0, y0, w, h = c["x"], c["y"], c["w"], c["h"]
    fs, step = c["font"], c["step"]
    adv = ADV * fs
    panel_rect(P, x0, y0, w, h)
    bar = 28
    P.add('<path d="M%s %sH%s" stroke="%s" stroke-opacity=".4"/>' % (n(x0), n(y0 + bar), n(x0 + w), DIM))
    P.word("s", 12, x0 + 16, y0 + 18.5, c["file"], "d1")
    gx = x0 + 16 + 3 * adv  # right edge of the line numbers
    tx = gx + 18
    for i, line in enumerate(c["lines"]):
        y = c["line0"] + step * i
        P.add('<text class="m d1" x="%s" y="%s" font-size="%s" text-anchor="end" fill-opacity=".7">%d</text>' % (n(gx), n(y), n(fs - 1), i + c.get("first_line", 1)))
        if not line:
            continue
        # walk the line: words (tokens), spaces and keys
        col = 0
        out = []
        for m in re.finditer(r"<<(\w+)>>|\s+|(?:(?!<<)\S)+", line):
            piece = m.group(0)
            if m.group(1):
                text = KEYS[m.group(1)][0]
                P.keys.append({"id": m.group(1), "x": tx + col * adv, "y": y, "fs": fs, "text": text, "color": KEYS[m.group(1)][1], "w": len(text) * adv})
                out.append(esc(text))
                col += len(text)
            elif piece.isspace():
                out.append(NBSP * len(piece))
                col += len(piece)
            else:
                word = piece
                core = word.strip('"(){}[];,')
                if core in KEYWORDS:
                    out.append('<tspan class="d2">%s</tspan>' % esc(word))
                else:
                    out.append(esc(word))
                P.tokens.append({"fam": "m", "size": fs, "x": tx + col * adv, "y": y, "w": len(word) * adv, "text": word, "weight": None})
                col += len(word)
        tone = "d2" if line.startswith("//") else "d1"
        P.add('<text class="m %s" x="%s" y="%s" font-size="%s" textLength="%s" lengthAdjust="spacing">%s</text>' % (tone, n(tx), n(y), n(fs), n(col * adv), "".join(out)))
    # a scrollbar thumb, as the real page has
    P.add('<rect x="%s" y="%s" width="4" height="%s" rx="2" fill="%s" fill-opacity=".3"/>' % (n(x0 + w - 12), n(y0 + bar + 12), n(h * 0.34), DIM))


def commits(P, c):
    if c["dir"] == "h":  # a strip along the bottom
        y, x0, x1 = c["y"], c["x0"], c["x1"]
        P.add('<path d="M%s %sH%s" stroke="%s" stroke-opacity=".5"/>' % (n(x0), n(y), n(x1), DIM))
        gap = (x1 - x0) / float(len(COMMITS))
        for i, (sha, msg) in enumerate(COMMITS):
            x = x0 + 8 + gap * i
            P.add('<circle cx="%s" cy="%s" r="4.2" fill="%s" stroke="%s" stroke-width="1.5"/>' % (n(x), n(y), PAGE, DIM2))
            w = P.word("m", 11, x + 12, y + 4, sha, "d2")
            P.word("s", 11, x + 12 + w + 8, y + 4, msg, "d1")
        return
    x0, y0, w, h = c["x"], c["y"], c["w"], c["h"]  # a history panel down the right side
    panel_rect(P, x0, y0, w, h)
    P.add('<path d="M%s %sH%s" stroke="%s" stroke-opacity=".4"/>' % (n(x0), n(y0 + 28), n(x0 + w), DIM))
    P.word("s", 12, x0 + 16, y0 + 18.5, "History", "d1")
    rail = x0 + 24
    pitch = 48
    ys = [y0 + 66 + pitch * i for i in range(len(COMMITS))]
    P.add('<path d="M%s %sV%s" stroke="%s" stroke-opacity=".5"/>' % (n(rail), n(ys[0]), n(ys[-1]), DIM))
    for (sha, msg), cy in zip(COMMITS, ys):
        P.add('<circle cx="%s" cy="%s" r="4.4" fill="%s" stroke="%s" stroke-width="1.5"/>' % (n(rail), n(cy), PAGE, DIM2))
        P.word("s", 13, rail + 20, cy - 1, msg, "d2")
        P.word("m", 11, rail + 20, cy + 15, sha, "d1")


def build_page(spec):
    P = Page()
    if spec.get("header"):
        header(P, spec["header"])
    if spec.get("tree"):
        tree(P, spec["tree"])
    code(P, spec["code"])
    if spec.get("commits"):
        commits(P, spec["commits"])
    return P


# ---- words the crawlers pass light up -----------------------------------------------
PULSE_NEAR = 34  # px between the centipede's head and a word for it to light up
REACH = 86       # px the crawler keeps from the title corner: its long leg spokes reach about 80 px


class Pendulum:
    """The small crawler's track: down and up a line once per loop, eased at both ends. Like
    Route it answers at(s) for s in [0, L), with the loop time of s being s / L * T."""

    def __init__(self, x, y0, y1):
        self.x, self.y0, self.y1 = x, y0, y1
        self.L = 1000.0

    def at(self, s):
        u = (s % self.L) / self.L
        return (self.x, self.y0 + (self.y1 - self.y0) * (0.5 - 0.5 * math.cos(2 * math.pi * u)))


def pulses(css, P, tracks, animated):
    """A bright copy of each word a crawler's head passes, laid over the dim one. Its
    opacity follows one shared pulse (up fast, held while the body goes by, a slow fade),
    started at the loop time the head arrives. Hidden in the base styles, so the still shows
    none. tracks: [(route, px within which a word lights up)]."""
    if not animated:
        return ""
    css.rules.append("@keyframes pl{0%{opacity:0}1.5%{opacity:.5}8%{opacity:.5}25%{opacity:0}100%{opacity:0}}")
    out = []
    for tok in P.tokens:
        rect = (tok["x"], tok["y"] - tok["size"] * 0.8, tok["w"], tok["size"] * 1.05)
        for route, near in tracks:
            for t_in, _t_out, _d in visits(route, rect, near, gap=2.0):
                wt = ' font-weight="%s"' % tok["weight"] if tok["weight"] else ""
                tl = ' textLength="%s" lengthAdjust="spacing"' % n(tok["w"]) if tok["fam"] == "m" else ""
                out.append(
                    '<text class="k pl %s" style="%s" x="%s" y="%s" font-size="%s"%s%s fill="%s" opacity="0">%s</text>'
                    % (tok["fam"], delay(t_in), n(tok["x"]), n(tok["y"]), n(tok["size"]), wt, tl, WIRE, esc(tok["text"]))
                )
    return "".join(out)


def spider_svg(rng, scale, animated):
    """A small ice crawler: eight legs (each a chain of joints), chords between neighbours
    and a few strays. The legs wiggle on a 1 s loop, phase-shifted, so it looks alive."""
    legs = []
    for i in range(8):
        a = (i + rng.uniform(-0.16, 0.16)) * 2 * math.pi / 8
        pts = [(0.0, 0.0)]
        r = rng.uniform(22, 32)
        x, y = r * math.cos(a), r * math.sin(a)
        pts.append((x, y))
        for _ in range(rng.choice([2, 2, 3])):
            a += rng.uniform(-0.75, 0.75)
            r = rng.uniform(18, 34)
            x, y = x + r * math.cos(a), y + r * math.sin(a)
            pts.append((x, y))
        legs.append(pts)
    out = ['<g transform="scale(%s)">' % n(scale)]
    for i in range(7):
        base = legs[rng.randrange(8)]
        j = base[rng.randrange(1, len(base))]
        ang = rng.uniform(0, 2 * math.pi)
        rr = rng.uniform(18, 38)
        e = (j[0] + rr * math.cos(ang), j[1] + rr * math.sin(ang))
        out.append('<line x1="%s" y1="%s" x2="%s" y2="%s" stroke="%s" stroke-opacity=".4" stroke-width="1.2"/>' % (n(j[0]), n(j[1]), n(e[0]), n(e[1]), WIRE))
        out.append('<circle cx="%s" cy="%s" r="2" fill="%s" fill-opacity=".85"/>' % (n(e[0]), n(e[1]), ICE))
    for i in range(8):
        if rng.random() < 0.75:
            a, b = legs[i][1], legs[(i + 1) % 8][1]
            out.append('<line x1="%s" y1="%s" x2="%s" y2="%s" stroke="%s" stroke-opacity=".45" stroke-width="1.2"/>' % (n(a[0]), n(a[1]), n(b[0]), n(b[1]), WIRE))
    for i, pts in enumerate(legs):
        poly = " ".join("%s,%s" % (n(x), n(y)) for x, y in pts)
        cls = ' class="w" style="animation-delay:-%ss"' % n(i * 0.125) if animated else ""
        out.append("<g%s>" % cls)
        out.append('<polyline points="%s" fill="none" stroke="%s" stroke-opacity=".8" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>' % (poly, WIRE))
        for j, (x, y) in enumerate(pts[1:], start=1):
            out.append('<circle cx="%s" cy="%s" r="%s" fill="%s"/>' % (n(x), n(y), 3.2 if j < len(pts) - 1 else 2.4, ICE))
        out.append("</g>")
    out.append('<circle r="19" fill="%s" fill-opacity=".10"/><circle r="11" fill="none" stroke="%s" stroke-opacity=".75" stroke-width="1.4"/>' % (WIRE, WIRE))
    out.append('<circle r="5.6" fill="%s"/><circle r="2.2" fill="%s"/>' % (ICE, PAGE))
    out.append("</g>")
    return "".join(out)


def spider_track(css, track, s_rest, animated):
    """The small crawler on its track: placed at rest, and, animated, one eased pass down
    and back per loop."""
    x, y = track.at(s_rest)
    cls = ""
    if animated:
        frames = []
        for k in range(41):
            px, py = track.at(track.L * k / 40.0)
            frames.append((T * k / 40.0, "transform:translate(%spx,%spx)" % (n(px), n(py))))
        css.frames("sp", frames)
        cls = ' class="k" style="animation-name:sp"'
    return "<g%s transform=\"translate(%s %s)\">%s</g>" % (cls, n(x), n(y), spider_svg(random.Random(SEED + 3), 0.42, animated))


# ---- the crawler ---------------------------------------------------------------------
def crawl_frames(route, samples):
    frames = []
    prev = None
    for k in range(samples + 1):
        s = route.L * k / samples
        x, y = route.at(s)
        a = route.heading(s)
        if prev is not None:
            while a - prev > math.pi:
                a -= 2 * math.pi
            while a - prev < -math.pi:
                a += 2 * math.pi
        prev = a
        frames.append((T * k / samples, "transform:translate(%spx,%spx) rotate(%sdeg)" % (n(x), n(y), n(math.degrees(a)))))
    return frames


def centipede(css, route, spec, s_head, rng, animated):
    """A chain of lime chips with fine legs. Every chip plays the same keyframes (the route
    at constant speed) a little later than the one in front, so the body follows the head."""
    nseg, spacing = spec["n"], spec["spacing"]
    sz = spec.get("sz", 1.0)  # the phone variant draws the crawler larger, so it still reads at 56 %
    gap = spacing / route.L * T
    if animated:
        css.frames("crawl", crawl_frames(route, 260), seam=False)
        css.rules.append("@keyframes lw{0%,100%{transform:rotate(-11deg)}50%{transform:rotate(11deg)}}")
        css.rules.append("@keyframes an{0%,100%{transform:rotate(-9deg)}50%{transform:rotate(9deg)}}")
    parts = []
    for i in reversed(range(nseg)):  # tail first, so the head draws on top
        t_s = i / float(nseg - 1)
        w = (25.0 if i == 0 else 19.0 - 6.0 * t_s) * sz
        h = (22.0 if i == 0 else 16.5 - 4.5 * t_s) * sz
        glen = (16.0 + 30.0 * math.sin(math.pi * (i + 0.5) / nseg)) * sz
        if i % 5 == 2:
            glen *= 1.5  # a few long spokes
        s = s_head - i * spacing
        x, y = route.at(s)
        base = "translate(%s %s) rotate(%s)" % (n(x), n(y), n(math.degrees(route.heading(s))))
        cls = ' class="k cr" style="animation-delay:%ss"' % n(i * gap - T) if animated else ""
        seg = ['<g%s transform="%s">' % (cls, base)]
        lw = ' class="k lw" style="animation-delay:-%ss"' % n((i * 0.09) % 0.8) if animated else ""
        seg.append("<g%s>" % lw)
        for side in (1, -1):
            knee = (-rng.uniform(1.0, 7.0) * sz, side * (h / 2.0 + glen * 0.55))
            foot = (-rng.uniform(10.0, 22.0) * sz, side * (h / 2.0 + glen))
            seg.append(
                '<polyline points="0,%s %s,%s %s,%s" fill="none" stroke="%s" stroke-opacity=".7" stroke-width="%s" stroke-linecap="round" stroke-linejoin="round"/>'
                % (n(side * h / 2.0), n(knee[0]), n(knee[1]), n(foot[0]), n(foot[1]), LIME, n(1.2 * sz))
            )
            seg.append('<circle cx="%s" cy="%s" r="%s" fill="%s" fill-opacity=".8"/><circle cx="%s" cy="%s" r="%s" fill="%s"/>' % (n(knee[0]), n(knee[1]), n(1.3 * sz), LIME, n(foot[0]), n(foot[1]), n(2 * sz), LIME))
        seg.append("</g>")
        if i == 0:
            seg.append('<rect x="%s" y="%s" width="%s" height="%s" rx="4" fill="%s" fill-opacity=".92" stroke="%s" stroke-width="%s"/>' % (n(-w / 2), n(-h / 2), n(w), n(h), LIME, LIME, n(1.5 * sz)))
            seg.append('<circle cx="%s" cy="%s" r="%s" fill="%s"/><circle cx="%s" cy="%s" r="%s" fill="%s"/>' % (n(w / 4), n(-h / 4), n(2.3 * sz), PAGE, n(w / 4), n(h / 4), n(2.3 * sz), PAGE))
            for side in (1, -1):  # each antenna turns about its root, out of step with the other
                an = ' class="k an" style="animation-delay:-%ss"' % ("0" if side == 1 else "0.8") if animated else ""
                seg.append(
                    '<g transform="translate(%s %s)"><g%s><polyline points="0,0 %s,%s %s,%s" fill="none" stroke="%s" stroke-opacity=".85" stroke-width="%s" stroke-linecap="round" stroke-linejoin="round"/>'
                    '<circle cx="%s" cy="%s" r="%s" fill="%s"/></g></g>' % (n(w / 2), n(side * 3 * sz), an, n(16 * sz), n(side * 7 * sz), n(32 * sz), n(side * 5 * sz), LIME, n(1.2 * sz), n(32 * sz), n(side * 5 * sz), n(2 * sz), ICE)
                )
        else:
            seg.append('<rect x="%s" y="%s" width="%s" height="%s" rx="3" fill="%s" fill-opacity=".74" stroke="%s" stroke-width="%s"/>' % (n(-w / 2), n(-h / 2), n(w), n(h), PAGE, LIME, n(1.5 * sz)))
            seg.append('<rect x="%s" y="%s" width="%s" height="%s" rx="1.5" fill="%s" fill-opacity="%s"/>' % (n(-w / 2 + 3.5 * sz), n(-h / 2 + 3.5 * sz), n(w - 7 * sz), n(h - 7 * sz), LIME, ".9" if i < nseg - 1 else ".6"))
        seg.append("</g>")
        parts.append("".join(seg))
    return "".join(parts)


def aura(route, spec, s_head, animated):
    """The scan glow: soft lime discs that ride the route with the body (the same keyframes,
    the same delays) and carry on behind the tail with less and less light, so the glow is
    brightest at the head and fades along the path the crawler just walked."""
    nseg, spacing, tail = spec["n"], spec["spacing"], spec["glow_tail"]
    sz = spec.get("sz", 1.0)
    gap = spacing / route.L * T
    out = []
    for i in range(nseg + tail):
        if i < nseg:
            a = 1.0 - 0.4 * i / nseg
        else:
            a = 0.6 * (1.0 - (i - nseg + 1.0) / (tail + 1.0))
        x, y = route.at(s_head - i * spacing)
        cls = ' class="k cr" style="animation-delay:%ss"' % n(i * gap - T) if animated else ""
        out.append('<circle%s r="%s" fill="url(#halo)" opacity="%s" transform="translate(%s %s)"/>' % (cls, n((46 if i == 0 else 36) * sz), n(a), n(x), n(y)))
    return "".join(out)


# ---- the lit keys --------------------------------------------------------------------
KEY_NEAR = 46  # px between the head and a key for it to light up
GLOW_S = 1.9   # seconds from the head's arrival to the key being back at its quiet mark
Q_OL, Q_TX = 0.32, 0.82  # a found key at rest: its outline at a third of full strength, its text a little dimmed
LIT = {  # seconds after ignition -> opacity; the rest of the loop a key sits at its quiet mark
    "ko": [(0, Q_OL), (0.12, 1), (1.0, 1), (GLOW_S, Q_OL), (T, Q_OL)],  # the outline
    "kt": [(0, Q_TX), (0.12, 1), (1.0, 1), (GLOW_S, Q_TX), (T, Q_TX)],  # the key text
    "kf": [(0, 0), (0.12, 1), (0.6, 0.55), (GLOW_S, 0), (T, 0)],        # the neon glow around it
}


def lit_keys(css, P, route, animated, lit_ids=()):
    """Each key gets a dark plate (it covers the quotes round the key, so the dim line never shows
    through), an outline, a glow and bright text laid over the dim line. All of them sit at the
    key's quiet mark in the base styles, which is what prefers-reduced-motion shows; the loop
    raises them to full when the head arrives and lets them fall back. They share keyframes; a
    key's own animation-delay starts them at the head's arrival. lit_ids are keys drawn fully
    lit in the base styles (the still of the social card)."""
    if animated:
        for name, pts in LIT.items():
            css.rules.append("@keyframes %s{%s}" % (name, "".join("%s%%{opacity:%s}" % (n(t / T * 100.0), v) for t, v in pts)))
    out = []
    found = []
    for k in P.keys:
        fs = k["fs"]
        adv = ADV * fs
        rect = (k["x"], k["y"] - fs * 0.8, k["w"], fs * 1.1)
        vs = visits(route, rect, KEY_NEAR, gap=1.0)
        best = min(vs, key=lambda v: v[2]) if vs else None
        t_ign = best[0] if best else None
        found.append((k["id"], t_ign, best[2] if best else None, len(vs)))
        col = k["color"]
        on = k["id"] in lit_ids
        x0, y0 = k["x"] - 6, k["y"] - fs * 0.88 - 4
        w, h = k["w"] + 12, fs * 1.16 + 8
        r = 4.0
        d = "M%s %sH%sa%s %s 0 0 1 %s %sV%sa%s %s 0 0 1 -%s %sH%sa%s %s 0 0 1 -%s -%sV%sa%s %s 0 0 1 %s -%sZ" % (
            n(x0 + r), n(y0), n(x0 + w - r), r, r, r, r, n(y0 + h - r), r, r, r, r, n(x0 + r), r, r, r, r, n(y0 + r), r, r, r, r)
        dl = ' style="%s"' % delay(t_ign - 0.05) if animated and t_ign is not None else ""
        kc = lambda name: (' class="k %s"' % name) if animated else ""
        out.append(
            # the plate: one character wider than the key on each side, so it hides the quote marks
            '<rect x="%s" y="%s" width="%s" height="%s" rx="%s" fill="%s" opacity=".97"/>'
            "<g%s%s opacity=\"%s\">"
            '<rect x="%s" y="%s" width="%s" height="%s" rx="11" fill="%s" opacity=".14"/>'
            '<rect x="%s" y="%s" width="%s" height="%s" rx="7" fill="%s" opacity=".22"/></g>'
            '<path%s%s opacity="%s" d="%s" fill="%s" fill-opacity=".1" stroke="%s" stroke-width="1.5" stroke-opacity=".9" stroke-linejoin="round"/>'
            '<text class="m%s"%s opacity="%s" x="%s" y="%s" font-size="%s" font-weight="700" fill="%s" textLength="%s" lengthAdjust="spacing">%s</text>'
            % (
                n(x0 - adv), n(y0), n(w + 2 * adv), n(h), n(r), PANEL,
                kc("kf"), dl, "1" if on else "0",
                n(x0 - 6), n(y0 - 6), n(w + 12), n(h + 12), col,
                n(x0 - 2), n(y0 - 2), n(w + 4), n(h + 4), col,
                kc("ko"), dl, "1" if on else n(Q_OL), d, col, col,
                (" k kt" if animated else ""), dl, "1" if on else n(Q_TX),
                n(k["x"]), n(k["y"]), n(fs), ICE, n(k["w"]), esc(k["text"]),
            )
        )
    return "".join(out), found


# ---- neon strips ---------------------------------------------------------------------
def strip_svg(css, W, H, top):
    """A violet neon tube along one edge, with a wash that falls onto the page, a bloom
    around a hot core and a thin white-hot line in the middle. The bottom one is the top
    one turned over, so the page is lit from both sides."""
    cy = 8.0
    wash = '<rect width="%d" height="130" fill="url(#wash)"/>' % W
    bloom = '<ellipse cx="%s" cy="%s" rx="540" ry="74" fill="url(#bloom)"/>' % (n(W / 2.0), n(cy))
    tube = (
        '<rect x="10" y="2" width="%d" height="14" rx="7" fill="url(#tube)" fill-opacity=".4"/>'
        '<rect x="14" y="5.5" width="%d" height="5" rx="2.5" fill="url(#tube)"/>' % (W - 20, W - 28)
    )
    core = '<rect x="%s" y="6.6" width="760" height="2.8" rx="1.4" fill="url(#core)"/>' % n(W / 2.0 - 380)
    hot = '<ellipse cx="%s" cy="%s" rx="230" ry="17" fill="url(#hot)" opacity=".85"/>' % (n(W / 2.0), n(cy + 0.5))
    pul = ' class="pu" style="animation-delay:-%ss"' % ("0" if top else "2") if css.animated else ""
    body = "<g%s>%s%s</g>%s%s%s" % (pul, wash, bloom, tube, core, hot)
    if top:
        return "<g>%s</g>" % body
    return '<g transform="translate(0 %d) scale(1 -1)">%s</g>' % (H, body)


# ---- the title block -----------------------------------------------------------------
def brand_svg(b):
    wm = 8 * ADV * b["mark"]
    tag = "Your keys never reach GitHub."
    return (
        '<text class="m" x="%s" y="%s" font-size="%s" font-weight="700" fill="%s" textLength="%s" lengthAdjust="spacing">keyguard</text>'
        '<text class="s" x="%s" y="%s" font-size="%s" font-weight="600" fill="%s" textLength="%s" lengthAdjust="spacing">%s</text>'
        % (n(b["x"]), n(b["mark_y"]), n(b["mark"]), ICE, n(wm), n(b["x"] + 1), n(b["tag_y"]), n(b["tag"]), ICE, n(len(tag) * 0.5 * b["tag"]), esc(tag))
    )


# ---- the render ----------------------------------------------------------------------
def render(spec):
    W, H = spec["W"], spec["H"]
    animated = spec["animated"]
    rng = random.Random(SEED)
    css = Css(animated)
    route = Route(spec["route"])
    P = build_page(spec)
    warnings = []

    lit_s, found = lit_keys(css, P, route, animated, spec.get("lit", ()))
    for kid, t, dist, nvisits in found:
        if animated and t is None:
            warnings.append("the head never comes within %d px of key %s" % (KEY_NEAR, kid))
        if animated and nvisits > 1:
            warnings.append("key %s is reached %d times a lap and can light only once" % (kid, nvisits))
    times = sorted(t for _k, t, _d, _v in found if t is not None)
    if animated and len(times) > 1:
        gaps = [b - a for a, b in zip(times, times[1:])] + [times[0] + T - times[-1]]
        limit = max(3.0, 1.25 * T / len(times))  # evenly spread finds are T / count apart
        if max(gaps) > limit:
            warnings.append("%s s pass between two finds; spread the keys along the route" % n(max(gaps)))
    if spec.get("head_at") is not None:  # the still: the head sits on one of the waypoints
        s_head = route.cum[spec["head_at"] * 40]
        t_rest = route.time(s_head)
    else:
        t_rest = spec["t_rest"] if spec["t_rest"] is not None else (times[-1] + 0.9 if times else 0.0)
        s_head = t_rest / T * route.L

    # the route stays out of the title corner: a long spoke of the crawler's legs reaches about
    # 80 px from its path, and a leg tip must never touch the tagline
    kx, ky, kw, kh = spec["brand"]["keepout"]
    for k in range(int(route.L / 4)):
        px, py = route.at(k * 4.0)
        reach = spec.get("reach", REACH)
        if rect_dist((px, py), (kx, ky, kw, kh)) < reach:
            warnings.append("the route comes within %d px of the title corner at (%d, %d)" % (reach, px, py))
            break

    cent = centipede(css, route, spec["centipede"], s_head, random.Random(SEED + 7), animated)
    glow = aura(route, spec["centipede"], s_head, animated)
    tracks = [(route, PULSE_NEAR)]
    spider = ""
    if spec.get("spider"):
        sp = Pendulum(*spec["spider"])
        tracks.append((sp, 26))
        spider = spider_track(css, sp, t_rest / T * sp.L, animated)
    pls = pulses(css, P, tracks, animated)

    rx = 16
    style = [
        ".m{font-family:%s}" % MONO,
        ".s{font-family:%s}" % SANS,
        ".d1{fill:%s}.d2{fill:%s}" % (DIM, DIM2),
    ]
    if animated:
        style += [
            ".k{animation-duration:%ss;animation-iteration-count:infinite;animation-timing-function:linear;transform-box:view-box}" % n(T),
            ".cr{animation-name:crawl}",
            ".lw{animation-name:lw;animation-duration:.8s}",
            ".an{animation-name:an;animation-duration:1.6s}",
            ".pl{animation-name:pl}",
            ".ko{animation-name:ko}.kt{animation-name:kt}.kf{animation-name:kf}",
            ".w{animation:wig 1s ease-in-out infinite}",
            "@keyframes wig{0%,100%{transform:rotate(-5deg)}50%{transform:rotate(5deg)}}",
            ".pu{animation:pul 4s ease-in-out infinite}",
            "@keyframes pul{0%,100%{opacity:.8}50%{opacity:1}}",
        ]
        style += css.rules
        style.append("@media (prefers-reduced-motion:reduce){.k,.w,.pu{animation:none!important}}")
    svg = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-labelledby="t d">' % (W, H, W, H),
        '<title id="t">%s</title><desc id="d">%s</desc>' % (esc(spec["title"]), esc(spec["desc"])),
        "<defs>",
        '<clipPath id="rc"><rect width="%d" height="%d" rx="%d"/></clipPath>' % (W, H, rx),
        '<radialGradient id="halo"><stop offset="0" stop-color="%s" stop-opacity=".25"/><stop offset=".5" stop-color="%s" stop-opacity=".08"/><stop offset="1" stop-color="%s" stop-opacity="0"/></radialGradient>' % (LIME, LIME, LIME),
        '<pattern id="sl" width="4" height="3" patternUnits="userSpaceOnUse"><rect width="4" height="1" fill="%s" fill-opacity=".05"/></pattern>' % ICE,
        '<linearGradient id="wash" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="%s" stop-opacity=".66"/><stop offset=".22" stop-color="%s" stop-opacity=".28"/><stop offset=".6" stop-color="%s" stop-opacity=".08"/><stop offset="1" stop-color="%s" stop-opacity="0"/></linearGradient>' % (VIOLET, VIOLET, VIOLET, VIOLET),
        '<radialGradient id="bloom"><stop offset="0" stop-color="%s" stop-opacity=".95"/><stop offset=".35" stop-color="%s" stop-opacity=".5"/><stop offset="1" stop-color="%s" stop-opacity="0"/></radialGradient>' % (VIOLET, VIOLET, VIOLET),
        '<radialGradient id="hot"><stop offset="0" stop-color="%s" stop-opacity=".95"/><stop offset=".4" stop-color="%s" stop-opacity=".45"/><stop offset="1" stop-color="%s" stop-opacity="0"/></radialGradient>' % (ICE, VIOLET, VIOLET),
        '<linearGradient id="tube" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="%s" stop-opacity="0"/><stop offset=".12" stop-color="%s" stop-opacity=".85"/><stop offset=".5" stop-color="%s"/><stop offset=".88" stop-color="%s" stop-opacity=".85"/><stop offset="1" stop-color="%s" stop-opacity="0"/></linearGradient>' % (VIOLET, VIOLET, VIOLET, VIOLET, VIOLET),
        '<linearGradient id="core" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="%s" stop-opacity="0"/><stop offset=".5" stop-color="%s"/><stop offset="1" stop-color="%s" stop-opacity="0"/></linearGradient>' % (ICE, ICE, ICE),
        "</defs>",
        "<style>%s</style>" % "".join(style),
        '<g clip-path="url(#rc)">',
        '<rect width="%d" height="%d" fill="%s"/>' % (W, H, PAGE),
        "<g>%s</g>" % "".join(P.parts),
        strip_svg(css, W, H, True),
        strip_svg(css, W, H, False),
        "<g>%s</g>" % pls,
        "<g>%s</g>" % glow,
        "<g>%s</g>" % cent,
        spider,
        "<g>%s</g>" % lit_s,
        brand_svg(spec["brand"]),
        # the scan lines lie over everything, so a key's plate does not show as a smooth box in the striped page
        '<rect width="%d" height="%d" fill="url(#sl)"/>' % (W, H),
        "</g></svg>",
    ]
    info = {"route": route, "page": P, "found": found, "t_rest": t_rest}
    return "\n".join(svg) + "\n", warnings, info


TAGLINE = "Your keys never reach GitHub."
BRIGHT_WORDS = set(["keyguard", TAGLINE] + [text for text, _col in KEYS.values()])


def check(path):
    root = ET.parse(path).getroot()  # well-formed
    with open(path, encoding="utf-8") as fh:
        s = fh.read()
    body = s.replace('xmlns="http://www.w3.org/2000/svg"', "")
    for bad in ("<script", "foreignObject", "<image", "href=", "src=", "url(http", "@import", "BEGIN", "BLOCKED"):
        if bad in body:
            raise SystemExit("%s: forbidden %r" % (path, bad))
    # only palette colors, and no hollow boxes (a rect with no fill is an empty outline)
    allowed = set(PALETTE)
    for hexcol in set(re.findall(r"#[0-9a-fA-F]{6}\b", s)):
        if hexcol.lower() not in allowed:
            raise SystemExit("%s: color %s is not in the palette" % (path, hexcol))
    if re.search(r'<rect[^>]*fill="none"', s):
        raise SystemExit("%s: a rect with fill none (an empty outline box)" % path)
    # what the first hero had and this one must not: stamps, ids, rule names, pills of finds
    for gone in (r"\bkg[0-9a-f]{6}\b", r"-access-token", r"github-pat", r"private-key", r"\b1 key\b"):
        if re.search(gone, s):
            raise SystemExit("%s: %r is back" % (path, gone))
    for el in root.iter():
        if el.tag.endswith("}text"):
            cls = (el.get("class") or "").split()
            if "transform" in el.attrib:
                raise SystemExit("%s: a moved or rotated label %r" % (path, "".join(el.itertext())))
            if "d1" in cls or "d2" in cls or "pl" in cls:  # the dim page, and its bright copies
                continue
            words = "".join(el.itertext())
            if words not in BRIGHT_WORDS:  # the only readable words: wordmark, tagline, the masked keys
                raise SystemExit("%s: unexpected bright text %r" % (path, words))
        # nothing in the text may look like a key: no long run of plain key characters
        if not el.tag.endswith("}style"):
            for chunk in (el.text or "", el.tail or ""):
                m = re.search(r"[A-Za-z0-9]{20,}", chunk)
                if m:
                    raise SystemExit("%s: key-shaped run %r" % (path, m.group(0)))
    for text, _col in KEYS.values():
        assert BUL in text and len(text) <= 22, text
    return len(s.encode("utf-8"))


def render_png(svg_path, png_path, w, h):
    """The social card still, rendered by headless Chrome on a black page, so the 16 px
    rounded corners come out black instead of transparent."""
    # The two keychain flags keep Chrome off the macOS keychain: under an odd HOME it would
    # otherwise raise a "Keychain Not Found" dialog.
    cmd = [CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1",
           "--use-mock-keychain", "--password-store=basic",
           "--window-size=%d,%d" % (w, h), "--default-background-color=000000ff", "--screenshot=%s" % png_path, "file://" + svg_path]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=90)


def report_contrast():
    """The real text against the worst thing that can be behind it."""
    rows = [("wordmark and tagline over the top wash", ICE, blend(VIOLET, PAGE, 0.3))]
    for kid, (text, col) in sorted(KEYS.items()):
        rows.append(("lit key %s over its flare" % kid, ICE, blend(col, PANEL, 0.45)))
    worst = min(rows[1:], key=lambda r: contrast(r[1], r[2]))
    for label, fg, bg in rows[:1] + [worst]:
        print("  contrast %-42s %.1f:1" % (label, contrast(fg, bg)))


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    out = os.path.abspath(args[0]) if args else DEFAULT_OUT
    os.makedirs(out, exist_ok=True)
    for spec in (HERO, NARROW, CARD):
        svg, warns, info = render(spec)
        path = os.path.join(out, spec["name"] + ".svg")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(svg)
        print("%s  %d bytes" % (path, check(path)))
        if spec["animated"]:
            print("  route %d px, head speed %d px/s" % (info["route"].L, info["route"].L / T))
            for kid, t, dist, nvisits in sorted(info["found"], key=lambda f: f[1]):
                print("  key %-9s lit at t=%ss (head %s px away)" % (kid, n(t), n(dist)))
        for w in warns:
            print("  WARN", w)
        if "--png" in argv and spec is CARD:
            png = os.path.join(out, spec["name"] + ".png")
            render_png(path, png, spec["W"], spec["H"])
            print("%s  %d bytes" % (png, os.path.getsize(png)))
    report_contrast()


if __name__ == "__main__":
    main(sys.argv)
