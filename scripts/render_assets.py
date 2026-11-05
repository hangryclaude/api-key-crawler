#!/usr/bin/env python3
"""Render the five README images that carry a diagram or a number.

  layers.svg         a crawler climbs the path keyboard -> commit -> push -> GitHub; each gate stops a key
  layers-narrow.svg  the same path stood upright, 640 px wide, for a phone (README serves it below 600 px)
  speed.svg          hook latency against its budget, a whole commit, a full public-repo scan
  accuracy.svg       recall and precision for each engine, the three together, the pipeline
  terminal.svg       a commit blocked, then the same commit with --no-verify blocked too

Every number drawn comes from docs/assets/numbers.json. A new measurement is one JSON edit
and a re-run: bars, budget boxes, axis ticks, dot counts and callouts all move together. Bars
start at zero and share one scale per axis; a budget is a thin box drawn to the same scale; a
field of dots has exactly as many dots as the number it stands for.

Deterministic: every random choice comes from random.Random(seed), so a re-run writes
byte-identical files. System python3 (3.9), standard library only.

Look: the same tokens as hero.svg. A pure black page with a dim GitHub page under everything
(tabs, file lists, diffs, commit logs, a line-number gutter), violet neon strips along the top and
bottom edge, neon boxes (magenta, blue, amber, sky) on the keys and the numbers, and a thin
crawler: small glowing dots joined by straight hairlines, with more hairlines reaching out to
what it finds. Few words: the crawler and the numbers carry each image; labels are short and
quiet. The name, API KEY CRAWLER, sits small in a corner of each image.
CSS @keyframes only, and only transform and opacity move (a hairline draws itself with scaleX),
one 8 s loop. A reader needs the numbers more than the show, so every image is whole at t = 0:
a still frame, a slow load and prefers-reduced-motion all show the finished chart. It holds for
about 4.5 s, glitches out, and rebuilds in about 2.5 s (the build is compressed: a bar grows
faster than the thing it measures). The timelines below are written on a build clock (empty at
0, built by about 2.8 s, glitch-out at T_OFF); Css.tl cuts the loop at T_CUT so the page clock
starts on the finished chart. With prefers-reduced-motion the keyframes are switched off and the
base styles show that same finished frame.

Every key here is a mask: a constant prefix, a run of bullets or an ellipsis, at most four
characters. No string in this file is long enough to look like a real key.

Text sits on black, on a panel plate, or on a bar. Text on a bar is whichever of white or
black clears 4.5:1 on that bar (white on magenta is 3.2:1, so magenta carries black). Text on
bare page gets a near-black plate, so a beam or a crawler passing behind it never drops it
under 4.5:1.

Usage: render_assets.py [out_dir]       (default: ../docs/assets next to this script)
       render_assets.py --dump-blocks   print the two terminal block messages and exit
"""
import json
import math
import os
import random
import re
import sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(os.path.dirname(HERE), "docs", "assets")

T = 8.0       # loop length in seconds
T_OFF = 7.5   # build clock: the glitch-out starts here; each image builds in about 2.5 s, then holds the full chart until now
T_CUT = 3.0   # build clock: where the loop is cut, so the page clock starts on the finished chart (all builds end before this)

# ---- palette (the only colours used) -------------------------------------------------
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
WHITE = "#ffffff"
MONO = 'ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace'
ADV = 0.6  # monospace advance in em; textLength pins every real font to it
BUL = chr(0x2022)
ELL = chr(0x2026)
NBSP = chr(0xA0)
EN = chr(0x2013)


# ---- small helpers -------------------------------------------------------------------
def n(x):
    s = ("%.2f" % x).rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def g(v):
    return "%.10g" % v


def _lin(c):
    c = c / 255.0
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def lum(h):
    r, gg, b = int(h[1:3], 16), int(h[3:5], 16), int(h[5:7], 16)
    return 0.2126 * _lin(r) + 0.7152 * _lin(gg) + 0.0722 * _lin(b)


def contrast(a, b):
    la, lb = lum(a), lum(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


def ink(bg):
    """White or black, whichever reads better on bg; it must clear 4.5:1."""
    best = max((WHITE, PAGE), key=lambda c: contrast(c, bg))
    assert contrast(best, bg) >= 4.5, (bg, contrast(best, bg))
    return best


def rect_hit(a, b, margin=0):
    ax, ay, aw, ah = a
    bx, by, bw, bh = b
    return not (ax + aw + margin <= bx or bx + bw + margin <= ax or ay + ah + margin <= by or by + bh + margin <= ay)


def mask(prefix, bullets, tail):
    """A key as the page shows it: a constant prefix, a run of bullets, at most four characters."""
    assert len(tail) <= 4, tail
    return prefix + BUL * bullets + tail


def load_numbers(out_dir):
    with open(os.path.join(out_dir, "numbers.json"), encoding="utf-8") as fh:
        return json.load(fh)


# ---- CSS keyframes -------------------------------------------------------------------
STEP = "steps(1,end)"
OUT_EASE = "cubic-bezier(.16,1,.3,1)"
IO_EASE = "cubic-bezier(.65,0,.35,1)"
LIN = "linear"


def pg(t):
    """A time on the page clock (0 = the moment the image loads) as a time on the build clock."""
    return (t + T_CUT) % T


class Css:
    """Collects @keyframes. Every timeline starts and ends in the same state, so the loop
    has no seam. A frame is (t_seconds, {prop: value}, easing_or_None). Identical
    timelines share one rule. Timelines are written on the build clock (empty at 0); tl cuts
    the loop at T_CUT, so on the page clock every element is on at t = 0, glitches out at
    T_OFF - T_CUT and builds again before the loop ends."""

    def __init__(self):
        self.rules = []
        self.cache = {}

    @staticmethod
    def cut(frames):
        """Rotate a build-clock timeline so that the page clock starts at T_CUT. The timeline has to be
        at rest there (a hold, or a step); a frame's easing is the one that leaves it."""
        before = [f for f in frames if f[0] <= T_CUT + 1e-9]
        after = [f for f in frames if f[0] > T_CUT + 1e-9]
        a, b = before[-1], after[0]
        if a[2] != STEP and a[1] != b[1]:
            raise ValueError("a timeline is moving at the cut (t=%s): %s -> %s" % (a[0], a[1], b[1]))
        rest = dict(a[1])
        out = [(0.0, rest, a[2])]
        out += [(t - T_CUT, p, e) for t, p, e in after if t < T - 1e-9]
        out.append((T - T_CUT, frames[0][1], frames[0][2]))  # the build clock's 0 and T are one instant
        out += [(t + T - T_CUT, p, e) for t, p, e in before if t > 1e-9]
        out.append((T, rest, None))
        return out

    def tl(self, frames, rot=True):
        frames = sorted(frames, key=lambda f: f[0])
        assert abs(frames[0][0]) < 1e-9, "timeline must start at 0"
        assert abs(frames[-1][0] - T) < 1e-9, "timeline must end at the loop length"
        assert frames[0][1] == frames[-1][1], "loop seam: first and last state differ"
        key = (rot,) + tuple((round(t, 4), tuple(p.items()), e) for t, p, e in frames)
        if key in self.cache:
            return self.cache[key]
        if rot:
            frames = self.cut(frames)
        last = -1.0
        body = []
        for t, props, ease in frames:
            assert t > last, "frames must be strictly increasing (%s)" % t
            last = t
            pct = ("%.3f" % (t / T * 100.0)).rstrip("0").rstrip(".")
            decl = ";".join("%s:%s" % (k, v) for k, v in props.items())
            if ease:
                decl += ";animation-timing-function:%s" % ease
            body.append("%s%%{%s}" % (pct, decl))
        name = "a%d" % (len(self.cache) + 1)
        self.cache[key] = name
        self.rules.append("@keyframes %s{%s}.%s{animation-name:%s}" % (name, "".join(body), name, name))
        return name

    def attr(self, frames, origin=None, cls="", rot=True):
        """class/style attributes. With frames the element joins a timeline."""
        classes = [cls] if cls else []
        style = ""
        if frames is not None:
            classes += ["k", self.tl(frames, rot)]
            if origin is not None:
                style = "transform-origin:%spx %spx" % (n(origin[0]), n(origin[1]))
        out = ""
        if classes:
            out += ' class="%s"' % " ".join(classes)
        if style:
            out += ' style="%s"' % style
        return out


def seam(frames, hidden):
    """Start and end the loop in the same hidden state. Frame 0 holds (steps) until the
    next frame, so an element stays hidden until its moment."""
    frames = list(frames)
    frames[0] = (frames[0][0], dict(hidden), STEP)
    if abs(frames[-1][0] - T) < 1e-9:
        frames[-1] = (T, dict(hidden), frames[-1][2])
    else:
        frames.append((T, dict(hidden), None))
    return frames


def flicker(t_off, extra=None):
    """The end-of-loop glitch-out: on, off, on, off, gone. extra props ride on every frame."""
    ex = extra or {}
    seq = [(0.0, "1", STEP), (0.04, ".2", STEP), (0.08, "1", STEP), (0.14, ".15", STEP), (0.2, "0", None)]
    out = []
    for dt, o, e in seq:
        p = {"opacity": o}
        p.update(ex)
        out.append((t_off + dt, p, e))
    return out


def off_at(i):
    """Stagger of the glitch-out; the last element still finishes before the loop ends."""
    return T_OFF + 0.02 * (i % 12)


def fade_in(t, off):
    hid = {"opacity": "0"}
    return seam([(0, hid, STEP), (t, {"opacity": "1"}, None)] + flicker(off), hid)


def grow(t, off, dur=0.5):
    """A bar growing from its baseline (scaleX about the element's origin)."""
    hid = {"transform": "scaleX(.001)", "opacity": "0"}
    return seam(
        [(0, hid, STEP), (t, {"transform": "scaleX(.001)", "opacity": "1"}, OUT_EASE), (t + dur, {"transform": "scaleX(1)", "opacity": "1"}, None)]
        + flicker(off, {"transform": "scaleX(1)"}),
        hid,
    )


def grow_lin(t, dur, off):
    """A bar growing at a steady rate, so its length reads as elapsed time."""
    hid = {"transform": "scaleX(.001)", "opacity": "0"}
    return seam(
        [(0, hid, STEP), (t, {"transform": "scaleX(.001)", "opacity": "1"}, LIN), (t + dur, {"transform": "scaleX(1)", "opacity": "1"}, None)]
        + flicker(off, {"transform": "scaleX(1)"}),
        hid,
    )


def jitter_in(t, off):
    """Appears with a three-step horizontal jitter, like the hero's key text."""
    hid = {"opacity": "0", "transform": "translateX(0)"}
    return seam(
        [
            (0, hid, STEP),
            (t, {"opacity": "1", "transform": "translateX(7px)"}, STEP),
            (t + 0.034, {"opacity": "1", "transform": "translateX(-5px)"}, STEP),
            (t + 0.068, {"opacity": "1", "transform": "translateX(3px)"}, STEP),
            (t + 0.10, {"opacity": "1", "transform": "translateX(0)"}, None),
        ]
        + flicker(off, {"transform": "translateX(0)"}),
        hid,
    )


def stamp_in(t, off):
    """The BLOCKED stamp lands: big, then settles."""
    hid = {"opacity": "0", "transform": "scale(1.5)"}
    return seam(
        [
            (0, hid, STEP),
            (t, {"opacity": "1", "transform": "scale(1.5)"}, STEP),
            (t + 0.04, {"opacity": "1", "transform": "scale(1.12)"}, STEP),
            (t + 0.08, {"opacity": "1", "transform": "scale(1)"}, None),
        ]
        + flicker(off, {"transform": "scale(1)"}),
        hid,
    )


def slide_in(t, off):
    hid = {"opacity": "0", "transform": "translateX(-12px)"}
    return seam(
        [(0, hid, STEP), (t, hid, OUT_EASE), (t + 0.14, {"opacity": "1", "transform": "translateX(0)"}, None)]
        + flicker(off, {"transform": "translateX(0)"}),
        hid,
    )


def stutter(t0, dx=0, on=None):
    """A short stutter on something that stays on: it dips, jumps sideways, dips again and is back.
    on is the state it keeps; without a transform in it, only the opacity stutters."""
    on = on or {"opacity": "1", "transform": "translateX(0)"}

    def at(o, x):
        d = {"opacity": o}
        if "transform" in on:
            d["transform"] = "translateX(%dpx)" % x
        return d

    return [
        (0, on, STEP),
        (t0, at(".15", dx), STEP),
        (t0 + 0.04, on, STEP),
        (t0 + 0.09, at(".3", -dx), STEP),
        (t0 + 0.13, on, None),
        (T, on, None),
    ]


def blip(t, dur=0.5):
    """Shows only for a moment: a flash or a ping that is gone before the loop ends and is
    hidden in the final frame."""
    hid = {"opacity": "0"}
    return seam([(0, hid, STEP), (t, {"opacity": ".9"}, STEP), (t + dur, hid, None)], hid)


def ping(t, dur=0.5):
    """A ring that grows out of its centre and fades."""
    hid = {"opacity": "0", "transform": "scale(1)"}
    return seam([(0, hid, STEP), (t, {"opacity": ".9", "transform": "scale(1)"}, OUT_EASE), (t + dur, {"opacity": "0", "transform": "scale(2.1)"}, STEP)], hid)


# ---- the scene container -------------------------------------------------------------
class Scene:
    LAYERS = ("tex", "fx", "back", "plate", "mid", "front", "top")

    def __init__(self, name, W, H, title, desc, seed):
        self.name, self.W, self.H = name, W, H
        self.title, self.desc = title, desc
        self.rng = random.Random(seed)
        self.css = Css()
        self.defs = []
        self.layers = dict((k, []) for k in self.LAYERS)
        self.clear = []   # rects every word and mark occupies (the dim page ignores them unless strict)
        self.keepout = []  # rects strict dim pages keep clean: cards, legends, the crawler's rail
        self.notes = []   # (text, fg, bg, ratio) for every piece of text
        self.words = 0

    def add(self, layer, s):
        self.layers[layer].append(s)

    def clr(self, x, y, w, h):
        self.clear.append((x, y, w, h))

    def keep(self, x, y, w, h):
        self.keepout.append((x, y, w, h))

    def text(self, layer, x, y, s, size, fill, bg=PAGE, bold=False, align="l", frames=None, origin=None, clear=True, nb=False, extra="", plate=None, track=0):
        """One pinned line of monospace. fill must clear 4.5:1 on bg; the call fails otherwise.
        Text on bare page (bg PAGE) gets a near-black plate behind it, animated with it.
        track is extra letter-spacing in px (textLength spreads it)."""
        tl = len(s) * (ADV * size + track)
        if align == "r":
            x -= tl
        elif align == "c":
            x -= tl / 2.0
        c = contrast(fill, bg)
        if c < 4.5:
            raise ValueError("%s: %r is %.2f:1 (%s on %s)" % (self.name, s, c, fill, bg))
        self.notes.append((s, fill, bg, c))
        self.words += len(s.split())
        if plate is None:
            plate = bg == PAGE
        if plate:
            self.add(
                "plate",
                '<rect%s x="%s" y="%s" width="%s" height="%s" rx="3" fill="%s" fill-opacity=".94"/>'
                % (self.css.attr(frames, origin=origin), n(x - 5), n(y - size * 0.95 - 2), n(tl + 10), n(size * 1.32 + 4), PANEL),
            )
        a = self.css.attr(frames, origin=origin, cls="m")
        body = s.replace(" ", NBSP) if nb else s
        self.add(
            layer,
            '<text%s x="%s" y="%s" font-size="%s"%s fill="%s"%s textLength="%s" lengthAdjust="spacing">%s</text>'
            % (a, n(x), n(y), n(size), ' font-weight="700"' if bold else "", fill, extra, n(tl), esc(body)),
        )
        if clear:
            self.clr(x - 5, y - size * 0.95 - 2, tl + 10, size * 1.32 + 4)
        return tl

    def finish(self):
        W, H = self.W, self.H
        a = self.css.attr(
            [
                (0, {"transform": "translateY(-12px)", "opacity": "0"}, None),
                (0.01, {"transform": "translateY(-12px)", "opacity": ".06"}, None),
                (T - 0.01, {"transform": "translateY(%dpx)" % (H + 12), "opacity": ".06"}, None),
                (T, {"transform": "translateY(-12px)", "opacity": "0"}, None),
            ],
            rot=False,  # it sweeps the whole loop, so it has no rest to cut at
        )
        scan = '<rect%s x="0" y="0" width="%d" height="2" fill="%s" opacity="0"/>' % (a, W, ICE)
        style = [
            ".m{font-family:%s}" % MONO,
            ".d1,.d2{font-family:%s;font-size:11px}" % MONO,
            ".d1{fill:%s}.d2{fill:%s}" % (DIM, DIM2),
            ".k{animation-duration:%ss;animation-iteration-count:infinite;animation-timing-function:linear}" % n(T),
            ".w{animation:wig 1s ease-in-out infinite}",
            ".w2{animation:wig2 .8s ease-in-out infinite}",
            ".pu{animation:pul 4s ease-in-out infinite}",
            "@keyframes wig{0%{transform:rotate(-5deg)}50%{transform:rotate(5deg)}100%{transform:rotate(-5deg)}}",
            "@keyframes wig2{0%{transform:rotate(-10deg)}50%{transform:rotate(10deg)}100%{transform:rotate(-10deg)}}",
            "@keyframes pul{0%,100%{opacity:.8}50%{opacity:1}}",
        ]
        style += self.css.rules
        style.append("@media (prefers-reduced-motion:reduce){.k,.w,.w2,.pu{animation:none!important}}")
        defs = [
            '<clipPath id="rc"><rect width="%d" height="%d" rx="16"/></clipPath>' % (W, H),
            '<pattern id="sl" width="4" height="3" patternUnits="userSpaceOnUse"><rect width="4" height="1" fill="%s" fill-opacity=".05"/></pattern>' % ICE,
        ] + self.defs
        svg = [
            '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-labelledby="t d">' % (W, H, W, H),
            '<title id="t">%s</title><desc id="d">%s</desc>' % (esc(self.title), esc(self.desc)),
            "<defs>%s</defs>" % "".join(defs),
            "<style>%s</style>" % "".join(style),
            '<g clip-path="url(#rc)">',
            '<rect width="%d" height="%d" fill="%s"/>' % (W, H, PAGE),
            '<g aria-hidden="true">%s</g>' % "".join(self.layers["tex"]),
            '<rect width="%d" height="%d" fill="url(#sl)"/>' % (W, H),
        ]
        for k in ("fx", "back", "plate", "mid", "front", "top"):
            svg.append("<g>%s</g>" % "".join(self.layers[k]))
        svg.append(scan)
        svg.append("</g></svg>")
        return "\n".join(svg) + "\n"

    def min_contrast(self):
        return min(c for _, _, _, c in self.notes)


# ---- the kit: neon strips, dim page, bars, pills, crawlers ---------------------------
def neon(sc):
    """A violet neon tube along the top and the bottom edge, the way the hero has it: a wash
    that falls onto the page, a bloom, the tube, a white-hot core and a hot spot that surges
    once per loop. The bottom strip is the top one turned over, so the page is lit from both
    sides."""
    W, H = sc.W, sc.H
    sc.defs += [
        '<linearGradient id="wash" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="%s" stop-opacity=".66"/><stop offset=".22" stop-color="%s" stop-opacity=".28"/><stop offset=".6" stop-color="%s" stop-opacity=".08"/><stop offset="1" stop-color="%s" stop-opacity="0"/></linearGradient>' % (VIOLET, VIOLET, VIOLET, VIOLET),
        '<radialGradient id="bloom"><stop offset="0" stop-color="%s" stop-opacity=".95"/><stop offset=".35" stop-color="%s" stop-opacity=".5"/><stop offset="1" stop-color="%s" stop-opacity="0"/></radialGradient>' % (VIOLET, VIOLET, VIOLET),
        '<radialGradient id="hot"><stop offset="0" stop-color="%s" stop-opacity=".95"/><stop offset=".4" stop-color="%s" stop-opacity=".45"/><stop offset="1" stop-color="%s" stop-opacity="0"/></radialGradient>' % (ICE, VIOLET, VIOLET),
        '<linearGradient id="tube" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="%s" stop-opacity="0"/><stop offset=".12" stop-color="%s" stop-opacity=".85"/><stop offset=".5" stop-color="%s"/><stop offset=".88" stop-color="%s" stop-opacity=".85"/><stop offset="1" stop-color="%s" stop-opacity="0"/></linearGradient>' % (VIOLET, VIOLET, VIOLET, VIOLET, VIOLET),
        '<linearGradient id="core" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="%s" stop-opacity="0"/><stop offset=".5" stop-color="%s"/><stop offset="1" stop-color="%s" stop-opacity="0"/></linearGradient>' % (ICE, ICE, ICE),
    ]
    cy = 8.0
    for top, t_surge in ((True, 1.4), (False, 5.0)):
        wash = '<rect width="%d" height="130" fill="url(#wash)"/>' % W
        bloom = '<ellipse cx="%s" cy="%s" rx="540" ry="74" fill="url(#bloom)"/>' % (n(W / 2.0), n(cy))
        tube = (
            '<rect x="10" y="2" width="%d" height="14" rx="7" fill="url(#tube)" fill-opacity=".4"/>'
            '<rect x="14" y="5.5" width="%d" height="5" rx="2.5" fill="url(#tube)"/>' % (W - 20, W - 28)
        )
        core = '<rect x="%s" y="6.6" width="760" height="2.8" rx="1.4" fill="url(#core)"/>' % n(W / 2.0 - 380)
        hot = '<ellipse cx="%s" cy="%s" rx="230" ry="17" fill="url(#hot)" opacity=".85"/>' % (n(W / 2.0), n(cy + 0.5))
        surge = sc.css.attr(
            seam(
                [
                    (0, {"transform": "scaleX(1)", "opacity": ".85"}, STEP),
                    (t_surge, {"transform": "scaleX(1)", "opacity": ".85"}, OUT_EASE),
                    (t_surge + 0.14, {"transform": "scaleX(1.7)", "opacity": "1"}, IO_EASE),
                    (t_surge + 0.55, {"transform": "scaleX(1)", "opacity": ".85"}, None),
                ],
                {"transform": "scaleX(1)", "opacity": ".85"},
            ),
            origin=(W / 2.0, cy),
        )
        pul = ' class="pu" style="animation-delay:-%ss"' % ("0" if top else "2")
        # a few bright slivers off the line of the tube, as if the signal had torn; every other one stutters
        srng = random.Random(7 if top else 8)
        slivers = ""
        for k in range(5):
            sx, sw, dy = srng.uniform(0.05, 0.95) * W, srng.choice([34, 48, 66, 90]), srng.choice([-4.5, -3.5, 3.5, 4.5])
            fr = stutter(srng.uniform(0.3, 7.2), srng.choice([-6, -4, 4, 6])) if k % 2 == 0 else None
            slivers += '<rect%s x="%s" y="%s" width="%s" height="2.4" rx="1.2" fill="%s" fill-opacity=".85"/>' % (sc.css.attr(fr), n(sx), n(cy + dy - 1.2), n(sw), ICE if k % 2 else WIRE)
        body = "<g%s>%s%s</g>%s%s%s<g%s>%s</g>" % (pul, wash, bloom, tube, core, slivers, surge, hot)
        sc.add("fx", "<g>%s</g>" % body if top else '<g transform="translate(0 %d) scale(1 -1)">%s</g>' % (H, body))


# The dim page: what GitHub looks like through a scanner. Each block is a list of (kind, text):
#   ""  dim text      "b" brighter text      "+" an added line      "-" a removed line      "@" a hunk header
TINT = {"+": (MINT, ".055"), "-": (RED, ".07"), "@": (VIOLET, ".12")}
NO_VERIFY_TAG = "ignores --no-verify"  # the magenta tag: git's --no-verify has no effect on that gate


def dim_page(sc, panes, pitch=14, n_flick=10, step=6.6, strict=False, op=1.0, bright=0.16):
    """Lay the dim page out. panes: dicts with x, y, room (the widest a line may be) and lines.
    A line wider than its room is dropped rather than clipped. Every word of the scene sits on a
    plate, a bar or a pill, so the page may run behind them; strict=True also drops any line that
    would touch a keep-out rect (a card, a legend, the crawler's rail). op dims the whole page (charts run it at .7)."""
    emitted = []
    for p in panes:
        px, py = p["x"], p["y"]
        room = p.get("room", 400)
        band = p.get("band", min(room, 380))
        for r, (kind, line) in enumerate(p["lines"]):
            y = py + pitch * r
            if y < 26 or y > sc.H - 22 or len(line.strip()) < 3:
                continue
            w = len(line) * step
            if w > room:
                continue
            tinted = kind in TINT
            box = (px - 3, y - 10, max(w, band) + 6 if tinted else w + 6, 14)
            if strict and any(rect_hit(box, c, 3) for c in sc.keepout):
                continue
            emitted.append((px, y, kind, line, box))
    flick = {}
    if emitted:
        for i in sc.rng.sample(range(len(emitted)), min(n_flick, len(emitted))):
            t0 = sc.rng.uniform(0.3, 7.0)
            flick[i] = stutter(t0, sc.rng.choice([-5, -3, 3, 5, 8]))
    bands, parts = [], []
    for i, (x, y, kind, line, box) in enumerate(emitted):
        if kind in TINT:
            col, tint_op = TINT[kind]
            bands.append('<rect x="%s" y="%s" width="%s" height="14" fill="%s" fill-opacity="%s"/>' % (n(box[0]), n(box[1]), n(box[2]), col, tint_op))
        lit = kind in ("b", "@") or sc.rng.random() < bright
        a = sc.css.attr(flick.get(i), cls="d2" if lit else "d1")
        parts.append('<text%s x="%s" y="%s">%s</text>' % (a, n(x), n(y), esc(line.replace(" ", NBSP))))
    inner = "".join(bands) + "".join(parts)
    sc.add("tex", '<g opacity="%s">%s</g>' % (op_s(op), inner) if op < 1 else inner)


def gutter(sc, x=31, y0=36, pitch=14):
    """The line numbers of a code view, down the left edge, and the rule beside them."""
    parts = ['<line x1="37" y1="24" x2="37" y2="%d" stroke="%s" stroke-opacity=".3"/>' % (sc.H - 24, DIM)]
    k, y = 1, y0
    while y < sc.H - 24:
        parts.append('<text class="d1" style="font-size:10px" x="%d" y="%s" text-anchor="end">%d</text>' % (x, n(y), k))
        k += 1
        y += pitch
    sc.add("tex", "".join(parts))


def bar_path(x, y, w, h, r=4):
    """Flat at the baseline (left), rounded at the data end (right)."""
    r = min(r, w / 2.0, h / 2.0)
    if r <= 0.01:
        return "M%s %sh%sv%sh%sz" % (n(x), n(y), n(w), n(h), n(-w))
    return "M%s %sh%sa%s %s 0 0 1 %s %sv%sa%s %s 0 0 1 %s %sh%sz" % (
        n(x), n(y), n(w - r), n(r), n(r), n(r), n(r), n(h - 2 * r), n(r), n(r), n(-r), n(r), n(-(w - r)),
    )


def op_s(v):
    return ("%.2f" % v).rstrip("0").rstrip(".")


def h_bar(sc, x, y, w, h, color, frames=None, rad=4, glow=True, opacity=None, ghost=False):
    """A highlighter bar with the soft glow layers of the hero's key bars. The glow goes
    behind every solid, so a neighbouring bar is never tinted over. ghost draws the box a second
    time as an outline, a few pixels off: a torn edge, the way a glitch doubles a box."""
    origin = (x, y + h / 2.0)
    if glow:
        a = sc.css.attr(frames, origin=origin)
        edge = '<rect x="%s" y="%s" width="%s" height="%s" rx="3" fill="none" stroke="%s" stroke-opacity=".6" stroke-width="1.2"/>' % (n(x + 5), n(y - 4), n(w), n(h), color) if ghost else ""
        sc.add(
            "back",
            '<g%s><rect x="%s" y="%s" width="%s" height="%s" rx="7" fill="%s" opacity=".10"/>'
            '<rect x="%s" y="%s" width="%s" height="%s" rx="5" fill="%s" opacity=".22"/>%s</g>'
            % (a, n(x - 4), n(y - 4), n(w + 8), n(h + 8), color, n(x - 2), n(y - 2), n(w + 4), n(h + 4), color, edge),
        )
    a = sc.css.attr(frames, origin=origin)
    op = ' fill-opacity="%s"' % op_s(opacity) if opacity is not None else ""
    sc.add("mid", '<path%s d="%s" fill="%s"%s/>' % (a, bar_path(x, y, w, h, rad), color, op))
    sc.clr(x - 5, y - 5, w + 10, h + 10)


def stamp(sc, layer, x, y, frames=None, word="BLOCKED", fill=RED, size=14):
    """The verdict tag of the hero: BLOCKED in black on red (6.0:1). The watcher cannot block
    a key that is already on GitHub, so its tag says FOUND, in black on amber."""
    tag_len = len(word) * (ADV * size + 1)
    pad = round(size * 1.3)
    w = tag_len + pad
    h = size + 10
    assert contrast(PAGE, fill) >= 4.5
    sc.notes.append((word, PAGE, fill, contrast(PAGE, fill)))
    sc.words += 1
    a = sc.css.attr(frames, origin=(x + w / 2.0, y + h / 2.0))
    sc.add(
        layer,
        '<g%s><rect x="%s" y="%s" width="%s" height="%s" rx="2" fill="%s"/>'
        '<text class="m" x="%s" y="%s" font-size="%s" font-weight="700" fill="%s" textLength="%s" lengthAdjust="spacing">%s</text></g>'
        % (a, n(x), n(y), n(w), n(h), fill, n(x + pad / 2.0), n(y + h * 0.6875), n(size), PAGE, n(tag_len), word),
    )
    sc.clr(x, y, w, h)
    return w


def pill(sc, layer, x, y, text, size, fill, stroke=None, h=None, padx=10, bold=True, frames=None, align="l", behind=PANEL, rx=None):
    """A rounded label. fill None draws an outline pill with WIRE text; otherwise the text is
    whichever of white or black clears 4.5:1 on the fill. rx squares the corners (a number plate)."""
    tl = len(text) * ADV * size
    h = h if h else round(size * 1.75)
    w = tl + 2 * padx
    if align == "r":
        x -= w
    elif align == "c":
        x -= w / 2.0
    if fill is None:
        fg, bgc = WIRE, behind
    else:
        fg, bgc = ink(fill), fill
    c = contrast(fg, bgc)
    assert c >= 4.5, (text, c)
    sc.notes.append((text, fg, bgc, c))
    sc.words += len(text.split())
    a = sc.css.attr(frames, origin=(x + w / 2.0, y + h / 2.0))
    rect = '<rect x="%s" y="%s" width="%s" height="%s" rx="%s" fill="%s"%s/>' % (
        n(x), n(y), n(w), n(h), n(h / 2.0 if rx is None else rx), fill if fill else "none", (' stroke="%s" stroke-width="1.3"' % stroke) if stroke else "",
    )
    t = '<text class="m" x="%s" y="%s" font-size="%s"%s fill="%s" textLength="%s" lengthAdjust="spacing">%s</text>' % (
        n(x + padx), n(y + h / 2.0 + size * 0.34), n(size), ' font-weight="700"' if bold else "", fg, n(tl), esc(text),
    )
    sc.add(layer, "<g%s>%s%s</g>" % (a, rect, t))
    sc.clr(x, y, w, h)
    return w


def dots(pts, r, color, op=None):
    """Round dots as one path: a segment a hundredth of a pixel long, drawn with a round cap, is a
    circle, so a field of dots costs a few bytes each."""
    d = "".join("M%s %sh.01" % (n(x), n(y)) for x, y in pts)
    return '<path d="%s" fill="none" stroke="%s" stroke-width="%s" stroke-linecap="round"%s/>' % (d, color, n(2 * r), (' stroke-opacity="%s"' % op) if op else "")


def spider_svg(rng, scale, rmax=96.0, wire=WIRE, node=ICE, core=MINT):
    """The crawler as a net: eight legs (each a chain of glowing dots on hairlines), chords between
    neighbours and a few strays, drawn at final size so hairlines stay hairlines. Legs rock on a
    1 s loop. wire, node and core tint it. Returns the markup and the radius it reaches."""
    legs = []
    for i in range(8):
        a = (i + rng.uniform(-0.16, 0.16)) * 2 * math.pi / 8
        pts = [(0.0, 0.0)]
        r = rng.uniform(26, 38)
        x, y = r * math.cos(a), r * math.sin(a)
        pts.append((x, y))
        for _ in range(rng.choice([2, 2, 3])):
            a += rng.uniform(-0.75, 0.75)
            r = rng.uniform(22, 40)
            x, y = x + r * math.cos(a), y + r * math.sin(a)
            pts.append((x, y))
        k = min(1.0, rmax / max(math.hypot(x, y), 1.0)) * scale
        legs.append([(px * k, py * k) for px, py in pts])
    strays = []
    for _ in range(6):
        base = legs[rng.randrange(8)]
        j = base[rng.randrange(1, len(base))]
        ang = rng.uniform(0, 2 * math.pi)
        rr = rng.uniform(18, 38) * scale
        strays.append((j, (j[0] + rr * math.cos(ang), j[1] + rr * math.sin(ang))))
    bs = max(scale, 0.6)
    out = []
    for a, b in strays:
        out.append('<line x1="%s" y1="%s" x2="%s" y2="%s" stroke="%s" stroke-opacity=".4" stroke-width="1"/>' % (n(a[0]), n(a[1]), n(b[0]), n(b[1]), wire))
    out.append(dots([b for _, b in strays], 1.6, node, ".85"))
    for i in range(8):
        if rng.random() < 0.75:
            a, b = legs[i][1], legs[(i + 1) % 8][1]
            out.append('<line x1="%s" y1="%s" x2="%s" y2="%s" stroke="%s" stroke-opacity=".45" stroke-width="1"/>' % (n(a[0]), n(a[1]), n(b[0]), n(b[1]), wire))
    for i, pts in enumerate(legs):
        poly = " ".join("%s,%s" % (n(x), n(y)) for x, y in pts)
        out.append('<g class="w" style="animation-delay:-%ss">' % n(i * 0.125))
        out.append('<polyline points="%s" fill="none" stroke="%s" stroke-opacity=".75" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>' % (poly, wire))
        out.append(dots(pts[1:], 6 * bs, wire, ".10"))
        out.append(dots(pts[1:-1], 2.4, node))
        out.append(dots(pts[-1:], 1.8, node))
        out.append("</g>")
    out.append('<circle r="%s" fill="%s" fill-opacity=".08"/>' % (n(19 * bs), wire))
    out.append('<circle r="%s" fill="none" stroke="%s" stroke-opacity=".7" stroke-width="1.2"/>' % (n(11 * bs), wire))
    out.append('<circle r="%s" fill="%s"/>' % (n(5.4 * bs), node))
    out.append('<circle r="%s" fill="%s"/>' % (n(2.2 * bs), core))
    radius = max(math.hypot(px, py) for pts in legs for px, py in pts)
    return "<g>%s</g>" % "".join(out), radius


def crawler_svg(x0, y0, length, amp, wl, nseg, phase=0.0, sz=1.0, leg=26.0, seed=5, wire=WIRE, node=ICE, core=MINT):
    """The crawler on the move, thin: a chain of small glowing dots joined by straight hairlines,
    two hairline legs on every dot (a knee and a foot, both dots) and a head with a sight ring and
    two feelers that reach ahead. The head is at the right end and the body follows a sine path.
    The legs rock, so it crawls in place; crawl() moves it."""
    rng = random.Random(seed)

    def P(s):
        return (x0 + s, y0 + amp * math.sin(2 * math.pi * s / wl + phase))

    def TAN(s):
        dy = amp * 2 * math.pi / wl * math.cos(2 * math.pi * s / wl + phase)
        return math.atan2(dy, 1.0)

    step = length / (nseg - 1.0)
    spine = " ".join("%s,%s" % (n(P(length - i * step)[0]), n(P(length - i * step)[1])) for i in reversed(range(nseg)))
    parts = [
        '<polyline points="%s" fill="none" stroke="%s" stroke-opacity=".09" stroke-width="%s" stroke-linecap="round" stroke-linejoin="round"/>' % (spine, wire, n(20 * sz)),
        '<polyline points="%s" fill="none" stroke="%s" stroke-opacity=".9" stroke-width="1.4" stroke-linejoin="round"/>' % (spine, wire),
    ]
    for i in reversed(range(nseg)):  # tail first, so the head draws on top
        ts = i / float(nseg - 1)
        glen = leg * (0.5 + 0.5 * math.sin(math.pi * (i + 0.6) / (nseg + 0.2)))
        s = length - i * step
        x, y = P(s)
        a = math.degrees(TAN(s))
        seg = ['<g transform="translate(%s %s) rotate(%s)"><g class="w2" style="animation-delay:-%ss">' % (n(x), n(y), n(a), n((i * 0.09) % 0.8))]
        knees, feet = [], []
        for side in (1, -1):
            k1 = (-rng.uniform(1.0, 5.0) * sz, side * glen * 0.55)
            k2 = (-rng.uniform(8.0, 16.0) * sz, side * glen)
            seg.append(
                '<polyline points="0,0 %s,%s %s,%s" fill="none" stroke="%s" stroke-opacity=".7" stroke-width="1.1" stroke-linecap="round" stroke-linejoin="round"/>'
                % (n(k1[0]), n(k1[1]), n(k2[0]), n(k2[1]), wire)
            )
            knees.append(k1)
            feet.append(k2)
        seg.append(dots(knees, 1.2 * sz, node, ".7"))
        seg.append(dots(feet, 1.8 * sz, node, ".95"))
        seg.append("</g>")
        if i == 0:
            seg.append(dots([(0, 0)], 19 * sz, wire, ".14"))
            seg.append('<circle r="%s" fill="none" stroke="%s" stroke-opacity=".9" stroke-width="1.3"/>' % (n(10 * sz), wire))
            for side in (1, -1):
                seg.append(
                    '<polyline points="%s,%s %s,%s %s,%s" fill="none" stroke="%s" stroke-opacity=".9" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>'
                    % (n(5 * sz), n(side * 3 * sz), n(18 * sz), n(side * 9 * sz), n(32 * sz), n(side * 8 * sz), wire)
                )
            seg.append(dots([(32 * sz, 8 * sz), (32 * sz, -8 * sz)], 2.0 * sz, node))
            seg.append(dots([(0, 0)], 4.4 * sz, core))
        else:
            seg.append(dots([(0, 0)], (11 - 3 * ts) * sz, wire, ".16"))
            seg.append(dots([(0, 0)], (3.6 - 1.0 * ts) * sz, node))
        seg.append("</g>")
        parts.append("".join(seg))
    return "<g>%s</g>" % "".join(parts)


def crawl(sc, svg, ox, oy, deg, frames, rest):
    """A crawler that travels along a line: the line starts at (ox, oy) and points deg degrees
    (counter-clockwise, as on a page). The art is drawn with its head at its own origin, and
    `frames` move it along the line by translateX(s). rest is where it sits in the final frame,
    which is also what prefers-reduced-motion shows."""
    return sc.add(
        "mid",
        '<g transform="translate(%s %s) rotate(%s)"><g class="k %s" style="transform:translateX(%spx)">%s</g></g>'
        % (n(ox), n(oy), n(-deg), sc.css.tl(frames), n(rest), svg),
    )


def beams(sc, specs):
    """Long diagonal magenta beams that sweep across behind everything else, like scan sweeps.
    spec: (angle, thickness, centre, (t_start, t_end), rest_offset_or_None). A rest offset also
    leaves a still beam there. Text on bare page carries a plate, so a beam never sits directly
    behind a word."""
    W, H = sc.W, sc.H
    for angle, th, (cx, cy), (t0, t1), rest in specs:
        r = math.radians(angle)
        nx, ny = -math.sin(r), math.cos(r)
        proj = [(px - cx) * nx + (py - cy) * ny for px in (0, W) for py in (0, H)]
        lo, hi = min(proj) - th / 2 - 8, max(proj) + th / 2 + 8
        length = int(math.hypot(W, H)) + 200
        hid = {"transform": "translateY(%spx)" % n(lo), "opacity": "0"}
        a = sc.css.attr(
            [
                (0, hid, STEP),
                (t0, {"transform": "translateY(%spx)" % n(lo), "opacity": ".92"}, IO_EASE),
                (t1, {"transform": "translateY(%spx)" % n(hi), "opacity": ".92"}, STEP),
                (t1 + 0.02, {"transform": "translateY(%spx)" % n(hi), "opacity": "0"}, STEP),
                (T, hid, None),
            ]
        )
        for cls, op, at in ([("", "0.92", rest)] if rest is not None else []) + [(a, "0", lo)]:
            # a beam with a rest stays lit on the finished chart, so the first frame, a still and reduced motion agree;
            # the sweep is a second rect that is only on while it passes
            sc.add(
                "fx",
                '<g transform="translate(%s %s) rotate(%s)"><rect%s x="%d" y="%s" width="%d" height="%s" fill="%s" opacity="%s" transform="translate(0 %s)"/></g>'
                % (n(cx), n(cy), n(angle), cls, -length // 2, n(-th / 2.0), length, n(th), MAGENTA, op, n(at)),
            )


def hairline(sc, layer, x1, y1, x2, y2, color, t0=None, t1=None, off=None, width=1.3, op=".85"):
    """A straight hairline from (x1, y1) to (x2, y2). With t0 it draws itself between t0 and t1: the
    line lies along its own x axis and grows by scaleX about its start, so only a transform moves.
    Returns its length."""
    ln = math.hypot(x2 - x1, y2 - y1)
    deg = math.degrees(math.atan2(y2 - y1, x2 - x1))
    a = sc.css.attr(grow(t0, off, t1 - t0), origin=(0, 0)) if t0 is not None else ""
    sc.add(
        layer,
        '<g transform="translate(%s %s) rotate(%s)"><line%s x2="%s" stroke="%s" stroke-opacity="%s" stroke-width="%s"/></g>' % (n(x1), n(y1), n(deg), a, n(ln), color, op, n(width)),
    )
    return ln


def snap(t, off):
    """The sights close on a key: wide at first, then they drop onto it."""
    hid = {"opacity": "0", "transform": "scale(1.3)"}
    return seam(
        [
            (0, hid, STEP),
            (t, {"opacity": "1", "transform": "scale(1.3)"}, STEP),
            (t + 0.05, {"opacity": "1", "transform": "scale(1.12)"}, STEP),
            (t + 0.10, {"opacity": "1", "transform": "scale(1)"}, None),
        ]
        + flicker(off, {"transform": "scale(1)"}),
        hid,
    )


def reticle(sc, layer, x, y, w, h, color, arm=9, width=1.6, frames=None):
    """Four corner brackets round a found key: the crawler has it in its sights. A wider, fainter
    pass under the brackets is the glow."""
    d = "M%s %sV%sH%sM%s %sH%sV%sM%s %sV%sH%sM%s %sH%sV%s" % (
        n(x), n(y + arm), n(y), n(x + arm),
        n(x + w - arm), n(y), n(x + w), n(y + arm),
        n(x + w), n(y + h - arm), n(y + h), n(x + w - arm),
        n(x + arm), n(y + h), n(x), n(y + h - arm),
    )
    a = sc.css.attr(frames, origin=(x + w / 2.0, y + h / 2.0))
    sc.add(
        layer,
        '<g%s fill="none" stroke="%s" stroke-linecap="round" stroke-linejoin="round"><path d="%s" stroke-width="%s" stroke-opacity=".25"/><path d="%s" stroke-width="%s"/></g>'
        % (a, color, d, n(width + 4), d, n(width)),
    )


def web(sc, region, count, gap, link, hubs=(), seed=1):
    """The crawler's web over a patch of empty page: small glowing dots joined by straight hairlines.
    Dots keep gap apart, a hairline is at most link long, and nothing lands on a keep-out rect or on
    a word. hubs are dots that have to be in it (a node on the track, the corner of a key box); the
    hairlines that leave a hub are a little brighter."""
    rng = random.Random(seed)
    blocked = sc.keepout + sc.clear

    def free(p, m):
        return not any(rect_hit((p[0] - 1, p[1] - 1, 2, 2), b, m) for b in blocked)

    def open_line(a, b):
        return all(free((a[0] + (b[0] - a[0]) * u / 10.0, a[1] + (b[1] - a[1]) * u / 10.0), 3) for u in range(1, 10))

    x0, y0, w, h = region
    pts = [tuple(p) for p in hubs]
    for _ in range(count * 40):
        if len(pts) >= len(hubs) + count:
            break
        p = (x0 + rng.random() * w, y0 + rng.random() * h)
        if free(p, 8) and all(math.hypot(p[0] - q[0], p[1] - q[1]) >= gap for q in pts):
            pts.append(p)
    edges = set()
    for i, p in enumerate(pts):
        near = sorted((math.hypot(p[0] - q[0], p[1] - q[1]), j) for j, q in enumerate(pts) if j != i)
        for d, j in near[:2]:
            if d <= link and rng.random() < 0.9 and open_line(p, pts[j]):
                edges.add((min(i, j), max(i, j)))
    dim, lit = [], []
    for i, j in sorted(edges):
        seg = "M%s %sL%s %s" % (n(pts[i][0]), n(pts[i][1]), n(pts[j][0]), n(pts[j][1]))
        (lit if min(i, j) < len(hubs) else dim).append(seg)
    out = ['<path d="%s" fill="none" stroke="%s" stroke-opacity=".3" stroke-width="1"/>' % ("".join(dim), WIRE)]
    if lit:
        out.append('<path d="%s" fill="none" stroke="%s" stroke-opacity=".6" stroke-width="1.2"/>' % ("".join(lit), WIRE))
    free_pts = pts[len(hubs):]
    out.append(dots(free_pts, 5.5, WIRE, ".10"))
    out.append(dots(free_pts, 1.8, ICE, ".8"))
    out.append(dots(pts[: len(hubs)], 3.0, ICE))
    # a few dots breathe, out of step with each other
    for k, p in enumerate(free_pts[:: max(1, len(free_pts) // 5)]):
        out.append('<circle class="pu" style="animation-delay:-%ss" cx="%s" cy="%s" r="3" fill="%s"/>' % (n(0.7 * k), n(p[0]), n(p[1]), SKY))
    sc.add("back", "".join(out))


def wordmark(sc, x, y, size=13, align="r", t_glitch=None):
    """The name, small, in a corner: ice white monospace, letter-spaced, with a little crawler (four
    dots on a hairline) in front of it, on its own plate. (x, y) is the end of the baseline that
    align names. It stays on through the glitch-out and only stutters."""
    name, track, pad, gw = "API KEY CRAWLER", round(size * 0.25, 1), 9, 30
    tl = len(name) * (ADV * size + track)
    w = pad + gw + 8 + tl + pad
    left = x - w if align == "r" else x
    top = y - size - 5
    h = size + 12
    fr = stutter(t_glitch, 0, {"opacity": "1"}) if t_glitch is not None else None
    sc.add("plate", '<rect%s x="%s" y="%s" width="%s" height="%s" rx="4" fill="%s" fill-opacity=".95" stroke="%s" stroke-opacity=".3"/>' % (sc.css.attr(fr), n(left), n(top), n(w), n(h), PANEL, WIRE))
    mx, my = left + pad, y - size * 0.34
    pts = [(mx + 2, my + 2), (mx + 10, my - 3), (mx + 18, my + 3), (mx + 26, my - 2)]
    sc.add(
        "top",
        '<g%s><polyline points="%s" fill="none" stroke="%s" stroke-opacity=".85" stroke-width="1.2" stroke-linejoin="round"/>%s%s</g>'
        % (sc.css.attr(fr), " ".join("%s,%s" % (n(px), n(py)) for px, py in pts), WIRE, dots(pts[:-1], 2.0, ICE), dots(pts[-1:], 2.8, MINT)),
    )
    sc.text("top", left + pad + gw + 8, y, name, size, ICE, bg=PANEL, bold=True, frames=fr, plate=False, clear=False, track=track)
    sc.clr(left - 2, top - 2, w + 4, h + 4)
    sc.keep(left - 6, top - 6, w + 12, h + 12)


def repo_tiles(sc, x, y, count, tw, th, gap, t0, dt):
    """One small card per repo. Each lights amber when the crawler passes it. The base state is
    lit, so the final frame shows every repo scanned."""
    cards, lit = [], []
    for k in range(count):
        tx = x + k * (tw + gap)
        cards.append(
            '<rect x="%s" y="%s" width="%s" height="%s" rx="3" fill="%s" fill-opacity=".94" stroke="%s" stroke-opacity=".6" stroke-width="1.2"/>'
            % (n(tx), n(y), n(tw), n(th), PANEL, WIRE)
        )
        a = sc.css.attr(fade_in(t0 + k * dt, off_at(k)))
        lit.append(
            '<g%s><rect x="%s" y="%s" width="%s" height="%s" rx="3" fill="%s" fill-opacity=".92"/>'
            '<rect x="%s" y="%s" width="%s" height="2" fill="%s"/></g>'
            % (a, n(tx), n(y), n(tw), n(th), AMBER, n(tx + 3), n(y + 3), n(tw * 0.5), PAGE)
        )
    sc.add("back", "".join(cards))
    sc.add("mid", "".join(lit))
    sc.clr(x - 6, y - 6, count * (tw + gap) - gap + 12, th + 12)


def commit_graph(sc, x0, x1, y, branches, seed=3):
    """A `git log --graph` rail along the page: a main line of commits and a few branches that
    leave it and merge back. Dim, drawn in the page's own colours, and it carries no number: it is
    the history the crawler walks. branches: (x_from, x_to, dy, colour)."""
    rng = random.Random(seed)
    parts = ['<line x1="%s" y1="%s" x2="%s" y2="%s" stroke="%s" stroke-opacity=".5" stroke-width="2" stroke-linecap="round"/>' % (n(x0), n(y), n(x1), n(y), DIM2)]
    dots = []

    def run(xa, xb, yy, col):
        x = xa
        while x <= xb:
            dots.append('<circle cx="%s" cy="%s" r="3.2" fill="%s" stroke="%s" stroke-opacity=".85" stroke-width="1.4"/>' % (n(x), n(yy), PANEL, col))
            x += rng.choice([20, 24, 28])

    run(x0 + 8, x1 - 8, y, WIRE)
    for xa, xb, dy, col in branches:
        yy = y + dy
        d = "M%s %sC%s %s %s %s %s %sH%sC%s %s %s %s %s %s" % (n(xa), n(y), n(xa + 14), n(y), n(xa + 14), n(yy), n(xa + 30), n(yy), n(xb - 30), n(xb - 14), n(yy), n(xb - 14), n(y), n(xb), n(y))
        parts.append('<path d="%s" fill="none" stroke="%s" stroke-opacity=".5" stroke-width="2" stroke-linecap="round"/>' % (d, col))
        run(xa + 38, xb - 38, yy, col)
    sc.add("back", "".join(parts + dots))


# ---- the dim page's text: GitHub seen through a scanner, plus keyguard's own files ------
# No keys here. Variable names appear with empty values; code is real or generic.
def diff_rows(a, b, rows):
    """GitHub's unified diff: a hunk header, then old and new line numbers in a two-column gutter
    and the sign. The header's counts are counted from the rows, so the page agrees with itself."""
    out, old_n, new_n = [], 0, 0
    for sign, text in rows:
        if sign == " ":
            out.append(("", "%3d %3d   %s" % (a + old_n, b + new_n, text)))
            old_n, new_n = old_n + 1, new_n + 1
        elif sign == "-":
            out.append(("-", "%3d       - %s" % (a + old_n, text)))
            old_n += 1
        else:
            out.append(("+", "    %3d   + %s" % (b + new_n, text)))
            new_n += 1
    return [("@", "@@ -%d,%d +%d,%d @@" % (a, old_n, b, new_n))] + out


TABS = [("b", "<> Code     Issues     Pull requests     Actions     Security     Insights")]
FILES = [
    ("b", "Name           Last commit message         Last commit date"),
    ("", "internal/      add known-key matcher       yesterday"),
    ("", "cmd/           wire up the poll command    yesterday"),
    ("", "rules/         tune the extra rules        last week"),
    ("", "docs/          benchmarks                  last week"),
    ("", ".gitignore     ignore .env and *.pem       last week"),
    ("", "go.mod         init                        last week"),
]
COMMITS = [
    ("b", "Commits on Nov 3, 2026"),
    ("", "fix webhook retries"),
    ("", "add .env.example"),
    ("", "move secrets to the vault"),
    ("", "bump deps"),
    ("", "ci: cache npm"),
    ("", "initial import"),
]
DIFF = (
    [("b", "src/billing.js")]
    + diff_rows(
        4, 4,
        [
            ("-", "const key = readSecret();"),
            ("+", 'const key = "%s";' % mask("sk_live_", 4, "a1B2")),
            (" ", ""),
            (" ", 'app.post("/pay", async (req, res) => {'),
            (" ", "  const pay = await stripe.charges.create({"),
            (" ", "    amount: req.body.amount,"),
        ],
    )
)


def plain_diff(a, b, rows):
    """What `git diff` prints: a hunk header and the rows with a one-character sign, no gutter."""
    out, old_n, new_n = [], 0, 0
    for sign, text in rows:
        out.append(("" if sign == " " else sign, "%s %s" % (sign, text)))
        old_n += sign != "+"
        new_n += sign != "-"
    return [("@", "@@ -%d,%d +%d,%d @@" % (a, old_n, b, new_n))] + out


GIT_DIFF = (
    [("b", "src/billing.js")]
    + plain_diff(
        4, 4,
        [
            ("-", "const key = readSecret();"),
            ("+", 'const key = "%s";' % mask("sk_live_", 4, "a1B2")),
            (" ", ""),
            (" ", 'app.post("/pay", async (req, res) => {'),
            (" ", "  const pay = await stripe.charges.create({"),
            (" ", "    amount: req.body.amount,"),
        ],
    )
)

ENV = [
    ("b", ".env.example"),
    ("", "STRIPE_SECRET_KEY="),
    ("", "OPENAI_API_KEY="),
    ("", "SLACK_BOT_TOKEN="),
    ("", "AWS_ACCESS_KEY_ID="),
    ("", "GITHUB_TOKEN="),
]
WORKFLOW = [
    ("b", ".github/workflows/ci.yml"),
    ("", "on: [push, pull_request]"),
    ("", "jobs:"),
    ("", "  test:"),
    ("", "    runs-on: ubuntu-latest"),
    ("", "    steps:"),
    ("", "      - uses: actions/checkout"),
    ("", "      - run: go test ./..."),
]
HOOKS = [
    ("b", "# ~/.gitconfig"),
    ("", '[hook "keyguard-precommit"]'),
    ("", "  event = pre-commit"),
    ("", "  command = test -x ~/.keyguard/bin/keyguard || exit 0;"),
    ("", "    exec ~/.keyguard/bin/keyguard hook pre-commit"),
    ("", '[hook "keyguard-prepush"]'),
    ("", "  event = pre-push"),
    ("", '[hook "keyguard-reftx"]'),
    ("", "  event = reference-transaction"),
]
CMDS = [
    ("b", "$ keyguard doctor"),
    ("", "$ keyguard selftest"),
    ("", "$ keyguard learn"),
    ("", "$ keyguard publish-check owner/name"),
    ("", "$ git push origin main"),
    ("", "$ keyguard github-settings --apply"),
    ("", "$ keyguard report --open"),
]
PLIST = [
    ("b", "# ~/Library/LaunchAgents/io.github.hangryclaude.keyguard.poll.plist"),
    ("", "<dict>"),
    ("", "  <key>Label</key>"),
    ("", "  <string>io.github.hangryclaude.keyguard.poll</string>"),
    ("", "  <key>StartInterval</key>"),
    ("", "  <integer>%d</integer>"),
    ("", "</dict>"),
]
RATE_GO = [
    ("b", "// Rate is found/total for one slice of the plants."),
    ("", "type Rate struct {"),
    ("", '  Total           int     `json:"total"`'),
    ("", '  Found           int     `json:"found"`'),
    ("", '  Recall          float64 `json:"recall"`'),
    ("", '  Detectable      int     `json:"detectable"`'),
    ("", '  FoundDetectable int     `json:"found_detectable"`'),
    ("", "}"),
]


def cycle(blocks, rows, skip=0):
    """Cycle through blocks of lines (a blank line between them) until there are `rows` lines."""
    flat = []
    for b in blocks:
        flat += list(b) + [("", "")]
    out, i = [], skip
    while len(out) < rows:
        out.append(flat[i % len(flat)])
        i += 1
    return out


def plist_lines(nums):
    return [(k, s % nums["watcher"]["poll_seconds"] if "%d" in s else s) for k, s in PLIST]


def every(minutes):
    # the program's own wording: "every minute", never "every 1 minutes"
    return "every minute" if minutes == 1 else "every %d minutes" % minutes


def layer_gates(nums):
    """The seven gates, in the order a key meets them: layer, name, caption, masked key, side of the
    track (wide picture), whether git's --no-verify skips it, colour."""
    poll_min = nums["watcher"]["poll_seconds"] // 60
    pem = "-----BEGIN" + ELL + "KEY-----"
    return [
        ("L2", "AI-agent guard", "denies --no-verify", mask("sk-ant-", 4, "Lm9Q"), "up", False, BLUE),
        ("L1", "pre-commit", "what you staged", mask("AIza", 6, "xR0s"), "dn", True, AMBER),
        ("L1", "reference-transaction", "learned keys only", mask("sk_live_", 3, "a1B2"), "up", False, VIOLET),
        ("L1", "pre-push", "commits a push sends", mask("AKIA", 5, "Q7XZ"), "dn", True, SKY),
        ("L3", "GitHub scanning", "free on public repos", mask("ghp_", 6, "9f3K"), "up", False, AMBER),
        ("L5", "publish check", "whole history", pem, "dn", False, BLUE),
        ("L4", "crawler", every(poll_min), mask("glpat-", 4, "nB4y"), "up", False, SKY),
    ]


# ---- layers.svg ------------------------------------------------------------------------
def build_layers(nums):
    W, H = 1280, 580
    sc = Scene(
        "layers", W, H,
        "keyguard: five layers between your keyboard and GitHub",
        "A thin crawler, small glowing dots joined by hairlines, climbs a rising track from KEYBOARD through COMMIT and PUSH to "
        "GITHUB. Gates stand on the track, in this order: L2 AI-agent guard, L1 pre-commit, L1 reference-transaction, L1 pre-push, "
        "L3 GitHub scanning, L5 publish check and L4 crawler. L1 is three git hooks, so it has three gates. Six gates stamp a "
        "masked API key BLOCKED (the AI-agent guard blocks the command that would let a key through); the crawler finds keys "
        "already on GitHub and stamps them FOUND. A magenta tag marks the gates that ignore git --no-verify; an outline tag marks "
        "the two it skips. Two more crawlers hang off the track: one at the GitHub end reaches the two layers that scan GitHub "
        "and has two more masked keys in its sights, one under KEYBOARD has a masked key of its own in its sights.",
        31,
    )
    css, rng = sc.css, sc.rng
    XT0, XT1, M, YT0 = 28, 1252, 0.12, 372
    ANG = math.atan(M)
    DEG = math.degrees(ANG)

    def BY(x):
        return YT0 - M * (x - XT0)

    WU, UH, KS, KH = 278, 140, 22, 40
    DROP = int(round(M * (WU + 8)))  # the track is this much lower at a card's left end than at its gate
    GX = [316, 460, 604, 748, 892, 1036, 1180]
    T1, DT = 0.55, 0.24  # the crawler reaches the first gate at T1 and the next one DT later: the whole build is done by 2.5 s
    GATES = layer_gates(nums)
    STATIONS = [("KEYBOARD", 160), ("COMMIT", 676), ("PUSH", 820), ("GITHUB", 964)]
    neon(sc)
    gutter(sc)

    # the track: a dim rail that rises to the right, with chevrons
    L = (XT1 - XT0) / math.cos(ANG)
    chev, x = [], 24
    while x < L - 20:
        chev.append("M%d -5l8 5l-8 5" % x)
        x += 40
    sc.add(
        "back",
        '<g transform="translate(%s %s) rotate(%s)"><rect x="0" y="-16" width="%s" height="32" rx="16" fill="%s" fill-opacity=".10"/><rect x="0" y="-11" width="%s" height="22" rx="11" fill="%s" fill-opacity=".16"/>'
        '<rect x="0" y="-7" width="%s" height="14" rx="7" fill="%s" fill-opacity=".55"/>'
        '<path d="M7 -7H%s M7 7H%s" stroke="%s" stroke-opacity=".3"/>'
        '<path d="%s" fill="none" stroke="%s" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" opacity=".7"/></g>'
        % (n(XT0), n(YT0), n(-DEG), n(L), VIOLET, n(L), VIOLET, n(L), DIM, n(L - 7), n(L - 7), WIRE, "".join(chev), DIM2),
    )

    boxes = []
    for i, (lay, name, cap, key, side, skippable, color) in enumerate(GATES):
        gx = GX[i]
        by = BY(gx)
        up = side == "up"
        top = by - 44 - UH if up else by + 44 + DROP
        ux = gx - 8 - WU
        t = T1 + DT * i
        off = off_at(i)
        assert len(name) * ADV * 19 <= WU and len(cap) * ADV * 15 <= WU and len(key) * ADV * KS + 24 <= WU, name
        boxes.append((name, (ux - 6, top - 6, WU + 6, UH + 12)))
        sc.add("plate", '<rect%s x="%s" y="%s" width="%s" height="%s" rx="6" fill="%s" fill-opacity=".93"/>' % (css.attr(fade_in(t - 0.4, off)), n(ux - 6), n(top - 6), n(WU + 6), n(UH + 12), PANEL))
        sc.clr(ux - 8, top - 8, WU + 10, UH + 16)
        sc.keep(ux - 16, top - 16, WU + 28, UH + 32)
        sc.text("front", ux, top + 20, name, 19, ICE, bg=PANEL, bold=True, frames=fade_in(t - 0.35, off), clear=False)

        # the key it stops: a neon bar wiping in from the left until it meets the barrier
        bar_y = top + 30
        fr = grow(t + 0.05, off, 0.30)
        origin = (ux, bar_y + KH / 2.0)
        sc.add(
            "back",
            '<g%s><rect x="%s" y="%s" width="%s" height="%s" rx="9" fill="%s" opacity=".10"/><rect x="%s" y="%s" width="%s" height="%s" rx="6" fill="%s" opacity=".22"/>'
            '<rect x="%s" y="%s" width="%s" height="%s" rx="3" fill="none" stroke="%s" stroke-opacity=".55" stroke-width="1.2"/></g>'
            % (css.attr(fr, origin=origin), n(ux - 10), n(bar_y - 10), n(WU + 20), n(KH + 20), color, n(ux - 5), n(bar_y - 5), n(WU + 10), n(KH + 10), color, n(ux + 5), n(bar_y - 4), n(WU), n(KH), color),
        )
        sc.add("mid", '<rect%s x="%s" y="%s" width="%s" height="%s" rx="2" fill="%s"/>' % (css.attr(fr, origin=origin), n(ux), n(bar_y), n(WU), n(KH), color))
        sc.text("front", ux + WU / 2.0, bar_y + KH / 2.0 + 0.33 * KS, key, KS, ink(color), bg=color, bold=True, align="c", frames=jitter_in(t + 0.14, off), clear=False)
        reticle(sc, "front", ux - 4, bar_y - 4, WU + 8, KH + 8, color, arm=9, width=1.5, frames=snap(t + 0.2, off))

        # the verdict, and whether --no-verify can skip this gate
        found = lay == "L4"  # the watcher finds keys that are already on GitHub; it cannot block them
        sw = stamp(sc, "front", ux, top + 80, frames=stamp_in(t + 0.34, off), word="FOUND" if found else "BLOCKED", fill=AMBER if found else RED, size=15)
        # the tag says what the flag does to this gate, not that nothing can switch it off: a
        # person can still turn a hook off for one command (see README, Limits)
        if skippable:
            wp = pill(sc, "front", ux + sw + 8, top + 80, "skippable", 14, None, stroke=WIRE, h=25, padx=10, frames=slide_in(t + 0.44, off))
        else:
            wp = pill(sc, "front", ux + sw + 8, top + 80, NO_VERIFY_TAG, 14, MAGENTA, h=25, padx=10, frames=slide_in(t + 0.44, off))
        assert sw + 8 + wp <= WU, "the verdict row is wider than its card: %s" % name
        sc.text("front", ux, top + 130, cap, 15, WIRE, bg=PANEL, frames=fade_in(t + 0.5, off), clear=False)

        # the gate: a post from the node to a barrier at the end of the bar. It is drawn when the
        # crawler's head reaches the node, so it reads as the crawler reaching out to the key.
        if up:
            y1, y2 = by - 26, bar_y + KH + 8
        else:
            y1, y2 = by + 26, bar_y - 8
        hairline(sc, "front", gx, y1, gx, y2, ICE, t, t + 0.2, off, width=2, op=".75")
        sc.add(
            "front",
            '<g%s><rect x="%d" y="%s" width="16" height="%d" rx="6" fill="%s" fill-opacity=".22"/><rect x="%d" y="%s" width="6" height="%d" rx="3" fill="%s"/></g>'
            % (css.attr(fade_in(t - 0.3, off)), gx - 8, n(bar_y - 11), KH + 22, WIRE, gx - 3, n(bar_y - 8), KH + 16, ICE),
        )
        sc.add("front", '<rect%s x="%d" y="%s" width="22" height="%d" rx="8" fill="%s" opacity="0"/>' % (css.attr(blip(t + 0.1, 0.12)), gx - 11, n(bar_y - 16), KH + 32, WIRE))
        for s_i in range(2):
            sw_, sh_ = rng.choice([10, 14, 18]), rng.choice([3, 4])
            sy = bar_y + rng.uniform(-4, KH)
            a = css.attr(seam([(0, {"opacity": "0"}, STEP), (t + 0.12, {"opacity": "1"}, STEP), (t + 0.17, {"opacity": "0"}, STEP), (t + 0.20, {"opacity": "1"}, STEP), (t + 0.30, {"opacity": "0"}, None)], {"opacity": "0"}))
            sc.add("mid", '<rect%s x="%s" y="%s" width="%d" height="%d" fill="%s" opacity="0"/>' % (a, n(gx + 6 + s_i * 7), n(sy), sw_, sh_, color if s_i == 0 else ICE))

        # the node on the track, with a ping when the crawler arrives
        sc.add("front", '<circle cx="%d" cy="%s" r="27" fill="none" stroke="%s" stroke-opacity=".35"/><circle cx="%d" cy="%s" r="22" fill="%s"/>' % (gx, n(by), WIRE, gx, n(by), ICE))
        sc.add("front", '<circle%s cx="%d" cy="%s" r="27" fill="none" stroke="%s" stroke-width="2" opacity="0"/>' % (css.attr(ping(t, 0.45), origin=(gx, by)), gx, n(by), ICE))
        sc.text("front", gx, by + 5.6, lay, 17, PAGE, bg=ICE, bold=True, align="c")

        # a small crawler climbs the post to the key
        sp, _ = spider_svg(random.Random(100 + i), 0.34, 96.0)
        dy = (bar_y + KH / 2.0) - by
        hid = {"opacity": "0", "transform": "translateY(0px)"}
        fr = seam(
            [
                (0, hid, STEP),
                (t, {"opacity": "1", "transform": "translateY(0px)"}, LIN),
                (t + 0.26, {"opacity": "1", "transform": "translateY(%spx)" % n(dy)}, STEP),
                (t + 0.8, {"opacity": "0", "transform": "translateY(%spx)" % n(dy)}, STEP),
            ],
            hid,
        )
        sc.add("mid", '<g transform="translate(%d %s)"><g class="k %s" opacity="0">%s</g></g>' % (gx, n(by), css.tl(fr), sp))

    # the stations on the track
    for name, cx in STATIONS:
        pill(sc, "front", cx, BY(cx) - 15, name, 16, ICE, h=30, padx=14, align="c")

    # the thin crawler climbs the track, head first, pausing at every gate; it rests at GITHUB's end
    s_of = lambda x: (x - XT0) / math.cos(ANG)
    s_start, s_rest = -40.0, s_of(1236)
    hid = {"opacity": "0", "transform": "translateX(%spx)" % n(s_start)}
    fr = [(0, hid, STEP), (0.3, {"opacity": "1", "transform": "translateX(%spx)" % n(s_start)}, IO_EASE)]
    for i, gx in enumerate(GX):
        t = T1 + DT * i
        s = s_of(gx)
        fr.append((t, {"opacity": "1", "transform": "translateX(%spx)" % n(s)}, LIN))
        fr.append((t + 0.08, {"opacity": "1", "transform": "translateX(%spx)" % n(s)}, IO_EASE))
    t_end = T1 + DT * 6 + 0.08 + 0.3
    fr.append((t_end, {"opacity": "1", "transform": "translateX(%spx)" % n(s_rest)}, STEP))
    fr += flicker(T_OFF + 0.02, {"transform": "translateX(%spx)" % n(s_rest)})
    fr.append((T, hid, None))
    cp = crawler_svg(-700, 0, 700, 5, 120, 32, phase=0.6, sz=0.9, leg=21.0)
    crawl(sc, cp, XT0, YT0, DEG, fr, s_rest)

    # the crawler at GitHub's end reaches the two layers that scan GitHub (publish check and
    # watcher) and has two more masked keys in its sights
    sx, sy = 1150, 424
    sp, srad = spider_svg(random.Random(77), 0.62, 96.0)
    sc.add("mid", '<g%s><g transform="translate(%d %d)">%s</g></g>' % (css.attr(fade_in(T1 + DT * 4.6, off_at(7))), sx, sy, sp))
    sc.clr(sx - srad - 6, sy - srad - 6, 2 * srad + 12, 2 * srad + 12)
    sc.keep(sx - srad - 10, sy - srad - 10, 2 * srad + 20, 2 * srad + 20)
    for k, gi in enumerate((5, 6)):
        nx, ny = GX[gi], BY(GX[gi])
        dx, dy = nx - sx, ny - sy
        d = math.hypot(dx, dy)
        ex, ey = nx - dx / d * 28, ny - dy / d * 28
        t = T1 + DT * gi + 0.12
        hairline(sc, "mid", sx, sy, ex, ey, WIRE, t, t + 0.3, off_at(8 + k), width=1.3, op=".85")
    FOUND = [(mask("xoxb-", 6, "7Hq2"), SKY, 1066, 292), (mask("sk-proj-", 5, "Zt8w"), MAGENTA, 1106, 492)]
    for k, (key, color, fx, fy) in enumerate(FOUND):
        t, off = T1 + DT * 5 + 0.2 * k, off_at(9 + k)
        fw = pill(sc, "front", fx, fy, key, 13, color, h=24, padx=8, rx=3, frames=jitter_in(t, off))
        reticle(sc, "front", fx - 5, fy - 5, fw + 10, 34, color, arm=7, width=1.4, frames=snap(t + 0.1, off))
        ex, ey = (fx + fw / 2.0, fy + 29) if fy < sy else (fx + fw / 2.0, fy - 5)
        hairline(sc, "mid", sx, sy, ex, ey, WIRE, t, t + 0.3, off, width=1.2, op=".7")
        sc.add("mid", '<g%s>%s</g>' % (css.attr(fade_in(t + 0.28, off)), dots([(ex, ey)], 2.6, ICE)))

    # and one at the start of the track, under KEYBOARD: it has the first key in its sights
    lx, ly = 98, 466
    sp, lrad = spider_svg(random.Random(79), 0.5, 96.0)
    sc.add("mid", '<g%s><g transform="translate(%d %d)">%s</g></g>' % (css.attr(fade_in(T1 - 0.2, off_at(11))), lx, ly, sp))
    sc.clr(lx - lrad - 6, ly - lrad - 6, 2 * lrad + 12, 2 * lrad + 12)
    sc.keep(lx - lrad - 10, ly - lrad - 10, 2 * lrad + 20, 2 * lrad + 20)
    key, color, fx, fy = mask("hf_", 6, "pQ4x"), AMBER, 36, 528
    t, off = T1 - 0.1, off_at(12)
    fw = pill(sc, "front", fx, fy, key, 13, color, h=24, padx=8, rx=3, frames=jitter_in(t, off))
    reticle(sc, "front", fx - 5, fy - 5, fw + 10, 34, color, arm=7, width=1.4, frames=snap(t + 0.1, off))
    hairline(sc, "mid", lx, ly, fx + fw / 2.0, fy - 5, WIRE, t, t + 0.3, off, width=1.2, op=".7")
    sc.add("mid", '<g%s>%s</g>' % (css.attr(fade_in(t + 0.28, off)), dots([(fx + fw / 2.0, fy - 5)], 2.6, ICE)))
    hairline(sc, "mid", lx, ly, 150, BY(150) + 17, WIRE, t, t + 0.3, off, width=1.2, op=".7")


    # a scan sweep during the build, and a second one over the finished chart (it sits behind
    # the plates, so no word is ever on it)
    beams(sc, [(-27, 30, (640, 290), (0.3, 1.2), None), (-27, 14, (640, 290), (4.9, 5.7), 150)])

    # the one legend: what the magenta tag means
    sc.add("plate", '<rect x="38" y="34" width="440" height="72" rx="6" fill="%s" fill-opacity=".94"/>' % PANEL)
    sc.clr(34, 30, 448, 80)
    sc.keep(30, 26, 456, 88)
    for kx in range(XT0 - 20, XT1 + 20, 36):  # the rail the crawler walks stays clean
        sc.keep(kx, BY(kx + 18) - 40, 36, 80)
    cx = 50
    w1 = pill(sc, "top", cx, 42, NO_VERIFY_TAG, 15, MAGENTA, h=26, padx=10)
    sc.text("top", cx + w1 + 12, 61, "git's flag has no effect", 15, ICE, bg=PANEL, clear=False)
    w2 = pill(sc, "top", cx, 72, "skippable", 15, None, stroke=WIRE, h=26, padx=10)
    sc.text("top", cx + w2 + 12, 91, "--no-verify skips it", 15, ICE, bg=PANEL, clear=False)
    wordmark(sc, W - 18, H - 30, t_glitch=pg(3.6))

    for i in range(len(boxes)):
        for j in range(i + 1, len(boxes)):
            if rect_hit(boxes[i][1], boxes[j][1], 4):
                raise SystemExit("layers: units overlap: %s x %s" % (boxes[i][0], boxes[j][0]))

    web(sc, (48, 392, 114, 100), 5, 30, 64, seed=3)
    web(sc, (494, 22, 100, 78), 4, 30, 74, hubs=[(491, 58)], seed=4)

    rows = (H - 60) // 14
    panes = [
        {"x": 640, "y": 36, "room": 580, "lines": TABS},
        {"x": 46, "y": 118, "room": 400, "lines": cycle([FILES, DIFF, COMMITS], rows, 0)},
        {"x": 462, "y": 64, "room": 400, "lines": cycle([HOOKS, ENV, plist_lines(nums)], rows, 3)},
        {"x": 878, "y": 64, "room": 380, "lines": cycle([COMMITS, WORKFLOW, CMDS], rows, 5)},
    ]
    dim_page(sc, panes, strict=True)
    return sc


# ---- layers-narrow.svg: the same path, stood upright for a phone ------------------------
def build_layers_narrow(nums):
    """The layers picture for a 358 px wide column. The rail runs down the left, the thin crawler
    climbs down it, and each gate is a row: its name, the masked key it stops, the verdict, and
    whether git's --no-verify skips it. The canvas is 640 px wide, so the phone shows it at 56 %
    and every size here is about twice the wide picture's. README serves it below 600 px."""
    W = 640
    gates = layer_gates(nums)
    # the rail, top to bottom: KEYBOARD, then the gates, with COMMIT, PUSH and GITHUB between them
    seq = [("st", "KEYBOARD"), ("g", 0), ("g", 1), ("g", 2), ("st", "COMMIT"), ("g", 3), ("st", "PUSH"), ("g", 4), ("st", "GITHUB"), ("g", 5), ("g", 6)]
    TOP, ROW, STN = 132, 124, 40
    ys, y = [], TOP
    for kind, _v in seq:
        ys.append(y)
        y += ROW if kind == "g" else STN
    H = int(y + 52)
    sc = Scene(
        "layers-narrow", W, H,
        "keyguard: five layers between your keyboard and GitHub",
        "The phone-sized version of the layers picture. A rail runs down the left from KEYBOARD through COMMIT and PUSH to GITHUB, "
        "and a thin crawler, small glowing dots joined by hairlines, climbs down it. Seven gates stand along it, each a row: L2 AI-agent guard, L1 pre-commit, "
        "L1 reference-transaction, L1 pre-push, L3 GitHub scanning, L5 publish check and L4 watcher. Each row shows a masked API key, "
        "the verdict BLOCKED (FOUND for the watcher, which finds keys already on GitHub) and a tag: a magenta tag for the gates "
        "that ignore git --no-verify, an outline tag for the two it skips.",
        32,
    )
    css = sc.css
    RX, CX0, CW = 70, 136, 484
    neon(sc)
    gutter(sc)

    # the legend, above the rail
    sc.add("plate", '<rect x="%d" y="34" width="%d" height="84" rx="6" fill="%s" fill-opacity=".94"/>' % (CX0 - 100, CW + 100 - 20, PANEL))
    sc.clr(CX0 - 104, 30, CW + 90, 92)
    sc.keep(CX0 - 108, 26, CW + 98, 100)
    w1 = pill(sc, "top", 44, 44, NO_VERIFY_TAG, 16, MAGENTA, h=28, padx=10)
    sc.text("top", 44 + w1 + 12, 64, "git's flag has no effect", 16, ICE, bg=PANEL, clear=False)
    w2 = pill(sc, "top", 44, 80, "skippable", 16, None, stroke=WIRE, h=28, padx=10)
    sc.text("top", 44 + w2 + 12, 100, "--no-verify skips it", 16, ICE, bg=PANEL, clear=False)

    # the rail
    y0, y1 = ys[0], ys[-1] + 60
    chev = "".join("M%d %dl4 6l4 -6" % (RX - 4, yy) for yy in range(int(y0) + 30, int(y1) - 20, 36))
    sc.add(
        "back",
        '<rect x="%d" y="%d" width="12" height="%d" rx="6" fill="%s" fill-opacity=".55"/>'
        '<path d="%s" fill="none" stroke="%s" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" opacity=".7"/>'
        % (RX - 6, y0 - 8, y1 - y0 + 8, DIM, chev, DIM2),
    )
    sc.keep(RX - 20, y0 - 10, 40, y1 - y0 + 12)

    # build: the crawler reaches element k at t0 + k * dt; everything is on screen by about 2.5 s
    T0, DTK = 0.35, 0.17
    marks = []
    for k, ((kind, v), top) in enumerate(zip(seq, ys)):
        t = T0 + DTK * k
        off = off_at(k)
        if kind == "st":
            pill(sc, "front", RX, top + 6, v, 16, ICE, h=28, padx=14, align="c", frames=fade_in(t, off))
            marks.append((t, top + 20))
            continue
        lay, name, cap, key, _side, skippable, color = gates[v]
        card_top = top
        sc.add("plate", '<rect%s x="%d" y="%d" width="%d" height="%d" rx="6" fill="%s" fill-opacity=".93"/>' % (css.attr(fade_in(t - 0.1, off)), CX0 - 8, card_top, CW + 8, ROW - 10, PANEL))
        sc.clr(CX0 - 10, card_top - 2, CW + 12, ROW - 6)
        sc.keep(CX0 - 14, card_top - 6, CW + 24, ROW + 2)
        sc.text("front", CX0 + 4, card_top + 22, name, 21, ICE, bg=PANEL, bold=True, frames=fade_in(t, off), clear=False)
        sc.text("front", CX0 + CW - 12, card_top + 22, cap, 16, WIRE, bg=PANEL, align="r", frames=fade_in(t + 0.3, off), clear=False)
        bar_y, KH = card_top + 32, 42
        fr = grow(t + 0.05, off, 0.25)
        origin = (CX0 + 4, bar_y + KH / 2.0)
        sc.add(
            "back",
            '<g%s><rect x="%d" y="%d" width="%d" height="%d" rx="9" fill="%s" opacity=".10"/><rect x="%d" y="%d" width="%d" height="%d" rx="6" fill="%s" opacity=".22"/>'
            '<rect x="%d" y="%d" width="%d" height="%d" rx="3" fill="none" stroke="%s" stroke-opacity=".55" stroke-width="1.2"/></g>'
            % (css.attr(fr, origin=origin), CX0 - 6, bar_y - 6, CW - 8 + 4, KH + 12, color, CX0 - 2, bar_y - 2, CW - 8 + 4 - 8, KH + 4, color, CX0 + 9, bar_y - 4, CW - 16, KH, color),
        )
        sc.add("mid", '<rect%s x="%d" y="%d" width="%d" height="%d" rx="2" fill="%s"/>' % (css.attr(fr, origin=origin), CX0 + 4, bar_y, CW - 16, KH, color))
        sc.text("front", CX0 + 4 + (CW - 16) / 2.0, bar_y + KH / 2.0 + 0.33 * 26, key, 26, ink(color), bg=color, bold=True, align="c", frames=jitter_in(t + 0.12, off), clear=False)
        reticle(sc, "front", CX0, bar_y - 4, CW - 8, KH + 8, color, arm=10, width=1.8, frames=snap(t + 0.2, off))
        found = lay == "L4"
        sw = stamp(sc, "front", CX0 + 4, bar_y + KH + 8, frames=stamp_in(t + 0.22, off), word="FOUND" if found else "BLOCKED", fill=AMBER if found else RED, size=17)
        if skippable:
            wp = pill(sc, "front", CX0 + 4 + sw + 8, bar_y + KH + 8, "skippable", 16, None, stroke=WIRE, h=27, padx=10, frames=slide_in(t + 0.3, off))
        else:
            wp = pill(sc, "front", CX0 + 4 + sw + 8, bar_y + KH + 8, NO_VERIFY_TAG, 16, MAGENTA, h=27, padx=10, frames=slide_in(t + 0.3, off))
        assert 4 + sw + 8 + wp <= CW - 4, "the verdict row is wider than its card: %s" % name
        # the node on the rail, and a short link to the card
        ny = bar_y + KH / 2.0
        sc.add("front", '<path d="M%d %sH%d" stroke="%s" stroke-width="2" stroke-opacity=".75"/>' % (RX + 14, n(ny), CX0 - 6, ICE))
        sc.add("front", '<circle cx="%d" cy="%s" r="22" fill="none" stroke="%s" stroke-opacity=".35"/><circle cx="%d" cy="%s" r="18" fill="%s"/>' % (RX, n(ny), WIRE, RX, n(ny), ICE))
        sc.add("front", '<circle%s cx="%d" cy="%s" r="22" fill="none" stroke="%s" stroke-width="2" opacity="0"/>' % (css.attr(ping(t, 0.45), origin=(RX, ny)), RX, n(ny), ICE))
        sc.text("front", RX, ny + 5.5, lay, 15, PAGE, bg=ICE, bold=True, align="c")
        marks.append((t, ny))

    # the thin crawler climbs down the rail, one step per element, and rests at the last gate
    s_start, s_rest = -40.0, marks[-1][1]
    hid = {"opacity": "0", "transform": "translateX(%spx)" % n(s_start)}
    fr = [(0, hid, STEP), (0.15, {"opacity": "1", "transform": "translateX(%spx)" % n(s_start)}, IO_EASE)]
    for t, yy in marks:
        fr.append((t, {"opacity": "1", "transform": "translateX(%spx)" % n(yy)}, LIN))
    fr.append((marks[-1][0] + 0.2, {"opacity": "1", "transform": "translateX(%spx)" % n(s_rest)}, STEP))
    fr += flicker(T_OFF + 0.02, {"transform": "translateX(%spx)" % n(s_rest)})
    fr.append((T, hid, None))
    crawl(sc, crawler_svg(-330, 0, 330, 4, 100, 16, phase=0.5, sz=1.05, leg=22.0), RX, 0, -90, fr, s_rest)
    sc.clr(RX - 36, 120, 72, y1 - 100)

    # a loose web of dots and hairlines fills the gaps between the cards, where the rail meets a station
    for k, ((kind, v), top) in enumerate(zip(seq, ys)):
        if kind == "st":
            web(sc, (CX0 - 4, top - 2, CW - 20, 34), 4, 70, 150, seed=20 + k)
    wordmark(sc, W - 18, H - 28, size=18, t_glitch=pg(3.2))

    beams(sc, [(-27, 30, (320, H / 2.0), (0.3, 1.5), None), (-27, 12, (320, H / 2.0), (5.0, 5.9), None)])
    return sc


# ---- speed.svg -------------------------------------------------------------------------
def build_speed(nums):
    W, H = 1280, 460
    hk, scn = nums["hooks"], nums["scans"]
    runs = int(re.search(r"(\d+) timed runs", hk["source"]).group(1))
    lo, hi = [float(v) for v in str(hk["git_commit_with_hooks_ms"]).split("-")]
    pc, pcb = hk["pre_commit_p50_ms"], hk["pre_commit_budget_ms"]
    rt, rtb = hk["reference_transaction_p50_ms"], hk["reference_transaction_budget_ms"]
    off_ms = hk["git_commit_without_hooks_ms"]
    scan_s, repos, workers = scn["public_full_history_seconds"], scn["public_repos"], scn["public_workers"]
    all_n, all_s, all_w = scn["all_repos_and_gists"], scn["all_repos_seconds"], scn["all_repos_workers"]
    ax_max = float(max(pcb, rtb, hi))
    assert ax_max % 50 == 0, "the ms axis ticks every 50 ms; make the maximum a multiple of 50"
    desc = (
        "Bars start at zero. The pre-commit hook takes %s ms at the median (95th percentile %s ms) against a %s ms budget. "
        "The reference-transaction hook takes %s ms (95th percentile %s ms) against a %s ms budget. A whole git commit takes "
        "%s ms without the hooks and %s ms with them. A full-history scan of %d public repos takes %s s. A thin crawler, small "
        "glowing dots joined by hairlines, climbs between the two panels and reaches a hairline out to the end of every bar; "
        "a spider walks across %d repo cards as the scan bar grows. A field of %d dots, one for each repo and gist, lies under "
        "the scan time of all of them."
        % (g(pc), g(hk["pre_commit_p95_ms"]), g(pcb), g(rt), g(hk["reference_transaction_p95_ms"]), g(rtb), g(off_ms), hk["git_commit_with_hooks_ms"], repos, g(scan_s), repos, all_n)
    )
    sc = Scene("speed", W, H, "keyguard: hook speed against budget", desc, 41)
    css = sc.css
    neon(sc)
    gutter(sc)
    sc.defs.append('<pattern id="hz" width="9" height="9" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="9" height="1.4" fill="%s" fill-opacity=".34"/></pattern>' % BLUE)
    X0, AXW = 300, 430.0
    pxms = AXW / ax_max
    X1 = X0 + AXW
    YAX = 372
    CX = 806  # the corridor the crawler climbs

    # the axis: one scale from zero, ticks every 50 ms
    sc.text("front", 40, 38, "median of %d runs" % runs, 15, WIRE)
    ticks = [float(v) for v in range(0, int(ax_max) + 1, 50)]
    grid = "".join("M%s 52V%d" % (n(X0 + v * pxms), YAX) for v in ticks)
    sc.add("back", '<path d="%s" fill="none" stroke="%s" stroke-opacity=".35" stroke-width="1"/>' % (grid, DIM2))
    sc.add("back", '<path d="M%s %dH%s" fill="none" stroke="%s" stroke-opacity=".5" stroke-width="1"/>' % (n(X0), YAX, n(X1), WIRE))
    for v in ticks:
        sc.add("back", '<path d="M%s %dv6" stroke="%s" stroke-opacity=".5" stroke-width="1"/>' % (n(X0 + v * pxms), YAX, WIRE))
        sc.text("front", X0 + v * pxms, YAX + 26, g(v) + (" ms" if v == ticks[-1] else ""), 15, WIRE, align="c")

    # the crawler's visits: its head passes each row top to bottom, and a hairline reaches out to the end of each bar
    T_V = {"pc": 0.35, "rt": 0.7, "off": 1.05, "on": 1.4}
    YC = {}

    def spoke(key, yc, tip_x, color):
        t = T_V[key]
        YC[key] = yc
        hairline(sc, "mid", CX, yc, tip_x, yc, WIRE, t, t + 0.22, off_at(9), width=1.3, op=".85")
        sc.add("mid", '<g%s>%s<circle cx="%s" cy="%s" r="7" fill="none" stroke="%s" stroke-opacity=".6"/></g>' % (css.attr(fade_in(t + 0.2, off_at(10))), dots([(tip_x, yc)], 3.2, ICE), n(tip_x), n(yc), color))

    def hook_row(top, key, name, val, bud, color):
        t, off = T_V[key] + 0.06, off_at(2 if key == "pc" else 3)
        sc.text("front", 40, top + 17, name, 19, ICE, bold=True)
        sc.text("front", 40, top + 58, "%s ms" % g(val), 44, ICE, bold=True, frames=jitter_in(t + 0.25, off))
        by = top + 26
        # the budget: a neon box drawn to the same scale, hatched, so the room that is left shows
        sc.add("back", '<rect x="%s" y="%s" width="%s" height="40" rx="3" fill="url(#hz)"/>' % (n(X0), n(by - 6), n(bud * pxms)))
        sc.add("back", '<rect x="%s" y="%s" width="%s" height="40" rx="5" fill="none" stroke="%s" stroke-opacity=".25" stroke-width="5"/>' % (n(X0 - 1), n(by - 7), n(bud * pxms + 2), BLUE))
        h_bar(sc, X0, by, val * pxms, 28, color, frames=grow(t, off, 0.45), ghost=True)
        sc.add("mid", '<rect x="%s" y="%s" width="%s" height="40" rx="3" fill="none" stroke="%s" stroke-width="1.6"/>' % (n(X0), n(by - 6), n(bud * pxms), BLUE))
        pill(sc, "front", X0 + bud * pxms, by - 33, "budget %s ms" % g(bud), 14, BLUE, h=24, padx=9, rx=3, align="r")
        spoke(key, by + 14, X0 + val * pxms, color)

    hook_row(54, "pc", "pre-commit", pc, pcb, MAGENTA)
    hook_row(132, "rt", "reference-transaction", rt, rtb, MAGENTA)

    sc.add("back", '<path d="M40 214H%s" stroke="%s" stroke-opacity=".5" stroke-width="1"/>' % (n(X1), DIM2))
    sc.text("front", 40, 238, "a whole git commit", 15, WIRE)

    def commit_row(top, key, name, val_text, w_solid, w_ext):
        t, off = T_V[key] + 0.06, off_at(4 if key == "off" else 5)
        sc.text("front", 40, top + 17, name, 19, ICE, bold=True)
        sc.text("front", 40, top + 49, val_text, 32, ICE, bold=True, frames=jitter_in(t + 0.25, off))
        by = top + 22
        h_bar(sc, X0, by, w_solid, 26, SKY, frames=grow(t, off, 0.45), rad=4 if not w_ext else 0, ghost=True)
        if w_ext:
            h_bar(sc, X0 + w_solid, by, w_ext, 26, SKY, frames=grow(t + 0.4, off, 0.2), rad=4, glow=False, opacity=0.5)
        spoke(key, by + 13, X0 + w_solid + w_ext, SKY)

    commit_row(248, "off", "hooks off", "%s ms" % g(off_ms), off_ms * pxms, 0)
    commit_row(310, "on", "hooks on", "%s%s%s ms" % (g(lo), EN, g(hi)), lo * pxms, (hi - lo) * pxms)
    calls = hk["reference_transaction_calls_per_commit"]
    sc.text("front", 40, 428, "Reference-transaction runs %d times per commit; one call does work." % calls, 15, WIRE)

    # the crawler climbs down the corridor between the panels, head first, pausing at each bar
    s_start, s_rest = -30.0, 360.0
    hid = {"opacity": "0", "transform": "translateX(%spx)" % n(s_start)}
    fr = [(0, hid, STEP), (0.15, {"opacity": "1", "transform": "translateX(%spx)" % n(s_start)}, IO_EASE)]
    for key in ("pc", "rt", "off", "on"):
        t, yc = T_V[key], YC[key]
        fr.append((t, {"opacity": "1", "transform": "translateX(%spx)" % n(yc)}, LIN))
        fr.append((t + 0.22, {"opacity": "1", "transform": "translateX(%spx)" % n(yc)}, IO_EASE))
    fr.append((1.9, {"opacity": "1", "transform": "translateX(%spx)" % n(s_rest)}, STEP))
    fr += flicker(T_OFF + 0.02, {"transform": "translateX(%spx)" % n(s_rest)})
    fr.append((T, hid, None))
    crawl(sc, crawler_svg(-300, 0, 300, 4, 90, 14, phase=0.5, sz=0.85, leg=18.0), CX, 0, -90, fr, s_rest)
    sc.clr(CX - 34, 52, 68, 330)

    # panel B: a scan of the public repos, in seconds, on its own axis from zero
    PX, SW = 884, 352.0
    s_max = float(math.ceil(scan_s))
    pxs = SW / s_max
    T_S = 0.5
    SCAN_ANIM = 1.4  # seconds the scan bar takes to draw: the real scan takes the number printed below, the build is compressed so the numbers show early
    t_done = T_S + SCAN_ANIM
    sc.add("back", '<path d="M858 44V440" stroke="%s" stroke-opacity=".35" stroke-width="1"/>' % DIM2)
    dt = SCAN_ANIM / repos
    gap = 5
    tw = (SW - gap * (repos - 1)) / repos
    repo_tiles(sc, PX, 52, repos, tw, 18, gap, T_S + 0.1, dt)
    sc.text("front", PX, 158, "%s s" % g(scan_s), 72, ICE, bold=True, frames=jitter_in(t_done + 0.05, off_at(7)))
    sc.text("front", PX, 182, "%d public repos, full history" % repos, 15, WIRE)
    sc.text("front", PX, 201, "%d workers" % workers, 15, WIRE)
    sgrid = "".join("M%s 214V262" % n(PX + v * pxs) for v in range(0, int(s_max) + 1))
    sc.add("back", '<path d="%s" fill="none" stroke="%s" stroke-opacity=".35" stroke-width="1"/>' % (sgrid, DIM2))
    sc.add("back", '<path d="M%s 262H%s" fill="none" stroke="%s" stroke-opacity=".5" stroke-width="1"/>' % (n(PX), n(PX + SW), WIRE))
    for v in range(0, int(s_max) + 1):
        sc.add("back", '<path d="M%s 262v6" stroke="%s" stroke-opacity=".5" stroke-width="1"/>' % (n(PX + v * pxs), WIRE))
        sc.text("front", PX + v * pxs, 288, str(v) + (" s" if v == int(s_max) else ""), 15, WIRE, align="c")
    bar_y = 222
    h_bar(sc, PX, bar_y, scan_s * pxs, 28, AMBER, frames=grow_lin(T_S + 0.1, SCAN_ANIM, off_at(7)), ghost=True)
    sc.text("front", PX, 340, "%s s" % g(all_s), 34, ICE, bold=True, frames=fade_in(t_done + 0.4, off_at(8)))
    sc.text("front", PX, 363, "all %d repos and gists, %d workers" % (all_n, all_w), 15, WIRE, frames=fade_in(t_done + 0.5, off_at(8)))

    # one dot for each repo and gist that took the 196 s: the field has exactly as many dots as the
    # number beside it, in rows of seven; a bright band sweeps across it once per loop
    FY = 374
    for FR in range(7, 16):  # more rows only when the dots would otherwise crowd (a pitch under 3 px)
        cols = -(-all_n // FR)
        fp = min(SW / cols, 6.0)
        if fp >= 3.0:
            break
    if FR * fp > 40:
        raise SystemExit("speed: the field of dots does not fit under the scan time; the scan covers too many repos and gists")
    pts = [(PX + 2 + (k % cols) * fp, FY + (k // cols) * fp) for k in range(all_n)]
    assert len(pts) == all_n
    sc.add("back", dots(pts, fp * 0.5, WIRE, ".12") + dots(pts, min(1.5, fp * 0.29), WIRE, ".75"))
    band = [
        (0, {"opacity": "0", "transform": "translateX(0px)"}, STEP),
        (t_done + 0.1, {"opacity": "1", "transform": "translateX(0px)"}, LIN),
        (t_done + 0.9, {"opacity": "1", "transform": "translateX(%dpx)" % int(SW - 26)}, STEP),
        (t_done + 0.95, {"opacity": "0", "transform": "translateX(%dpx)" % int(SW - 26)}, STEP),
        (T, {"opacity": "0", "transform": "translateX(0px)"}, None),
    ]
    sc.add("mid", '<rect%s x="%s" y="%s" width="26" height="%s" rx="3" fill="%s" fill-opacity=".30" opacity="0"/>' % (css.attr(band), n(PX), n(FY - 7), n(FR * fp + 4), AMBER))
    sc.clr(PX - 6, FY - 9, SW + 12, FR * fp + 8)

    # a spider walks the repo cards at the speed the scan runs; it ends at the right edge and
    # reaches down to the end of the bar
    sp, srad = spider_svg(random.Random(78), 0.42, 96.0)
    x_end, y_c = PX + SW - 18, 61
    s0 = PX + 2
    hid = {"opacity": "0", "transform": "translateX(%spx)" % n(s0 - x_end)}
    fr = seam(
        [
            (0, hid, STEP),
            (T_S - 0.2, {"opacity": "0", "transform": "translateX(%spx)" % n(s0 - x_end)}, STEP),
            (T_S, {"opacity": "1", "transform": "translateX(%spx)" % n(s0 - x_end)}, LIN),
            (t_done, {"opacity": "1", "transform": "translateX(0px)"}, STEP),
        ]
        + flicker(T_OFF + 0.04, {"transform": "translateX(0px)"})
        + [(T, hid, None)],
        hid,
    )
    sc.add("mid", '<g transform="translate(%s %d)"><g class="k %s">%s</g></g>' % (n(x_end), y_c, css.tl(fr), sp))
    ex, ey = PX + scan_s * pxs, bar_y + 14
    hairline(sc, "mid", x_end, y_c, ex, ey, WIRE, t_done, t_done + 0.3, off_at(9), width=1.3, op=".85")
    sc.add("mid", '<g%s>%s<circle cx="%s" cy="%s" r="7" fill="none" stroke="%s" stroke-opacity=".6"/></g>' % (css.attr(fade_in(t_done + 0.25, off_at(10))), dots([(ex, ey)], 3.2, ICE), n(ex), n(ey), AMBER))
    sc.clr(x_end - srad - 4, y_c - srad - 4, 2 * srad + 8, 2 * srad + 8)

    wordmark(sc, W - 18, H - 30, t_glitch=pg(2.9))
    beams(sc, [(-27, 26, (640, 230), (0.3, 1.1), None), (-27, 12, (640, 230), (4.9, 5.7), None)])
    rows = (H - 60) // 14
    panes = [
        {"x": 330, "y": 30, "room": 520, "lines": TABS},
        {"x": 46, "y": 50, "room": 400, "lines": cycle([FILES, DIFF, COMMITS], rows, 0)},
        {"x": 462, "y": 50, "room": 400, "lines": cycle([HOOKS, ENV, WORKFLOW], rows, 3)},
        {"x": 878, "y": 50, "room": 380, "lines": cycle([COMMITS, CMDS, DIFF], rows, 5)},
    ]
    sc.keep(X0 - 16, 44, AXW + 32, YAX - 44 + 40)  # the plot stays clean: bars, boxes, spokes, ticks
    sc.keep(CX - 40, 40, 80, 350)
    sc.keep(PX - 12, 206, SW + 24, 96)
    sc.keepout += sc.clear
    dim_page(sc, panes, strict=True, bright=0.3)
    return sc


# ---- accuracy.svg ------------------------------------------------------------------------
def wrap_words(text, width):
    lines, cur = [], ""
    for w in text.split(" "):
        if cur and len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = w
        else:
            cur = (cur + " " + w).strip()
    if cur:
        lines.append(cur)
    return lines


def build_accuracy(nums):
    W, H = 1280, 540
    b = nums["bench"]
    rows = b["rows"]
    plants, det, neg = b["positive_plants"], b["detectable_by_design"], b["negatives"]
    RC, RA, PR = MAGENTA, AMBER, SKY
    # the first row names its three bars, so the colours need no legend
    series = [
        ("recall_detectable_pct", RC, "recall on the %d covered plants" % det),
        ("recall_all_plants_pct", RA, "recall on all %d plants" % plants),
        ("precision_pct", PR, "precision, %d lookalikes planted to trip it" % neg),
    ]

    def label(row):
        name = row["name"]
        if " (" in name:
            head, detail = name.split(" (", 1)
            return head, wrap_words(detail.rstrip(")"), 22)
        if name in nums["engines"]:
            return name, [nums["engines"][name].split(" ")[0]]
        parts = [r["name"] for r in rows if r["name"] in nums["engines"]]
        return name, wrap_words(" + ".join(parts), 22)

    bits = []
    for row in rows:
        head, _ = label(row)
        got = ["recall %s%% on the %d covered plants" % (g(row["recall_detectable_pct"]), det)]
        if "recall_all_plants_pct" in row:
            got.append("%s%% on all %d" % (g(row["recall_all_plants_pct"]), plants))
        got.append("precision %s%%" % g(row["precision_pct"]))
        bits.append("%s: %s" % (head, ", ".join(got)))
    desc = (
        "Horizontal bars from zero to 100 percent, %d planted fake keys, %d of them covered by some engine's rules, "
        "and %d lookalikes planted to trip precision. The first row labels its three bars: recall on the covered plants, "
        "recall on all plants and precision. %s. Beside the bars, a field of %d dots stands for the planted keys (%d of them "
        "lit as covered) and a field of %d rings for the lookalikes. A thin crawler, small glowing dots joined by hairlines, "
        "walks a git-log rail along the bottom edge and reaches a hairline out to the end of each of the pipeline's three bars."
        % (plants, det, neg, "; ".join(bits), plants, det, neg)
    )
    sc = Scene("accuracy", W, H, "keyguard: recall and precision on %d planted fake keys" % plants, desc, 61)
    css = sc.css
    neon(sc)
    gutter(sc)
    X0, W100, TOP0, PITCH, BH, BP = 330, 600.0, 54, 76, 21, 22
    YAX = TOP0 + PITCH * len(rows) - 1
    VX = 1008  # right edge of the value column

    grid = "".join("M%s 46V%d" % (n(X0 + W100 * p / 100.0), YAX) for p in (0, 25, 50, 75, 100))
    sc.add("back", '<path d="%s" fill="none" stroke="%s" stroke-opacity=".35" stroke-width="1"/>' % (grid, DIM2))
    sc.add("back", '<path d="M%d %dH%s" fill="none" stroke="%s" stroke-opacity=".5" stroke-width="1"/>' % (X0, YAX, n(X0 + W100), WIRE))
    for p in (0, 25, 50, 75, 100):
        sc.add("back", '<path d="M%s %dv6" stroke="%s" stroke-opacity=".5" stroke-width="1"/>' % (n(X0 + W100 * p / 100.0), YAX, WIRE))
        sc.text("front", X0 + W100 * p / 100.0, YAX + 26, "%d%%" % p, 15, WIRE, align="c")

    tips = []  # where the pipeline's three bars end: the crawler reaches out to them
    for r, row in enumerate(rows):
        top = TOP0 + PITCH * r
        t = 0.3 + 0.28 * r
        off = off_at(r)
        head, sub = label(row)
        last = r == len(rows) - 1
        sc.text("front", 40, top + 28, head, 21, ICE, bold=True)
        for k, line in enumerate(sub):
            sc.text("front", 40, top + 50 + 16 * k, line, 15, WIRE)
        if last:
            sc.add("back", '<rect x="%d" y="%d" width="%s" height="%d" rx="6" fill="%s" fill-opacity=".12"/>' % (X0 - 8, top - 2, n(W100 + 16), PITCH - 3, VIOLET))
            sc.add("back", '<rect x="%d" y="%d" width="%s" height="%d" rx="4" fill="none" stroke="%s" stroke-opacity=".28" stroke-width="6"/>' % (X0, top, n(W100), PITCH - 6, ICE))
        sc.add(
            "mid",
            '<rect x="%d" y="%d" width="%s" height="%d" rx="3" fill="none" stroke="%s" stroke-opacity="%s" stroke-width="%s"/>'
            % (X0, top, n(W100), PITCH - 6, ICE if last else WIRE, ".9" if last else ".45", "2" if last else "1.2"),
        )
        for i, (key, color, name) in enumerate(series):
            by = top + 4 + BP * i
            v = row[key]
            h_bar(sc, X0, by, v / 100.0 * W100, BH, color, frames=grow(t + 0.06 * i, off, 0.5), rad=3, ghost=last)
            if last:
                tips.append((X0 + v / 100.0 * W100, by + BH / 2.0, color))
            if r == 0:
                sc.text("front", X0 + 10, by + 14.5, name, 15, ink(color), bg=color, bold=True, frames=fade_in(t + 0.06 * i + 0.3, off), clear=False)
            sc.text("front", VX, by + 15.5, g(v) + "%", 19, ICE, bold=True, align="r", frames=jitter_in(t + 0.06 * i + 0.4, off))

    # the callouts, stacked up from the bottom of the right-hand column: what the whole pipeline scores
    pr = rows[-1]
    if pr["recall_detectable_pct"] == pr["recall_all_plants_pct"]:
        calls = [(pr["recall_all_plants_pct"], RC, "pipeline recall", ("pipeline", "recall"))]
    else:  # the two recalls differ: each gets the colour of its bar
        calls = [
            (pr["recall_detectable_pct"], RC, "pipeline recall, covered", ("recall", "covered")),
            (pr["recall_all_plants_pct"], RA, "pipeline recall, all", ("recall", "all plants")),
        ]
    calls.append((pr["precision_pct"], PR, "pipeline precision", ("pipeline", "precision") if len(calls) == 1 else ("precision", "")))
    bx, y_bot = 1048, 460
    FY0 = 158  # the fields of dots start here and stop above the callouts

    def stack(compact):
        """Tops of the callouts and the lowest y the fields may reach. Roomy: a caption above each pill;
        compact: the pill with a two-line caption beside it."""
        ph, cs, lh, cg = (38, 26, 0, 10) if compact else ((48, 34, 15, 14) if len(calls) == 2 else (40, 28, 14, 10))
        tops, y = [], y_bot
        for _ in calls:
            tops.append(y - ph)
            y -= ph + (0 if compact else 9 + lh) + cg
        tops.reverse()
        return (ph, cs, lh), tops, tops[0] - (0 if compact else 9 + lh) - 14

    def fit(limit, least):
        """The widest pitch (down to least) at which both fields fit between FY0 and limit."""
        pitch = 7.0
        while pitch >= least:
            cols = int(208 // pitch) + 1
            ra, rb = -(-plants // cols), -(-neg // cols)
            if FY0 + (ra + rb) * pitch + 10 <= limit:
                return pitch, cols, ra
            pitch -= 0.2
        return None

    compact = False
    sizes, slots, y_limit = stack(compact)
    got = fit(y_limit, 5.0)
    if got is None:  # a bigger bench: shrink the callouts rather than the dots
        compact = True
        sizes, slots, y_limit = stack(compact)
        got = fit(y_limit, 4.4)
        if got is None:
            raise SystemExit("accuracy: the fields of dots do not fit beside the bars; the bench has too many plants")
    pitch, cols, ra = got
    ph, cs, lh = sizes

    # the size of the test, in a column of numbers and under it a field of dots: one dot for each
    # planted key (lit when a rule covers it) and one ring for each lookalike
    sc.text("front", bx, 66, "the bench, seed 1", 15, WIRE, frames=fade_in(0.3, off_at(7)))
    swatch = {0: [(MAGENTA, 0), (WIRE, 8)], 1: [(MAGENTA, 4)], 2: [(SKY, 4)]}
    for k, (num, what) in enumerate(((plants, "fake keys planted"), (det, "covered by a rule"), (neg, "lookalikes"))):
        y = 94 + 25 * k
        fo = fade_in(0.4 + 0.1 * k, off_at(8 + k))
        sc.text("front", bx + 54, y, str(num), 19, ICE, bold=True, align="r", frames=fo)
        sc.text("front", bx + 64, y, what, 14, WIRE, frames=fo)
        sw = "".join(dots([(bx + 4 + dx, y - 6)], 3.2, col) for col, dx in swatch[k])
        if k == 2:
            sw += dots([(bx + 8, y - 6)], 1.4, PAGE)
        sc.add("front", "<g%s>%s</g>" % (css.attr(fo), sw))

    def field(y0, count):
        return [(bx + 3 + (k % cols) * pitch, y0 + (k // cols) * pitch) for k in range(count)]

    dr = min(2.5, pitch * 0.36)  # dot radius; the glow under it is a little under twice that
    A, B = field(FY0, plants), field(FY0 + ra * pitch + 10, neg)
    sc.add("back", dots(A[:det], dr * 1.75, MAGENTA, ".14") + dots(A[:det], dr, MAGENTA, ".95") + dots(A[det:], dr * 0.9, WIRE, ".5"))
    sc.add("back", dots(B, dr * 1.1, SKY, ".95") + dots(B, dr * 0.5, PAGE))
    fh = B[-1][1] + 6 - FY0
    sc.clr(bx - 4, FY0 - 8, cols * pitch + 8, fh + 14)
    sweep = [
        (0, {"opacity": "0", "transform": "translateX(0px)"}, STEP),
        (1.9, {"opacity": "1", "transform": "translateX(0px)"}, LIN),
        (2.7, {"opacity": "1", "transform": "translateX(%dpx)" % int(cols * pitch - 14)}, STEP),
        (2.75, {"opacity": "0", "transform": "translateX(%dpx)" % int(cols * pitch - 14)}, STEP),
        (T, {"opacity": "0", "transform": "translateX(0px)"}, None),
    ]
    sc.add("mid", '<rect%s x="%s" y="%s" width="14" height="%s" rx="3" fill="%s" fill-opacity=".28" opacity="0"/>' % (css.attr(sweep), n(bx - 4), n(FY0 - 8), n(fh + 12), ICE))

    for k, ((val, color, cap, two), y) in enumerate(zip(calls, slots)):
        t, off = 1.5 + 0.3 * k, off_at(11 + k)
        w = pill(sc, "front", bx, y, g(val) + "%", cs, color, h=ph, padx=11 if compact else 14, rx=4, frames=slide_in(t, off))
        if not compact:
            sc.text("front", bx + 2, y - 9, cap, lh, WIRE, frames=fade_in(t + 0.2, off))
        else:  # one or two short lines to the right of the pill
            for j, line in enumerate(l for l in two if l):
                sc.text("front", bx + w + 10, y + (ph / 2.0 + 5 if not two[1] else 16 + 17 * j), line, 14, WIRE, frames=fade_in(t + 0.2, off))

    # the crawler: a thin crawler walks the git-log rail along the bottom edge and, once it has
    # arrived, reaches out to the end of each of the pipeline's three bars
    RY = 500
    s_start, s_rest = -40.0, 1000.0
    hid = {"opacity": "0", "transform": "translateX(%spx)" % n(s_start)}
    fr = [
        (0, hid, STEP),
        (0.15, {"opacity": "1", "transform": "translateX(%spx)" % n(s_start)}, IO_EASE),
        (2.4, {"opacity": "1", "transform": "translateX(%spx)" % n(s_rest)}, STEP),
    ]
    fr += flicker(T_OFF + 0.02, {"transform": "translateX(%spx)" % n(s_rest)})
    fr.append((T, hid, None))
    commit_graph(sc, 40, 1030, RY, [(190, 400, -18, VIOLET), (520, 760, -18, BLUE), (830, 990, -18, MAGENTA)])
    crawl(sc, crawler_svg(-420, 0, 420, 5, 110, 18, phase=0.2, sz=0.8, leg=17.0), 0, RY, 0, fr, s_rest)
    sc.clr(0, RY - 26, W, 52)
    for k, (tx, ty, color) in enumerate(tips):
        t = 2.0 + 0.12 * k
        hairline(sc, "mid", s_rest, RY, tx, ty, WIRE, t, t + 0.3, off_at(9 + k), width=1.2, op=".75")
        sc.add("mid", '<g%s>%s<circle cx="%s" cy="%s" r="7" fill="none" stroke="%s" stroke-opacity=".6"/></g>' % (css.attr(fade_in(t + 0.25, off_at(12 + k))), dots([(tx, ty)], 3.0, ICE), n(tx), n(ty), color))

    wordmark(sc, W - 18, H - 30, t_glitch=pg(3.1))
    beams(sc, [(-27, 28, (640, 270), (0.3, 1.7), None), (-27, 12, (640, 270), (5.0, 5.8), None)])
    nrows = (H - 60) // 14
    panes = [
        {"x": 640, "y": 36, "room": 580, "lines": TABS},
        {"x": 46, "y": 50, "room": 400, "lines": cycle([FILES, RATE_GO, COMMITS], nrows, 0)},
        {"x": 462, "y": 50, "room": 400, "lines": cycle([DIFF, ENV, HOOKS], nrows, 4)},
        {"x": 878, "y": 50, "room": 380, "lines": cycle([COMMITS, WORKFLOW, CMDS], nrows, 2)},
    ]
    sc.keep(X0 - 16, 44, W100 + 32, YAX - 44 + 40)  # the plot and its value column stay clean
    sc.keep(950, 50, 70, YAX - 44)
    sc.keepout += sc.clear
    dim_page(sc, panes, strict=True, bright=0.3)
    return sc


# ---- terminal.svg ------------------------------------------------------------------------
SHAPE = "sk_live_" + ELL + "a1B2"   # what fp.Shape prints for a long sk_live_ key
FID = "kg1a2b3c"                     # "kg" + six hex digits, as fp.ID makes it
SHA = "9752a3e"                      # a short commit id: a block about history adds a COMMIT column
WHY = "your learned key STRIPE_SECRET_KEY (%s)" % FID


def block_lines(title, path, line, typ, shape, why, fid, poll_min, commit=None):
    """The block message of internal/hooks/report.go writeBlock for one finding: a title, a
    table whose columns tabwriter pads to the widest cell plus two spaces (the last column
    is not padded), then the fix. A finding in history carries a commit, and the table then
    starts with a COMMIT column (the ref-update block always does; the commit block never).
    The strings are copied from that file; `--dump-blocks` prints them so they can be diffed
    against the real function's output."""
    line_s = str(line)
    lw = max(len("LINE"), len(line_s))
    head = ["FILE", "LINE".rjust(lw), "TYPE", "SECRET", "WHY"]
    row = [path, line_s.rjust(lw), typ, shape, why]
    if commit:
        head, row = ["COMMIT"] + head, [commit] + row
    last = len(head) - 1
    widths = [max(len(head[i]), len(row[i])) + 2 for i in range(last)]

    def fmt(cells):
        return "  " + "".join(cells[i].ljust(widths[i]) for i in range(last)) + cells[last]

    return [
        "keyguard: %s: 1 finding" % title,
        "",
        fmt(head),
        fmt(row),
        "",
        "  fix: move the value to a gitignored .env and read it from the environment.",
        "  do not bypass with --no-verify: real keys are also blocked at the",
        "  ref level, and GitHub is re-scanned %s." % every(poll_min),
        "  false positive? keyguard allow %s" % fid,
    ]


def build_terminal(nums):
    W, H = 1280, 460
    poll_min = nums["watcher"]["poll_seconds"] // 60
    git_v = re.search(r"git ([\d.]+)", nums["machine"]).group(1)
    desc = (
        "A terminal. The command git commit prints keyguard: commit blocked: 1 finding, with a table of file, line, type, "
        "secret and why. The secret column shows only the shape %s. The same commit with --no-verify prints keyguard: ref "
        "update blocked: 1 finding, because the key is one keyguard learned; that table starts with a commit column. git then "
        "stops with a fatal line. Beside each block, outside the terminal, a tag names the layer that stopped it and the "
        "verdict BLOCKED. A thin crawler, a net of small glowing dots on hairlines, sits in the right margin and reaches out "
        "to both tags and to the key on the diff above them." % SHAPE
    )
    sc = Scene("terminal", W, H, "keyguard: a commit blocked, and blocked again with --no-verify", desc, 51)
    css = sc.css
    neon(sc)
    gutter(sc)
    FS, X0 = 14, 54  # the widest line is the ref-update row, 100 characters; at 14 px it fits the window
    WIN = (40, 24, 880, 414)  # the terminal window: one card, so no line needs its own plate
    AD = ADV * FS
    PITCH, HALF, Y0 = 20, 9, 54
    b1 = block_lines("commit blocked", "src/billing.js", 4, "known", SHAPE, WHY, FID, poll_min)
    b2 = block_lines("ref update blocked", "src/billing.js", 4, "known", SHAPE, WHY, FID, poll_min, commit=SHA)
    items = [("cmd", 'git commit -m "add billing config"')]
    items += [("out", s) for s in b1]
    items.append(("cmd", 'git commit --no-verify -m "add billing config"'))
    items += [("out", s) for s in b2]
    items.append(("out", "fatal: in 'prepared' phase, update aborted by the reference-transaction hook"))
    B1, B2 = 1, 11
    assert len(items) == 21 and items[B2 - 1][0] == "cmd"
    assert max(len(s) for _, s in items) * AD + X0 + 16 <= WIN[0] + WIN[2], "a line is wider than the terminal window"
    ys, y = [], Y0
    for kind, s in items:
        ys.append(y + 15)  # the baseline of the line in its slot
        y += HALF if s == "" else PITCH
    assert y < H - 24, y
    # The first block is on from the first frame and never leaves: it is the point of the image, so a
    # still, a slow load and prefers-reduced-motion all open on the blocked commit. Only the
    # --no-verify block builds (output lands fast, like a real terminal) and glitches out, and a
    # prompt waits for it in between. A stutter now and then keeps the first block alive.
    times = {B2 - 1: 0.6, 20: 1.2}
    for k in range(9):
        times[B2 + k] = 0.75 + 0.04 * k
    style = {0: (ICE, True), 2: (WIRE, False), 3: (ICE, False), 5: (WIRE, False), 6: (WIRE, False), 7: (WIRE, False), 8: (WIRE, False)}
    FIND_T = {B2: 1.4}
    still = stutter(pg(0.45), 3)
    still_op = stutter(pg(0.6), 0, {"opacity": "1"})

    sc.add("plate", '<rect x="%d" y="%d" width="%d" height="%d" rx="10" fill="%s" fill-opacity=".96" stroke="%s" stroke-opacity=".28"/>' % (WIN + (PANEL, WIRE)))
    sc.add("plate", '<path d="M%d %dH%d" stroke="%s" stroke-opacity=".25"/>' % (WIN[0], WIN[1] + 30, WIN[0] + WIN[2], WIRE))
    sc.keep(WIN[0] - 6, WIN[1] - 6, WIN[2] + 12, WIN[3] + 12)
    sc.text("front", X0, WIN[1] + 20, "~/dev/shop (main)", 14, WIRE, bg=PANEL, plate=False)
    sc.text("front", WIN[0] + WIN[2] - 14, WIN[1] + 20, "git %s" % git_v, 14, WIRE, bg=PANEL, plate=False, align="r")
    for i, (kind, s) in enumerate(items):
        if not s:
            continue
        y = ys[i]
        live = i >= B2 - 1
        fr = fade_in(times[i], off_at(i)) if live else None
        if kind == "cmd":
            # the prompt is there all along; only the command after it is typed in
            sc.text("front", X0, y, "$", FS, SKY, bold=True, frames=stutter(off_at(i), 0, {"opacity": "1"}) if live else None, bg=PANEL, plate=False)
            sc.text("front", X0 + 2 * AD, y, s, FS, ICE, frames=fr, nb=True, bg=PANEL, plate=False)
            continue
        if B1 <= i < B1 + 9:
            col, bold = style.get(i - B1, (WIRE, False))
        elif B2 <= i < B2 + 9:
            col, bold = style.get(i - B2, (WIRE, False))
        else:
            col, bold = ICE, False
        # the secret and the id are drawn on their own boxes; leave their columns empty here
        spans = sorted((s.index(needle), len(needle)) for needle in (SHAPE, FID) if needle in s)
        pos = 0
        for c0, cl in spans + [(len(s), 0)]:
            piece = s[pos:c0]
            if piece.strip():
                lead = len(piece) - len(piece.lstrip(" "))
                sc.text("front", X0 + (pos + lead) * AD, y, piece.strip(" "), FS, col, bold=bold, frames=fr, nb=True, bg=PANEL, plate=False)
            pos = c0 + cl
        # in the live block the secret and the id are plain text until the find lands, and hidden at rest
        if i >= B2:
            for needle in (SHAPE, FID):
                if needle in s:
                    hid = {"opacity": "0"}
                    gone = seam([(0, hid, STEP), (times[i], {"opacity": "1"}, STEP), (FIND_T[B2], {"opacity": "0"}, None)], hid)
                    sc.text("front", X0 + s.index(needle) * AD, y, needle, FS, col, bold=bold, frames=gone, nb=True, extra=' opacity="0"', bg=PANEL, plate=False)

    # a cursor blinks where the second command will be typed
    cur = [(0, {"opacity": "1"}, STEP), (0.28, {"opacity": "0"}, STEP), (0.48, {"opacity": "1"}, STEP), (times[B2 - 1], {"opacity": "0"}, STEP), (off_at(B2 - 1) + 0.2, {"opacity": "1"}, STEP), (T, {"opacity": "1"}, None)]
    sc.add("front", '<rect%s x="%s" y="%s" width="%s" height="16" fill="%s" opacity="0"/>' % (css.attr(cur), n(X0 + 2 * AD), n(ys[B2 - 1] - 12), n(AD - 1), ICE))

    # the finds: the key lights up, the row is outlined, the id is tagged. Outside the window, the
    # layer that stopped the commit is named and the verdict is stamped: the hooks print no
    # BLOCKED of their own, so the stamp is an annotation and sits beside the terminal, not in it.
    reach = []  # where the crawler's hairlines land: the right-hand end of each tag
    for bi, (B, pill_text) in enumerate(((B1, "L1 pre-commit"), (B2, "L1 reference-transaction"))):
        live = bi == 1
        tf, off = FIND_T.get(B), off_at(12 + bi)
        y_row = ys[B + 3]
        row = items[B + 3][1]
        xs = X0 + row.index(SHAPE) * AD
        wbar = len(SHAPE) * AD
        fr = grow(tf, off, 0.25) if live else still
        origin = (xs - 6, y_row - 5)
        sc.add(
            "back",
            '<g%s><rect x="%s" y="%s" width="%s" height="28" rx="8" fill="%s" opacity=".10"/><rect x="%s" y="%s" width="%s" height="24" rx="5" fill="%s" opacity=".22"/></g>'
            % (css.attr(fr, origin=origin), n(xs - 12), n(y_row - 19), n(wbar + 24), MAGENTA, n(xs - 8), n(y_row - 17), n(wbar + 16), MAGENTA),
        )
        sc.add("mid", '<rect%s x="%s" y="%s" width="%s" height="20" rx="2" fill="%s"/>' % (css.attr(fr, origin=origin), n(xs - 6), n(y_row - 15), n(wbar + 12), MAGENTA))
        reticle(sc, "mid", xs - 12, y_row - 20, wbar + 24, 28, MAGENTA, arm=7, frames=snap(tf + 0.1, off) if live else None)
        sc.text("front", xs, y_row, SHAPE, FS, ink(MAGENTA), bg=MAGENTA, bold=True, frames=jitter_in(tf + 0.1, off) if live else still, nb=True, clear=False)
        row_w = len(row) * AD
        sc.add(
            "mid",
            '<rect%s x="%s" y="%s" width="%s" height="22" rx="3" fill="none" stroke="%s" stroke-width="1.6"/>'
            % (css.attr(fade_in(tf + 0.15, off) if live else None), n(X0 - 8), n(y_row - 16), n(row_w + 16), RED),
        )
        for yy, text_line in ((y_row, row), (ys[B + 8], items[B + 8][1])):
            ix = X0 + text_line.index(FID) * AD
            a = css.attr(fade_in(tf + 0.2, off) if live else None)
            sc.add("mid", '<rect%s x="%s" y="%s" width="%s" height="19" rx="2" fill="%s"/>' % (a, n(ix), n(yy - 14.5), n(len(FID) * AD), MINT))
            sc.text("front", ix, yy, FID, FS, ink(MINT), bg=MINT, bold=True, frames=fade_in(tf + 0.2, off) if live else None, nb=True, clear=False)
        if live:
            hairline(sc, "mid", X0 + row_w + 8, y_row - 6, 936, y_row - 6, WIRE, tf + 0.3, tf + 0.45, off, width=1, op=".6")
        else:
            hairline(sc, "mid", X0 + row_w + 8, y_row - 6, 936, y_row - 6, WIRE, width=1, op=".6")
        wp = pill(sc, "front", 940, y_row - 22, pill_text, 16, ICE, h=32, padx=12, frames=slide_in(tf + 0.3, off) if live else None)
        stamp(sc, "front", 940, y_row + 16, frames=stamp_in(tf + 0.4, off) if live else still_op)
        reach.append((940 + wp, y_row - 6))
        if live:
            pill(sc, "front", 940, y_row + 46, "--no-verify can't skip", 15, MAGENTA, h=26, padx=10, frames=slide_in(tf + 0.5, off))

    # the crawler: a net of dots and hairlines in the right margin, reaching out to the first tag,
    # to the key on the diff above it and, once the second find lands, to the second tag
    key = mask("sk_live_", 4, "a1B2")
    kx = 940 + GIT_DIFF[3][1].index(key) * 6.6
    ky = 36 + 14 * 3
    kw = len(key) * ADV * 12
    SX, SY = 1168, 232
    sp, srad = spider_svg(random.Random(81), 0.95, 96.0)
    sc.add("mid", '<g transform="translate(%d %d)">%s</g>' % (SX, SY, sp))
    sc.clr(SX - srad - 6, SY - srad - 6, 2 * srad + 12, 2 * srad + 12)
    ends = [(kx + kw / 2.0, ky + 6, None), (reach[0][0], reach[0][1], None), (1120, 294, FIND_T[B2] + 0.3)]
    for ex, ey, t in ends:
        if t is None:
            hairline(sc, "mid", SX, SY, ex, ey, ICE, width=1.3, op=".8")
            sc.add("mid", dots([(ex, ey)], 3.0, ICE) + '<circle cx="%s" cy="%s" r="6.5" fill="none" stroke="%s" stroke-opacity=".5"/>' % (n(ex), n(ey), WIRE))
        else:
            hairline(sc, "mid", SX, SY, ex, ey, ICE, t, t + 0.3, off_at(14), width=1.3, op=".8")
            sc.add("mid", '<g%s>%s<circle cx="%s" cy="%s" r="6.5" fill="none" stroke="%s" stroke-opacity=".5"/></g>' % (css.attr(fade_in(t + 0.25, off_at(15))), dots([(ex, ey)], 3.0, ICE), n(ex), n(ey), WIRE))

    panes = [{"x": 940, "y": 36, "room": 292, "lines": cycle([GIT_DIFF], 5)}]
    dim_page(sc, panes)

    # the key on the diff, lit: the same key the table names (line 4 of src/billing.js)
    origin = (kx - 5, ky - 4)
    sc.add("back", '<g%s><rect x="%s" y="%s" width="%s" height="24" rx="7" fill="%s" opacity=".10"/><rect x="%s" y="%s" width="%s" height="20" rx="5" fill="%s" opacity=".22"/></g>' % (css.attr(still, origin=origin), n(kx - 11), n(ky - 16), n(kw + 22), MAGENTA, n(kx - 8), n(ky - 14), n(kw + 16), MAGENTA))
    sc.add("mid", '<rect%s x="%s" y="%s" width="%s" height="16" rx="2" fill="%s"/>' % (css.attr(still, origin=origin), n(kx - 5), n(ky - 12), n(kw + 10), MAGENTA))
    reticle(sc, "mid", kx - 10, ky - 14, kw + 20, 20, MAGENTA, arm=5, width=1.3)
    sc.text("front", kx, ky + 1, key, 12, ink(MAGENTA), bg=MAGENTA, bold=True, frames=still, clear=False)

    wordmark(sc, W - 18, H - 30, t_glitch=pg(3.3))
    web(sc, (1010, 96, 250, 330), 16, 34, 80, seed=8)
    return sc


# ---- output ------------------------------------------------------------------------------
def check(path):
    ET.parse(path)  # well-formed
    with open(path, encoding="utf-8") as fh:
        s = fh.read()
    body = s.replace('xmlns="http://www.w3.org/2000/svg"', "")
    for bad in ("<script", "foreignObject", "<image", "href=", "src=", "url(http", "@import"):
        if bad in body:
            raise SystemExit("%s: forbidden %r" % (path, bad))
    size = len(s.encode("utf-8"))
    if size >= 400 * 1024:
        raise SystemExit("%s: %d bytes is over 400 KB" % (path, size))
    return size


BUILDERS = (("layers", build_layers), ("layers-narrow", build_layers_narrow), ("speed", build_speed), ("accuracy", build_accuracy), ("terminal", build_terminal))


def main(argv):
    flags = [a for a in argv[1:] if a.startswith("--")]
    args = [a for a in argv[1:] if not a.startswith("--")]
    out = args[0] if args else DEFAULT_OUT
    nums = load_numbers(out)
    if "--dump-blocks" in flags:
        poll_min = nums["watcher"]["poll_seconds"] // 60
        for title, commit in (("commit blocked", None), ("ref update blocked", SHA)):
            print("\n".join(block_lines(title, "src/billing.js", 4, "known", SHAPE, WHY, FID, poll_min, commit)))
        return 0
    os.makedirs(out, exist_ok=True)
    for name, fn in BUILDERS:
        sc = fn(nums)
        path = os.path.join(out, name + ".svg")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(sc.finish())
        print("%s  %d bytes  %d words  lowest text contrast %.2f:1" % (path, check(path), sc.words, sc.min_contrast()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
