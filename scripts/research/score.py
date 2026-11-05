#!/usr/bin/env python3
"""Scores engine output against planted.json. Prints only aggregates, never a raw value.

    python3 score.py RUN_DIR

RUN_DIR is a directory gen.py wrote (planted.json, vec/) after run_engines.py ran the four engines
over vec/ and left bl.json, gl.json, th.jsonl and ti.json beside it. A planted value counts as found
when an engine reported a string of at least 8 characters that contains it, or that it contains,
once escapes and quoting are folded away (the engines report different extents of one credential).
"""
import base64, json, os, pathlib, re, subprocess, sys

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common

if len(sys.argv) != 2:
    common.die("usage: score.py RUN_DIR")
run = pathlib.Path(sys.argv[1])
planted = json.loads((run / "planted.json").read_text())
vec = run / "vec"


def norm(s):
    return re.sub(r'(\\n|\\r|\\t|\s|"|,|\\)', "", s)


def strs(x, acc):
    if isinstance(x, str):
        acc.append(x)
    elif isinstance(x, list):
        for y in x:
            strs(y, acc)
    elif isinstance(x, dict):
        for y in x.values():
            strs(y, acc)
    return acc


def unb64(items):
    """Titus writes the bytes of a group and of a snippet as base64: offer the text as well as the string."""
    out = []
    for x in items:
        out.append(x)
        try:
            out.append(base64.b64decode(x, validate=True).decode("utf-8", "replace"))
        except ValueError:
            pass
    return out


# engine -> {relpath: [(rule, [candidate strings])]}
eng = {"BL": {}, "GL": {}, "TH": {}, "TI": {}}


def rel(p):
    p = str(p)
    i = p.find("vec/")
    return p[i + 4:] if i >= 0 else p


for name, fn in (("BL", "bl.json"), ("GL", "gl.json")):
    for f in json.loads((run / fn).read_text()):
        eng[name].setdefault(rel(f["File"]), []).append((f["RuleID"], [f.get("Secret", ""), f.get("Match", "")]))
for l in (run / "th.jsonl").read_text().splitlines():
    if not l.startswith("{"):
        continue
    f = json.loads(l)
    p = rel(f["SourceMetadata"]["Data"]["Filesystem"]["file"])
    eng["TH"].setdefault(p, []).append((f["DetectorName"] + ("/" + f["DecoderName"] if f.get("DecoderName") not in (None, "PLAIN") else ""), [f.get("Raw", ""), f.get("RawV2", "")]))
# titus: map blob id -> path with git's blob hash
blob = {}
for rp in planted:
    out = subprocess.run(["git", "hash-object", str(vec / rp)], capture_output=True, text=True,
                         env=common.hermetic_git_env()).stdout.strip()
    blob[out] = rp
for f in json.loads((run / "ti.json").read_text()):
    p = blob.get(f["BlobID"], "?" + f["BlobID"][:8])
    eng["TI"].setdefault(p, []).append((f["RuleID"], unb64(strs(f.get("Groups"), []) + strs(f.get("Snippet"), []))))


def hit(cands, val):
    v = norm(val)
    for c in cands:
        n = norm(c)
        if len(n) >= 8 and (n in v or v in n):
            return True
    return False


rows = []
tot = {e: [0, 0] for e in eng}
miss = {e: [] for e in eng}
for rp, secs in sorted(planted.items()):
    cells = []
    for e in ("BL", "GL", "TH", "TI"):
        fs = eng[e].get(rp, [])
        got = 0
        used = set()
        for s in secs:
            ok = False
            for i, (rule, cands) in enumerate(fs):
                if hit(cands, s["value"]):
                    ok = True
                    used.add(i)
            got += ok
            tot[e][1] += 1
            tot[e][0] += ok
            if not ok:
                miss[e].append(f"{rp}:{s['label']}")
        extra = len(fs) - len(used)
        cells.append(f"{got}/{len(secs)}" + (f"+{extra}" if extra else ""))
    rows.append((rp, cells))

w = max(len(r[0]) for r in rows)
print(f"{'file':<{w}}  BL     GL     TH     TI")
for rp, cells in rows:
    print(f"{rp:<{w}}  " + "  ".join(f"{c:<5}" for c in cells))
print("TOTAL recall (planted values found / planted):", {e: f"{a}/{b}" for e, (a, b) in tot.items()})
union = 0
allv = 0
for rp, secs in planted.items():
    for s in secs:
        allv += 1
        key = f"{rp}:{s['label']}"
        if any(key not in miss[e] for e in eng):
            union += 1
print(f"UNION of 4 engines: {union}/{allv}")
print("MISSED BY ALL FOUR:", [f"{rp}:{s['label']}" for rp, secs in planted.items() for s in secs if all(f"{rp}:{s['label']}" in miss[e] for e in eng)])
