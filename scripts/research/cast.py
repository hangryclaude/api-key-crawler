#!/usr/bin/env python3
"""Asciinema v2 recordings: token echoed per keystroke (typed) vs in one event (pasted). Prints only counts.

    python3 cast.py OUT_DIR

OUT_DIR must be new or empty. Writes OUT_DIR/castvec/typed.cast and pasted.cast, each holding one fake
GitHub token, and counts what each engine reports in each file (docs/STEAL.md P1-24: a token typed
in a terminal is echoed one character per event, so no engine sees it; the same token pasted is
found by all four). The last two lines show that concatenating the "o" payloads, as a cast-aware
pre-pass would, recovers the token. Engines are $KEYGUARD_<NAME> or the first on PATH.
"""
import json, os, pathlib, subprocess, sys

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common

if len(sys.argv) != 2:
    common.die("usage: cast.py OUT_DIR")
out = pathlib.Path(sys.argv[1])
common.empty_dir(out)
d = out / "castvec"
d.mkdir(parents=True, exist_ok=True)
tok = common.gh_pat()
hdr = json.dumps({"version": 2, "width": 80, "height": 24, "timestamp": 1700000000})
line = f"export GITHUB_TOKEN={tok}"
typed = [hdr, json.dumps([0.1, "o", "$ "])]
t = 0.5
for c in line:
    typed.append(json.dumps([round(t, 3), "o", c]))
    t += 0.07
typed.append(json.dumps([round(t, 3), "o", "\r\n"]))
(d / "typed.cast").write_text("\n".join(typed) + "\n")
pasted = [hdr, json.dumps([0.1, "o", "$ "]), json.dumps([0.5, "o", line + "\r\n"])]
(d / "pasted.cast").write_text("\n".join(pasted) + "\n")


def run(cmd, **kw):
    return common.run(cmd, **kw).stdout


# titus keeps its compiled rules in a cache directory; keep it inside OUT_DIR, not the user's home
titus_env = dict(os.environ, TITUS_CACHE_DIR=str(out / "titus-cache"))
os.makedirs(titus_env["TITUS_CACHE_DIR"], exist_ok=True)
bl = json.loads(run([common.engine("betterleaks"), "dir", str(d), "-f", "json", "-r", "-", "--no-banner", "-l", "error", "--exit-code", "0"]) or "[]")
gl = json.loads(run([common.engine("gitleaks"), "dir", str(d), "-f", "json", "-r", "-", "--no-banner", "-l", "error", "--exit-code", "0"]) or "[]")
th = [json.loads(l) for l in run([common.engine("trufflehog"), "filesystem", str(d), "--json", "--no-verification", "--no-update"]).splitlines() if l.startswith("{")]
ti = json.loads(run([common.engine("titus"), "scan", str(d), "--format", "json", "--output", ":memory:", "-q"], env=titus_env) or "[]")
blob = {subprocess.run(["git", "hash-object", str(d / f)], capture_output=True, text=True,
                       env=common.hermetic_git_env()).stdout.strip(): f for f in ("typed.cast", "pasted.cast")}


def by_file(items, getter):
    c = {"typed.cast": 0, "pasted.cast": 0}
    for it in items:
        f = getter(it)
        if f in c:
            c[f] += 1
    return c


print("betterleaks:", by_file(bl, lambda f: pathlib.Path(f["File"]).name))
print("gitleaks   :", by_file(gl, lambda f: pathlib.Path(f["File"]).name))
print("trufflehog :", by_file(th, lambda f: pathlib.Path(f["SourceMetadata"]["Data"]["Filesystem"]["file"]).name))
print("titus      :", by_file(ti, lambda f: blob.get(f["BlobID"])))
# reassembly: concatenating the 'o' payloads recovers the token, which is what a cast-aware pre-pass would feed to the matcher
for name in ("typed.cast", "pasted.cast"):
    ev = [json.loads(l) for l in (d / name).read_text().splitlines()[1:]]
    text = "".join(e[2] for e in ev if e[1] == "o")
    print(f"reassembled {name}: token recovered = {tok in text}")
