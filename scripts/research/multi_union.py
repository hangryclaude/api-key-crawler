#!/usr/bin/env python3
"""File-level recall of all four engines, and of their union, over several draws of the plant matrix.

    python3 multi_union.py RULES.toml WORK_DIR [DRAWS]

multi_draw.py counts betterleaks alone. This runs betterleaks and gitleaks with and without the
extra rules file (RULES.toml, normally rules/keyguard.toml), trufflehog and titus over each draw
of gen_matrix.py, and prints per draw how many of its files have a finding from each engine and
from the union of the engines with the extra rules on. That union is the baseline a single new
engine is held to (docs/STEAL.md: 125 of 139 in one draw). DRAWS defaults to 3. WORK_DIR is a new
or empty directory; each draw is generated into WORK_DIR/draw-N and left there (fake secrets only).

A file counts as found when the engine reports anything in it: each file holds exactly one fake.
The reports are read from stdout with --redact where the engine has the flag, and only file names
are kept. trufflehog and titus have no redaction, so their stdout is read in this process and
dropped; nothing but names and counts is printed. Engines are found as in common.py.
"""
import collections
import json
import os
import subprocess
import sys

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINES = ["betterleaks", "betterleaks+kg", "gitleaks", "gitleaks+kg", "trufflehog", "titus"]


def leaks(binpath, draw, rules, name):
    cmd = [binpath, "dir", draw, "-f", "json", "-r", "-", "--no-banner", "-l", "error", "--exit-code", "0",
           "--ignore-gitleaks-allow", "--redact", "-i", os.devnull] + (["-c", rules] if rules else [])
    if name == "betterleaks":
        cmd.append("--no-color")
    return {os.path.basename(f["File"]) for f in json.loads(common.run(cmd).stdout or "[]")}


def trufflehog(binpath, draw):
    out = common.run([binpath, "filesystem", draw, "--json", "--no-verification", "--no-update", "--no-color",
                      "--log-level=-1", "--no-ignore-tag",
                      "--results=verified,unknown,unverified,filtered_unverified"]).stdout
    found = set()
    for line in out.splitlines():
        if line.startswith("{"):
            found.add(os.path.basename(json.loads(line)["SourceMetadata"]["Data"]["Filesystem"]["file"]))
    return found


def titus(binpath, draw, cache):
    env = dict(os.environ, TITUS_CACHE_DIR=cache)
    os.makedirs(cache, exist_ok=True)
    # titus reports a git blob id, not a path: map each blob id back to the files that hold it
    blob = collections.defaultdict(set)
    for fn in os.listdir(draw):
        h = common.run(["git", "hash-object", os.path.join(draw, fn)], env=common.hermetic_git_env()).stdout.strip()
        blob[h].add(fn)
    out = common.run([binpath, "scan", draw, "--format", "json", "--output", ":memory:", "-q",
                      "--ignore", os.devnull], env=env).stdout
    found = set()
    for f in json.loads(out or "[]"):
        found |= blob.get(f["BlobID"], set())
    return found


def main(argv):
    if len(argv) not in (3, 4):
        common.die("usage: multi_union.py RULES.toml WORK_DIR [DRAWS]")
    rules, work = os.path.abspath(argv[1]), os.path.abspath(argv[2])
    draws = int(argv[3]) if len(argv) == 4 else 3
    if not os.path.isfile(rules):
        common.die(rules + " is not a file")
    common.empty_dir(work)
    bl, gl = common.engine("betterleaks"), common.engine("gitleaks")
    th, ti = common.engine("trufflehog"), common.engine("titus")

    print("%-7s %5s  %s" % ("draw", "files", "  ".join("%14s" % e for e in ENGINES) + "  %14s %5s" % ("union+kg", "none")))
    tot = collections.Counter()
    unions = []
    for i in range(draws):
        d = os.path.join(work, "draw-%d" % i)
        common.run([sys.executable, os.path.join(HERE, "gen_matrix.py"), d])
        files = sorted(os.listdir(d))
        found = {
            "betterleaks": leaks(bl, d, None, "betterleaks"),
            "betterleaks+kg": leaks(bl, d, rules, "betterleaks"),
            "gitleaks": leaks(gl, d, None, "gitleaks"),
            "gitleaks+kg": leaks(gl, d, rules, "gitleaks"),
            "trufflehog": trufflehog(th, d),
            "titus": titus(ti, d, d + "-titus-cache"),
        }
        union = set().union(*found.values())
        unions.append(len(union))
        for e in ENGINES:
            tot[e] += len(found[e])
        tot["union"] += len(union)
        tot["files"] += len(files)
        print("%-7s %5d  %s" % ("draw-%d" % i, len(files),
                                "  ".join("%14d" % len(found[e]) for e in ENGINES) + "  %14d %5d" % (len(union), len(files) - len(union))))
    n = tot["files"]
    print("%-7s %5d  %s" % ("total", n, "  ".join("%9d %4.1f%%" % (tot[e], 100 * tot[e] / n) for e in ENGINES) +
                            "  %9d %4.1f%% %5d" % (tot["union"], 100 * tot["union"] / n, n - tot["union"])))
    print("union+kg per draw: min %d, max %d of %d files" % (min(unions), max(unions), n // draws))


main(sys.argv)
