#!/usr/bin/env python3
"""Recall of betterleaks with its default rules vs the default rules plus an extra rules file,
over several independent random draws of the plant matrix (gen_matrix.py).

    python3 multi_draw.py RULES.toml WORK_DIR [DRAWS]

RULES.toml is the file to measure, normally rules/keyguard.toml. WORK_DIR is a new or empty
directory; each draw is generated into WORK_DIR/draw-N and left there (fake secrets only). DRAWS
defaults to 6. The engine is $KEYGUARD_BETTERLEAKS or the first betterleaks on PATH.

A plant counts as found when betterleaks reports anything in its file: each file holds exactly one
fake, so a finding there is a finding for it. The table lists the plants whose count differs
between the two runs or that were missed in some draw, then the totals, which are the numbers
docs/STEAL.md quotes (68.7% -> 84.1% on 834 plants). The report is read from stdout with
--redact, so no fake value is written anywhere but the draw directories.
"""
import json
import os
import subprocess
import sys

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common

HERE = os.path.dirname(os.path.abspath(__file__))


def found_files(bl, target, rules):
    """The basenames betterleaks reports a finding in, with or without an extra rules file."""
    cmd = [bl, "dir", target, "--no-banner", "--no-color", "-l", "error", "-f", "json", "-r", "-",
           "--redact", "--exit-code", "0"]
    if rules:
        cmd += ["-c", rules]
    out = common.run(cmd).stdout
    return {os.path.basename(f["File"]) for f in json.loads(out or "[]")}


def main(argv):
    if len(argv) not in (3, 4):
        common.die("usage: multi_draw.py RULES.toml WORK_DIR [DRAWS]")
    rules, work = os.path.abspath(argv[1]), os.path.abspath(argv[2])
    draws = int(argv[3]) if len(argv) == 4 else 6
    if not os.path.isfile(rules):
        common.die(rules + " is not a file")
    common.empty_dir(work)
    bl = common.engine("betterleaks")

    tot = {}
    for i in range(draws):
        d = os.path.join(work, "draw-%d" % i)
        common.run([sys.executable, os.path.join(HERE, "gen_matrix.py"), d])
        files = sorted(os.listdir(d))
        for label, extra in (("default", None), ("extra", rules)):
            found = found_files(bl, d, extra)
            for f in files:
                key = f.rsplit(".", 1)[0]  # plant__context
                tot.setdefault(key, {"default": 0, "extra": 0})
                if f in found:
                    tot[key][label] += 1

    print("plant__ctx (detections over %d draws)         default  extra" % draws)
    n_def = n_ext = 0
    for k, v in sorted(tot.items()):
        n_def += v["default"]
        n_ext += v["extra"]
        if v["default"] != v["extra"] or v["extra"] < draws:
            print("  %-42s %5d/%d %5d/%d" % (k, v["default"], draws, v["extra"], draws))
    total = len(tot) * draws
    print("TOTAL recall: default %d/%d (%.1f%%)   +extra %d/%d (%.1f%%)"
          % (n_def, total, 100 * n_def / total, n_ext, total, 100 * n_ext / total))


main(sys.argv)
