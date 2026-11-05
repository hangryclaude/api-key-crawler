#!/usr/bin/env python3
"""Runs the four engines over the artifacts gen.py wrote, leaving the reports score.py reads.

    python3 run_engines.py RUN_DIR [RULES.toml]

RUN_DIR is the directory gen.py wrote. Next to its vec/ this writes bl.json (betterleaks),
gl.json (gitleaks), th.jsonl (trufflehog) and ti.json (titus). RULES.toml, when given, is passed
to betterleaks and gitleaks as their config (rules/keyguard.toml). The reports hold the fake
secrets in the clear because score.py has to match them, so keep RUN_DIR in a scratch directory.

The flags are keyguard's own (docs/STEAL.md section 5.1): inline allow markers ignored, trufflehog
unverified and not self-updating, titus in memory so it writes no datastore. Each engine's exit
status is checked: a failed engine stops the run instead of reading as a clean scan.
"""
import os
import sys

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common


def main(argv):
    if len(argv) not in (2, 3):
        common.die("usage: run_engines.py RUN_DIR [RULES.toml]")
    run = os.path.abspath(argv[1])
    vec = os.path.join(run, "vec")
    if not os.path.isdir(vec):
        common.die(vec + " does not exist; run gen.py first")
    rules = os.path.abspath(argv[2]) if len(argv) == 3 else None
    if rules and not os.path.isfile(rules):
        common.die(rules + " is not a file")
    # titus compiles its rules once into a cache; keep that cache out of the user's home
    env = dict(os.environ, TITUS_CACHE_DIR=os.path.join(run, "titus-cache"))
    os.makedirs(env["TITUS_CACHE_DIR"], exist_ok=True)

    leaks = ["dir", vec, "-f", "json", "-r", "-", "--no-banner", "-l", "error", "--exit-code", "0",
             "--ignore-gitleaks-allow"] + (["-c", rules] if rules else [])
    jobs = [
        ("bl.json", [common.engine("betterleaks")] + leaks + ["--no-color"]),
        ("gl.json", [common.engine("gitleaks")] + leaks),
        ("th.jsonl", [common.engine("trufflehog"), "filesystem", vec, "--json", "--no-verification",
                      "--no-update", "--no-color", "--log-level=-1", "--no-ignore-tag",
                      "--results=verified,unknown,unverified,filtered_unverified"]),
        ("ti.json", [common.engine("titus"), "scan", vec, "--format", "json", "--output", ":memory:", "-q",
                     "--ignore", os.devnull]),
    ]
    for name, cmd in jobs:
        out = common.run(cmd, env=env).stdout
        with open(os.path.join(run, name), "w") as f:
            f.write(out)
        print("%-9s %s" % (os.path.basename(cmd[0]), name))


main(sys.argv)
