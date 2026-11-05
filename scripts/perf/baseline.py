#!/usr/bin/env python3
"""Runs every baseline measurement of docs/NATIVE-BASELINE.md and keeps the raw outputs.

    python3 -I baseline.py --keyguard BIN --out DIR [--only bench,speed,research,devtool,perf]

BIN is a built keyguard (go build -o BIN ./cmd/keyguard). DIR is new or empty; each step writes
under it. Nothing touches the real data root: every keyguard run gets its own KEYGUARD_HOME and
TMPDIR under DIR, and the bench builds its corpus in that TMPDIR. The steps:

    bench     keyguard bench, seeds 1 and 2, all four engines, with and without rules/keyguard.toml
              (without it is the run the README table comes from), and the production tier
              (betterleaks, gitleaks, trufflehog) with the rules file on
    speed     keyguard bench --speed 5 on seed 1: the S1 baseline, one cold run and four warm
    research  multi_draw.py (betterleaks alone, 6 draws) and multi_union.py (all four engines, 3 draws)
    devtool   gen.py, run_engines.py and score.py: the 57-value dev-tool study, with and without the rules
    perf      run.py: the four engines and the read floor over the perf corpus, 5 rounds

The 1-minute load average is read before and after every step and written to steps.json beside
its wall time: a timing means nothing without it, and the plan judges none above load 6. The
fakes the research scripts plant sit under DIR and are never printed.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time

sys.dont_write_bytecode = True  # no __pycache__ in the source tree

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
RESEARCH = os.path.join(REPO, "scripts", "research")
RULES = os.path.join(REPO, "rules", "keyguard.toml")
PY = [sys.executable, "-I"]


def die(msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(2)


def loadavg():
    out = subprocess.run(["sysctl", "-n", "vm.loadavg"], capture_output=True, text=True).stdout
    return float(out.strip("{} \n").split()[0])


steps = []


def run(out, label, argv, env=None, cwd=None):
    """Run argv, keep its stdout and stderr in out/label.{out,err}, record wall time and load."""
    os.makedirs(out, exist_ok=True)
    l0, t0 = loadavg(), time.time()
    with open(os.path.join(out, label + ".out"), "w") as fo, open(os.path.join(out, label + ".err"), "w") as fe:
        p = subprocess.run(argv, stdout=fo, stderr=fe, env=env, cwd=cwd)
    rec = {"step": label, "rc": p.returncode, "wall_s": round(time.time() - t0, 2),
           "load_before": l0, "load_after": loadavg()}
    steps.append(rec)
    print("%-28s rc=%d %6.1fs load %5.1f -> %5.1f" % (label, p.returncode, rec["wall_s"], l0, rec["load_after"]), flush=True)
    return p.returncode


def keyguard_env(root, rules_on):
    home = os.path.join(root, "home-rules" if rules_on else "home-norules")
    tmp = os.path.join(root, "tmp")
    os.makedirs(tmp, exist_ok=True)
    if rules_on and not os.path.isfile(os.path.join(home, "rules", "keyguard.toml")):
        os.makedirs(os.path.join(home, "rules"), exist_ok=True)
        shutil.copyfile(RULES, os.path.join(home, "rules", "keyguard.toml"))
    os.makedirs(home, exist_ok=True)
    return dict(os.environ, KEYGUARD_HOME=home, TMPDIR=tmp)


def step_bench(a, root):
    out = os.path.join(root, "bench")
    for rules_on in (True, False):
        env = keyguard_env(root, rules_on)
        tag = "rules" if rules_on else "norules"
        for seed in (1, 2):
            run(out, "seed%d-%s-all" % (seed, tag),
                [a.keyguard, "bench", "--seed", str(seed), "--engines", "all", "--json",
                 "--out", os.path.join(out, "seed%d-%s-all" % (seed, tag))], env)
    env = keyguard_env(root, True)
    for seed in (1, 2):
        run(out, "seed%d-rules-prod" % seed,
            [a.keyguard, "bench", "--seed", str(seed), "--json", "--out", os.path.join(out, "seed%d-rules-prod" % seed)], env)


def step_speed(a, root):
    out = os.path.join(root, "speed")
    run(out, "seed1-rules-speed5",
        [a.keyguard, "bench", "--seed", "1", "--engines", "all", "--speed", "5", "--json",
         "--out", os.path.join(out, "seed1-rules-speed5")], keyguard_env(root, True))


def step_research(a, root):
    out = os.path.join(root, "research")
    run(out, "multi_draw", PY + [os.path.join(RESEARCH, "multi_draw.py"), RULES, os.path.join(out, "multi_draw-work"), "6"])
    run(out, "multi_union", PY + [os.path.join(RESEARCH, "multi_union.py"), RULES, os.path.join(out, "multi_union-work"), "3"])


def step_devtool(a, root):
    out = os.path.join(root, "devtool")
    work = os.path.join(out, "with-rules")
    if run(out, "gen", PY + [os.path.join(RESEARCH, "gen.py"), work]) != 0:
        return
    bare = os.path.join(out, "without-rules")
    shutil.copytree(work, bare)  # the same 57 values, scanned without the extra rules
    for d, rules, label in ((work, RULES, "with-rules"), (bare, None, "without-rules")):
        if run(out, "run_engines-" + label, PY + [os.path.join(RESEARCH, "run_engines.py"), d] + ([rules] if rules else [])) == 0:
            run(out, "score-" + label, PY + [os.path.join(RESEARCH, "score.py"), d])


def step_perf(a, root):
    run(os.path.join(root, "perf"), "run", PY + [os.path.join(HERE, "run.py"), "--rounds", "5", "--variants",
                                                  "--out", os.path.join(root, "perf", "data")] + (["--corpus", a.corpus] if a.corpus else []))


STEPS = {"bench": step_bench, "speed": step_speed, "research": step_research, "devtool": step_devtool, "perf": step_perf}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--keyguard", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--only", default=",".join(STEPS))
    ap.add_argument("--corpus", default=None)
    a = ap.parse_args()
    a.keyguard, root = os.path.abspath(a.keyguard), os.path.abspath(a.out)
    if not os.access(a.keyguard, os.X_OK):
        die(a.keyguard + " is not an executable file; build it with go build -o BIN ./cmd/keyguard")
    if os.path.isdir(root) and os.listdir(root):
        die(root + " is not empty; pass a new directory")
    os.makedirs(root, exist_ok=True)
    cpus = int(subprocess.run(["sysctl", "-n", "hw.ncpu"], capture_output=True, text=True).stdout)
    print("machine: %d CPUs, load %.1f at the start" % (cpus, loadavg()), flush=True)
    for name in a.only.split(","):
        if name not in STEPS:
            die("unknown step " + name)
        STEPS[name](a, root)
        with open(os.path.join(root, "steps.json"), "w") as f:
            json.dump({"cpus": cpus, "steps": steps}, f, indent=1)
    print("raw outputs are in " + root)


main()
