#!/usr/bin/env python3
"""Times the scanner engines and the read floor over the perf corpus: gate S2 of the native-engine plan.

    python3 -I run.py [--corpus DIR] [--out DIR] [--rounds 5] [--variants]

Every round runs each engine once and then the floor, in the same order, so a drift in the
machine's load reaches all of them alike. Each run is timed with /usr/bin/time -l (wall, user and
system seconds, peak resident set), and the machine's 1-minute load average is read before and after it. The
engines run in directory mode with the flags the research run used (docs/NATIVE-BASELINE.md):

    betterleaks / gitleaks   dir ... -f json -r - --exit-code 0 --ignore-gitleaks-allow
    trufflehog               filesystem --no-verification --no-update --json
    titus                    scan --format json --output :memory: --ignore <.git/>, warm rule cache

--variants adds gitleaks and betterleaks with decode depth 0 (what keyguard passes to gitleaks) and
betterleaks on the stdlib regex engine, 3 rounds each. The floor is scripts/perf/floor: walk and
read every file, nothing else, which is the least any engine can take on this machine.

An engine's findings are counted in memory and only counted: the report holds the values of
whatever it found, so it is never written to disk or printed. What is kept is the count per rule.

S2 asks for at most (W + F) / 2, where W is the fastest engine's median wall time and F the floor's,
both taken in this run. The load is printed beside every row, and a run above load 6 is marked: the
plan does not judge a timing taken on a machine that busy.
"""
import argparse
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True  # no __pycache__ in the source tree

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
DEFAULT_CORPUS = os.path.join(os.path.expanduser("~"), ".cache", "keyguard-dev", "perf", "corpus")
JUDGE_BELOW_LOAD = 6.0  # the plan refuses to judge a timing taken above this load


def die(msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(2)


def engine_path(name):
    pin = os.environ.get("KEYGUARD_" + name.upper())
    if pin:
        if not (os.path.isfile(pin) and os.access(pin, os.X_OK)):
            die("KEYGUARD_%s=%s is not an executable file" % (name.upper(), pin))
        return pin
    found = shutil.which(name)
    if not found:
        die("%s is not on PATH; set KEYGUARD_%s to its path" % (name, name.upper()))
    return found


def loadavg():
    """The 1-minute load average, as sysctl reports it: '{ 1.23 2.34 3.45 }'."""
    out = subprocess.run(["sysctl", "-n", "vm.loadavg"], capture_output=True, text=True).stdout
    return float(out.strip("{} \n").split()[0])


def sha12(path):
    import hashlib
    h = hashlib.sha256()
    with open(os.path.realpath(path), "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()[:12]


def leaks_cmd(binary, corpus, empty, extra=()):
    return [binary, "dir", corpus, "--no-banner", "--no-color", "-l", "info", "-f", "json", "-r", "-",
            "--exit-code", "0", "-i", empty, "--ignore-gitleaks-allow"] + list(extra)


def commands(corpus, work, variants):
    """name -> (argv, env). The default four first; the variants are separate rows."""
    empty = os.path.join(work, "empty")
    os.makedirs(empty, exist_ok=True)
    ignore = os.path.join(work, "titus.ignore")
    with open(ignore, "w") as f:
        f.write(".git/\n")
    titus_env = dict(os.environ, TITUS_CACHE_DIR=os.path.join(work, "titus-cache"))
    os.makedirs(titus_env["TITUS_CACHE_DIR"], exist_ok=True)
    bl, gl = engine_path("betterleaks"), engine_path("gitleaks")
    cmds = {
        "gitleaks": (leaks_cmd(gl, corpus, empty), None),
        "betterleaks": (leaks_cmd(bl, corpus, empty), None),
        "trufflehog": ([engine_path("trufflehog"), "filesystem", corpus, "--no-verification", "--no-update",
                        "--json", "--no-color"], None),
        "titus": ([engine_path("titus"), "scan", corpus, "--format", "json", "--output", ":memory:",
                   "--context-lines", "1", "--ignore", ignore, "--accessibility", "private"], titus_env),
    }
    extra = {}
    if variants:
        extra = {
            "gitleaks-d0": (leaks_cmd(gl, corpus, empty, ["--max-decode-depth", "0"]), None),
            "betterleaks-d0": (leaks_cmd(bl, corpus, empty, ["--max-decode-depth", "0"]), None),
            "betterleaks-std": (leaks_cmd(bl, corpus, empty, ["--regex-engine", "stdlib"]), None),
        }
    return cmds, extra


def count_findings(name, out):
    """Number of findings and the count per rule id in an engine's stdout; the values are dropped here."""
    rules = {}
    try:
        if name.startswith("trufflehog"):
            for line in out.splitlines():
                if line.startswith("{"):
                    r = json.loads(line).get("DetectorName", "?")
                    rules[r] = rules.get(r, 0) + 1
        else:
            for f in json.loads(out or "[]"):
                r = f.get("RuleID", "?")
                rules[r] = rules.get(r, 0) + 1
    except ValueError:
        return None, {}
    return sum(rules.values()), rules


TIME_RE = {
    "real": re.compile(r"^\s*([\d.]+)\s+real", re.M),
    "user": re.compile(r"\s([\d.]+)\s+user", re.M),
    "sys": re.compile(r"\s([\d.]+)\s+sys", re.M),
    "rss": re.compile(r"^\s*(\d+)\s+maximum resident set size", re.M),
}


def timed(name, argv, env, keep_rules):
    tf = tempfile.NamedTemporaryFile(prefix="perf-time-", delete=False)
    tf.close()
    l0 = loadavg()
    p = subprocess.run(["/usr/bin/time", "-l", "-o", tf.name] + argv, capture_output=True, text=True, env=env)
    l1 = loadavg()
    with open(tf.name) as f:
        t = f.read()
    os.unlink(tf.name)
    row = {"engine": name, "rc": p.returncode, "load0": l0, "load1": l1}
    for k, rx in TIME_RE.items():
        m = rx.search(t)
        row[k] = float(m.group(1)) if m else None
    if row["rss"] is not None:
        row["rss_mib"] = round(row["rss"] / 1048576)
    if name != "floor":
        n, rules = count_findings(name, p.stdout)
        row["findings"] = n
        keep_rules[name] = rules
    else:
        row["floor"] = json.loads(p.stdout)
    return row


def median(xs):
    return statistics.median(xs) if xs else None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--corpus", default=DEFAULT_CORPUS)
    ap.add_argument("--out", default=None, help="directory for runs.json and the floor binary (new or empty)")
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--variants", action="store_true")
    a = ap.parse_args()
    corpus = os.path.abspath(a.corpus)
    if not os.path.isdir(corpus):
        die(corpus + " is not a directory; build it with corpus.py")
    out = os.path.abspath(a.out or tempfile.mkdtemp(prefix="perf-run-"))
    os.makedirs(out, exist_ok=True)
    if os.listdir(out):
        die(out + " is not empty; pass a new directory")

    floor_bin = os.path.join(out, "floor")
    subprocess.run(["go", "build", "-o", floor_bin, "./scripts/perf/floor"], cwd=REPO, check=True)
    cmds, extra = commands(corpus, out, a.variants)
    floor = ([floor_bin, "-dir", corpus], None)

    meta = {"corpus": os.path.basename(corpus), "cpus": int(subprocess.run(["sysctl", "-n", "hw.ncpu"], capture_output=True, text=True).stdout),
            "engines": {n: {"path_hash": sha12(c[0][0])} for n, c in cmds.items()}}
    for n in ("betterleaks", "gitleaks", "trufflehog", "titus"):
        v = subprocess.run([cmds[n][0][0], "--version" if n == "trufflehog" else "version"], capture_output=True, text=True)
        m = re.search(r"\d+\.\d+\.\d+", (v.stdout or "") + (v.stderr or ""))
        meta["engines"][n]["version"] = m.group(0) if m else "?"

    # One untimed run of titus fills its rule cache, so the timed ones are warm (a cold start is 2.7 s more).
    subprocess.run(cmds["titus"][0], capture_output=True, env=cmds["titus"][1])

    rows, rules = [], {}
    for rnd in range(1, a.rounds + 1):
        for name, (argv, env) in list(cmds.items()) + [("floor", floor)]:
            r = timed(name, argv, env, rules)
            r["round"] = rnd
            rows.append(r)
    for rnd in range(1, min(a.rounds, 3) + 1):
        for name, (argv, env) in extra.items():
            r = timed(name, argv, env, rules)
            r["round"] = rnd
            rows.append(r)

    bad = [r for r in rows if r["rc"] != 0]
    with open(os.path.join(out, "runs.json"), "w") as f:
        json.dump({"meta": meta, "rows": rows, "rules": rules}, f, indent=1)

    nbytes = None
    print("corpus %s: %d CPUs; %d round(s); load = 1-minute average before and after each run" % (meta["corpus"], meta["cpus"], a.rounds))
    print("%-16s %7s %7s %7s %7s %9s %9s %5s" % ("run", "wall_s", "cpu_s", "rss_MB", "MB/s", "findings", "load", "runs"))
    summary = {}
    for name in list(cmds) + ["floor"] + list(extra):
        rs = [r for r in rows if r["engine"] == name]
        if not rs:
            continue
        wall = median([r["real"] for r in rs])
        if name == "floor":
            nbytes = rs[0]["floor"]["bytes"]
        summary[name] = {"wall": wall, "cpu": median([r["user"] + r["sys"] for r in rs]),
                         "rss_mib": median([r["rss_mib"] for r in rs]), "findings": rs[0].get("findings"),
                         "load_lo": min(min(r["load0"], r["load1"]) for r in rs),
                         "load_hi": max(max(r["load0"], r["load1"]) for r in rs), "n": len(rs)}
    for name, s in summary.items():
        mbps = (nbytes / 1e6 / s["wall"]) if nbytes and s["wall"] else 0
        print("%-16s %7.2f %7.2f %7.0f %7.0f %9s %9s %5d" % (
            name, s["wall"], s["cpu"], s["rss_mib"], mbps, s["findings"] if s["findings"] is not None else "-",
            "%.0f-%.0f" % (s["load_lo"], s["load_hi"]), s["n"]))
    default = [n for n in ("betterleaks", "gitleaks", "trufflehog", "titus") if n in summary]
    fastest = min(default, key=lambda n: summary[n]["wall"])
    W, F = summary[fastest]["wall"], summary["floor"]["wall"]
    hi = max(s["load_hi"] for s in summary.values())
    print()
    print("S2: fastest engine %s W = %.3f s, floor F = %.3f s -> a native engine must take at most (W + F) / 2 = %.3f s;"
          " the literal 2x of W is %.3f s, %s the floor" % (fastest, W, F, (W + F) / 2, W / 2, "under" if W / 2 < F else "above"))
    if hi > JUDGE_BELOW_LOAD:
        print("load reached %.0f on %d CPUs (the plan judges timings at load %.0f or less): these are indicative, not a verdict"
              % (hi, meta["cpus"], JUDGE_BELOW_LOAD))
    if bad:
        print("NOT CLEAN: %s exited non-zero" % ", ".join(sorted(set(r["engine"] for r in bad))), file=sys.stderr)
        sys.exit(1)
    print("rows and per-rule counts are in %s/runs.json" % out)


main()
