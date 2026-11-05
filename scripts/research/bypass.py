#!/usr/bin/env python3
"""Can an agent silence the scanner by editing files inside the repo? Prints counts only.

    python3 bypass.py OUT_DIR

OUT_DIR must be new or empty. Plants a fake GitHub token in two files and shows what an engine
reports before and after the two edits an agent can make from inside the repo: an inline allow
comment (betterleaks:allow, trufflehog:ignore) and a repo-local ignore file holding the finding's
fingerprint. Each line pairs the engine's default behaviour with the flag keyguard always passes:
--ignore-gitleaks-allow, --no-ignore-tag, and an empty directory for -i. Engines are
$KEYGUARD_BETTERLEAKS / $KEYGUARD_TRUFFLEHOG or the first on PATH. These are the cases the
selftest plants for docs/STEAL.md P0-12.
"""
import json
import os
import pathlib
import sys

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common

if len(sys.argv) != 2:
    common.die("usage: bypass.py OUT_DIR")
out = pathlib.Path(sys.argv[1])
common.empty_dir(out)
BL = common.engine("betterleaks")
TH = common.engine("trufflehog")


def bl(d, *extra):
    p = common.run([BL, "dir", str(d), "-f", "json", "-r", "-", "--no-banner", "-l", "error", "--exit-code", "0", *extra])
    return json.loads(p.stdout or "[]")


def th(d, *extra):
    p = common.run([TH, "filesystem", str(d), "--json", "--no-verification", "--no-update", *extra])
    return [l for l in p.stdout.splitlines() if l.startswith("{")]


# 1. inline allow comment
d1 = out / "allow"
d1.mkdir(parents=True, exist_ok=True)
(d1 / "a.py").write_text(f'GH = "{common.gh_pat()}"  # betterleaks:allow\n')
(d1 / "b.py").write_text(f'GH = "{common.gh_pat()}"  # trufflehog:ignore\n')
print("inline betterleaks:allow     -> betterleaks findings:", len([f for f in bl(d1) if f["File"].endswith("a.py")]), "| with --ignore-gitleaks-allow:", len([f for f in bl(d1, "--ignore-gitleaks-allow") if f["File"].endswith("a.py")]))
print("inline trufflehog:ignore     -> trufflehog findings:", len([l for l in th(d1) if "b.py" in l]), "| with --no-ignore-tag:", len([l for l in th(d1, "--no-ignore-tag") if "b.py" in l]))

# 2. repo-local ignore file with the fingerprint
d2 = out / "ignorefile"
d2.mkdir(parents=True, exist_ok=True)
(d2 / "c.py").write_text(f'GH = "{common.gh_pat()}"\n')
first = bl(d2)
print("baseline findings:", len(first))
(d2 / ".betterleaksignore").write_text("\n".join(f["Fingerprint"] for f in first) + "\n")
after = [f for f in bl(d2) if f["File"].endswith("c.py")]
empty = out / "emptyignore"
empty.mkdir(exist_ok=True)
after_empty = [f for f in bl(d2, "-i", str(empty)) if f["File"].endswith("c.py")]
print("repo-local .betterleaksignore -> findings:", len(after), "| with -i <empty dir>:", len(after_empty))
