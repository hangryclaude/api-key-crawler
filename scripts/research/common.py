"""Plumbing the research tools share: where an engine lives, how to run it, how to fake a token.

Nothing here knows a path on the user's Mac. An engine is found the way a person would find it:
$KEYGUARD_<NAME> (KEYGUARD_BETTERLEAKS, KEYGUARD_GITLEAKS, KEYGUARD_TRUFFLEHOG, KEYGUARD_TITUS)
names the binary to use, otherwise the first one on PATH. The tools take every directory and
file as an argument and write only under the directory they are given.

A script imports this as a sibling and puts its own directory on sys.path first, so it also
works under `python3 -I`, which leaves the script's directory out.

Every fake secret is assembled at run time from a prefix and random characters, so no file in
this directory holds a secret-shaped literal (PLAN invariant 2) and each run draws new values.
"""
import os
import random
import shutil
import string
import subprocess
import sys
import zlib

ENGINES = ("betterleaks", "gitleaks", "trufflehog", "titus")

# SystemRandom, not a seeded generator: a draw is meant to be a fresh sample, and nothing here
# needs to be repeatable (the Go bench is the repeatable corpus).
rng = random.SystemRandom()

ALNUM = string.ascii_letters + string.digits
B62 = string.digits + string.ascii_uppercase + string.ascii_lowercase


def die(msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(2)


def engine(name):
    """Path of an engine binary, or exit with a message that says how to point at one."""
    pin = os.environ.get("KEYGUARD_" + name.upper())
    if pin:
        if not (os.path.isfile(pin) and os.access(pin, os.X_OK)):
            die("KEYGUARD_%s=%s is not an executable file" % (name.upper(), pin))
        return pin
    found = shutil.which(name)
    if not found:
        die("%s is not on PATH; set KEYGUARD_%s to its path" % (name, name.upper()))
    return found


def run(cmd, **kw):
    """Run a command, return its CompletedProcess with text output.

    An engine exiting non-zero is an engine failure, never an empty result: callers pass
    --exit-code 0 so that findings are not an error, and anything else stops the tool.
    """
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if p.returncode != 0:
        # stderr's first line only: engines can echo the offending input
        first = (p.stderr or "").strip().splitlines()[:1]
        die("%s exited %d: %s" % (os.path.basename(cmd[0]), p.returncode, first[0][:200] if first else ""))
    return p


def hermetic_git_env():
    """An environment where git reads no user config: keyguard's own hooks must not see these fakes."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull, GIT_CONFIG_NOSYSTEM="1",
               GIT_TERMINAL_PROMPT="0")
    return env


def rnd(n, cs=ALNUM):
    return "".join(rng.choice(cs) for _ in range(n))


def b62(n, width):
    s = ""
    while n:
        n, r = divmod(n, 62)
        s = B62[r] + s
    return s.rjust(width, "0")


def gh_pat():
    """A GitHub classic token with its real structure: 30 random characters, then their CRC32 in base62."""
    body = rnd(30)
    return "ghp_" + body + b62(zlib.crc32(body.encode()) & 0xFFFFFFFF, 6)


def empty_dir(path):
    """Create path for output, refusing a directory that already holds something.

    A tool that wrote into a used directory would mix this run's fakes with an older run's and
    score the two together.
    """
    if os.path.isdir(path) and os.listdir(path):
        die("%s is not empty; pass a new directory" % path)
    os.makedirs(path, exist_ok=True)
