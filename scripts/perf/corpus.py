#!/usr/bin/env python3
"""The perf corpus: public open-source code, rebuilt from pinned upstream releases.

    python3 -I corpus.py verify   [--corpus DIR]   compare DIR with manifest.json, exit 1 on a difference
    python3 -I corpus.py build    [--corpus DIR]   make DIR from the pinned sources
    python3 -I corpus.py manifest [--corpus DIR]   rewrite the measured fields of manifest.json from DIR
    python3 -I corpus.py resolve                   fill in the upstream commit of each pinned source

DIR defaults to ~/.cache/keyguard-dev/perf/corpus. The corpus is never committed and never lives in
the repository: manifest.json is what is committed, and it names only public projects, the
release each file set was taken from, and that release's commit. A file set is the source's
regular files; symlinks and .git directories are left out, as the scanners leave them out. The
digest of a file set is the sha256 of its sorted "path, size, sha256" lines, so two corpora with
the same digest hold the same bytes under the same names.

The sources are the Go toolchain's own source tree, four Kubernetes and x/tools modules from the
Go module cache, four globally installed npm packages and the npm dependency tree of one
package. They are code a person already has on a development machine, which is what a scanner
meets on a disk. None of it was picked for what it contains.

build copies from the machine when the pinned version is installed there (the Go toolchain, the
module cache, `npm root -g`) and fetches the pinned release from the public registries when it is
not. It never overwrites: a source directory that exists is kept, so a build that stopped can be run
again and builds what is missing.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True  # no __pycache__ in the source tree

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(HERE, "manifest.json")
DEFAULT_CORPUS = os.path.join(os.path.expanduser("~"), ".cache", "keyguard-dev", "perf", "corpus")
FETCH_CACHE = os.path.join(os.path.expanduser("~"), ".cache", "keyguard-dev", "perf", "fetched")


def die(msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(2)


def sh(cmd, **kw):
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if p.returncode != 0:
        tail = (p.stderr or p.stdout or "").strip().splitlines()[-1:] or [""]
        die("%s failed (%d): %s" % (" ".join(cmd[:3]), p.returncode, tail[0][:200]))
    return p.stdout


def load_manifest():
    with open(MANIFEST) as f:
        return json.load(f)


def save_manifest(m):
    with open(MANIFEST, "w") as f:
        json.dump(m, f, indent=2)
        f.write("\n")


# ----- file sets -----

def walk_files(root):
    """Relative POSIX paths of the regular files under root, symlinks and .git left out."""
    out = []
    for dp, dn, fn in os.walk(root, followlinks=False):
        dn[:] = [d for d in dn if d != ".git"]
        for f in fn:
            p = os.path.join(dp, f)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            out.append(os.path.relpath(p, root).replace(os.sep, "/"))
    out.sort()
    return out


def file_sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def measure(root):
    """(files, bytes, digest) of the file set under root."""
    h = hashlib.sha256()
    n = size = 0
    for rel in walk_files(root):
        p = os.path.join(root, rel)
        sz = os.path.getsize(p)
        h.update(("%s\t%d\t%s\n" % (rel, sz, file_sha(p))).encode())
        n += 1
        size += sz
    return n, size, h.hexdigest()


def measure_corpus(corpus, sources, alias):
    """Per-source measures and the corpus-wide digest (over the sources' digests, in manifest order)."""
    per = {}
    top = hashlib.sha256()
    files = size = 0
    for s in sources:
        d = os.path.join(corpus, alias.get(s["name"], s["name"]))
        if not os.path.isdir(d):
            die("%s has no %s directory" % (corpus, alias.get(s["name"], s["name"])))
        n, b, dg = measure(d)
        per[s["name"]] = (n, b, dg)
        top.update(("%s\t%d\t%d\t%s\n" % (s["name"], n, b, dg)).encode())
        files += n
        size += b
    return per, (files, size, top.hexdigest())


def copy_tree(src, dst):
    """Copy the file set of src into dst; dst must not exist yet."""
    if os.path.exists(dst):
        die("%s exists already; the build never overwrites" % dst)
    rels = walk_files(src)
    if not rels:
        die("%s holds no files to copy" % src)
    for rel in rels:
        to = os.path.join(dst, rel)
        os.makedirs(os.path.dirname(to), exist_ok=True)
        shutil.copyfile(os.path.join(src, rel), to)


# ----- where each kind of source comes from -----

def goroot_src(s):
    root = sh(["go", "env", "GOROOT"]).strip()
    have = sh(["go", "version"]).split()[2]
    if have != s["ref"]:
        die("the pinned Go source is %s and this toolchain is %s; install it, or set GOTOOLCHAIN=%s" % (s["ref"], have, s["ref"]))
    return root


def gomod_dir(s):
    # `go mod download` finds the module in the module cache and fetches it from the proxy when it is missing.
    info = json.loads(sh(["go", "mod", "download", "-json", "%s@%s" % (s["module"], s["version"])]))
    if info.get("Error"):
        die("go mod download %s: %s" % (s["module"], info["Error"]))
    return info["Dir"]


def npm_global_dir(s):
    root = sh(["npm", "root", "-g"]).strip()
    d = os.path.join(root, s["package"])
    try:
        with open(os.path.join(d, "package.json")) as f:
            have = json.load(f).get("version")
    except OSError:
        have = None
    if have == s["version"]:
        return d
    prefix = os.path.join(FETCH_CACHE, "npm-global")
    os.makedirs(prefix, exist_ok=True)
    sh(["npm", "install", "-g", "--prefix", prefix, "--ignore-scripts", "--no-audit", "--no-fund",
        "%s@%s" % (s["package"], s["version"])])
    return os.path.join(prefix, "lib", "node_modules", s["package"])


def npm_local_dir(s):
    """The flat node_modules of every pinned package, installed into a scratch project."""
    proj = tempfile.mkdtemp(prefix="perf-npm-", dir=os.path.join(os.path.dirname(FETCH_CACHE)))
    deps = dict((p["name"], p["version"]) for p in s["packages"])
    with open(os.path.join(proj, "package.json"), "w") as f:
        json.dump({"name": "perf-corpus-source", "private": True, "dependencies": deps}, f)
    sh(["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", "--no-package-lock"], cwd=proj)
    return os.path.join(proj, "node_modules")


SOURCE_DIR = {"goroot": goroot_src, "gomod": gomod_dir, "npm-global": npm_global_dir, "npm-local": npm_local_dir}


# ----- commands -----

def cmd_verify(a):
    m = load_manifest()
    per, total = measure_corpus(a.corpus, m["sources"], a.alias)
    bad = 0
    for s in m["sources"]:
        n, b, dg = per[s["name"]]
        ok = (n, b, dg) == (s["files"], s["bytes"], s["sha256"])
        bad += not ok
        print("%-22s %6d files %12d bytes  %s" % (s["name"], n, b, "ok" if ok else
              "DIFFERS (manifest: %d files, %d bytes)" % (s["files"], s["bytes"])))
    t = m["totals"]
    ok = total == (t["files"], t["bytes"], t["sha256"])
    bad += not ok
    print("%-22s %6d files %12d bytes  %s" % ("total", total[0], total[1], "ok" if ok else "DIFFERS"))
    sys.exit(1 if bad else 0)


def cmd_manifest(a):
    m = load_manifest()
    for s in m["sources"]:
        if s["kind"] == "npm-local":
            s["packages"] = packages_in(os.path.join(a.corpus, a.alias.get(s["name"], s["name"])))
    per, total = measure_corpus(a.corpus, m["sources"], a.alias)
    for s in m["sources"]:
        s["files"], s["bytes"], s["sha256"] = per[s["name"]]
    m["totals"] = {"files": total[0], "bytes": total[1], "sha256": total[2]}
    save_manifest(m)
    print("manifest.json: %d files, %d bytes" % (total[0], total[1]))


def packages_in(node_modules):
    """name, version and public repository of each package at the top level of a node_modules tree."""
    out = []
    for e in sorted(os.listdir(node_modules)):
        if e.startswith("."):
            continue
        dirs = [os.path.join(node_modules, e)]
        if e.startswith("@"):
            dirs = [os.path.join(node_modules, e, x) for x in sorted(os.listdir(os.path.join(node_modules, e)))]
        for d in dirs:
            pj = os.path.join(d, "package.json")
            if not os.path.isfile(pj):
                continue
            with open(pj) as f:
                j = json.load(f)
            repo = j.get("repository")
            if isinstance(repo, dict):
                repo = repo.get("url")
            out.append({"name": j["name"], "version": j["version"], "repository": repo,
                        "licence": j.get("license") if isinstance(j.get("license"), str) else None})
    return out


def cmd_build(a):
    m = load_manifest()
    os.makedirs(a.corpus, exist_ok=True)
    for s in m["sources"]:
        if os.path.exists(os.path.join(a.corpus, s["name"])):
            print("kept  %-22s (already there; the build never overwrites)" % s["name"])
            continue
        src = SOURCE_DIR[s["kind"]](s)
        if s.get("subdir"):
            src = os.path.join(src, s["subdir"])
        copy_tree(src, os.path.join(a.corpus, s["name"]))
        print("built %-22s from %s" % (s["name"], s.get("ref") or s.get("version") or s["kind"]))
    print("now run: corpus.py verify --corpus %s" % a.corpus)


def ls_remote(url, tag):
    out = sh(["git", "ls-remote", url, "refs/tags/" + tag, "refs/tags/" + tag + "^{}"]).splitlines()
    rows = dict((r.split("\t")[1], r.split("\t")[0]) for r in out if "\t" in r)
    return rows.get("refs/tags/" + tag + "^{}") or rows.get("refs/tags/" + tag)


def cmd_resolve(a):
    m = load_manifest()
    for s in m["sources"]:
        if s["kind"] == "gomod":
            info = json.loads(sh(["go", "mod", "download", "-json", "%s@%s" % (s["module"], s["version"])]))
            s["commit"] = (info.get("Origin") or {}).get("Hash")
        elif s.get("tag"):
            s["commit"] = ls_remote(s["project"], s["tag"])
        if "commit" in s and not s["commit"]:
            die("no commit found for " + s["name"])
        print("%-22s %s" % (s["name"], s.get("commit", "-")))
    save_manifest(m)


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("command", choices=["verify", "build", "manifest", "resolve"])
    p.add_argument("--corpus", default=DEFAULT_CORPUS)
    p.add_argument("--alias", action="append", default=[], metavar="NAME=DIR",
                   help="a source kept in DIR under the corpus, not in a directory named NAME (an older corpus's layout)")
    a = p.parse_args()
    a.corpus = os.path.abspath(a.corpus)
    a.alias = dict(x.split("=", 1) for x in a.alias)
    {"verify": cmd_verify, "build": cmd_build, "manifest": cmd_manifest, "resolve": cmd_resolve}[a.command](a)


main()
