#!/usr/bin/env bun
// Dev-time rule extraction: betterleaks's rules, as data, into this repository.
//
//   bun scripts/rulegen/extract.mjs [--src CLONE] [--corpus DIR] [--out DIR] [--explain 1]
//
// Only the people who refresh the rule data run this, and only with Bun installed. Nothing at
// build or test time needs it: the Go table it feeds (internal/pattern/rules/rules_gen.go) is
// generated from the JSON written here and committed.
//
// CLONE is a checkout of betterleaks at the commit rules/SOURCES.lock pins (default
// ~/.cache/keyguard-dev/upstream/betterleaks). The script refuses a checkout that is at another
// commit or has local changes, because a pin that the data does not follow is worse than no pin.
//
// It writes:
//   rules/src/<name>.json   the rules of one upstream generator file, without examples; and
//                           _global.json, the config's own prefilter and filter. Licence: MIT.
//   DIR/                    the example cache (default ~/.cache/keyguard-dev/rulecorpus): the true and
//                           false positives betterleaks checks each rule against. Made-up secrets
//                           inside test strings, so never committed. Written by
//                           scripts/rulegen/examples (Go, standard library only), which this runs.
//
// TruffleHog is not read. Its detectors are AGPL-3.0 and this project copies nothing from them.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

const repo = resolve(dirname(import.meta.path), "..", "..");
const cache = join(homedir(), ".cache", "keyguard-dev");

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith("--") ? [...acc, [a.slice(2), all[i + 1]]] : acc), []),
);
const src = resolve(args.src ?? join(cache, "upstream", "betterleaks"));
const corpus = resolve(args.corpus ?? join(cache, "rulecorpus"));
const out = resolve(args.out ?? join(repo, "rules", "src"));

function die(msg) {
  console.error("extract: " + msg);
  process.exit(1);
}

const git = (...a) => execFileSync("git", ["-C", src, ...a], { encoding: "utf8" }).trim();

// ---- the pin
const lock = readFileSync(join(repo, "rules", "SOURCES.lock"), "utf8")
  .split("\n")
  .filter((l) => l.trim() && !l.startsWith("#"))
  .map((l) => {
    const [name, lineage, url, ref, commit, licence] = l.split("\t");
    return { name, lineage, url, ref, commit, licence };
  });
const pin = lock.find((s) => s.name === "betterleaks");
if (!pin) die("rules/SOURCES.lock has no betterleaks line");
if (pin.lineage !== "betterleaks" || pin.licence !== "MIT") die("the betterleaks pin must be lineage betterleaks, licence MIT");

if (!existsSync(join(src, "config", "betterleaks.toml"))) die(`${src} is not a betterleaks checkout (no config/betterleaks.toml)`);
const head = git("rev-parse", "HEAD");
if (head !== pin.commit) die(`${src} is at ${head}, but rules/SOURCES.lock pins ${pin.commit} (${pin.ref})`);
if (git("status", "--porcelain")) die(`${src} has local changes; the data must be the pinned commit's`);

// ---- the rules
const cfg = Bun.TOML.parse(readFileSync(join(src, "config", "betterleaks.toml"), "utf8"));
if (!Array.isArray(cfg.rules) || cfg.rules.length === 0) die("the config has no rules");
const ids = cfg.rules.map((r) => r.id);
if (new Set(ids).size !== ids.length) die("the config repeats a rule id");

// Which upstream generator file defines each rule: its RuleID literal, else the file that
// names the id as a string (a helper called with the id).
const genDir = join(src, "cmd", "generate", "config", "rules");
const genFiles = readdirSync(genDir).filter((f) => f.endsWith(".go") && !f.endsWith("_test.go")).sort();
const texts = new Map(genFiles.map((f) => [f, readFileSync(join(genDir, f), "utf8")]));
const fileOf = new Map();
for (const [f, text] of texts) for (const m of text.matchAll(/RuleID:\s*"([^"]+)"/g)) if (!fileOf.has(m[1])) fileOf.set(m[1], f);
for (const id of ids) {
  if (fileOf.has(id)) continue;
  for (const [f, text] of texts) if (text.includes(`"${id}"`)) { fileOf.set(id, f); break; }
}

// ---- filters
// betterleaks decides what to discard with a small expression language (Expr). The rules use a
// handful of forms, and those are read into fields here; anything else is counted in `residual`
// so that a later stage knows the rule still has behaviour this table does not carry.
//
// A literal that looks like a key (a documentation example in an allow list) is never written:
// it is replaced by the sha256 of its bytes, and the engine compares the digest of a value. The
// repository holds no secret-shaped literal (invariant 2), and these are what a scanner would flag.
const sha256 = (s) => createHash("sha256").update(s).digest("hex");
const REGEX_META = /[\\.^$*+?()[\]{}|]/;
function secretShaped(s) {
  if (s.length < 16) return false;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(s)).length;
  return classes >= 3;
}

// topLevel splits text at the separator wherever it is outside strings and brackets, dropping // comments.
function topLevel(text, sep) {
  const parts = [];
  let cur = "", depth = 0, q = null;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      cur += c;
      if (c === "\\" && q !== "`") cur += text[++i] ?? "";
      else if (c === q) q = null;
      continue;
    }
    if (c === "/" && text[i + 1] === "/") { while (i < text.length && text[i] !== "\n") i++; cur += "\n"; continue; }
    if (c === "`" || c === '"' || c === "'") { q = c; cur += c; continue; }
    if ("([{".includes(c)) depth++;
    if (")]}".includes(c)) depth--;
    if (depth === 0 && text.startsWith(sep, i)) { parts.push(cur); cur = ""; i += sep.length - 1; continue; }
    cur += c;
  }
  parts.push(cur);
  return parts.map((p) => p.trim()).filter(Boolean);
}

// quoted reads the strings of an Expr list: [ `raw`, "escaped", ... ].
function quoted(list) {
  const out = [];
  for (let i = 0; i < list.length; i++) {
    const c = list[i];
    if (c === "`") { const j = list.indexOf("`", i + 1); out.push(list.slice(i + 1, j)); i = j; }
    else if (c === '"') {
      let j = i + 1, v = "";
      for (; list[j] !== '"'; j++) v += list[j] === "\\" ? ({ n: "\n", t: "\t" }[list[++j]] ?? list[j]) : list[j];
      out.push(v); i = j;
    } else if (!/[\s,]/.test(c)) return null;
  }
  return out;
}

// wrapped says whether the parenthesis that opens term closes at its very end.
function wrapped(term) {
  if (!term.startsWith("(") || !term.endsWith(")")) return false;
  let depth = 0, q = null;
  for (let i = 0; i < term.length; i++) {
    const c = term[i];
    if (q) { if (c === "\\" && q !== "`") i++; else if (c === q) q = null; continue; }
    if (c === "`" || c === '"' || c === "'") q = c;
    else if (c === "(") depth++;
    else if (c === ")" && --depth === 0) return i === term.length - 1;
  }
  return false;
}

const unparsed = []; // [rule id, the term], for --explain

function parseFilter(expr, id = "") {
  if (!expr) return undefined;
  const f = {};
  let residual = 0;
  const add = (k, v) => { (f[k] ??= []).push(...v); };
  const terms = (text) => {
    for (let term of topLevel(text, "||")) {
      if (wrapped(term)) { terms(term.slice(1, -1)); continue; }
      let m;
      if ((m = term.match(/^(?:filter\.)?entropy\(finding\["secret"\]\)\s*(<=|<)\s*(\d+(?:\.\d+)?)$/))) {
        f.entropy = { min: Number(m[2]), strict: m[1] === "<=" }; // strict: a value must exceed min; otherwise reach it
      } else if ((m = term.match(/^filter\.tokenRatio\(finding\["secret"\]\)\s*>=\s*(\d+(?:\.\d+)?)$/))) {
        f.tokenRatio = Number(m[1]);
      } else if ((m = term.match(/^(!?)(?:filter\.)?matchesAny\(\s*finding\["secret"\]\s*,\s*\[([\s\S]*)\]\s*\)$/)) && quoted(m[2])) {
        const items = quoted(m[2]);
        if (m[1]) {
          (f.require ??= []).push(items); // dropped unless it matches one of these
        } else {
          for (const it of items) {
            if (REGEX_META.test(it)) add("dropRegex", [it]);
            else if (secretShaped(it)) add("dropSha256", [sha256(it)]);
            else add("dropWords", [it]);
          }
        }
      } else if ((m = term.match(/^(?:filter\.)?containsAny\(\s*finding\["secret"\]\s*,\s*\[([\s\S]*)\]\s*\)$/)) && quoted(m[1])) {
        for (const it of quoted(m[1])) add(secretShaped(it) ? "dropSha256" : "dropWords", [secretShaped(it) ? sha256(it) : it]);
      } else if ((m = term.match(/^(?:filter\.)?matchesAny\(\s*attributes\["path"\]\s*,\s*\[([\s\S]*)\]\s*\)$/)) && quoted(m[1])) {
        add("dropPath", quoted(m[1]));
      } else {
        residual++;
        unparsed.push([id, term.replace(/\s+/g, " ").slice(0, 110)]);
      }
    }
  };
  const statements = topLevel(expr, ";");
  residual += statements.length - 1; // `let` bindings before the final expression
  terms(statements.at(-1));
  if (residual) f.residual = residual;
  return f;
}

// splitLiterals breaks a long run of plain key-like characters in a regex with an empty group,
// (?:), which matches nothing and changes nothing, so that the regex of a rule whose whole pattern
// is a fixed token prefix is not itself a key-shaped literal in the source.
function splitLiterals(re) {
  let out = "", run = "", inClass = false;
  const flush = () => {
    if (run.length >= 24 && secretShaped(run)) for (let i = 0; i < run.length; i += 12) out += (i ? "(?:)" : "") + run.slice(i, i + 12);
    else out += run;
    run = "";
  };
  for (let i = 0; i < re.length; i++) {
    const c = re[i];
    if (c === "\\") { flush(); out += c + (re[++i] ?? ""); continue; }
    if (inClass) { out += c; if (c === "]") inClass = false; continue; }
    if (c === "[") { flush(); inClass = true; out += c; continue; }
    if (/[A-Za-z0-9_+=-]/.test(c)) { run += c; continue; }
    flush();
    out += c;
  }
  flush();
  return out;
}

const keep = (v) => v !== undefined && v !== null && v !== "" && v !== false && !(Array.isArray(v) && v.length === 0) && v !== 0;
function shape(r) {
  const o = { id: r.id };
  const put = (k, v) => { if (keep(v)) o[k] = v; };
  put("description", r.description);
  put("confidence", r.confidence);
  put("regex", r.regex && splitLiterals(r.regex));
  put("path", r.path);
  put("keywords", r.keywords);
  put("secretGroup", r.secretGroup);
  put("specificity", r.specificity);
  put("skipReport", r.skipReport);
  put("components", (r.components ?? []).map((c) => {
    const k = { id: c.id };
    if (c.within) k.within = c.within;
    if (c.optional) k.optional = true;
    return k;
  }));
  put("filter", parseFilter(r.filter, r.id));
  put("validates", Boolean(r.validate)); // the live check is not carried, only the fact that there is one
  return o;
}

const groups = new Map();
for (const r of cfg.rules) {
  const f = fileOf.get(r.id);
  if (!f) die(`no upstream generator file defines ${r.id}`);
  const stem = basename(f, ".go");
  if (!groups.has(stem)) groups.set(stem, []);
  groups.get(stem).push(shape(r));
}

mkdirSync(out, { recursive: true });
const written = new Set();
const emit = (name, obj) => {
  writeFileSync(join(out, name), JSON.stringify(obj, null, 2) + "\n");
  written.add(name);
};
for (const [stem, rules] of [...groups].sort(([a], [b]) => (a < b ? -1 : 1))) {
  rules.sort((a, b) => (a.id < b.id ? -1 : 1));
  emit(`${stem}.json`, { lineage: "betterleaks", licence: "MIT", source: `cmd/generate/config/rules/${stem}.go`, rules });
}
emit("_global.json", {
  lineage: "betterleaks",
  licence: "MIT",
  source: "config/betterleaks.toml",
  title: cfg.title,
  minVersion: cfg.minVersion,
  betterleaksMinVersion: cfg.betterleaksMinVersion,
  prefilter: parseFilter(cfg.prefilter, "(global prefilter)"),
  filter: parseFilter(cfg.filter, "(global filter)"),
});
const stale = readdirSync(out).filter((f) => f.endsWith(".json") && !written.has(f));
if (stale.length) die(`${out} holds files this run did not write: ${stale.join(", ")}; move them away`);

// ---- the examples
mkdirSync(corpus, { recursive: true });
execFileSync("go", ["run", "./scripts/rulegen/examples", "-src", src, "-out", corpus, "-commit", head], { cwd: repo, stdio: "inherit" });
const index = JSON.parse(readFileSync(join(corpus, "index.json"), "utf8"));
const none = ids.filter((id) => !index.rules[id] || index.rules[id].positives === 0);

console.log(`${ids.length} rules from ${pin.ref} (${head.slice(0, 12)}) in ${groups.size} files under ${out}`);
console.log(`examples in ${corpus}: ${ids.length - none.length} rules have at least one true positive, ${ids.filter((id) => index.rules[id]?.negatives > 0).length} at least one false positive`);
console.log(`no upstream examples for ${none.length}: ${none.join(", ")}`);
if (args.explain !== undefined) for (const [id, term] of unparsed) console.log(`residual ${id}: ${term}`);
