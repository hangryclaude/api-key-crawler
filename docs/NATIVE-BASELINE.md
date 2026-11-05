# Native engine baseline

Frozen on 2026-11-04 from the tree at its first public release (`ff479e8`), before any native-engine code.
These are the numbers the native engine is held to.
Everything below was measured on this Mac. Where a set could not be built, section 8 says so.

## 1. Answer first

- **Accuracy reruns to the digit.** Bench seeds 1 and 2, with and without `rules/keyguard.toml`, the production tier, the dev-tool set: every cell equals the research run.
- **The research set moves by chance.** It draws fresh fakes each run. Six runs: 83.8 to 84.2% with the extra rules, 67.5 to 68.1% without.
- **Timings are indicative only.** The Mac was at load 28 to 52 on 18 cores. The plan judges nothing above load 6. Order and ratios held; single numbers moved up to 19%.
- **Not built here:** corpus B (needs the owner's learned store, which this stage must not create), C and D (need downloads). Section 8.
- **One measurement the research did not have:** noise on 278 MB of public code, per engine and per rule (section 7). It is not corpus C.

## 2. What was measured

| item | value |
|---|---|
| machine | Apple M5 Max, 18 CPUs, 48 GiB, macOS 27.0.1 |
| load at start of the run | 29.0 (1-minute average, read before and after every step) |
| keyguard | built from `ff479e8` |
| Go | 1.26.5 |
| rules file | `rules/keyguard.toml`, 12 `kg-` rules, on unless a table says "without" |

The engines, as `sha256` prefix of the binary. A later stage can check it measures the same ones.

| engine | version | binary |
|---|---|---|
| betterleaks | 1.9.0 | `6f3197b51794` |
| gitleaks | 8.30.1 | `ba52fb1bfabb` |
| trufflehog | 3.99.8 | `a50a9195d35b` |
| titus | 1.2.10 | `1501333f62be` |

Every keyguard run had its own `KEYGUARD_HOME` and `TMPDIR`. Nothing touched the real data root.

## 3. Bench corpus A, seeds 1 and 2

Shipped state: rules file on. Recall is over the plants marked detectable by design.
Recall of all counts every positive plant. Brackets are Wilson 95% intervals, in percent.
Precision is true-positive fingerprints over distinct reported ones.

### Seed 1: 922 commits, 714 plants, 549 detectable, 227 negatives

| engine | recall of the 549 detectable | recall of all 714 | precision | false hits (negative / extent / other) |
|---|--:|--:|--:|--:|
| betterleaks 1.9.0 | 99.8 [99.0-100.0] (548) | 83.3 [80.4-85.9] (595) | 97.2 [95.7-98.2] | 15 / 1 / 2 |
| gitleaks 8.30.1 | 89.8 [87.0-92.1] (493) | 76.6 [73.4-79.6] (547) | 96.0 [94.1-97.3] | 22 / 0 / 1 |
| trufflehog 3.99.8 | 70.7 [66.7-74.3] (388) | 60.5 [56.9-64.0] (432) | 89.2 [86.2-91.7] | 46 / 0 / 7 |
| titus 1.2.10 | 76.5 [72.8-79.9] (420) | 66.5 [63.0-69.9] (475) | 90.9 [88.2-93.0] | 33 / 0 / 16 |
| known matcher | 98.7 [97.4-99.4] (542) | 97.3 [95.9-98.3] (695) | 100.0 [99.5-100.0] | 0 / 0 / 0 |
| union of the four | 100.0 [99.3-100.0] (549) | 91.5 [89.2-93.3] (653) | 89.0 [86.7-90.9] | 67 / 1 / 25 |
| pipeline (4 engines + known + triage) | 100.0 [99.3-100.0] (549) | 98.7 [97.6-99.3] (705) | 95.2 [93.5-96.4] | 17 / 1 / 25 |

Load 29.0 to 28.0. One run each, wall seconds: betterleaks 0.55, gitleaks 0.52, trufflehog 0.89, titus 3.26 (first run, rule cache cold), pipeline 3.27.

### Seed 2: 934 commits, 714 plants, 547 detectable, 227 negatives

| engine | recall of the 547 detectable | recall of all 714 | precision | false hits (negative / extent / other) |
|---|--:|--:|--:|--:|
| betterleaks 1.9.0 | 99.8 [99.0-100.0] (546) | 83.2 [80.3-85.8] (594) | 97.1 [95.5-98.1] | 16 / 1 / 2 |
| gitleaks 8.30.1 | 89.6 [86.7-91.9] (490) | 76.3 [73.1-79.3] (545) | 95.7 [93.7-97.0] | 23 / 0 / 2 |
| trufflehog 3.99.8 | 70.6 [66.6-74.2] (386) | 60.2 [56.6-63.8] (430) | 89.4 [86.4-91.8] | 46 / 0 / 6 |
| titus 1.2.10 | 76.8 [73.1-80.1] (420) | 66.8 [63.3-70.2] (477) | 90.4 [87.7-92.6] | 33 / 0 / 19 |
| known matcher | 98.7 [97.4-99.4] (540) | 97.3 [95.9-98.3] (695) | 100.0 [99.5-100.0] | 0 / 0 / 0 |
| union of the four | 100.0 [99.3-100.0] (547) | 91.6 [89.3-93.4] (654) | 88.8 [86.5-90.7] | 68 / 1 / 27 |
| pipeline | 100.0 [99.3-100.0] (547) | 98.7 [97.6-99.3] (705) | 95.0 [93.3-96.2] | 17 / 1 / 27 |

Load 28.0 to 28.7. Wall seconds: betterleaks 0.43, gitleaks 0.51, trufflehog 0.83, titus 0.25, pipeline 0.83.

### Production tier: betterleaks, gitleaks, trufflehog, known matcher, triage

| | recall of detectable | recall of all 714 | precision | false hits |
|---|--:|--:|--:|--:|
| seed 1 pipeline | 100.0 (549) | 98.7 [97.6-99.3] (705) | 97.2 [95.9-98.2] | 13 / 1 / 9 |
| seed 2 pipeline | 100.0 (547) | 98.7 [97.6-99.3] (705) | 97.3 [95.9-98.2] | 13 / 1 / 9 |

Load 28.4 to 29.1. Pipeline wall seconds: 1.17 (seed 1), 0.90 (seed 2).

### Without `rules/keyguard.toml`: the run the README table comes from

| engine | seed 1 recall of all | seed 1 precision | seed 2 recall of all | seed 2 precision |
|---|--:|--:|--:|--:|
| betterleaks | 79.7 [76.6-82.5] | 97.3 | 79.4 [76.3-82.2] | 97.1 |
| gitleaks | 73.7 [70.3-76.8] | 96.4 | 73.2 [69.9-76.4] | 96.0 |
| trufflehog | 60.5 [56.9-64.0] | 89.2 | 60.2 [56.6-63.8] | 89.4 |
| titus | 66.5 [63.0-69.9] | 90.9 | 66.8 [63.3-70.2] | 90.4 |
| union | 90.9 [88.6-92.8] | 89.0 | 91.0 [88.7-92.9] | 88.8 |
| pipeline | 98.7 [97.6-99.3] | 95.3 | 98.7 [97.6-99.3] | 95.1 |

The README is not edited by this stage. Its table is this one: the bench passes the rules file only
when `<root>/rules/keyguard.toml` exists, and the README run had none. With the file, betterleaks gains
3.6 points of recall of all and gitleaks 2.9.

## 4. History speed (gate S1): `bench --speed 5`, seed 1, rules on

One cold run, then four warm. Per repo of 922 commits and 11.8 MB, not per MB.

| engine | cold s | warm s (median) | min-max s | CPU s | peak RSS MB |
|---|--:|--:|--:|--:|--:|
| betterleaks 1.9.0 | 0.45 | 0.46 | 0.45-0.46 | 0.82 | 127 |
| gitleaks 8.30.1 | 0.52 | 0.53 | 0.52-0.54 | 0.82 | 135 |
| trufflehog 3.99.8 | 0.84 | 0.84 | 0.82-0.85 | 1.16 | 364 |
| titus 1.2.10 | 0.27 | 0.25 | 0.25-0.27 | 0.33 | 104 |

Load 28.2 to 27.6. The gate: wall 0.15 s, CPU 0.2 s and 100 MB, each or less. The 0.15 s is half of titus's 0.30 s in the research run;
this session measured titus at 0.25 s, so half of it is 0.125 s.

## 5. Directory speed (gate S2): the perf corpus

23,884 files, 278.3 MB of public code: the Go source tree, four Kubernetes and x/tools modules,
four npm packages and the dependency tree of one more. `scripts/perf/manifest.json` names each
release and its commit. `scripts/perf/corpus.py verify` checks a corpus against it.
The corpus these timings ran on has two files more (23,886, 278,323,600 bytes): small local cache
files that belong to no public release. `corpus.py build` leaves them out, and they change no timing.

Five rounds, every engine once per round in the same order, then the floor.
Wall is the median, with the range in brackets. Engines run in directory mode with their default flags.

| run | wall s | CPU s | peak RSS MB | MB/s | findings | load |
|---|--:|--:|--:|--:|--:|--:|
| gitleaks | 5.68 [5.60-5.91] | 72.0 | 130 | 49 | 121 | 28-37 |
| betterleaks | 3.34 [3.03-3.40] | 14.9 | 168 | 83 | 172 | 28-37 |
| trufflehog | 3.23 [3.15-3.41] | 26.6 | 512 | 86 | 59 to 61 | 28-36 |
| titus (rule cache warm) | 0.57 [0.50-0.61] | 5.0 | 228 | 488 | 166 | 28-38 |
| **read floor F** | **0.31 [0.24-0.49]** | 2.9 | 77 | 898 | | 28-38 |

Variants, three rounds each:

| run | wall s | CPU s | peak RSS MB | findings | load |
|---|--:|--:|--:|--:|--:|
| gitleaks, decode depth 0 (what keyguard passes) | 2.01 | 13.3 | 130 | 121 | 37-40 |
| betterleaks, decode depth 0 | 2.57 | 13.8 | 164 | 170 | 37-39 |
| betterleaks, stdlib regex engine | 4.30 | 41.0 | 157 | 172 | 37-52 |

The floor is `scripts/perf/floor`: walk the corpus and read every file once, nothing else.

**S2 from this session:** fastest engine W = 0.57 s (titus), floor F = 0.31 s.
The gate asks for at most (W + F) / 2 = **0.44 s**. The literal 2x of W is 0.285 s, which is under the floor, so it cannot be tested here.
The research session had W = 0.62 s and F = 0.385 s, which gave 0.50 s. Re-derive it in the session that judges.

## 6. The research set and the dev-tool set

### Research set (gate R3): 139 one-fake files per draw

A file counts as found when the engine reports anything in it. Fresh fakes each run.

`multi_draw.py`, betterleaks alone, six draws (834 files), six runs:

| | files found | share |
|---|--:|--:|
| defaults | 563 to 568 of 834 | 67.5 to 68.1% |
| with `rules/keyguard.toml` | 699 to 702 of 834 | 83.8 to 84.2% |

`multi_union.py`, all four engines, three draws:

| draw | betterleaks | +kg rules | gitleaks | +kg rules | trufflehog | titus | union with kg rules | found by none |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| 0 | 94 | 117 | 84 | 105 | 63 | 96 | 125 | 14 |
| 1 | 92 | 116 | 80 | 102 | 61 | 96 | 125 | 14 |
| 2 | 95 | 117 | 85 | 105 | 61 | 96 | 125 | 14 |
| total of 417 | 281 (67.4%) | 350 (83.9%) | 249 (59.7%) | 312 (74.8%) | 185 (44.4%) | 288 (69.1%) | 375 (89.9%) | 42 |

The union with the kg rules is 125 of 139 in every draw: 14 files in each draw are found by no engine.
Load 29.1 for `multi_draw.py` and 29.1 to 28.4 for `multi_union.py`.

### Dev-tool set (gate R4): 57 values in 36 files

| engine | found of 57 |
|---|--:|
| betterleaks | 46 |
| gitleaks | 45 |
| trufflehog | 32 |
| titus | 44 |
| union | 51 |

The same with and without the rules file. Found by none: an `x-api-key` and a session cookie in a
HAR, the `wp-config.php` salt, a session cookie and a JWT in a browser state file, a cookie in `cookies.txt`.
Load 28.4 to 28.2. Fakes are drawn fresh each run; the counts did not move.

## 7. Noise on public code (not corpus C)

Corpus C is 1 GB or more of public code. What was available is the 278 MB perf corpus, so this is a smaller stand-in.
The same findings as the table in section 5, counted per rule. Nothing in this code is meant to be a secret,
so each finding is a doubtful one, or a test key in a test directory. The engines scan different bytes (section 5), so compare rules, not totals.

| engine | findings | per MB | top rules |
|---|--:|--:|---|
| betterleaks | 172 | 0.62 | generic-api-key 66, generic-password 40, generic-credential-uri 35, private-key 17, square-access-token 12, jwt 2 |
| gitleaks | 121 | 0.43 | generic-api-key 90, private-key 17, square-access-token 12, jwt 2 |
| trufflehog | 59 | 0.21 | URI 25, PrivateKey 12, Parsers 12, MongoDB 8 |
| titus | 166 | 0.60 | np.generic.1 67, np.generic.5 24, np.pem.1 14, kingfisher.privkey.2 14, np.netrc.1 9 |

The plan's per-rule budget is 5 hits per GB, which is 1.4 hits on this corpus.
Each of the generic rules here is far over it. The native engine starts from that.

## 8. Not built here

| set | needs | status |
|---|---|---|
| **B** (oracle) | the owner's learned store and real mirrors, scored with the known matcher as the label | Not run. This stage must not create a learned store, and there is none to read. |
| **C** (natural) | 1 GB or more of public code, downloaded | Not run. Section 7 is a smaller stand-in. |
| **D** (CredData subset) | a download, never committed | Not run. |
| S3 (hook latency) | a quiet machine, and the selftest | Not measured. It needs load under 6. |
| P3 (hook-grade lookalikes) | the hook policy over 126 lookalikes | Not measured. 9 block, from the research run. |

No number for these sets appears anywhere in this file.

## 9. Do the reruns match the research?

The check: within 0.3 points on accuracy, within 10% on time, or an explanation.

| cell | research | rerun | verdict |
|---|---|---|---|
| bench seed 1, all four engines and the pipeline | section 3 | same in every cell | match |
| bench seed 2 | section 3 | same in every cell | match |
| README run (no rules file) | 79.7 / 73.7 / 60.5, pipeline 98.7 / 95.3 | same | match |
| production pipeline, seed 1 | 98.7 / 97.2 | 98.7 / 97.2 | match |
| dev-tool set | 46 / 45 / 32 / 44, union 51 | same | match |
| one-draw union with kg rules | 125 of 139 | 125, 125, 125 | match |
| one draw, betterleaks / +kg / gitleaks / +kg / trufflehog / titus | 94 / 117 / 83 / 104 / 61 / 96 | 94 / 117 / 84 / 105 / 63 / 96 | within 2 files; the draws are random |
| `multi_draw.py` defaults / +kg | 67.5% / 83.8% | 67.5-68.1% / 83.8-84.2% | up to 0.6 and 0.4 points. Fresh fakes each run: six runs span that range, and one equals the research figure (563, 699). |
| speed warm s: betterleaks, gitleaks, trufflehog, titus | 0.49, 0.60, 1.04, 0.30 | 0.46, 0.53, 0.84, 0.25 | -6%, -12%, -19%, -17%: explained below |
| speed peak RSS MB | 132, 133, 367, 101 | 127, 135, 364, 104 | within 4% |
| speed CPU s | 0.86, 0.86, 1.32, 0.37 | 0.82, 0.82, 1.16, 0.33 | -5%, -5%, -12%, -11% |
| perf wall s: gitleaks, betterleaks, trufflehog, titus | 5.64, 2.99, 3.21, 0.62 | 5.68, 3.34, 3.23, 0.57 | +1%, +12%, +1%, -8% |
| perf CPU s | 65.0, 14.5, 26.3, 5.5 | 72.0, 14.9, 26.6, 5.0 | +11%, +3%, +1%, -9% |
| perf variants wall s | 1.99, 2.50, 4.08 | 2.01, 2.57, 4.30 | +1%, +3%, +5% |
| perf floor F | 0.385 | 0.31 | -19% |
| perf findings | 121, 172, 61, 166 | 121, 172, 59 to 61, 166 | trufflehog varies by two between runs |

The differences over 10% are all on a shared machine at load 28 to 52, from single runs or medians of five.
The research session ran at load 22 to 46. A 10% band cannot be held at that load, and the plan does not judge timings above 6.
Betterleaks' five perf rounds span 3.03 to 3.40 s, so 12% above the research median is inside its own spread.
The speed rows are 6 to 19% faster than the research in every engine. No cause was isolated: both sessions ran on a
shared machine at load 26 to 29, and the bench takes one warm run of each engine. The order of the engines and the
ratios between them held.

## 10. Rerun it

```
go build -o /path/to/keyguard ./cmd/keyguard
python3 -I scripts/perf/corpus.py verify                  # or build, to recreate the corpus
python3 -I scripts/perf/baseline.py --keyguard /path/to/keyguard --out NEW_DIR
```

`baseline.py` runs sections 3 to 7 in about three minutes and keeps every raw output under `NEW_DIR`,
with the load before and after each step in `steps.json`. `--only bench,speed,research,devtool,perf` picks steps.
Bench seed N with the native stub: `keyguard bench --seed N --engines native` reports the engine as not built yet.

## 11. For the next stage

- `keyguard bench --engines native` is a stub. It exits 3 with "not built yet" when native is alone, and lists a skipped `native` row beside other engines. Delete `cmd/keyguard/bench_native.go` and its three call sites when the engine registers.
- Titus compiles its rules on first use (about 2.7 s). Time it with a warm cache.
- Trufflehog's finding count on the perf corpus is 59 to 61 between runs.
- The decisive gate numbers to beat: R1 549 of 549; R2a 693 or more of 714 alone; R3 130 of 139 per draw; R4 54 of 57; S1 0.15 s wall; S2 as section 5 re-derives it.
