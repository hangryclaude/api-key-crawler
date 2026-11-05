# Benchmarks

These numbers sit behind the charts in the [README](../README.md).\
They were measured on 2026-11-03, on one Mac.

The plants are synthetic.\
Real-repo numbers come later.\
The raw numbers are in [assets/numbers.json](assets/numbers.json).

## Summary

| Measure | Result |
|---|---|
| `pre-commit`, median | **38.8 ms**, budget 150 ms |
| `reference-transaction`, median | 19.2 ms, budget 40 ms |
| learned-key matcher | 1,696 MB/s on one core |
| 17 public repos, full history | 3.21 s |
| three engines, recall over all 321 plants | 93.8% |
| keyguard pipeline, precision | 98.3% |

MB/s means megabytes per second.

## Machine and software

| Item | Value |
|---|---|
| Machine | Apple M5 Max, 18 cores |
| macOS | 26 (the timings of 2026-11-03) |
| macOS, accuracy re-run | 27.0.1 (2026-11-04) |
| git | 2.55.0 |
| betterleaks | 1.9.0 (MIT) |
| gitleaks | 8.30.1 (MIT) |
| trufflehog | 3.99.8 (AGPL-3.0, a separate binary) |
| titus | 1.2.10 (Apache-2.0) |

The bench scored betterleaks, gitleaks and trufflehog.\
titus took no part.\
It is in no default tier.

## 1. Hook speed

### Method

The test is `TestPerfBudgets` in `internal/hooks`.

```sh
go test ./internal/hooks -run TestPerfBudgets -v
```

For each hook it does 3 warm-up runs, then 20 timed runs.\
It uses a temp repo with one small commit.

It starts each hook the way git does.\
That is through the shell wrapper that `install` writes.

- `pre-commit` sees one small clean file, staged.
- `reference-transaction` sees one new commit in the `prepared` phase.

If the first attempt is over budget, it measures once more.\
It keeps the faster median for each hook.

It enforces the budgets only on an idle Mac.\
When the load average is above the core count, it logs the timings and does not fail.

### Results

| Hook | Median | p95 | Budget |
|---|---|---|---|
| `pre-commit`, with betterleaks | **38.8 ms** | 40.2 ms | 150 ms |
| `reference-transaction` | 19.2 ms | 21 ms | 40 ms |
| `pre-commit`, pattern engine off | 16.2 ms | not recorded | none |

The last row calls the binary directly, without the shell wrapper.\
Compare it with the first row only as a rough guide.

### A whole commit

| Measure | Time |
|---|---|
| `git commit` with the hooks | 112 to 116 ms |
| `git commit` without the hooks | 22 ms |

git runs `reference-transaction` 7 times per commit.\
Only one call does work.\
Each call still starts a shell and the keyguard binary.

The count is from 2026-11-04, with git 2.55.0.\
A logging hook in a temp repo saw 7 calls for a first commit, a second commit and an amend:\
2 `preparing`, 2 `prepared`, 2 `committed` and 1 `aborted`.\
Only the `prepared` call for the branch passes keyguard's filter.

## 2. The learned-key matcher

### Speed

The benchmark is `BenchmarkMatch` in `internal/known`.

```sh
go test ./internal/known -run '^$' -bench Match
```

It scans 64 megabytes of random content on one core.\
The matcher holds 1,000 registered forms.\
A learned key has several forms, so that is fewer than 1,000 keys.

The content holds no key.\
The benchmark fails on any match.\
It runs once on a text buffer and once on a binary buffer.\
The figure recorded on 2026-11-03 is **1,696 MB/s**.\
That record does not say which buffer it came from.

A re-run on 2026-11-04 read 1,315 MB/s on the text buffer and 1,327 MB/s on the binary buffer.\
The Mac was busy then, with a load average of about 30 on 18 cores.\
Read the figure as "about 1.3 to 1.7 GB/s".\
The matcher uses one core, and 64 MB here means 64 MiB.

### Recall

The test in `internal/known` is the one whose name starts `TestRecall500`.\
Run it with `go test ./internal/known -run TestRecall500 -v`.\
It registers 500 values.\
It plants each one in four forms: raw, base64, base64url and URL-encoded.

Each copy sits in random content of up to about 60 kilobytes.\
Some copies sit at the very start or the very end.

The matcher must find each copy once, at the right offset.\
It must report the right id, name and shape.\
It found **2,000 of 2,000**.

### False positives

None, by design.\
The matcher confirms every candidate with a keyed hash (HMAC) of the exact bytes.\
It only knows keys that were learned from this Mac.

## 3. Accuracy bench

### Method

`keyguard bench` builds a synthetic git repo in a temp dir.\
The same seed builds the same repo.\
These numbers use seed 1.\
The counts below are from the run of 2026-11-04.

```sh
keyguard bench --seed 1
```

| Item | Value |
|---|---|
| Commits | 655 |
| Refs | 31 |
| Key formats | 83 |
| Plants | 321 |
| Covered plants | 281 |
| Lookalikes that must not alert | 126 |

Each fake key is a provider prefix plus random characters.\
The bench plants them in 21 kinds of place and encoding.

Examples are config and source files, notebooks and a minified bundle.\
Others are base64 copies, a zip, a file deleted in a later commit, a tag and a pull ref.

The lookalikes include example keys and lockfile hashes.\
They also include UUIDs, base64 images, public keys,\
the jwt.io sample token and keys that are public by design.

The engines run without live checks.\
Each engine scans the whole history, every ref.

### Definitions

- Recall is the share of plants found.\
  It is counted over the 281 covered plants and over all 321.
- A plant is covered when the bench's model of a scanner's rules says it matches as planted.\
  The code calls this "detectable by design".\
  The model holds the betterleaks rules and one trufflehog rule, `zerobounce`.\
  It has no model of the gitleaks or titus rules.
- Precision is the share of reports that match a real plant.\
  A report is one distinct fingerprint.\
  Lookalikes, other parts of a credential and noise count against it.
- The pipeline is the engines, the learned-key matcher and the real triage rules.\
  A hit that triage puts below low severity is not an alert.

The bench builds the model of the rules itself.\
So a high score on covered plants is expected.\
The score over all 321 plants is the stricter view.

### Results

| Engine | 281 covered plants | All 321 plants |
|---|---|---|
| betterleaks 1.9.0 | 100% | 90.3% |
| gitleaks 8.30.1 | 87.5% | 82.2% |
| trufflehog 3.99.8 | 68.7% | 61.1% |
| all three engines | 100% | 93.8% |
| keyguard pipeline | 100% | 100% |

| Engine | Precision | Scan time |
|---|---|---|
| betterleaks 1.9.0 | 96% | 0.46 s |
| gitleaks 8.30.1 | 95% | 0.37 s |
| trufflehog 3.99.8 | 100% | 0.83 s |
| all three engines | 96.2% | not recorded |
| keyguard pipeline | **98.3%** | 0.83 s |

The pipeline time is the three engines side by side.\
The slowest engine, trufflehog, sets it.

Recall and precision are from `keyguard bench --seed 1`, run on 2026-11-04 on the shipped tree.

The scan times are from 2026-11-03.\
The run of 2026-11-04, on the busy Mac, read 0.61 s, 0.43 s and 0.72 s for the three engines,\
and 0.73 s for the pipeline.

### Read the pipeline row with care

In the bench, the learned-key matcher is told every planted key.\
It acts as if you had learned all 321 from your Mac.\
So the pipeline's 100% over all plants is the best case.

A key keyguard has not learned depends on the engines.\
For that case, read the row for all three engines.\
It finds 100% of the covered plants and 93.8% of all plants.

### Engines and rules

The bench passes keyguard's installed rules file to the engines.\
It does this only if the file exists.

That file is a copy of `rules/keyguard.toml`.\
It holds no rules of its own yet, so it only extends the defaults.

titus is not in the default tiers.\
`DefaultTiers` in `internal/install/config.go` says why.\
It reports pieces of keys that another engine reports whole.

## 4. Research set

This is a separate research run, on 834 plants.

| Rules | Recall |
|---|---|
| betterleaks defaults | 68.7% |
| with keyguard's extra rules | **84.1%** |

The extra rules had 0 false hits on 1.2 gigabytes of real Rust and JavaScript code.

This run used a scratch rules file.\
The shipped `rules/keyguard.toml` does not hold those rules yet.\
Until it does, the engines run on their own default rules.

## 5. Scans of real accounts

betterleaks over bare mirrors, all refs, run on 2026-11-03.

| Scan | Time | Workers |
|---|---|---|
| 17 public repos, full history | 3.21 s | 8 |
| 469 repos and gists | 196 s | 6 |

These runs measure time only.\
They have no answer key, so they say nothing about recall.

The second run was a one-off probe.\
The sweep scans public repos, their wikis and secret gists only.

## 6. Tests

`go test ./... -count=1 -json` ran on 2026-11-04, over the 22 packages that have tests:

| Count | Result |
|---|---|
| tests | **1,106** |
| subtests | 1,449 |
| failed | 0 |
| skipped | 0 |

`go test -list '.*' ./...` lists 1,096 test functions and 10 fuzz targets.\
The seed cases of a fuzz target run as tests, so 1,096 + 10 = 1,106.\
The repo has 24 packages: 22 with tests and 2 without.

## What these numbers do not show

- Recall on real repos.\
  The plants are synthetic.
- How well live checks work.\
  The bench runs none, and its keys are fake.
- Speed on another Mac, or on Linux.
- Times for the weekly deep scan.

## Run it yourself

```sh
keyguard bench --seed 1
go test ./internal/hooks -run TestPerfBudgets -v
go test ./internal/known -run '^$' -bench Match
```

`keyguard bench` writes `results.json` and `results.md`.\
By default they go to `~/.keyguard/state/bench/<time>`.\
Pass `--out DIR` to choose another place.

## Redraw the images

`render_assets.py` draws five images, and `render_hero.py` draws three.\
Their numbers come from [assets/numbers.json](assets/numbers.json).\
Change a number there and run the script again.\
Bars, budget boxes and callouts move together.

```sh
python3 scripts/render_assets.py
python3 scripts/render_hero.py --png
```

| Script | Writes |
|---|---|
| `render_assets.py` | `layers.svg`, `layers-narrow.svg`, `speed.svg`, `accuracy.svg`, `terminal.svg` |
| `render_hero.py` | `hero.svg`, `hero-narrow.svg`, `social-card.svg` |
| `render_hero.py --png` | also `social-card.png`, with headless Chrome |

Both scripts use only the Python standard library.\
The same input gives the same files, byte for byte.

`social-card.png` is the repo's social preview.\
Upload it by hand in the repo's Settings.
