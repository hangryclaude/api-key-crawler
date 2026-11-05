# Rule data

Where the native engine's rules come from, how the table is made, and how to refresh it.
The table has 475 rules: 463 of betterleaks v1.9.0 and the 12 `kg-` rules of `rules/keyguard.toml`.

## The files

| file | what | made by |
|---|---|---|
| `rules/SOURCES.lock` | the pin: repo, tag, commit, licence of each source | by hand |
| `rules/src/*.json` | betterleaks's rules as data, one file per upstream generator file, no examples | `scripts/rulegen/extract.mjs` (Bun) |
| `rules/keyguard.toml` | the 12 rules of our own | by hand |
| `internal/pattern/rules/rules_gen.go` | the table, as Go source | `internal/pattern/rulegen` |
| `internal/pattern/rules/testdata/fidelity.golden.json` | one digest per rule of what it does with its upstream examples | `rulegen -golden` |
| `THIRD_PARTY_NOTICES.md` | the notices the licences ask for | by hand |
| `~/.cache/keyguard-dev/rulecorpus/` | the upstream examples: made-up secrets in test lines | `scripts/rulegen/extract.mjs`, never committed |

Nothing at build or test time needs Bun, a network or a clone: the JSON and the Go table are committed.
`go.mod` has no `require` line and there is no `go.sum`.

## Refreshing

```
git clone --depth 1 --branch TAG URL ~/.cache/keyguard-dev/upstream/betterleaks   # then pin the commit in rules/SOURCES.lock
bun scripts/rulegen/extract.mjs                       # rules/src/*.json and the example cache
go run ./internal/pattern/rulegen -golden             # rules_gen.go and the fidelity golden
go test ./internal/pattern/... ./internal/testkit     # the checks below, and the repo's scan for key-shaped literals
```

`extract.mjs` refuses a checkout that is not at the pinned commit or has local changes.
`rulegen -check` fails if `rules_gen.go` is not what the data produces; a test runs it.

## What a rule carries

`ID`, `Provider` (the first word of the id), `Desc`, `Keywords` (lower case), `Re` (RE2), `Group` (the secret group),
`Path`, `Confidence`, `Specificity`, `ComponentOnly`, `Needs` (composite rules), `Validates`, a `Filter`, and `Src`:
lineage, upstream id, commit, licence and how the regex differs from upstream's (`none`, or `split`).

The `Filter` is what betterleaks discards after the regex matched. `extract.mjs` reads the forms the rules use
into fields: an entropy floor (and whether a value exactly on it is kept), a token ratio, patterns and words
the secret must not match, patterns it must match, and paths to skip. Anything it cannot read is counted in
`Residual`. Of the 463 rules, 458 are read completely. Five keep a residual: `generic-api-key` (52 terms:
checks for provider test keys), `generic-password`, `generic-username`, `generic-credential-uri` and
`kubernetes-secret-yaml`. `TokenRatio` is carried as data and not evaluated; betterleaks's token-efficiency
data is not ours.

Not carried: the Expr source of the filters, and the live-validation recipes (only `Validates`).

## No key-shaped literal

The repository may hold none (invariant 2), and the data would otherwise: upstream's allow lists name
documentation keys, and the examples are keys inside test lines.

- A documentation key in a filter becomes its SHA-256 (`DropSHA256`).
- Five rules have a regex written differently from upstream's, with the same meaning (`Rewrite: "split"`): in three, a long fixed
  token prefix is split by an empty group `(?:)`; in two, a character class that spells out an alphabet is written as ranges.
- The examples stay in the cache. The golden holds hashes of hashes and counts.

## The checks (`go test ./internal/pattern/...`)

| test | says |
|---|---|
| `TestEveryRuleCompiles` | 475 of 475 rules compile in Go's `regexp`, as they are |
| `TestIDsAreBetterleaksOwnList` | the ids are what `betterleaks config show` lists for the defaults plus `keyguard.toml` |
| `TestFidelityDigest` | 458 of 458 rules that have upstream examples (8,398 of them) match their digest, and each one's true positives fire and false positives do not |
| `TestTheTableAgreesWithBetterleaksOnTheExamples` | the real betterleaks, run over the same examples, agrees on 7,382 of 7,440; the table alone fires on 58 (rules with a filter part it does not carry), betterleaks alone on none |
| `TestOwnRulesAgreeWithBetterleaksOnRunTimeFakes` | the 12 `kg-` rules, which have no upstream examples, agree with betterleaks on values built at run time |
| `TestLintRefusesTruffleHogAndUnknownLicences` | the lint refuses TruffleHog as a lineage, AGPL, and any licence or lineage not on the list |
| `TestBuildNeedsNothingFromTheNetwork` | `go build ./...` works with the proxy off, no `require` line and an empty `go.sum`; every package built is the standard library or this module |
| `internal/testkit` `TestTheRepoPasses*` | neither betterleaks nor trufflehog finds a key-shaped literal in `rules_gen.go` or `rules/src` |
| `internal/engines` `TestSourceHoldsNoSecretShapes` | all four engines, trufflehog with its dictionary filter off, find nothing in `rules/`, except that trufflehog may take two rule ids of 20 to 22 characters for GitLab tokens; the test skips a trufflehog finding on a line of `rules/src` that is nothing but an `"id"` entry |

The tests that need the example cache skip without it, and fail when `KEYGUARD_TEST_REQUIRE_ENGINES=1`.

Rules with no upstream examples: five of betterleaks's (two Dropbox, two Slack and one GitLab rule, which upstream returns
untested) and the 12 of ours. `jwt-base64` has false positives only: its true positives are built in a loop the extractor
does not evaluate.

## The licence wall

`rules.CheckSource` and `rules.Lint` (`internal/pattern/rules/provenance.go`) allow the lineages betterleaks, gitleaks, titus, noseyparker,
kingfisher, veles, detect-secrets and own, each with its licence (MIT, Apache-2.0, own), and CC-BY-4.0 for facts.
TruffleHog is AGPL-3.0 and is not on the list: nothing of its detectors, patterns, keywords or data enters the
repository. `rulegen` runs the lint and refuses to write a table that fails it.
