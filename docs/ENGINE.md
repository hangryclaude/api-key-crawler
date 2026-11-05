# The native engine

`internal/pattern` is a secret scanner in the Go standard library.
It reads bytes and a path. It reports where a rule of the table finds a secret.
It knows nothing of git, stores or fingerprints. Those come in later milestones.

This page is the state after M2 (scanner core and parity).
Rules and where they come from: [RULE-DATA.md](RULE-DATA.md).
Numbers the engine is held to: [NATIVE-BASELINE.md](NATIVE-BASELINE.md).

## Answer first

- **Parity.** On the same files with the same rules, native reports **100.00%** of what betterleaks 1.9.0 reports.
  That is 610 to 648 findings on each of four bench corpus A trees, and 170 of 170 on the 278 MB perf corpus.
  The gate is 99.5%.
- **Native reports more.** 13 to 15 more on A, 233 more on the perf corpus.
  Every one is a finding of a rule whose upstream filter has parts the table does not carry (section 4).
- **What native lacks is views.** Against betterleaks as keyguard runs it, native lacks 6.1 to 6.4% on A:
  32 findings made in decoded layers and 10 inside archives. No view exists yet.
- **Speed is not a gate yet.** 24 CPU-seconds for the perf corpus, betterleaks 15, titus 5 (section 7).
  The cause is Go's `regexp`; M3 replaces the hot rules with linear matchers.
- **A data bug surfaced.** The table gave every rule specificity 0. The real default is 100 (section 8).

## 1. How a scan works

One buffer, four steps. Files are `ac.go`, `window.go`, `anchor.go`, `scan.go`, `allow.go`, `checks.go`.

1. **Prefilter.** One Aho-Corasick DFA over the keywords of all 475 rules. It builds in a millisecond,
   once per process, on the first scan. Case folds in the byte-class map. Four lanes: 2.5 GB/s against 0.7 on one.
2. **Windows.** A keyword hit does not run a regex on the file. It opens a window around the hit.
   The window comes from the regex itself (section 2). Hits of one rule that touch are merged.
3. **Regex.** Compiled on the rule's first hit. The secret group is cut out of the match,
   then the rule's filter and the global filter decide (`allow.go`).
4. **Report.** Composite rules look for their other half. A finding of higher specificity silences a lower one
   on its line. The checks set tags. Nothing is dropped by a check.

Around that:

| piece | what |
|---|---|
| `ScanBytes(path, data)` | one buffer, returns spans, never the value |
| `ScanDir(ctx, dir, emit)` | workers, symlinks not followed, binary files skipped (NUL in the first 8 KiB) |
| tiles | a file over 16 MiB is read in tiles that share 64 KiB, a seam finds a secret once |
| `Stats.Notes()` | counts of everything skipped or cut, no paths, no values |
| `Version()` | `native/<semver>+<12 hex of the rule table>`; a rules change changes it |
| panics | a worker that panics ends the scan with an error that names the file, never the content |

A `Finding` carries `Rule`, `Path`, `Line`, the match span and the secret span, `Entropy`, `Tags`.
The value is `data[Start:End]`. Only the caller that holds `data` can read it.

## 2. Windows are read off the regex

Betterleaks runs a rule's regex over the whole 100 KB fragment once any keyword occurs in it.
That is simple and slow. A window gives the same matches if two things hold:

1. every match contains a keyword, so the hit finds it;
2. the window reaches as far as a match can: in bytes and in lines.

`anchor.go` derives both from the regex (`regexp/syntax`) and the rule's keywords, when the rule first runs.
Nothing is added to the rule data for it.

- It lists the small finite sets of strings that a regex part can match
  (`(?:sk|rk)_(?:test|live)_` is four strings) and finds a run of parts whose strings all hold a keyword.
- It bounds the bytes and the newlines a match can have before and after that run.
  `[\s'"]{0,3}` is at most 3 newlines; `[\w.-]+` is any bytes but no newline.
- A window is the bytes bound, cut at the lines bound, plus one byte of context each way.
  The byte is why `\b`, `^` and a class that eats the previous line's break behave as in the whole file.

Of the 472 rules that have a keyword:

| mode | rules | what runs |
|---|--:|---|
| anchored | 432 | a window per hit |
| gated | 40 | the whole buffer, once, when a keyword occurs (what betterleaks does) |
| no keyword | 2 | the whole buffer, always (`kg-fal-key`, `kg-discord-bot-token`) |

A rule is gated when no keyword is provably inside every match:
the keyword is only a gate (`twilio` for `SK[0-9a-f]{32}`), or one branch of an alternation has none,
or a side of the window cannot be bounded (a `\s+` between the keyword and the rest).
Gated is slower and never wrong. The 40, so that M3 can look at the ones with common keywords first:

```
airtable-personnal-access-token  alibaba-secret-key  alibaba-sts-access-key-secret  azure-client-id
azure-storage-account-key  azure-storage-account-name  azure-tenant-id  box-api-access-token
canadian-digital-service-notify-api-key  canva-client-id  curl-auth-user  facebook-access-token
fal-api-key.1  freemius-secret-key  gcp-application-default-credentials  gcp-service-account
generic-password  ibm-cloud-user-api-key  ionic-personal-access-token  jwt  jwt-base64
kg-discord-webhook-url  kubernetes-secret-yaml  miro-access-token  nuget-config-password
openai-api-key  ovh-application-key  ovh-application-secret  ovh-consumer-key  private-key
resend-api-key.1  salesforce-access-token.1  salesforce-instance-url.1  sidekiq-sensitive-url
slack-config-access-token  slack-webhook-url  snowflake-programmatic-access-token.1
tableau-personal-access-token.1  twilio-api-key  vault-service-token
```

Two limits, both counted in `Stats.Notes`:

- A run with no upper bound that cannot cross a line (a long token) is cut 4,352 bytes past the keyword.
- `(?i)` makes Go fold `K` and `s` onto the Kelvin sign and the long s. They are not counted when
  widths are measured. A secret that holds one is not a secret; the window would cut it short, nothing worse.

Two tests hold this to the exact answer.
`FuzzWindowsEqualTheWholeBuffer`: for any input under the cap, the windows and a scan with every rule gated
report the same findings.
`TestEveryRuleFindsWhatItsExamplesSay`: each of 378 rules, scanned alone over each of its 7,440 examples
(the strings betterleaks tests it with, positive and negative), reports exactly the secrets that the rule reports
over the whole text. No disagreement.

**The research prototype's 4 misses.** Its windows were the keyword's line and the next, and it missed 4 of
gitleaks's 121 findings on the perf corpus, all `generic-api-key`. A value can sit further from its name:
`api_key =` and three blank lines and then the value is one match, because the grammar allows up to
8 line breaks between a name and a value. `TestAssignmentAcrossBlankLines` is that case; a window of two lines misses it
and these windows, which allow the lines the regex allows, do not.
A one-off run with the prototype's window shape (keyword line and next, within the regex width) on this
perf corpus against betterleaks's rules missed none of the 403 findings, so those 4 were not
reproduced here. Native misses none of betterleaks's.

## 3. What is kept from betterleaks, because it decides results

| behaviour | why it is copied |
|---|---|
| the line is where the whole match starts | `(rule, path, line)` is the unit of comparison |
| line breaks are trimmed off both ends of a match before the secret is cut | the secret and its entropy depend on it |
| entropy = bits per rune, divided by the length in bytes | the floors were tuned on it; it differs from byte entropy only off ASCII |
| a group that did not take part gives an empty secret | the filters then see an empty string |
| a composite rule needs its other parts within `5L`, `10L`, `7L,200C` ... | 36 rules; `aws-access-token` is one |
| an optional part never gates, but silences a lower finding on its line | what the reference does |
| a finding of higher specificity silences a lower one on its line if its secret contains the other's | why a GitHub token is reported once |
| a rule that exists to be part of another never runs alone | else its findings would silence the rule they belong to |
| the global path list | see section 5 |

## 4. The differential

`go test ./internal/pattern -run TestDifferential -v`

Both scan a directory. The unit is the set of `(rule, path, line)`.
Betterleaks 1.9.0 runs with `rules/keyguard.toml`, decoding off and archives off.
Native runs with the whole upstream path list on for every rule, because the views do not exist yet.
Bench corpus A is the work tree at HEAD and a tree with every blob of the history, for seeds 1 and 2.
The perf corpus is 23,886 files, 278 MB, kept in the cache and never committed.

| corpus | betterleaks | native | in both | native has |
|---|--:|--:|--:|--:|
| A1 work tree | 610 | 623 | 610 | 100.00% |
| A1 every blob | 647 | 661 | 647 | 100.00% |
| A2 work tree | 612 | 625 | 612 | 100.00% |
| A2 every blob | 648 | 663 | 648 | 100.00% |
| perf (20,220 files read) | 170 | 403 | 170 | 100.00% |

**Betterleaks only: none.**

**Native only: all in three rules, all one cause.**

| corpus | native only | rules |
|---|--:|---|
| A1 work tree | 13 | generic-api-key 13 |
| A1 every blob | 14 | generic-api-key 14 |
| A2 work tree | 13 | generic-api-key 13 |
| A2 every blob | 15 | generic-api-key 15 |
| perf | 233 | generic-password 169, generic-api-key 62, generic-credential-uri 2 |

The cause: upstream filters these rules with programs the table cannot hold as data.
`Filter.Residual` counts the parts it does not carry:

| rule | residual terms | what they do |
|---|--:|---|
| generic-api-key | 52 | a word list around the match; ~48 pairs "secret has this shape and a provider's name is nearby"; two line patterns |
| generic-password | 28 | evidence in the nearby lines (a login call, a host, a comment), encrypted values, cipher names |
| generic-credential-uri | 12 | placeholder forms of the password |
| generic-username | 4 | |
| kubernetes-secret-yaml | 1 | |

`TokenRatio` (123 rules) is carried but not evaluated; betterleaks's token data is not ours.
Native tags `wordy` instead (section 6). No finding of a token-ratio rule differs on these corpora.

The test classifies every difference and fails on one it cannot name.
It also fails below 99.5%.

**As keyguard runs betterleaks** (decoding 5 deep, archives 8 deep), A1:

| | betterleaks | native has | missing |
|---|--:|--:|---|
| work tree | 652 | 610 (93.56%) | 32 decoded layer, 10 archive |
| every blob | 689 | 647 (93.90%) | 32 decoded layer, 10 archive |
| perf | 170 | 170 (100%) | none |

Those 42 are what M5 (views) is for. `TestDifferentialAsShipped` names each one by the archive separator
in its path or the `decoded:` tag, and fails on any other.

## 5. Where native differs on purpose

**Path policy** (`PathPolicy`). Betterleaks skips node_modules, vendor trees, lock files, minified libraries,
images and documents for every rule. A real key in a dependency tree is never seen.
Native applies that list to the generic rules only. Rules with a distinctive shape see every path.
Only `.git` and binary file types by extension are skipped for all.

- `PathsUpstream` applies the whole list to every rule. The differential uses it.
- `PathsNative` is the default.
- On A1 (every blob) and the perf corpus the native policy reads 3,553 more files and adds **no** finding.
  `TestPathPolicyOnlyAddsWhatItSays` holds that anything it ever adds is a non-generic rule in a skipped path.

**Whole files, not fragments.** Betterleaks cuts a file into fragments of about 100 KB at two blank lines.
Native scans whole files, in 16 MiB tiles. A match that crosses a fragment seam is found by native only.

**Binary files.** Betterleaks skips only files with certain magic numbers and scans the rest as text.
Native skips a file with a NUL in its first 8 KiB (1,374 on the perf corpus) and counts it in the notes.
No betterleaks finding was lost to it on these corpora.

**Specificity is the effective one** (section 8).

## 6. The checks

Tags are facts about a value. They never drop a finding. The names are the vocabulary the adapter maps.

| tag | meaning |
|---|---|
| `checksum-ok`, `checksum-bad` | GitHub's CRC32 tail (ghp gho ghu ghs ghr, npm); a card number's Luhn digit |
| `test-value` | a published payment test card (held as SHA-256 digests, no card number in source) |
| `uuid` | 8-4-4-4-12 hex |
| `hash-like` | all hex, a digest length, found by a generic rule |
| `templated` | `${VAR}`, `{{var}}`, `<placeholder>`, `%s`, `$VAR` |
| `sequential` | a run of the alphabet, the digits, a keyboard row, or one block repeated |
| `id-like` | the name before the value ends in id, uuid, hash, digest, checksum ... |
| `wordy` | reads like words; for generic rules and rules with a token ratio |
| `unlikely-random` | too many or too few digits for a random string of its alphabet; 1 in 1,000 |

A bad checksum keeps the finding. Entropy floors are the upstream ones, as written.
`RandomFloor` and `RejectRate` measure the floor for a given alphabet and length by seeded sampling.
`TestAFlatFloorRejectsRandomHexKeys` reproduces K8: a flat 3.5 rejects 18.9% of random 32-digit hex strings.
They are not wired to rules yet. That needs the classifier of M3, and wiring them now would move the differential.

The word scorer learns letter pairs from a short list of words in `checks.go`. It is this project's own.
On words it was not taught, 91% of two- and three-word compounds read as words and 1 in 2,000 random strings does.

## 7. Speed

`KEYGUARD_TIMING=1 go test ./internal/pattern -run TestScanSpeed -v`. Not a gate. The load average was 59 on 18 cores.

| threads | wall s | CPU s |
|--:|--:|--:|
| 2 | 18.0 | 23.9 |
| 6 | 13.8 | 25.0 |
| 18 | 4.3 | 25.2 |

254 MB read in 23,773 files. Betterleaks: 14.9 CPU-s. Titus: 5.0. The read floor: 2.9.
The prefilter is not the cost. Go's `regexp` is: 18.9 of the 24 CPU-s, 79%. M3's gate is 30%.

Where the regex time goes (a throwaway timer around every regex run, 6 workers; not kept in the code):

| rule | CPU s | share | how it runs |
|---|--:|--:|---|
| kg-discord-bot-token | 3.9 | 20.5% | no keyword: every byte of every file |
| generic-api-key | 3.6 | 18.9% | windows: 61,842 runs over 44 MB |
| kg-fal-key | 3.2 | 16.9% | no keyword: every byte of every file |
| azure-storage-account-key | 2.3 | 12.4% | gated on "storage": 1,049 whole files, 91 MB |
| generic-password | 2.0 | 10.6% | gated: 462 whole files, 54 MB |
| ibm-cloud-user-api-key | 0.8 | 4.1% | gated on "ibm" |
| box-api-access-token | 0.5 | 2.6% | gated |
| generic-username | 0.5 | 2.4% | a part of generic-password, searched near it |
| generic-credential-uri | 0.4 | 2.2% | windows |
| ovh-application-secret | 0.4 | 2.1% | gated |
| curl-auth-user, jwt | 0.3 each | 1.8%, 1.7% | gated |

Start-up, for the hooks (S3 asks for 3 ms): the first scan in a fresh process costs 2.4 to 4.2 ms of CPU on this loaded
Mac. The prefilter is 1.0 to 1.8 ms of it, the global filter 0.2, and a rule's regex is compiled when it first wakes
(0.3 to 1.5 ms for `generic-api-key`). Every later scan of a small buffer is 24 to 34 µs.

The two rules with no keyword are 37% of it, the gated rules about another 37%, `generic-api-key` 19%.
That is the list M3 starts from: shapes for the two `kg-` rules, a better anchor or a matcher for the gated
ones with common keywords, and the assignment matcher for `generic-api-key`.

## 8. A bug in the rule data, found by the first scan

Betterleaks gives a rule that sets no specificity the value 100.
Five set one: `generic-api-key` 0, `generic-password` 20, `generic-credential-uri` 30,
`gitlab-incoming-mail-address-token` 50, `monday-api-token.1` 110.
The extractor dropped the explicit 0 as an empty value and the generator left the rest at Go's 0.
Every rule tied with `generic-api-key`, so a GitHub token was reported twice.
`extract.mjs` now keeps a numeric specificity, `rulegen` reads an absent one as 100 and always writes it.

## 9. Fuzzing, races, and the repo's own scan

| check | command | result |
|---|---|---|
| fuzz the scan | `go test ./internal/pattern -run '^$' -fuzz FuzzScan -fuzztime 60s` | 796,976 runs, no failure |
| fuzz windows against the whole buffer | `... -fuzz FuzzWindowsEqualTheWholeBuffer` | 1,351,705 runs, no failure |
| fuzz the prefilter against a naive search | `... -fuzz FuzzAutomaton` | 1,649,600 runs, no failure |
| races | `go test -race ./internal/pattern/...` | clean; the whole scanner package took 609 s, and its unit tests (without the corpus differentials) were run again at the last commit, 297 s |
| no secret-shaped literal | `go test ./internal/testkit` | passes with the new code |

The first automaton run did fail, on `"\xcfuser"`: the test's own oracle lower-cased with `strings.ToLower`,
which rewrites a byte that is not UTF-8 and moves every offset after it. The oracle folds ASCII now, and the
input is a seed.

`FuzzScan` checks: no panic, under 5 seconds, allocation under 2 MiB + 400 bytes per input byte,
spans inside the data, the line is the line of the match start, findings in order and unique, no rule reports on its own
that is only a part, and a second scan agrees with the first.

## 10. Not done in M2

- The residual filter parts of five rules (section 4). M3 and M4 replace those rules with matchers and tiers.
- Views: decoding, archives, UTF-16, git text. M5.
- The linear matchers and the speed gates. M3.
- Corpus C (natural code, 1 GB) is not downloaded; the perf corpus stands in for it.
- Git, the adapter, triage. M6.
