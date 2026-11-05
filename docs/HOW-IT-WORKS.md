# How keyguard works

keyguard has five layers and a small data model.\
This page explains both in plain words.

The code is the source of truth.\
Where this page and the code differ, the code wins.

<p align="center"><picture>
<source media="(max-width: 600px)" srcset="assets/layers-narrow.svg">
<img src="assets/layers.svg" width="100%"
alt="The path of a key: keyboard, commit, push, GitHub. Seven gates stand along
it, and each is shown with a masked API key. L1 is three git hooks: pre-commit
and pre-push, which --no-verify skips, and reference-transaction, which ignores
it. L2 is the AI agent guard, which blocks the commands that would let a key
through. L3 is GitHub scanning and L5 the publish check; both block a key. L4
is the watcher, which finds a key that is already on GitHub. A magenta tag marks
the gates that ignore --no-verify.">
</picture></p>

## Contents

- [The path of a key](#the-path-of-a-key)
- [L1: git hooks](#l1-git-hooks)
- [L2: the agent guard](#l2-the-agent-guard)
- [L3: GitHub's own protections](#l3-githubs-own-protections)
- [L4: the watcher](#l4-the-watcher)
- [L5: the publish check](#l5-the-publish-check)
- [The data model](#the-data-model)

## The path of a key

A key can reach GitHub in many ways.\
keyguard puts a gate on three of them:\
you commit it, you push it, or you make a repo public.

Then it scans GitHub for anything the gates missed.

| Layer | What it is |
|---|---|
| L1 | three git hooks on your Mac |
| L2 | a guard for AI agents in Claude Code |
| L3 | GitHub's own secret scanning and push protection |
| L4 | a watcher that scans your public repos |
| L5 | a check before a repo goes public |

## L1: git hooks

Three hooks live in your global git config, not in each repo.\
They run in every repo on your Mac.

They run next to a repo's own hooks.\
That includes the `core.hooksPath` that tools such as husky set.\
It was tested on 2026-11-03.

git must be 2.54 or newer.\
It is the first version that runs hooks from config.

Each hook is a one-line shell wrapper around `keyguard hook <name>`.\
If the binary is missing, the wrapper exits 0 and git goes on.\
`keyguard doctor` reports a missing binary as a failure.

| Hook | Runs when | Looks at |
|---|---|---|
| `pre-commit` | before git makes a commit | names and added lines you staged |
| `pre-push` | before git sends commits | every new commit in the push |
| `reference-transaction` | when git updates a ref | new commits on a branch or tag |

### pre-commit

Three checks run.\
The pattern engine starts first.\
It runs while keyguard does the other two.

1. File names.
2. Learned keys, in every line you added.
3. Key patterns, in the staged diff. betterleaks does this one.

Names are matched in lower case, because macOS ignores case.\
These names block on their own:

- `.env` and `.env.*`
- `id_rsa`, `id_dsa`, `id_ecdsa` and `id_ed25519`
- `.git-credentials` and `.netrc`
- anything ending in `.p12`, `.pfx`, `.jks`, `.keystore` or `.tfstate`

These block only if the staged file holds a key:

- `.pem` and `.key` files, if they hold a private key
- `.npmrc`, if it sets a token to a literal value
- `.pypirc`, if it sets a password to a literal value
- `credentials.json` and service-account files, if they hold a `private_key`

`.env.example`, `.env.sample`, `.env.template`, `.env.dist` and `.env.defaults` do not block by name.\
Their lines are still scanned.

During a merge, a finding on an inherited line is dropped.\
A line is inherited if it came unchanged from the other side.\
Only lines new to both parents count.

An inline allow comment, such as `gitleaks:allow`, silences the pattern check on that line.\
It does not silence the learned-key check.

### pre-push

keyguard reads every commit in the push that the remote lacks.\
Three checks run side by side:

1. Learned keys, in every added line.
2. Key patterns, from betterleaks.
3. A live check, from trufflehog, for some remotes.

A learned key or a pattern hit blocks the push.\
The live check blocks only a key that the provider says still works.

The live check runs when the remote is public, a secret gist or unknown.

An unknown remote counts as public.\
That covers a repo made a minute ago, which is not in the saved repo list yet.\
It also covers any host other than GitHub.

This hook catches a commit made with `--no-verify`, if you push without the flag.\
It also catches rebases and cherry-picks.

### reference-transaction

git runs this hook each time it updates a ref.\
A commit, a branch, a tag, a merge and a rebase all do.\
`--no-verify` does not skip it.

Only the `prepared` phase can still stop the update.\
The other phases exit at once.

The hook looks at branches and tags that point at a new commit.\
A commit is new if no old value, branch, tag or remote reaches it.

It checks learned keys only.\
So it has no false positives.\
A gate that `--no-verify` cannot skip must never block by mistake.

A person can still switch it off for one command.\
`git -c hook.keyguard-reftx.enabled=false commit --no-verify` goes through.\
So does any git run with `GIT_CONFIG_GLOBAL=/dev/null`, which hides every global hook.\
The agent guard blocks both, in Claude Code only.

It leaves some things alone:

- bare repos and keyguard's own mirror cache
- history that arrives by fetch or clone
- commits past the newest 2,000

For fetched history that holds a learned key, it allows the update and prints a note.\
Past the cap, it prints a note too.\
`pre-push` and the poll cover those commits.

### What a block looks like

A block prints to stderr and exits with code 1.\
The first line names the hook and the count:\
`keyguard: commit blocked: 1 finding`.\
The other titles are `push blocked` and `ref update blocked`.

Then comes a table with the columns `FILE`, `LINE`, `TYPE`, `SECRET` and `WHY`.\
Findings in history add a `COMMIT` column.\
The table stops at 25 rows.

The `SECRET` column shows a shape and nothing more.\
Each `WHY` ends with an id such as `kg1a2b3c`.

Below the table, the message gives the fix.\
Move the value to a gitignored `.env`.\
Read it from the environment.

It also warns against `--no-verify`.\
For a false positive, it names `keyguard allow <id>`.

keyguard records each block in `state/blocked.jsonl`.\
That file holds ids, shapes and places, never a key.\
It lets `keyguard allow <id>` find a block that no sweep has seen.

### Fail open, block closed

A keyguard bug must never break git.\
So an internal error, a timeout or a missing engine only warns.\
git goes on.

A confirmed finding blocks.

| Hook | Time limit |
|---|---|
| `pre-commit` | 30 s |
| `pre-push` | 2 min |
| `reference-transaction` | 20 s |

## L2: the agent guard

`keyguard guard claude` is a Claude Code `PreToolUse` hook.\
It reads each shell command before Claude Code runs it.

Exit code 2 blocks the command and shows the reason to the agent.\
Exit code 0 lets it run.

It reads a command the way a shell does.\
It looks inside `;`, `&&`, `||`, pipes, `bash -c` and `$(...)`.\
It also looks through `env`, `sudo` and `xargs` wrappers and here-documents.

Text that only mentions a command, such as an `echo`, does not count.

It blocks these:

- `git commit --no-verify`, and `-n`, also inside a group like `-anm`
- `git push --no-verify`
- `git -c` settings for `core.hooksPath`, `core.bare`, include paths and `hook.*`
- `git config` edits to those same keys (reads are fine)
- `HOME`, `XDG_CONFIG_HOME` or `GIT_CONFIG_*` set for a commit or push, which hides the global hooks

It holds a public publish until `keyguard publish-check` passes:

- `gh repo create --public` with a source folder or a template
- `gh repo edit --visibility public`
- `gh api` calls that set `private=false` or `visibility=public`

The check gets 120 s.\
If it finds keys, or cannot run, the command is blocked.

It also reserves some keyguard commands for you.\
They let a finding through, or take protection away:

- `keyguard allow` (but `allow --list` is fine)
- `keyguard known forget`
- `keyguard learn --prune`
- `keyguard uninstall` (a dry run is fine)
- `keyguard import-triage` (a dry run is fine)

The message the agent sees starts with `BLOCKED by keyguard:` and gives the reason.\
For a false positive, it tells the agent to give you the id.

The guard allows anything it cannot read.\
A guard that blocks real work gets switched off.\
A switched-off guard protects nothing.\
The layers behind it still apply.

It follows an alias only on the same command line.\
It blocks `git -c alias.ci='commit -n' ci`.\
It lets through `git config alias.ci 'commit --no-verify'` in one command and `git ci` in the next.\
It also lets through a script that runs git itself,\
such as `subprocess.run(['git', 'commit', '--no-verify'])`.

It checks the Bash tool only.\
Writes, edits and MCP calls are not checked.\
Other agents are not covered.

You register the guard yourself.\
`keyguard install` prints one line that starts with `!`.\
Run it inside Claude Code.

The line needs `jq`.\
It edits `~/.claude/settings.json`, and keeps a dated backup first.\
`keyguard doctor` warns if the guard is not registered.

## L3: GitHub's own protections

`keyguard github-settings` checks four GitHub features on every repo:

- secret scanning
- push protection
- non-provider patterns
- validity checks

`--apply` tries to switch them on for every public repo.\
GitHub may refuse the optional ones on some plans.\
The command prints each refusal and GitHub's reason.

It also tries to switch secret scanning on for one private repo.\
That tells keyguard whether your plan allows it.\
If it does, that repo keeps it, and GitHub may charge for that.

`--apply` is the only command that changes anything on GitHub.

The command also imports GitHub's open alerts as hits.\
Each alert's secret is hashed, then dropped.

GitHub offers these features free on public repos only.\
One switch, "push protection for yourself", has no API.\
keyguard prints the link, and you set it by hand.

## L4: the watcher

`install` loads two launchd jobs.\
They run at low priority.

| Job | Runs | Does |
|---|---|---|
| `poll` | every 600 s | scans what changed on GitHub |
| `deep` | Sundays 03:30 | rescans everything |

### poll

The poll asks GitHub what changed since last time.\
It sends one GraphQL request per token.\
It sends one events request per account.\
The events request costs nothing when nothing changed.

It then fetches only the changed sources into bare mirrors.\
For each one, it scans only the new commits.\
It uses every engine in the poll tier, with live checks on.\
It also looks for learned keys in those commits.

When you learn a new key, the next poll searches every public repo's full history for it.

A private repo that turns public is scanned in full at once.\
The run notes say so.

Then the poll merges the findings, triages them and rewrites the report.

A new finding of high severity gets a macOS banner.\
A critical one also gets an iMessage, if you set a phone number or email in `notify.imessage_to`.\
An alert names an id, a shape and a place.\
It never holds a key.

Once a day the poll runs the selftest and the doctor.\
It alerts you if a layer broke.

A lock file stops two runs from overlapping.\
A poll that finds the lock held skips that run.

### deep

The deep job runs every Sunday.\
It relearns your keys and imports GitHub's alerts.

It rescans every public source in full.\
It uses every engine, with live checks.

When betterleaks says the provider rejects a key, keyguard marks it dead and drops it to info.\
That is how a rotated key leaves the list.

### What it does not scan yet

The sweep has a place for issues, pull requests, comments, releases and Actions logs.\
No scanner is wired into it yet.\
When such events show up, the run notes say they were not scanned.

## L5: the publish check

`keyguard publish-check <owner/name | path>` scans a repo's whole history, every ref,\
as if it were already public.\
It runs every engine with live checks, unless you pass `--no-verify`.\
That flag is keyguard's, not git's.

With live checks on, a key that the provider rejects is not a finding.\
So a repo can come back clean while it still holds a revoked key.\
`--no-verify` turns the live checks off and lists every match.

Exit code 0 means clean.\
Exit code 1 means findings, listed by id and shape, never shown.\
Any other code means the check could not finish.

It honors your ignore list.\
It writes no findings and no source state, because the repo is not public yet.

The agent guard runs this check before a public publish.\
You can run it yourself before you flip a repo to public.

## The data model

| Term | Meaning |
|---|---|
| hit | one detection by one engine, with its fingerprint made |
| secret | one distinct key, with every place it was seen |
| fingerprint | a keyed hash of the key |
| id | `kg` plus the first six hex digits of the fingerprint |
| shape | a safe display form of the key |
| location | where a hit was seen |

By the time a hit exists, the raw key is already gone.\
A hit holds the fingerprint, the shape, the length and the rule that fired.

It also holds the place.\
It holds a line of context too, with the key replaced by its shape.

Hits from many engines and places fold into one secret.\
The fingerprint decides which.

A secret holds every location and the provider's verdict.\
It also holds a triage label, a severity and a status.

### Fingerprints

keyguard never stores a key.\
It stores a fingerprint.

The fingerprint is a keyed hash (HMAC) of the key, cut to 32 hex characters.\
The secret that keys the hash is a random salt kept on your Mac.

The salt is 40 random bytes in `~/.keyguard/state/known/salt`.\
Only you can read it (mode 0600).

32 bytes key the hash.\
8 bytes seed the rolling hash that the matcher uses.

Without the salt, nobody can turn a fingerprint back into a key.\
Nobody can test a guess against it either.

The same key gives the same fingerprint in every engine and run.\
That is how keyguard merges hits and matches keys.

### Shapes

A shape is what keyguard may show.\
It is the public prefix of a key, then `…`, then at most four trailing characters.\
A private key block shows as `-----BEGIN…KEY-----`.

| Shape | Looks like |
|---|---|
| `ghp_…9f3K` | a GitHub token |
| `AKIA…Q7XZ` | an AWS access key id |
| `sk-ant-api03-…a1B2` | an Anthropic key |

A short key shows fewer trailing characters, or none.

Block messages, reports, alerts and `keyguard known list` show shapes.\
Error text goes through a scrubber that masks random-looking tokens.

### Severity

Severity says how urgent a secret is.\
A secret is exposed when a stranger can read where it sits.

A public repo, a wiki or a secret gist is exposed.\
So is a place whose visibility is unknown.

| Severity | When |
|---|---|
| critical | the key works, or you learned it, and it is exposed |
| high | the key works, or you learned it, and the place is private |
| medium | not checked, judged real, and exposed |
| low | not checked, judged real, private; or a test, or unreviewed |
| info | dead, resolved, placeholder, false positive, public by design or ignored |

A Google API key that is public by design counts as low, not info.\
It is often meant to ship, but an unrestricted one can still bill you.

Triage sets the label.\
It trusts these, in order:

1. your ignore list
2. the provider's verdict (a live key beats every "not real" label)
3. a key you learned from your Mac
4. an earlier reviewer's label
5. the rules

The rules call a hit not real when:

- it matches a placeholder or a value from public documentation
- its last characters look fake
- it has 16 characters or more, and its entropy is below 2.5 bits a character
- the line around it says placeholder
- it is a test or a fixture
- the key is public by design, such as a Stripe `pk_live_` key

### Learning keys

`keyguard learn` reads the secrets already on your Mac.\
It keeps only keyed hashes of them.

It reads these places:

- `.env` files under `~/dev`, `~/projects`, `~/Tools` and `~/sec`, and `~/.env*`
- shell files such as `.zshrc` and `.bashrc`
- launchd plists in `~/Library/LaunchAgents`
- credential files such as `~/.npmrc`, `~/.netrc`, `~/.pypirc`, `~/.aws/credentials`, `~/.docker/config.json` and `~/.kube/config`
- agent config files such as `~/.claude.json`
- files under `~/.config` up to 256 KB
- SSH private key bodies
- the `gh` tokens of two fixed accounts, and the environment of the shell that runs `learn`

A value becomes a learned key if it passes two tests.\
The name test:\
the name holds `KEY`, `TOKEN`, `SECRET`, `PASS` or a similar word,\
or an engine flags the value.

The value test: at least 12 characters, enough entropy, and not a placeholder, plain URL, path or number.

Entropy measures how random a value looks.\
It must be 3.0 bits per character or more.\
For values of 32 characters or more, 2.5 is enough.

Card numbers count too.\
That means 13 to 19 digits that pass the Luhn checksum.

Keys that are public by design are skipped.\
Pass `--keep-public` to learn them too.

keyguard stores each learned key in several forms:\
raw, base64, base64url, URL-encoded and JSON-escaped.\
It also finds a key inside a larger base64 blob, such as a basic-auth header.

Each form gets a record.\
The record holds an id, a name, a source, a length, a shape,\
two fingerprints and a hash of the form's last 12 bytes.\
It never holds the key.

### Finding keys

The matcher slides a 12-byte window over the content.\
A rolling hash moves it one byte at a time.\
That takes one multiply, one add and one table lookup per byte.

The end of a real key is random.\
Its start is often a public prefix such as `sk-ant-api03-`.\
So the matcher indexes the last 12 bytes of each form.

A bit set rejects almost every window at once.\
An exact lookup follows.\
Then keyguard takes the keyed hash of the candidate bytes and compares it.

Only a full match counts.\
So the matcher has no false positives.

In the benchmark it scans **1,696 MB/s** on one core.\
See [BENCHMARKS.md](BENCHMARKS.md).

The matcher runs in four places:

| Place | What it reads |
|---|---|
| `pre-commit` | the lines you added |
| `pre-push` | the lines in the commits you push |
| `reference-transaction` | the lines in new commits |
| the sweep | every blob in a mirror, binary files included |

The sweep skips blobs over 50 MiB and says how many it skipped.\
It reads each blob as raw bytes.\
It does not open archives yet.

The pattern engines are another matter.\
In a test on 2026-11-04, a key inside a committed binary file was found by trufflehog.\
betterleaks and gitleaks did not report it.\
So a key in a binary file is caught only if it is a learned key, or if trufflehog is installed.

This pass reads added lines in the hooks, and blobs in the sweep.\
It does not read commit messages or tag text.

### Where files live

Everything is under `~/.keyguard`.

| Path | Holds |
|---|---|
| `bin/keyguard` | the installed binary; the hooks run it |
| `rules/keyguard.toml` | extra rules for the pattern engines |
| `state/config.json` | accounts, orgs, engine paths, tiers |
| `state/install.json` | what `install` changed, so `uninstall` can undo it |
| `state/known/` | the salt and `known.json` (learned hashes) |
| `state/findings.json` | every secret, deduplicated by fingerprint |
| `state/ignore.json` | fingerprints you marked as false positives |
| `state/blocked.jsonl` | recent blocks, as ids, shapes and places |
| `state/inventory.json` | the last repo list, with visibility |
| `state/sources/` | per-source scan records |
| `state/runs/` | one stats file per run |
| `state/selftest.json` | the last full selftest |
| `cache/mirrors/` | bare mirrors of the sources |
| `report/index.html` | the dashboard |
| `logs/` | launchd output; ids and counts only |
| `.uninstalled/` | what `uninstall` moved aside |

The mirrors are plain git clones of your public repos.\
They hold whatever those repos hold.

### Rules for the code

Every package and every test must follow these:

1. No raw key leaves process memory.\
   Not to disk, logs, reports, alerts or error text.
2. No key-like string sits in the source or the tests.\
   Tests build fakes at run time from a prefix and random characters.
3. Tests never touch real state.\
   They use temp dirs and a temp git config.
4. Environment variables can only add protection.\
   Hooks always load `~/.keyguard`.\
   `KEYGUARD_HOME` adds a second learned store.\
   It replaces nothing.
5. Hooks fail open on keyguard's own errors and block on findings.
6. Mirror operations switch keyguard's own hooks off.\
   Otherwise a fetch of a leaked key would be blocked, and the sweep would never see it.
7. keyguard uses the Go standard library only.\
   It runs `git`, `gh` and the engines as separate programs.

## Where the numbers on this page come from

Each value below comes from the code.\
It was read with `rg` and `sed` on 2026-11-03.\
The last column names the file.

| Value | Number | File |
|---|---|---|
| poll interval | 600 s | `internal/install/launchd.go` |
| deep scan | Sunday 03:30 | `internal/install/launchd.go` |
| hook time limits | 30 s, 2 min, 20 s | `internal/hooks/hooks.go` |
| ref commit cap | 2,000 | `internal/hooks/hooks.go` |
| block message rows | 25 | `internal/hooks/report.go` |
| guard publish-check limit | 120 s | `internal/guard/guard.go` |
| matcher window, shortest learned value | 12 bytes | `internal/known/known.go` |
| salt, fingerprint, id | 40 bytes, 32 hex, 6 hex | `internal/fp/fp.go` |
| entropy floor | 3.0 (2.5 from 32 characters) | `internal/known/filters.go` |
| card number length | 13 to 19 digits | `internal/known/filters.go` |
| "fake" entropy rule | 2.5 bits, keys of 16 characters or more | `internal/triage/rules.go` |
| config file cap for `learn` | 256 KB | `internal/known/harvest.go` |
| sweep blob cap | 50 MiB | `internal/sweep/blobs.go` |
