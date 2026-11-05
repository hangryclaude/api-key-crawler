// Package bench measures keyguard's scanners. It holds three corpora (docs/STEAL.md P0-23) and the
// arithmetic that turns what the scanners report on them into figures that mean something
// (P0-24, P0-25, P0-26).
//
// Corpus A, the planted one. Generate builds a git repo in a temp dir: about 900 commits of neutral
// filler, over 80 provider formats planted in 42 places and encodings, each at least in six where
// an engine's rules reach it, and lookalikes that must not alert. Every random choice comes from
// the seed, so a seed is a corpus: commit ids, values and fingerprints repeat exactly. Score runs
// engines (and optionally the known-secret matcher) over it and compares what they report with
// truth.json.
//
// Corpus B, the oracle. ScoreOracle runs the known-secret matcher over every object of the
// mirrors, which finds real leaks of the user's own keys with no label to write, and scores each regex
// engine on how many of them it reports. Every secret none of them reports is a rule to write.
//
// Corpus C, natural code. LoadNatural and ScoreNatural count what the engines raise on public code
// with nothing planted in it: false alerts per megabyte and per line. That, with the recall
// measured elsewhere, is what decides the precision where secrets are rare.
//
// Every corpus is split in two by Half, a frozen function of a name (a format, a repo, a file):
// rules and triage are fitted to the misses of the tune half and judged on the held-out half. The
// reports (results.md, oracle.md) list the tune half's misses and only count the held-out half's;
// the JSON is complete, for machines.
//
// Wiring, which needs the bench keyring before the engines exist:
//
//	kr := bench.KeyringFor(seed)            // engines and the matcher fingerprint with this
//	c, _ := bench.Generate(dir, bench.Options{Seed: seed})
//	m := ...                                // a known matcher built from c.Secrets(); raw values stay in memory
//	res, _ := bench.Score(ctx, engines, m, dir)
//
// A plant is a value at a place: provider, variant (env, py, b64, zip, deleted, tag, pull, mcp, har,
// utf16, commit-msg, rename...), ref, commit, path, line. Its fingerprint is the HMAC of the raw
// value under the bench keyring; alt_fps are the other extents of the same credential an engine may
// report instead (a service account's private key, a database URL's host:port form, a decoded
// copy). The unit of scoring is the distinct fingerprint. A hit is a true positive when its
// fingerprint is any of them, or when it sits alone on the plant's line and is long enough to
// cover min(len, 12) characters of it (span containment); the rule id plays no part, and the type
// is scored apart. A hit that matches no plant is scored by what it sits on: a lookalike (fp:
// negative), a plant's own line under another fingerprint (fp: extent), or nothing (fp: other).
//
// Twins (P0-26). Beside a valid plant of most formats, in the same file, sit invalid twins: the
// same format with one thing wrong that the format's own rules refuse (two characters short, an
// entropy under the rule's floor, a checksum that does not match). They are negatives, and an
// engine that reports one has a pattern that is too loose.
//
// "Detectable by design" is a claim about regexes, made by simulating the engine's own rule on the
// file as planted: its keyword prefilter, pattern, secret group and entropy gate, the components a
// composite rule needs, the engines' percent- and base64-decoding, and betterleaks' path
// prefilter. It is computed from an embedded copy of the rules that a test compares with the
// installed binary. Formats and places no rule covers are marked undetected (a UTF-16 file, a .tgz
// or .jar, a typed recording, a commit message, a branch name), and the bench reports whether the
// engines found them anyway. The measured scores then test the claim: betterleaks recall over the
// plants its own rules cover is expected to be 100%.
//
// The gate (GateOf, P0-25): a recall figure is worth stating only with at least 300 detectable
// plants over at least 40 formats with at least 6 placements each. With no miss that proves 98% at
// 95% confidence from 189 plants, and with one from 280; every row carries its Wilson interval.
//
// Invariants: no raw value is written outside the corpus repo (truth.json and the results hold
// fingerprints, shapes and plant ids), and none appears as a literal in this package's source:
// fakes are assembled at run time from a prefix and random characters.
package bench
