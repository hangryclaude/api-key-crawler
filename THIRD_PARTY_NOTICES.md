# Third-party notices

keyguard's detection rules are built from rules other projects publish under permissive licences.
Their notices are kept here, as those licences require. Each rule in the generated table carries
where it came from (lineage, upstream id, commit, licence) in `internal/pattern/rules/rules_gen.go`,
and the commits are pinned in `rules/SOURCES.lock`.

## betterleaks (MIT)

Source: https://github.com/betterleaks/betterleaks, release v1.9.0, commit
`81aff7a638638aae3a659845d089043e1d8fe9ac`.

Taken from it: rule ids and descriptions, regular expressions, keywords, confidence labels, secret
groups, composite-rule links, and from each rule's filter the entropy threshold, the allow-list
regular expressions and words, and the path patterns. They are in `rules/src/*.json`.

Modified for keyguard:

- stored as JSON, and compiled into a Go table (`internal/pattern/rules/rules_gen.go`), so no rule is
  parsed at start-up;
- betterleaks reads its filters with an expression language; keyguard reads the forms the rules use into
  plain fields, and counts the rest as not carried;
- a documentation key inside an allow list is replaced by its SHA-256 digest, so that the repository
  holds no key-shaped literal;
- in three regular expressions a long fixed token prefix is split by an empty group `(?:)`, and in
  two a character class that spells out an alphabet is written as ranges; neither changes what the
  expression matches;
- the live-validation recipes are not carried, only whether a rule has one.

Not taken: betterleaks's word list and its token-efficiency data. keyguard's own scorers replace them.

Behaviour studied, code not taken: the scanner in `internal/pattern` is written for keyguard. Where a
result depends on how betterleaks decides (how a secret group is cut from a match, which line a finding
is on, which finding silences another, how near a composite rule's parts must be), the scanner does what
betterleaks does, found by reading its source and checked by `internal/pattern/diff_test.go` against the
program itself. No betterleaks code is copied.

The generated Go file says it is modified for keyguard.

### Licence

MIT License

Copyright (c) 2026 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## gitleaks (MIT)

betterleaks's rule set descends from gitleaks's, so the notice of the project it descends from is kept
beside its own. Source: https://github.com/gitleaks/gitleaks. keyguard reads gitleaks only through
betterleaks, and uses it as a scanner in the benchmark; no gitleaks file is copied.

### Licence

MIT License

Copyright (c) 2019 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Not used

- TruffleHog (AGPL-3.0). Nothing of it is read, copied or adapted: no detector, regular expression,
  keyword or data file. keyguard runs the unmodified binary as a separate process and reads its
  output, and nothing else.
- Data under CC-BY-SA, no licence, or a non-OSI licence.

## keyguard's own rules

The 12 `kg-` rules in `rules/keyguard.toml` are keyguard's own and carry no third-party notice.
