package pattern

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"keyguard/internal/pattern/rules"
)

// Semver is the scanner's own version. It moves when the scanner's behaviour does, apart from the rules.
const Semver = "0.2.0"

var (
	hashOnce sync.Once
	hashHex  string
)

// RulesHash is the first 12 hex digits of a digest of the whole rule table and its global filter:
// every id, regex, keyword, secret group, filter, composite link, specificity and source. A change to
// any of them changes it.
func RulesHash() string {
	hashOnce.Do(func() {
		sum := sha256.Sum256(fmt.Appendf(nil, "%#v\n%#v", rules.All, rules.Global))
		hashHex = hex.EncodeToString(sum[:])[:12]
	})
	return hashHex
}

// Version names this scanner and the rules it carries: "native/<semver>+<rules hash>". Scan progress
// and the ledger of blobs already read are keyed on it, so a change to the rules makes the next
// sweep read everything again without anyone editing a list of what depends on the rules.
func Version() string { return "native/" + Semver + "+" + RulesHash() }
