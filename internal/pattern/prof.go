package pattern

import (
	"sync/atomic"
	"time"
)

// ruleProf is the profile loop's instrument: how long each rule's matcher ran, and over how many
// bytes. It is off unless a test sets Scanner.prof, and then costs two clock reads a search. It times
// what Go's regexp and the linear matcher do for a rule, which is what the profile loop sorts by;
// the share of the whole scan that is regexp, filters included, is read from a CPU profile instead.
type ruleProf struct {
	lin, regex []profCol // per rule: the linear matcher, and regexp (the rule's own, or after a fallback)
	fallbacks  []atomic.Int64
}

type profCol struct {
	ns, calls, bytes atomic.Int64
}

func newRuleProf(n int) *ruleProf {
	return &ruleProf{lin: make([]profCol, n), regex: make([]profCol, n), fallbacks: make([]atomic.Int64, n)}
}

func (p *ruleProf) add(ri int32, col *[]profCol, d time.Duration, n int) {
	c := &(*col)[ri]
	c.ns.Add(int64(d))
	c.calls.Add(1)
	c.bytes.Add(int64(n))
}
