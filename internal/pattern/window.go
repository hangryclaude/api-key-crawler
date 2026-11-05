package pattern

import "bytes"

// Windows. A keyword hit says a rule may match nearby; the window is the stretch of the buffer the
// rule's regex is run over, sized by anchor.go from what the regex can cover around a keyword.
// Windows of one rule that touch are merged, so a dense file is scanned once, not once per hit.
//
// The regex sees one byte of context on each side of the stretch it must find matches in, so that
// \b, ^ and a class that consumes the character before a token (the line break that ends the
// previous line, say) behave as they would in the whole file. That byte is why a window begins at
// the line before and ends at the line after, not at the line itself.

const (
	// unboundedCap stands for "as far as the line goes" when a regex has no upper bound on a run of
	// characters that cannot cross a line: a token longer than this is cut at it. Cutting is noted.
	unboundedCap = 4096 + 256
	// mergeCap bounds a merged window, so one rule cannot turn a megabyte of dense hits into one regex run
	// whose cost no test could predict.
	mergeCap = 256 << 10
)

// windowOf returns the stretch around a keyword hit data[hs:he] that a match containing the hit must
// lie in, and whether a cap rather than the regex's own bounds is what ended it.
func windowOf(data []byte, hs, he int, a anchor) (lo, hi int, capped bool) {
	// After the hit the match is bounded by bytes and by lines; the stretch ends at the nearer. The
	// line bound is the newline that ends the line a.after.lines below the hit's own.
	limit := len(data)
	capAfter := false
	if a.after.bytes >= 0 {
		limit = min(limit, hs+a.after.bytes)
	} else if hs+unboundedCap < len(data) {
		limit, capAfter = hs+unboundedCap, true
	}
	limit = max(limit, he)
	hi = limit
	if a.after.lines >= 0 {
		p := he
		for need := a.after.lines + 1; need > 0; need-- {
			j := bytes.IndexByte(data[p:limit], '\n')
			if j < 0 {
				break
			}
			if need == 1 {
				hi, capAfter = p+j, false // the line ended before the cap did
				break
			}
			p += j + 1
		}
	}

	// Before the hit, the same.
	floor := 0
	capBefore := false
	if a.before.bytes >= 0 {
		floor = max(0, hs-a.before.bytes)
	} else if hs > unboundedCap {
		floor, capBefore = hs-unboundedCap, true
	}
	lo = floor
	if a.before.lines >= 0 {
		p := hs
		for need := a.before.lines + 1; need > 0; need-- {
			j := bytes.LastIndexByte(data[floor:p], '\n')
			if j < 0 {
				break
			}
			if need == 1 {
				lo, capBefore = floor+j+1, false
				break
			}
			p = floor + j
		}
	}

	// One byte of context each way.
	return max(0, lo-1), min(len(data), hi+1), capAfter || capBefore
}
