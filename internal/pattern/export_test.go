package pattern

// SetLinBudget gives the matcher of every linear rule this budget (see lin.Prog.SetBudget), so that
// a test can make them give up and see the scan carry on with the regexp. It builds every rule.
func (s *Scanner) SetLinBudget(base, perByte int) {
	s.ensure()
	for ri := range s.table {
		rt := &s.rt[ri]
		rt.init(s, int32(ri))
		if rt.lin != nil {
			rt.lin.SetBudget(base, perByte)
		}
	}
}

// LinearRules is how many rules run on the linear matcher.
func (s *Scanner) LinearRules() (n int) {
	s.ensure()
	for ri := range s.table {
		rt := &s.rt[ri]
		rt.init(s, int32(ri))
		if rt.lin != nil {
			n++
		}
	}
	return n
}
