package pattern

import (
	"bytes"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"keyguard/internal/pattern/rules"
)

// Fuzzing the scan. Three targets, each run for a minute at the milestone's exit:
//
//	go test ./internal/pattern -run '^$' -fuzz FuzzScan -fuzztime 60s
//
// FuzzScan holds the scan to its own invariants on any input: it does not panic, it does not take
// long or allocate without bound, and what it reports is a well-formed set of spans on the lines it says.
// FuzzWindowsEqualTheWholeBuffer holds the windows to the exact answer, which is to run each rule over
// the whole buffer when its keyword occurs. FuzzAutomaton holds the prefilter to a naive search.

// seeds are inputs the fuzzer starts from: the shapes the rules look for, built here from parts.
func seeds() [][]byte {
	f := newFakes(99)
	return [][]byte{
		[]byte("token = \"" + f.githubPAT() + "\"\n"),
		[]byte("api_key =\n\n\n  " + f.run(alnum, 30) + "\n"),
		[]byte("AWS_ACCESS_KEY_ID=" + f.awsKeyID() + "\nAWS_SECRET_ACCESS_KEY=" + f.awsSecret() + "\n"),
		[]byte("db_password = \"" + f.run(alnum, 14) + "\"\nusername: bob\n"),
		[]byte("DATABASE_URL=postgres://app:" + f.run(alnum, 18) + "@db.example.net:5432/app?sslmode=require\n"),
		// the markers are written in pieces so that this file does not hold a whole key block
		[]byte("-----BEGIN RSA " + "PRIVATE " + "KEY-----\n" + f.run(alnum+"+/", 64) + "\n" + f.run(alnum+"+/", 64) + "\n-----END RSA " + "PRIVATE " + "KEY-----\n"),
		[]byte("\n\n\r\n\t key : \"" + strings.Repeat("a", 40) + "\" \n"),
		[]byte("secret\n= \n\"" + f.run(alnum, 24) + "\""),
		[]byte("{\"token\":\"" + f.run(alnum, 32) + "\",\"user\":\"x\"}"),
		[]byte(strings.Repeat("key=value;token=value\n", 40)),
		[]byte("\x00\x01\x02 api_key=\xff\xfe\xfd"),
		[]byte(""),
	}
}

var wholeScanner = func() *Scanner {
	s := New(rules.All, rules.Global, Options{Paths: PathsUpstream})
	s.wholeFile = true
	return s
}()

var windowScanner = New(rules.All, rules.Global, Options{Paths: PathsUpstream})

// warm builds everything a scanner builds lazily, so that a measurement of one scan does not include
// the cost of the first one.
func warm(s *Scanner) *Scanner {
	s.ensure()
	for i := range s.table {
		s.rt[i].init(s, int32(i))
	}
	s.putWork(s.getWork())
	return s
}

func FuzzScan(f *testing.F) {
	warm(Default())
	for _, s := range seeds() {
		f.Add("src/app.py", s)
	}
	f.Add("keys/a.p12", []byte("x"))
	f.Add("node_modules/a/b.js", seeds()[0])
	f.Fuzz(func(t *testing.T, path string, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		got := Default().ScanBytes(path, data)
		took := time.Since(start)
		runtime.ReadMemStats(&after)

		if took > 5*time.Second {
			t.Fatalf("%d bytes took %v", len(data), took)
		}
		// Memory: the scan may keep a few arrays the size of the rule table and work in proportion
		// to its input, never in proportion to anything else.
		if alloc := after.TotalAlloc - before.TotalAlloc; alloc > uint64(2<<20)+400*uint64(len(data)) {
			t.Fatalf("%d bytes allocated %d", len(data), alloc)
		}

		lines := func(off int) int { return 1 + bytes.Count(data[:off], []byte{'\n'}) }
		seen := map[string]bool{}
		prev := -1
		for _, fd := range got {
			if fd.Rule == nil {
				t.Fatal("a finding with no rule")
			}
			if fd.Rule.Re == "" { // a rule about a path
				if fd.Line != 0 || fd.Start != 0 || fd.End != 0 {
					t.Fatalf("path-only finding with a span: %+v", fd)
				}
				continue
			}
			if fd.MatchStart < 0 || fd.MatchStart > fd.MatchEnd || fd.MatchEnd > len(data) {
				t.Fatalf("match span %d..%d in %d bytes", fd.MatchStart, fd.MatchEnd, len(data))
			}
			if fd.Start < fd.MatchStart || fd.Start > fd.End || fd.End > fd.MatchEnd {
				t.Fatalf("secret span %d..%d outside match %d..%d", fd.Start, fd.End, fd.MatchStart, fd.MatchEnd)
			}
			if fd.Line != lines(fd.MatchStart) {
				t.Fatalf("line %d, want %d", fd.Line, lines(fd.MatchStart))
			}
			if fd.MatchStart < prev {
				t.Fatal("findings are not in order")
			}
			prev = fd.MatchStart
			key := fmt.Sprint(fd.Rule.ID, fd.MatchStart)
			if seen[key] {
				t.Fatalf("%s reported twice at %d", fd.Rule.ID, fd.MatchStart)
			}
			seen[key] = true
			if fd.Rule.ComponentOnly {
				t.Fatalf("%s reported on its own", fd.Rule.ID)
			}
		}
		again := Default().ScanBytes(path, data)
		if len(again) != len(got) {
			t.Fatalf("a second scan found %d, the first %d", len(again), len(got))
		}
	})
}

// key reduces a finding to what two scans must agree on.
func key(fd Finding) string {
	return fmt.Sprint(fd.Rule.ID, " ", fd.Line, " ", fd.MatchStart, " ", fd.Start, " ", fd.End)
}

func keys(fs []Finding) []string {
	var out []string
	for _, fd := range fs {
		out = append(out, key(fd))
	}
	slices.Sort(out)
	return out
}

func FuzzWindowsEqualTheWholeBuffer(f *testing.F) {
	for _, s := range seeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		// Inputs under the cap that cuts a token short, where the windows promise the exact answer.
		if len(data) > unboundedCap {
			t.Skip()
		}
		w := keys(windowScanner.ScanBytes("a/b.txt", data))
		e := keys(wholeScanner.ScanBytes("a/b.txt", data))
		if !slices.Equal(w, e) {
			t.Fatalf("windows found %v, the whole buffer %v", w, e)
		}
	})
}

func FuzzAutomaton(f *testing.F) {
	pre := newPrefilter(rules.All)
	for _, s := range seeds() {
		f.Add(s)
	}
	f.Add(bytes.Repeat([]byte("Key"), 2000))
	f.Add([]byte("\xcfuser")) // bytes that are not UTF-8 move every offset after them in a naive lower-casing
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 32<<10 {
			t.Skip()
		}
		want := naiveHits(data, pre.pats)
		for _, lanes := range []int{1, 4} {
			got := sortedHits(pre.m.scanLanes(data, nil, lanes))
			if !slices.Equal(got, want) {
				t.Fatalf("%d lanes found %d hits, a naive search %d", lanes, len(got), len(want))
			}
		}
	})
}
