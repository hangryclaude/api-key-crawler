package known

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// encode runs an encoder that is not ours (system python3, node) over stdin and returns
// stdout, so the variants are checked against what other tools actually write.
func encode(t *testing.T, tool string, args []string, in string) string {
	t.Helper()
	cmd := exec.Command(tool, args...)
	cmd.Stdin = strings.NewReader(in)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	return string(out)
}

// tricky builds values full of the characters encoders disagree about, from parts.
func tricky(r interface{ IntN(int) int }, n int) string {
	specials := []rune("\"\\/<>&+=%! #'()*$;:@?~é \t")
	var sb strings.Builder
	for sb.Len() < n {
		if r.IntN(3) == 0 {
			sb.WriteRune(specials[r.IntN(len(specials))])
		} else {
			sb.WriteByte(alnum[r.IntN(len(alnum))])
		}
	}
	return sb.String()
}

func TestJSONFormsMatchEveryRealEncoder(t *testing.T) {
	r := newRNG(t)
	py := []string{"-I", "-c", "import json,sys; sys.stdout.write(json.dumps(sys.stdin.read())[1:-1])"}
	js := []string{"-e", "let s=require('fs').readFileSync(0,'utf8'); process.stdout.write(JSON.stringify(s).slice(1,-1))"}
	checked := 0
	for i := 0; i < 20; i++ {
		raw := []byte(randFrom(r, punct, 14+r.IntN(30)) + "é/&<" + randFrom(r, alnum, 4))
		forms := map[string]bool{}
		for _, v := range variantsOf(raw) {
			forms[string(v.b)] = true
		}
		var goJSON bytes.Buffer
		enc := json.NewEncoder(&goJSON) // escapes <, > and & by default, like json.Marshal
		enc.Encode(string(raw))
		for name, got := range map[string]string{
			"go":     strings.Trim(strings.TrimSpace(goJSON.String()), `"`),
			"python": encode(t, "python3", py, string(raw)),
			"node":   encode(t, "node", js, string(raw)),
		} {
			if got != string(raw) && !forms[got] {
				t.Fatalf("value %d: the %s JSON encoding is not among the registered forms", i, name)
			}
			checked++
		}
	}
	if checked != 60 {
		t.Fatalf("checked %d", checked)
	}
}

func TestURLAndBase64FormsMatchEveryRealEncoder(t *testing.T) {
	r := newRNG(t)
	pyQuote := []string{"-I", "-c", "import sys,urllib.parse as u; sys.stdout.write(u.quote(sys.stdin.read(), safe=''))"}
	pyPlus := []string{"-I", "-c", "import sys,urllib.parse as u; sys.stdout.write(u.quote_plus(sys.stdin.read()))"}
	jsURI := []string{"-e", "process.stdout.write(encodeURIComponent(require('fs').readFileSync(0,'utf8')))"}
	pyB64 := []string{"-I", "-c", "import sys,base64; d=sys.stdin.buffer.read(); sys.stdout.write(base64.b64encode(d).decode()+'\\n'+base64.urlsafe_b64encode(d).decode()+'\\n'+base64.urlsafe_b64encode(d).decode().rstrip('='))"}
	jsB64 := []string{"-e", "const d=require('fs').readFileSync(0); process.stdout.write(d.toString('base64')+'\\n'+d.toString('base64url'))"}
	for i := 0; i < 12; i++ {
		raw := []byte(tricky(r, 16+r.IntN(30)))
		forms := map[string]bool{}
		for _, v := range variantsOf(raw) {
			forms[string(v.b)] = true
		}
		in := string(raw)
		for name, got := range map[string]string{
			"python quote":        encode(t, "python3", pyQuote, in),
			"python quote_plus":   encode(t, "python3", pyPlus, in),
			"node encodeURIComp.": encode(t, "node", jsURI, in),
		} {
			if got != in && !forms[got] {
				t.Fatalf("value %d: the %s form is not among the registered forms", i, name)
			}
		}
		for name, out := range map[string]string{"python": encode(t, "python3", pyB64, in), "node": encode(t, "node", jsB64, in)} {
			for _, got := range strings.Split(out, "\n") {
				if !forms[got] {
					t.Fatalf("value %d: a %s base64 form is not among the registered forms", i, name)
				}
			}
		}
	}
}
