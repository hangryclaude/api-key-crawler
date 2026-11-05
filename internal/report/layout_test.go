package report

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func findChrome() string {
	for _, p := range []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	for _, n := range []string{"google-chrome", "chromium", "chromium-browser"} {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

// harness frames the report in an iframe of the width under test, opens every <details>,
// and writes what the browser laid out into the DOM for --dump-dom to print. An iframe
// gives an exact narrow viewport; headless Chrome will not make a window under 500 px.
const harness = `<!doctype html><meta charset="utf-8"><body style="margin:0">
<iframe id="f" src="%s" style="width:%dpx;height:900px;border:0"></iframe>
<script>
f.onload = () => {
  const d = f.contentDocument, root = d.documentElement;
  d.querySelectorAll('details').forEach((x) => (x.open = true));
  const wide = [...d.querySelectorAll('body *')]
    .filter((e) => e.getBoundingClientRect().right > root.clientWidth + 1)
    .slice(0, 5).map((e) => e.tagName + '.' + e.className);
  const w = (sel) => Math.min(...[...d.querySelectorAll(sel)].map((e) => e.getBoundingClientRect().width));
  document.body.insertAdjacentHTML('beforeend', '<pre id="kgm">' +
    JSON.stringify({ iw: f.contentWindow.innerWidth, sw: root.scrollWidth, cw: root.clientWidth, wide,
      minType: w('td[data-label="Type"]'), minBtn: w('.btn') }) + '</pre>');
};
</script>`

// The dumped DOM also contains the harness script, which spells the same tag in a string;
// only the real element's text starts with a brace.
// dumpDOM loads a local page in a throw-away Chrome profile and returns the DOM after load.
func dumpDOM(t *testing.T, chrome, page string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	// The mock keychain and basic password store keep Chrome off the macOS keychain: under a
	// HOME with no keychain (a CI-shaped run) macOS otherwise puts a "Keychain Not Found"
	// dialog on the user's screen and Chrome waits on it.
	out, err := exec.CommandContext(ctx, chrome, "--headless=new", "--disable-gpu", "--no-sandbox", "--no-first-run",
		"--disable-extensions", "--disable-background-networking", "--allow-file-access-from-files",
		"--use-mock-keychain", "--password-store=basic",
		"--user-data-dir="+t.TempDir(), "--window-size=1500,1000", "--dump-dom",
		(&url.URL{Scheme: "file", Path: page}).String()).Output()
	if err != nil {
		t.Fatalf("chrome: %v", err)
	}
	return out
}

var measureRe = regexp.MustCompile(`<pre id="kgm">(\{[^<]*\})</pre>`)

// A real browser lays the page out at phone, tablet and desktop widths: nothing may be wider
// than its window, so there is never a sideways scroll. Reading is done in a throw-away
// Chrome profile; no page script runs inside the report itself (its CSP stays in force).
func TestNoSidewaysScrollInARealBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome or Chromium installed; this check needs a real layout engine")
	}
	f, run, layers := stressed(t)
	r := reporter(filepath.Join(t.TempDir(), "index.html"))
	r.Coverage = Coverage{Repos: 439, Wikis: 29, Gists: 2, Public: 5, Refs: 18204, Commits: 41330, Blobs: 99120, APIItems: 812}
	if _, err := r.Write(f.secrets, run, layers); err != nil {
		t.Fatal(err)
	}
	reportURL := (&url.URL{Scheme: "file", Path: r.Path}).String()

	for _, w := range []int{320, 390, 600, 768, 900, 940, 941, 1000, 1024, 1160, 1440, 2000} {
		page := filepath.Join(t.TempDir(), "harness.html")
		if err := os.WriteFile(page, []byte(fmt.Sprintf(harness, reportURL, w)), 0o600); err != nil {
			t.Fatal(err)
		}
		out := dumpDOM(t, chrome, page)
		m := measureRe.FindSubmatch(out)
		if m == nil {
			t.Fatalf("width %d: the browser did not report a layout (iframe blocked?)", w)
		}
		var got struct {
			IW, SW, CW      int
			Wide            []string
			MinType, MinBtn float64
		}
		if err := json.Unmarshal([]byte(html.UnescapeString(string(m[1]))), &got); err != nil {
			t.Fatalf("width %d: %v", w, err)
		}
		if got.IW != w {
			t.Errorf("width %d: the iframe is %d px wide; the test is not measuring what it says", w, got.IW)
		}
		if got.SW > got.CW || len(got.Wide) > 0 {
			t.Errorf("width %d: the page scrolls sideways (scrollWidth %d > clientWidth %d); wider than the window: %v",
				w, got.SW, got.CW, got.Wide)
		}
		// In table mode a column of ours must not be squeezed by a neighbour's long word: the
		// type and the Rotate button need room to read. (Under 941 px they are cards.)
		if w > 940 && (got.MinType < 80 || got.MinBtn < 100) {
			t.Errorf("width %d: short columns were squeezed (Type cell %.0f px, Rotate button %.0f px)", w, got.MinType, got.MinBtn)
		}
		t.Logf("width %4d px: scrollWidth %d, clientWidth %d, narrowest Type cell %.0f px, narrowest button %.0f px",
			w, got.SW, got.CW, got.MinType, got.MinBtn)
	}
}

// The policy is the backstop for the escaping: if a bug ever let a script into the page, the
// browser must refuse to run it. Proved by putting one in on purpose and asking Chrome
// whether it ran. The same page with its policy removed is the control, so a pass cannot
// mean the probe is blind.
func TestPolicyStopsAScriptEvenIfEscapingFailed(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome or Chromium installed; this check needs a real browser")
	}
	b, err := reporter("").Render(nil, healthyRun(), healthyLayers())
	if err != nil {
		t.Fatal(err)
	}
	probe := `<script>document.documentElement.setAttribute("data-ran", "yes")</script>`
	guarded := strings.Replace(string(b), "</body>", probe+"</body>", 1)
	policy := regexp.MustCompile(`<meta http-equiv="Content-Security-Policy"[^>]*>`)
	unguarded := policy.ReplaceAllString(guarded, "")
	if unguarded == guarded {
		t.Fatal("the page has no policy to remove")
	}

	dir := t.TempDir()
	for name, want := range map[string]bool{"guarded": false, "unguarded": true} {
		src := guarded
		if name == "unguarded" {
			src = unguarded
		}
		page := filepath.Join(dir, name+".html")
		if err := os.WriteFile(page, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		ran := strings.Contains(string(dumpDOM(t, chrome, page)), `data-ran="yes"`)
		if ran != want {
			t.Errorf("%s page: script ran = %v, want %v", name, ran, want)
		}
	}
}
