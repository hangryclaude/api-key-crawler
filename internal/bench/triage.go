package bench

import (
	"regexp"
	"strings"

	"keyguard/internal/core"
)

var (
	// words that mark documentation, not credentials
	placeholderWords = regexp.MustCompile(`(?i)\b(example|placeholder|changeme|change_me|dummy|todo)\b|replace[_-]?with|your[_-]|<[a-z_ -]+>|\$\{|\{\{|x{6,}`)
	// words that mark a digest or lockfile entry
	hashCue = regexp.MustCompile(`(?i)\b(sha\d*|md5|checksum|integrity|digest|resolved|etag|hash)\b`)
	// rules whose findings are public by design
	publicRules = map[string]bool{"posthog-project-api-key": true, "mapbox-api-token": true, "supabase-project-url": true}
)

// publicSamples are documentation values every scanner trips on: the AWS docs example pair
// and the jwt.io sample token. A real deployment ships this list and hashes it with its salt.
func publicSamples() []string {
	return []string{
		"AKIA" + "IOSFODNN7" + "EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY",
		jwtIO(),
	}
}

// SimpleTriage is the pipeline's stand-in for the triage package: cheap rules over what a
// core.Hit still carries once the raw value is gone (shape, entropy, length, rule, context).
// It returns false for a hit that should not alert. A verified-live or learned-local hit
// always alerts, as in PLAN's accuracy design.
func SimpleTriage(fpr core.Fingerprinter) func(core.Hit) bool {
	samples := map[string]bool{}
	for _, s := range publicSamples() {
		samples[fpr.FP(s)] = true
	}
	return func(h core.Hit) bool {
		switch {
		case h.Verified == core.Live || h.Known != "":
			return true
		case samples[h.FP]:
			return false
		case h.Entropy > 0 && h.Entropy < 3.0 && h.Len >= 12:
			return false // placeholder-grade randomness
		case placeholderWords.MatchString(h.Context):
			return false
		case publicRules[h.Rule], publicShape(h.Shape):
			return false
		case strings.HasPrefix(h.Rule, "generic"):
			// the catch-all rules need more than a keyword to alert
			if h.Len == 36 || hashCue.MatchString(h.Context) || h.Entropy < 4.0 || h.Len < 16 {
				return false
			}
		}
		return true
	}
}

func publicShape(shape string) bool {
	for _, p := range []string{"pk_live_", "pk_test_", "phc_", "sb_publishable_"} {
		if strings.HasPrefix(shape, p) {
			return true
		}
	}
	return false
}
