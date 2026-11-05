package report

import (
	"time"

	"keyguard/internal/core"
)

// Summary is what a run's new secrets amount to, worded for a banner or a text message.
type Summary struct {
	Title string
	Body  string        // one line per secret, "\n"-separated; shapes and links only
	Sev   core.Severity // highest severity listed; None when nothing needs rotating
}

// maxListed is how many secrets a notification names. A first deep scan can find dozens;
// the page has the rest, and a text that scrolls is a text nobody reads.
const maxListed = 3

// Summarize builds the one notification for a batch of secrets. It lists only open ones at
// high or above, worst first, in the same words as the report's hero, and carries only
// what the page carries: type, shape, where, and the rotate link.
func Summarize(secrets []core.Secret) Summary {
	crit, high, _, _ := split(secrets)
	if len(crit)+len(high) == 0 {
		return Summary{}
	}
	sortSecrets(crit, urgentFirst)
	sortSecrets(high, urgentFirst)
	s := Summary{Sev: core.High, Title: highHeadline(high)}
	if len(crit) > 0 {
		s.Sev, s.Title = core.Critical, critHeadline(crit)
	}

	in := input{now: time.Now(), zone: time.Local}
	all := append(append([]core.Secret(nil), crit...), high...)
	for i, sec := range all {
		if i == maxListed {
			s.Body += "\nand " + num(len(all)-maxListed) + " more. Open the report."
			break
		}
		if i > 0 {
			s.Body += "\n"
		}
		s.Body += line(in.row(sec, true))
	}
	return s
}

// line is "Type shape in where. Rotate: link": short enough for a banner, complete enough
// to act on from a phone.
func line(r rowView) string {
	out := r.Type + " " + r.Shape + " in " + r.Where.Name + " (" + r.Where.Badge + ")."
	if r.Rotate.URL != "" {
		return out + " Rotate: " + r.Rotate.URL
	}
	return out + " " + r.Rotate.Hint
}
