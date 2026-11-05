package guard

// keyguard's own commands. The message that stops an agent says a false positive is a
// `keyguard allow <id>` away; an agent that took that advice itself would make the first gate
// it hit one command wide, which is the bypass the engines' own allow comments already showed
// (a committer, or an agent trying to make the commit pass, silences the scanner with one
// edit). So the commands that let a finding through, or take protection away, are the user's to
// run, from their terminal or with `!` in Claude Code, neither of which is a PreToolUse call.
//
// Only what widens what gets through is held back. Reading (allow --list, known list, doctor,
// match), adding protection (learn, install, github-settings --apply) and scanning are not.

var keyguardValued = set("--reason", "-reason", "--by", "-by", "--file", "-file", "--out", "-out",
	"--launchd-dir", "-launchd-dir", "--repo", "-repo", "--engines", "-engines")

// keyguard reads `keyguard <command> ...` (args exclude the program name).
func (d *decider) keyguard(args []string) {
	o := scanOptions(args, keyguardValued)
	if len(o.pos) == 0 {
		return
	}
	// A dry run changes nothing, and a person checking what a command would do is welcome to.
	dry := o.on("--dry-run") || o.on("-dry-run")
	switch o.pos[0] {
	case "allow":
		if !o.on("--list") && !o.on("-list") {
			d.deny(KindOwner, "`keyguard allow` lets a finding through for good (or takes it off the list again), and only the user decides that.")
		}
	case "known":
		if len(o.pos) > 1 && o.pos[1] == "forget" {
			d.deny(KindOwner, "`keyguard known forget` removes a learned key from every gate, so the key could be committed again.")
		}
	case "learn":
		if o.on("--prune") || o.on("-prune") {
			d.deny(KindOwner, "`keyguard learn --prune` drops learned keys whose file has moved, and a moved file is not a rotated key.")
		}
	case "uninstall":
		if !dry {
			d.deny(KindOwner, "`keyguard uninstall` takes the git hooks out, which switches every gate off.")
		}
	case "import-triage":
		if !dry {
			d.deny(KindOwner, "`keyguard import-triage` re-labels findings, and a real key labelled a placeholder stops alerting.")
		}
	}
}
