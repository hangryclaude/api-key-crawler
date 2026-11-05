package known

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type parseFunc func(l *learner, path string, data []byte)

// File size ceilings. A secrets file is small; a 5 MB file named .env is something else.
const (
	maxEnvFile    = 1 << 20
	maxConfigFile = 256 << 10 // PLAN.md: ~/.config files up to 256 KB
	maxKeyFile    = 64 << 10

	maxAgentConfig = 32 << 20
)

// skipDirNames are never entered while walking: dependency trees and caches hold
// thousands of fixture .env files and never the user's own.
var skipDirNames = map[string]bool{
	"node_modules": true, ".git": true, ".venv": true, "venv": true, "__pycache__": true,
	"site-packages": true, ".tox": true, "Pods": true, "DerivedData": true, ".gradle": true,
	".next": true, ".nuxt": true, ".turbo": true, ".parcel-cache": true, ".cache": true,
	".npm": true, ".cargo": true, ".rustup": true, ".Trash": true,
}

func home(h, rel string) string { return filepath.Join(h, filepath.FromSlash(rel)) }

// fixedSources are the credential files at known places under the home directory: the
// PLAN.md list first, then the same kind of file for tools the user uses (git's XDG credential
// store, Postgres, Vault, RubyGems, Cargo, Terraform, Yarn, S3 and rclone) and the two agent
// configs that carry MCP server keys in their env blocks. .claude.json is megabytes of
// history around a few kilobytes of config, so it gets a larger ceiling.
var fixedSources = []struct {
	rel string
	max int64
}{
	{".npmrc", maxConfigFile}, {".netrc", maxConfigFile}, {".pypirc", maxConfigFile},
	{".aws/credentials", maxConfigFile}, {".docker/config.json", maxConfigFile}, {".kube/config", maxConfigFile},
	{".codex/auth.json", maxConfigFile}, {".git-credentials", maxConfigFile}, {".gitconfig", maxConfigFile},
	{".config/git/credentials", maxConfigFile}, {".pgpass", maxConfigFile}, {".my.cnf", maxConfigFile},
	{".vault-token", maxConfigFile}, {".gem/credentials", maxConfigFile}, {".cargo/credentials.toml", maxConfigFile},
	{".cargo/credentials", maxConfigFile}, {".terraform.d/credentials.tfrc.json", maxConfigFile},
	{".yarnrc", maxConfigFile}, {".yarnrc.yml", maxConfigFile}, {".s3cfg", maxConfigFile}, {".boto", maxConfigFile},
	{".config/rclone/rclone.conf", maxConfigFile}, {".codex/config.toml", maxConfigFile},
	{".claude/settings.json", maxConfigFile}, {".claude/settings.local.json", maxConfigFile},
	{".claude.json", maxAgentConfig},
	// The agent and MCP stores, whose keys never reach a .env (STEAL P0-15). The paths are the
	// vendors' documented ones; Windsurf's older ~/.codeium path and Gemini CLI's settings are
	// guesses (STEAL G17) that cost nothing when the file is absent.
	{".claude/.credentials.json", maxConfigFile}, {"Library/Application Support/Claude/claude_desktop_config.json", maxConfigFile},
	{".cursor/mcp.json", maxConfigFile}, {".copilot/mcp-config.json", maxConfigFile}, {".kiro/settings/mcp.json", maxConfigFile},
	{".config/devin/mcp_config.json", maxConfigFile}, {".config/opencode/opencode.json", maxConfigFile},
	{".aider.conf.yml", maxConfigFile}, {".codeium/windsurf/mcp_config.json", maxConfigFile}, {".gemini/settings.json", maxConfigFile},
}

// environment learns the variables of the process that ran learn. Exports computed at shell
// start (from a keychain, from direnv) have no value in any file, but they have one here.
// Nothing is read unless the caller passes Options.Env; tests never do.
func (l *learner) environment() {
	if len(l.o.Env) == 0 {
		return
	}
	l.rep.Files++
	for _, kv := range l.o.Env {
		if name, value, ok := strings.Cut(kv, "="); ok {
			l.ingest(name, value, "environment", false)
		}
	}
	l.logf("learn: read the environment (%d variables)", len(l.o.Env))
}

// harvest reads every source in a fixed order, so two runs over the same machine see
// values in the same order and name them the same way.
func (l *learner) harvest() {
	o := l.o
	skip := map[string]bool{}
	for _, d := range o.SkipDirs {
		skip[filepath.Clean(d)] = true
	}
	for _, root := range o.EnvRoots {
		l.walk(root, skip, envRootFile)
	}
	// ~/.env* sit directly in the home directory, outside any project root.
	if ents, err := os.ReadDir(o.Home); err == nil {
		for _, e := range ents {
			if !e.IsDir() && isEnvName(e.Name()) {
				l.harvestFile(filepath.Join(o.Home, e.Name()), maxEnvFile)
			}
		}
	}
	for _, rc := range []string{".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile"} {
		l.harvestFile(home(o.Home, rc), maxEnvFile)
	}
	if ents, err := os.ReadDir(home(o.Home, "Library/LaunchAgents")); err == nil {
		for _, e := range ents {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".plist") {
				l.harvestFile(home(o.Home, "Library/LaunchAgents/"+e.Name()), maxConfigFile)
			}
		}
	}
	for _, f := range fixedSources {
		l.harvestFile(home(o.Home, f.rel), f.max)
	}
	// Claude Code keeps dated copies of ~/.claude.json. A key removed from the live file is
	// still in a backup, and still worth protecting.
	if ents, err := os.ReadDir(home(o.Home, ".claude/backups")); err == nil {
		for _, e := range ents {
			if !e.IsDir() && strings.HasPrefix(e.Name(), ".claude.json.backup") {
				l.harvestFile(home(o.Home, ".claude/backups/"+e.Name()), maxAgentConfig)
			}
		}
	}
	l.walk(home(o.Home, ".config"), nil, func(_, name string) (int64, bool) { return maxConfigFile, isConfigName(name) })
	l.sshKeys()
	for _, f := range o.Files {
		l.harvestFile(f, maxEnvFile)
	}
	l.environment()
	l.ghTokens()
}

// walk visits regular files (symlinks to them included) that pick accepts, and reads each up
// to the size pick gives it. pick sees the path and the file name.
func (l *learner) walk(root string, skip map[string]bool, pick func(path, name string) (max int64, ok bool)) {
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return // an absent root is normal: not every Mac has ~/projects
	}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if l.o.Ctx.Err() != nil {
			return filepath.SkipAll
		}
		if err != nil {
			l.unreadable++
			l.skip(p, "unreadable")
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if p != root && (skipDirNames[d.Name()] || skip[p]) {
				return filepath.SkipDir
			}
			return nil
		}
		if max, ok := pick(p, d.Name()); ok {
			l.harvestFile(p, max)
		}
		return nil
	})
}

// isEnvName matches .env, .env.local, .env.production, .envrc and app.env. The .example and
// .sample variants are read too: their placeholders fail the value filters, and a real key
// pasted into one by mistake is still a key.
func isEnvName(name string) bool {
	return name == ".env" || strings.HasPrefix(name, ".env.") || name == ".envrc" || strings.HasSuffix(name, ".env") ||
		name == ".dev.vars" || strings.HasPrefix(name, ".dev.vars.") // Wrangler's local secrets
}

// envRootFile picks what is read under the project roots: env files, and the agent and MCP
// configs a project carries (.mcp.json, .claude/settings*.json, .cursor/mcp.json ...), which
// hold keys that never reach a .env.
func envRootFile(path, name string) (int64, bool) {
	switch {
	case isEnvName(name):
		return maxEnvFile, true
	case isAgentConfig(path):
		return maxConfigFile, true
	}
	return 0, false
}

// isAgentConfig is AgentConfigFormat plus the local overrides, which are gitignored by design
// and are exactly where a personal key goes.
func isAgentConfig(path string) bool {
	if _, ok := AgentConfigFormat(path); ok {
		return true
	}
	p := strings.ToLower(filepath.ToSlash(path))
	return strings.HasSuffix(p, "/.claude/settings.local.json") || strings.HasSuffix(p, "/.devin/mcp_config.local.json")
}

func isConfigName(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".json", ".toml", ".yml", ".yaml", ".env":
		return true
	}
	return isEnvName(name)
}

// sshKeys reads every file in ~/.ssh that holds a private key, not just id_*: deploy keys
// get names like github_deploy. The cheap content check keeps config and known_hosts out.
func (l *learner) sshKeys() {
	dir := home(l.o.Home, ".ssh")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || strings.HasSuffix(n, ".pub") || strings.HasPrefix(n, "known_hosts") || n == "config" || strings.HasPrefix(n, "authorized_keys") {
			continue
		}
		l.harvestFile(filepath.Join(dir, n), maxKeyFile)
	}
}

// ghTokens learns the stored login token of each gh account. The token passes through
// this process's memory and a pipe, never a file.
func (l *learner) ghTokens() {
	for _, u := range l.o.GHUsers {
		out, err := l.o.Run(l.o.Ctx, "gh", "auth", "token", "--user", u)
		if err != nil { // most likely just not logged in; listed, but not a reason to refuse a prune
			l.skip("gh:"+u, "gh auth token failed")
			continue
		}
		l.rep.Files++
		l.ingestTrusted("gh auth token --user "+u, string(bytes.TrimSpace(out)), "gh:"+u)
		l.logf("learn: read gh:%s", u)
	}
}

// readFile returns a regular file's bytes, or reports why not. A missing file is normal and
// silent; an unreadable or oversized one is listed in the report.
func (l *learner) readFile(path string, max int64) ([]byte, bool) {
	st, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			l.unreadable++
			l.skip(path, "unreadable")
		}
		return nil, false
	}
	if !st.Mode().IsRegular() {
		return nil, false
	}
	if st.Size() > max {
		l.skip(path, "larger than the size limit")
		return nil, false
	}
	f, err := os.Open(path)
	if err != nil {
		l.unreadable++
		l.skip(path, "unreadable")
		return nil, false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		l.unreadable++
		l.skip(path, "unreadable")
		return nil, false
	}
	// Notepad and some editors prefix a byte-order mark, which would otherwise glue itself
	// onto the first variable name.
	return bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), true
}

// harvestFile parses one file by its name, then does the two scans that apply to any
// text: private keys wherever they sit, and passwords inside URLs.
func (l *learner) harvestFile(path string, max int64) { l.harvestWith(path, max, nil) }

// harvestWith is harvestFile with an explicit parser (nil picks one by name). Each path is
// read once per run, which also stops a source cycle in an rc file.
func (l *learner) harvestWith(path string, max int64, parse parseFunc) {
	if l.read[path] {
		return
	}
	l.read[path] = true
	data, ok := l.readFile(path, max)
	if !ok {
		return
	}
	isBinPlist := bytes.HasPrefix(data, []byte("bplist00"))
	if !isBinPlist && bytes.IndexByte(data[:min(len(data), 8192)], 0) >= 0 {
		l.skip(path, "binary file")
		return
	}
	l.rep.Files++
	before := len(l.cands)
	if parse == nil {
		parse = parserFor(path, data)
	}
	parse(l, path, data)
	if !isBinPlist {
		text := string(data)
		l.privateKeys(path, baseName(path), text)
		for _, pw := range urlPasswords(text) {
			l.consider(baseName(path)+" (url password)", pw, path, true)
		}
	}
	l.logf("learn: read %s (%d new values)", path, len(l.cands)-before)
}

// parserFor picks the reader for a file from its name, and from its directory where the
// name alone is ambiguous (config.json means docker only in ~/.docker).
func parserFor(path string, data []byte) parseFunc {
	base := filepath.Base(path)
	dir := filepath.Base(filepath.Dir(path))
	switch {
	case isEnvName(base):
		return parseDotenv
	case strings.HasPrefix(base, ".zsh") || strings.HasPrefix(base, ".bash") || base == ".profile":
		return parseShell
	case strings.HasSuffix(base, ".plist"):
		return parsePlist
	case base == ".npmrc":
		return parseNpmrc
	case base == ".netrc" || base == "_netrc":
		return parseNetrc
	case base == ".git-credentials" || base == ".vault-token" || base == "credentials" && dir == "git":
		return parseLines
	case base == ".pgpass":
		return parsePgpass
	case base == "config.json" && dir == ".docker":
		return parseDocker
	case strings.HasSuffix(base, ".json") || strings.HasSuffix(base, ".jsonc"):
		return parseJSON
	case base == "auth.json" || base == "credentials.json":
		return parseJSON
	case strings.HasSuffix(base, ".toml"):
		return parseTOML
	case strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml"):
		return parseYAML
	}
	// toml, yml, yaml, ini-style (.pypirc, aws credentials, kube config, .gitconfig) and
	// anything unnamed: the line reader, or JSON if it looks like it.
	if t := bytes.TrimSpace(data); len(t) > 0 && t[0] == '{' {
		return parseJSON
	}
	return parseKV
}

// expandHome resolves the path argument of a `source` line: quotes, a leading ~, and
// $HOME or ${HOME}. Anything else dynamic, or anything outside the home directory, is not
// followed.
func (l *learner) expandHome(raw string) (string, bool) {
	p := strings.Trim(raw, `"'`)
	h := l.o.Home
	switch {
	case p == "~":
		p = h
	case strings.HasPrefix(p, "~/"):
		p = h + p[1:]
	}
	p = strings.NewReplacer("${HOME}", h, "$HOME", h).Replace(p)
	if strings.ContainsAny(p, "$`*?[") || !filepath.IsAbs(p) {
		return "", false
	}
	p = filepath.Clean(p)
	if p != h && !strings.HasPrefix(p, h+string(filepath.Separator)) {
		return "", false
	}
	return p, true
}

// sortedKeys is shared by the parsers that walk maps.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
