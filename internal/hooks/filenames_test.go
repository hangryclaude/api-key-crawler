package hooks

import "testing"

func TestClassify(t *testing.T) {
	for _, c := range []struct {
		path      string
		id        string // "" = not a filename-rule file at all
		byContent bool
	}{
		{".env", "env-file", false},
		{".ENV", "env-file", false},
		{"a/b/.env", "env-file", false},
		{".env.local", "env-file", false},
		{".env.production.local", "env-file", false},
		{".env.", "env-file", false},
		{".env.example", "", false},
		{".env.EXAMPLE", "", false},
		{".env.local.example", "", false},
		{".env.sample", "", false},
		{".env.template", "", false},
		{".env.dist", "", false},
		{".env.defaults", "", false},
		{".envrc", "", false},
		{"env", "", false},
		{"my.env", "", false},
		{"id_rsa", "ssh-key", false},
		{"id_dsa", "ssh-key", false},
		{"id_ecdsa", "ssh-key", false},
		{"id_ed25519", "ssh-key", false},
		{"home/.ssh/ID_RSA", "ssh-key", false},
		{"id_rsa.pub", "", false},
		{"id_ed25519.pub", "", false},
		{"a.p12", "keystore", false},
		{"a.PFX", "keystore", false},
		{"a.jks", "keystore", false},
		{"a.keystore", "keystore", false},
		{".git-credentials", "git-credentials", false},
		{".netrc", "netrc", false},
		{"x/terraform.tfstate", "tfstate", false},
		{"x/terraform.tfstate.backup", "tfstate-x", false}, // STEAL 4.1: the backups keep the same secrets
		{"a.pem", "pem-key", true},
		{"a.KEY", "pem-key", true},
		{".npmrc", "npmrc-token", true},
		{"pkg/.pypirc", "pypirc-token", true},
		{"credentials.json", "service-account", true},
		{"my-service-account.json", "service-account", true},
		{"proj-firebase-adminsdk-x1.json", "service-account", true},
		{"service-account.txt", "", false},
		{"package.json", "", false},
		{"README.md", "", false},
	} {
		r, ok := classify(c.path)
		if (c.id != "") != ok || (ok && (r.id != c.id || (r.content != nil) != c.byContent)) {
			t.Errorf("classify(%q) = %q ok=%v content=%v; want %q content=%v", c.path, r.id, ok, r.content != nil, c.id, c.byContent)
		}
		if ok && r.why == "" {
			t.Errorf("classify(%q): rule has no reason", c.path)
		}
	}
}

func TestContentRules(t *testing.T) {
	rule := func(p string) func([]byte) bool {
		r, ok := classify(p)
		if !ok || r.content == nil {
			t.Fatalf("%s has no content rule", p)
		}
		return r.content
	}
	for _, c := range []struct {
		file, content string
		want          bool
	}{
		{"a.pem", "-----BEGIN PRIVATE KEY-----\nxx\n", true},
		{"a.pem", "-----BEGIN RSA PRIVATE KEY-----\nxx\n", true},
		{"a.pem", "-----BEGIN CERTIFICATE-----\nxx\n", false},
		{"a.key", "-----BEGIN PUBLIC KEY-----\n", false},
		{"a.key", "", false},

		{".npmrc", "//registry.npmjs.org/:_authToken=abc123\n", true},
		{".npmrc", "//registry.npmjs.org/:_authToken=abc123==\n", true},
		{".npmrc", "//registry.npmjs.org/:_authToken = \"abc123\"\n", true},
		{".npmrc", "_authToken=abc123\n", true},
		{".npmrc", "_auth=dXNlcjpwYXNz\n", true},
		{".npmrc", "//host/:_password=c2VjcmV0\n", true},
		{".npmrc", "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n", false},
		{".npmrc", "//registry.npmjs.org/:_authToken=\"${NPM_TOKEN}\"\n", false},
		{".npmrc", "_authToken=$NPM_TOKEN\n", false},
		{".npmrc", "_authToken=\n", false},
		{".npmrc", "; _authToken=abc\n# _auth=abc\n", false},
		{".npmrc", "registry=https://registry.npmjs.org/\nalways-auth=true\n", false},
		{".npmrc", "", false},

		{".pypirc", "[pypi]\nusername = __token__\npassword = pypi-" + randString(40, alnum) + "\n", true},
		{".pypirc", "[pypi]\npassword: hunter2\n", true},
		{".pypirc", "[pypi]\nPassword = hunter2\n", true},
		{".pypirc", "[pypi]\npassword = ${PYPI_TOKEN}\n", false},
		{".pypirc", "[pypi]\npassword = <your token>\n", false},
		{".pypirc", "[pypi]\npassword =\n", false},
		{".pypirc", "[pypi]\npassword = %(token)s\n", false},
		{".pypirc", "[pypi]\nusername = __token__\n", false},

		{"credentials.json", `{"private_key": "x"}`, true},
		{"credentials.json", `{"client_secret": "x"}`, false},
		{"a-service-account.json", `{"type":"service_account","private_key":"-----BEGIN"}`, true},
		{"a-service-account.json", `{}`, false},
	} {
		if got := rule(c.file)([]byte(c.content)); got != c.want {
			t.Errorf("%s %q: got %v, want %v", c.file, c.content, got, c.want)
		}
	}
}
