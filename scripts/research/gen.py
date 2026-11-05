#!/usr/bin/env python3
"""Builds a synthetic corpus of agent/dev-tool artifacts with runtime-generated fake secrets.

    python3 gen.py OUT_DIR

OUT_DIR must be new or empty. Writes OUT_DIR/vec/** (the artifacts: MCP and agent configs,
HAR and Postman captures, tfstate, notebooks, browser sessions, key files), OUT_DIR/planted.json
(file -> list of {label, value}) and OUT_DIR/keys/ (throwaway key material made with ssh-keygen
and openssl). Run the engines over OUT_DIR/vec with run_engines.py, then score.py.

No secret-shaped literal appears in this file; every value is assembled at runtime.
"""
import base64, json, os, pathlib, shutil, string, subprocess, sys

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common
from common import gh_pat, rng, rnd, ALNUM

if len(sys.argv) != 2:
    common.die("usage: gen.py OUT_DIR")
out = pathlib.Path(sys.argv[1])
common.empty_dir(out)
for tool in ("ssh-keygen", "openssl"):
    if not shutil.which(tool):
        common.die(tool + " is needed for the throwaway key material and is not on PATH")
vec = out / "vec"
vec.mkdir(parents=True, exist_ok=True)

GH = gh_pat()
GH2 = gh_pat()
ANT = "sk-ant-api03-" + rnd(93, ALNUM + "-_") + "AA"
STR = "sk_live_" + rnd(24)
AKIA = "AKIA" + rnd(16, string.ascii_uppercase + "234567")
AWSS = rnd(40, ALNUM + "+/")
HEX = "".join(rng.choice("0123456789abcdef") for _ in range(40))
HEX64 = "".join(rng.choice("0123456789abcdef") for _ in range(64))
PW = rnd(20)
PGPW = rnd(24)
DSN = f"postgresql://app:{PGPW}@db.example.com:5432/app"
JWT = ".".join(base64.urlsafe_b64encode(os.urandom(n)).decode().rstrip("=") for n in (24, 60, 32))
FC = "fc-" + "".join(rng.choice("0123456789abcdef") for _ in range(32))
UUIDK = "-".join("".join(rng.choice("0123456789abcdef") for _ in range(n)) for n in (8, 4, 4, 4, 12))
WPSALT = rnd(64, ALNUM + "!@#$%^&*()-_=+[]{}<>~")

planted = {}


def put(rel, content, secrets):
    p = vec / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    mode = "wb" if isinstance(content, bytes) else "w"
    with open(p, mode) as f:
        f.write(content)
    planted[rel] = [{"label": k, "value": v} for k, v in secrets]


def b64(s):
    return base64.b64encode(s.encode()).decode()


# throwaway key material generated at runtime (never real credentials)
keydir = out / "keys"
keydir.mkdir(exist_ok=True)
ssh_path = keydir / "k"
if not ssh_path.exists():
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(ssh_path)], check=True)
SSHKEY = ssh_path.read_text()
p8_path = keydir / "ec.p8"
subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(p8_path)], check=True)
P8 = p8_path.read_text()
p8_body = "".join(l for l in P8.splitlines() if "-----" not in l)
ssh_body = "".join(l for l in SSHKEY.splitlines() if "-----" not in l)

# control
put("00_control/.env", f"GITHUB_TOKEN={GH}\n", [("gh", GH)])

# ---- MCP / agent config
put("mcp/.mcp.json", json.dumps({"mcpServers": {"github": {"type": "http", "url": "https://api.githubcopilot.com/mcp/", "headers": {"Authorization": f"Bearer {GH}"}}}}, indent=2), [("gh", GH)])
put("mcp/.cursor/mcp.json", json.dumps({"mcpServers": {"scrape": {"command": "npx", "args": ["-y", "firecrawl-mcp"], "env": {"FIRECRAWL_API_KEY": FC}}}}, indent=2), [("firecrawl_fc", FC)])
put("mcp/.vscode/mcp.json", json.dumps({"servers": {"search": {"type": "http", "url": f"https://mcp.example.com/mcp?api_key={UUIDK}&profile=dev"}}}, indent=2), [("uuid_query_key", UUIDK)])
put("mcp/claude_desktop_config.json", json.dumps({"mcpServers": {"db": {"command": "npx", "args": ["-y", "@bytebase/dbhub", "--dsn", DSN]}}}, indent=2), [("pg_dsn_pw", PGPW)])
put("mcp/.codex/config.toml", f'[mcp_servers.pay]\ncommand = "npx"\nargs = ["-y", "pay-mcp"]\n\n[mcp_servers.pay.env]\nSTRIPE_API_KEY = "{STR}"\nGENERIC_API_KEY = "{HEX}"\n', [("stripe", STR), ("generic_hex", HEX)])
put("mcp/.continue/config.yaml", f"models:\n  - name: claude\n    provider: anthropic\n    apiKey: {ANT}\n", [("anthropic", ANT)])
put("agent/.claude/settings.local.json", json.dumps({"permissions": {"allow": [f'Bash(curl -s -H "Authorization: Bearer {GH}" https://api.github.com/user)', f"Bash(ANTHROPIC_API_KEY={ANT} python run.py)"]}}, indent=2), [("gh", GH), ("anthropic", ANT)])
put("agent/.claude/settings.json", json.dumps({"env": {"MY_SERVICE_TOKEN": HEX64}}, indent=2), [("env_hex64", HEX64)])
put("agent/.aider.conf.yml", f"anthropic-api-key: {ANT}\nmodel: sonnet\n", [("anthropic", ANT)])
put("agent/.aider.chat.history.md", f"#### set up the key\n\n> export GITHUB_TOKEN={GH}\n\nOK, done.\n", [("gh", GH)])
put("agent/.specstory/history/2026-11-03_12-00Z-fix-auth.md", f"_**User**_\n\nhere is my key {ANT}\n\n_**Assistant**_\n\n```bash\ncurl -H 'x-api-key: {ANT}' https://api.anthropic.com/v1/models\n```\n", [("anthropic", ANT)])
tr_lines = [
    {"type": "assistant", "message": {"role": "assistant", "content": [{"type": "tool_use", "name": "Bash", "input": {"command": "cat .env"}}]}},
    {"type": "user", "message": {"role": "user", "content": [{"type": "tool_result", "content": f"ANTHROPIC_API_KEY={ANT}\nGITHUB_TOKEN={GH}\nSERVICE_SECRET={HEX64}\n"}]}},
]
put("agent/projects/session-1.jsonl", "\n".join(json.dumps(x) for x in tr_lines) + "\n", [("anthropic", ANT), ("gh", GH), ("generic_hex64", HEX64)])

# ---- API clients / captures
har = {"log": {"version": "1.2", "entries": [{"request": {"method": "GET", "url": "https://api.example.com/me", "headers": [{"name": "Authorization", "value": f"Bearer {GH2}"}, {"name": "x-api-key", "value": HEX}, {"name": "Cookie", "value": f"sessionid={HEX64}"}], "cookies": [{"name": "sessionid", "value": HEX64}]}, "response": {"status": 200, "content": {"mimeType": "application/json", "text": json.dumps({"access_token": GH})}}}]}}
put("api/trace.har", json.dumps(har, indent=2), [("gh2_authz", GH2), ("generic_hex_xapikey", HEX), ("cookie_hex64", HEX64), ("gh_in_body", GH)])
put("api/dev.postman_environment.json", json.dumps({"id": "1", "name": "dev", "values": [{"key": "token", "value": GH, "type": "secret", "enabled": True}, {"key": "api_key", "value": HEX, "type": "default", "enabled": True}]}, indent=2), [("gh", GH), ("generic_hex", HEX)])
put("api/cassettes/test_user.yaml", f"interactions:\n- request:\n    headers:\n      Authorization:\n      - Bearer {GH}\n    method: GET\n    uri: https://api.github.com/user\n  response:\n    status: {{code: 200}}\nversion: 1\n", [("gh", GH)])
put("api/requests.http", f"GET https://api.example.com/me\nAuthorization: Bearer {GH}\n\n###\nGET https://api.example.com/x?api_key={HEX}\n", [("gh", GH), ("generic_hex_query", HEX)])
put("api/collection/auth.bru", f"auth:bearer {{\n  token: {GH}\n}}\n\nvars {{\n  api_key: {HEX}\n}}\n", [("gh", GH), ("generic_hex", HEX)])

# ---- IaC / platform CLIs
tfstate = {"version": 4, "resources": [{"type": "aws_iam_access_key", "instances": [{"attributes": {"id": AKIA, "secret": AWSS, "user": "ci"}}]}, {"type": "aws_db_instance", "instances": [{"attributes": {"username": "app", "password": PW}}]}]}
put("iac/terraform.tfstate", json.dumps(tfstate, indent=2), [("akia", AKIA), ("aws_secret", AWSS), ("db_pw", PW)])
put("iac/terraform.tfvars", f'db_password = "{PW}"\napi_key     = "{HEX}"\n', [("db_pw", PW), ("generic_hex", HEX)])
put("iac/.dev.vars", f"API_KEY={HEX}\nSTRIPE_SECRET={STR}\n", [("generic_hex", HEX), ("stripe", STR)])
put("iac/.serverless/cloudformation-template-update-stack.json", json.dumps({"Resources": {"Fn": {"Type": "AWS::Lambda::Function", "Properties": {"Environment": {"Variables": {"STRIPE_KEY": STR, "DB_PASSWORD": PW}}}}}}, indent=2), [("stripe", STR), ("db_pw", PW)])
put("iac/supabase/config.toml", f'[auth.external.github]\nenabled = true\nclient_id = "Iv1.0123456789abcdef"\nsecret = "{HEX}"\n', [("generic_hex", HEX)])
put("iac/wp-config.php", f"<?php\ndefine( 'DB_PASSWORD', '{PW}' );\ndefine( 'AUTH_KEY', '{WPSALT}' );\n", [("db_pw", PW), ("wp_salt", WPSALT)])
put("iac/.github/workflows/deploy.yml", f"name: deploy\non: push\njobs:\n  d:\n    runs-on: ubuntu-latest\n    env:\n      GH_TOKEN: {GH}\n    steps:\n      - run: echo hi\n", [("gh", GH)])
put("iac/docker-compose.yml", f"services:\n  db:\n    image: postgres\n    environment:\n      POSTGRES_PASSWORD: {PW}\n  api:\n    environment:\n      - STRIPE_SECRET_KEY={STR}\n", [("db_pw", PW), ("stripe", STR)])
put("iac/Dockerfile", f"FROM node:22\nENV GITHUB_TOKEN={GH}\nARG NPM_TOKEN={HEX}\n", [("gh", GH), ("generic_hex", HEX)])

# ---- base64 / encoded containers
put("enc/secret.yaml", f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\ndata:\n  token: {b64(GH)}\n  anthropic: {b64(ANT)}\n", [("gh_b64", GH), ("ant_b64", ANT)])
dcj = {"auths": {"ghcr.io": {"auth": b64("someone:" + GH)}}}
put("enc/.dockerconfigjson", json.dumps(dcj, indent=2), [("gh_in_basic_b64", GH)])
put("enc/basic.txt", f"Authorization: Basic {b64('svc:' + GH)}\n", [("gh_in_basic_b64", GH)])
put("enc/double_b64.yaml", f"data:\n  .dockerconfigjson: {b64(json.dumps(dcj))}\n", [("gh_double_b64", GH)])

# ---- notebooks
nb = {"cells": [{"cell_type": "code", "execution_count": 1, "metadata": {}, "outputs": [{"name": "stdout", "output_type": "stream", "text": ["sk set\n"]}], "source": [f'import os\n', f'os.environ["ANTHROPIC_API_KEY"] = "{ANT}"\n']}, {"cell_type": "code", "execution_count": 2, "metadata": {}, "outputs": [{"name": "stdout", "output_type": "stream", "text": [l + "\n" for l in SSHKEY.strip().splitlines()]}], "source": ["print(open('k').read())"]}], "metadata": {}, "nbformat": 4, "nbformat_minor": 5}
put("nb/analysis.ipynb", json.dumps(nb, indent=1), [("anthropic", ANT), ("ssh_body", ssh_body[:60])])

# ---- browser sessions
state = {"cookies": [{"name": "sessionid", "value": HEX64, "domain": ".example.com", "path": "/", "expires": 1795000000, "httpOnly": True, "secure": True, "sameSite": "Lax"}], "origins": [{"origin": "https://example.com", "localStorage": [{"name": "access_token", "value": JWT}]}]}
put("browser/playwright/.auth/user.json", json.dumps(state, indent=2), [("cookie_hex64", HEX64), ("jwt", JWT)])
put("browser/cookies.txt", f"# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tTRUE\t1795000000\tsessionid\t{HEX64}\n", [("cookie_hex64", HEX64)])

# ---- key files
put("keys/AuthKey_ABC123DEFG.p8", P8, [("p8_body", p8_body[:60])])
put("keys/id_ed25519", SSHKEY, [("ssh_body", ssh_body[:60])])

(out / "planted.json").write_text(json.dumps(planted))
print(f"wrote {len(planted)} files, {sum(len(v) for v in planted.values())} planted values")
