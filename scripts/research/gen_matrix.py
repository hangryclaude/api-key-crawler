#!/usr/bin/env python3
"""Build fake provider keys at runtime (never literal) into one file per plant.

    python3 gen_matrix.py OUT_DIR

OUT_DIR must be new or empty. It gets one small file per plant and context, 137 files in all
(67 providers x 2 contexts, plus the Google service-account and Firebase admin files), each
holding exactly one fake secret. multi_draw.py repeats this and counts a plant as found when an
engine reports anything in its file. docs/STEAL.md counts 139 files per draw (834 over six). The
generator recovered from the research transcripts made 137, with Telegram and Discord tokens in a shape no
real token has, so that the rules written for those formats could not match them; those fakes are now
built in the real shape (see tg_secret and snowflake_b64), and the claude.ai session token, which one of
the rules names and which the recovered file did not plant, is back. That makes 139 files.

Contexts:
  named : realistic env-var line (provider-typical variable name)
  bare  : the token alone in a prose comment, no variable name / keyword
"""
import os
import random
import string
import sys
import base64
import json

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common

if len(sys.argv) != 2:
    common.die("usage: gen_matrix.py OUT_DIR")
out = sys.argv[1]
common.empty_dir(out)
rnd = random.SystemRandom()

AN = string.ascii_letters + string.digits
ANU = AN + "_-"
HEX = "0123456789abcdef"
UP = string.ascii_uppercase + string.digits
B32 = string.ascii_uppercase + "234567"


def r(cs, n):
    return "".join(rnd.choice(cs) for _ in range(n))


def b64url(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def jwt(payload):
    h = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = b64url(json.dumps(payload).encode())
    return h + "." + p + "." + r(ANU, 43)


def snowflake_b64():
    """The first segment of a Discord bot token: the bot's user id, 18 digits, in base64url without padding.

    Its first two characters are therefore one of MT, Mj, Mz, ND, NT, Nj, Nz, OD, OT, which is what the
    keyguard rule for these tokens keys on.
    """
    sid = str(rnd.randint(1, 9)) + "".join(rnd.choice(string.digits) for _ in range(17))
    return b64url(sid.encode())


def tg_secret():
    """A Telegram bot secret: 35 characters, the first an A (the rule betterleaks ships requires exactly that)."""
    return "AA" + r(ANU, 33)


def uuid_like():
    return "-".join([r(HEX, 8), r(HEX, 4), r(HEX, 4), r(HEX, 4), r(HEX, 12)])


def luhn_card():
    digits = [4] + [rnd.randint(0, 9) for _ in range(14)]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    check = (10 - total % 10) % 10
    return "".join(map(str, digits)) + str(check)


def pem(kind, lines=26):
    body = "\n".join(r(string.ascii_letters + string.digits + "+/", 64) for _ in range(lines))
    return "-----BEGIN %s-----\n%s\n-----END %s-----" % (kind, body, kind)


plants = {}  # id -> (named_line, bare_value)


def add(pid, name, value, fmt=None):
    named = (fmt or "{name}={value}").format(name=name, value=value)
    plants[pid] = (named, value)


add("anthropic_api", "ANTHROPIC_API_KEY", "sk-ant-api03-" + r(ANU, 93) + "AA")
add("anthropic_admin", "ANTHROPIC_ADMIN_KEY", "sk-ant-admin01-" + r(ANU, 93) + "AA")
add("anthropic_oauth_access", "CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-oat01-" + r(ANU, 93) + "AA")
add("anthropic_oauth_refresh", "CLAUDE_REFRESH", "sk-ant-ort01-" + r(ANU, 93) + "AA")
add("anthropic_session", "CLAUDE_AI_SESSION", "sk-ant-sid01-" + r(ANU, 93) + "AA")
add("openai_legacy_marker", "OPENAI_API_KEY", "sk-proj-" + r(ANU, 74) + "T3BlbkFJ" + r(ANU, 74))
add("openai_no_marker", "OPENAI_API_KEY", "sk-proj-" + r(ANU, 156))
add("github_pat_classic", "GITHUB_TOKEN", "ghp_" + r(AN, 36))
add("github_oauth", "GH_OAUTH", "gho_" + r(AN, 36))
add("github_fine_grained", "GH_PAT", "github_pat_" + r(AN + "_", 82))
add("aws_key_id", "AWS_ACCESS_KEY_ID", "AKIA" + r(B32, 16))
add("aws_secret", "AWS_SECRET_ACCESS_KEY", r(AN + "/+", 40))
add("stripe_sk_live", "STRIPE_SECRET_KEY", "sk_live_" + r(AN, 24))
add("stripe_rk_live", "STRIPE_RESTRICTED_KEY", "rk_live_" + r(AN, 24))
add("stripe_whsec", "STRIPE_WEBHOOK_SECRET", "whsec_" + r(AN, 32))
add("slack_bot", "SLACK_BOT_TOKEN", "xoxb-" + r(string.digits, 12) + "-" + r(string.digits, 13) + "-" + r(AN, 24))
add("slack_app", "SLACK_APP_TOKEN", "xapp-1-A" + r(UP, 10) + "-" + r(string.digits, 13) + "-" + r(HEX, 64))
add("slack_webhook", "SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T" + r(UP, 10) + "/B" + r(UP, 10) + "/" + r(AN, 24))
add("discord_bot", "DISCORD_BOT_TOKEN", snowflake_b64() + "." + r(ANU, 6) + "." + r(ANU, 38))
add("discord_bot_noname", "BOT_TOKEN", snowflake_b64() + "." + r(ANU, 6) + "." + r(ANU, 38))
add("discord_webhook", "DISCORD_WEBHOOK", "https://discord.com/api/webhooks/" + r(string.digits, 19) + "/" + r(ANU, 68))
add("telegram_bot", "TELEGRAM_BOT_TOKEN", r(string.digits, 10) + ":" + tg_secret())
add("telegram_bot_noname", "BOT_TOKEN", r(string.digits, 10) + ":" + tg_secret())
add("google_aiza", "GOOGLE_API_KEY", "AIza" + r(ANU, 35))
add("gemini_new_aq", "GEMINI_API_KEY", "AQ.Ab8RN6" + r(ANU, 44))
add("fcm_legacy", "FCM_SERVER_KEY", "AAAA" + r(ANU, 7) + ":APA91b" + r(ANU, 134))
add("supabase_service_role_jwt", "SUPABASE_SERVICE_ROLE_KEY",
    jwt({"iss": "supabase", "ref": r(string.ascii_lowercase, 20), "role": "service_role", "iat": 1700000000, "exp": 2000000000}))
add("supabase_anon_jwt", "SUPABASE_ANON_KEY",
    jwt({"iss": "supabase", "ref": r(string.ascii_lowercase, 20), "role": "anon", "iat": 1700000000, "exp": 2000000000}))
add("supabase_sb_secret", "SUPABASE_SECRET_KEY", "sb_secret_" + r(ANU, 31))
add("supabase_mgmt", "SUPABASE_ACCESS_TOKEN", "sbp_" + r(HEX, 40))
add("vercel_vcp", "VERCEL_TOKEN", "vcp_" + r(ANU, 56))
add("vercel_legacy24", "VERCEL_TOKEN", r(string.ascii_uppercase + string.digits, 24))
add("cloudflare_token40", "CLOUDFLARE_API_TOKEN", r(ANU, 40))
add("cloudflare_token40_cfname", "CF_API_TOKEN", r(ANU, 40))
add("fal_key", "FAL_KEY", uuid_like() + ":" + r(HEX, 32))
add("replicate", "REPLICATE_API_TOKEN", "r8_" + r(AN, 37))
add("huggingface", "HF_TOKEN", "hf_" + r(string.ascii_letters, 34))
add("groq", "GROQ_API_KEY", "gsk_" + r(AN, 52))
add("xai", "XAI_API_KEY", "xai-" + r(AN, 80))
add("openrouter", "OPENROUTER_API_KEY", "sk-or-v1-" + r(HEX, 64))
add("elevenlabs_new", "ELEVENLABS_API_KEY", "sk_" + r(HEX, 48))
add("elevenlabs_xi_name", "XI_API_KEY", "sk_" + r(HEX, 48))
add("twilio_sk", "TWILIO_API_KEY", "SK" + r(HEX, 32))
add("twilio_ac_sid", "TWILIO_ACCOUNT_SID", "AC" + r(HEX, 32))
add("twilio_auth_token", "TWILIO_AUTH_TOKEN", r(HEX, 32))
add("sendgrid", "SENDGRID_API_KEY", "SG." + r(ANU, 22) + "." + r(ANU, 43))
add("mailgun_key", "MAILGUN_API_KEY", "key-" + r(HEX, 32))
add("shopify_shpat", "SHOPIFY_ACCESS_TOKEN", "shpat_" + r(HEX, 32))
add("npm", "NPM_TOKEN", "npm_" + r(AN, 36))
add("pypi", "PYPI_TOKEN", "pypi-" + "AgEIcHlwaS5vcmc" + r(ANU, 70))
add("dockerhub", "DOCKERHUB_TOKEN", "dckr_pat_" + r(ANU, 27))
add("digitalocean", "DIGITALOCEAN_TOKEN", "dop_v1_" + r(HEX, 64))
add("linear", "LINEAR_API_KEY", "lin_api_" + r(AN, 40))
add("notion_new", "NOTION_TOKEN", "ntn_" + r(string.digits, 11) + r(AN, 35))
add("notion_legacy", "NOTION_TOKEN", "secret_" + r(AN, 43))
add("airtable_pat", "AIRTABLE_TOKEN", "pat" + r(AN, 14) + "." + r(HEX, 64))
add("zoom_secret", "ZOOM_CLIENT_SECRET", r(AN, 32))
add("calcom", "CAL_API_KEY", "cal_live_" + r(HEX, 32))
add("zerobounce", "ZEROBOUNCE_API_KEY", r(HEX, 32))
add("postgres_url", "DATABASE_URL", "postgresql://app_user:" + r(AN, 20) + "@db.example-host.net:5432/appdb")
add("mongo_srv_url", "MONGODB_URI", "mongodb+srv://app_user:" + r(AN, 20) + "@cluster0.abcde.mongodb.net/appdb")
add("redis_url", "REDIS_URL", "rediss://default:" + r(AN, 24) + "@usw1-fake-1234.upstash.io:6379")
add("card_number", "CARD_NUMBER", luhn_card())
add("generic_hex32", "API_KEY", r(HEX, 32))
add("generic_mixed40", "SECRET_KEY", r(AN, 40))
add("private_key_rsa", "PEM", pem("RSA PRIVATE KEY"), fmt="{value}")
add("private_key_openssh", "PEM", pem("OPENSSH PRIVATE KEY"), fmt="{value}")
add("private_key_ec", "PEM", pem("EC PRIVATE KEY", 6), fmt="{value}")

for pid, (named, bare) in plants.items():
    with open(os.path.join(out, pid + "__named.env"), "w") as f:
        f.write("# config\n" + named + "\n")
    with open(os.path.join(out, pid + "__bare.txt"), "w") as f:
        if "PRIVATE KEY" in bare:
            f.write("notes:\n" + bare + "\n")
        else:
            f.write("remember this one for later: " + bare + " (do not share)\n")

# gcp service account json (pretty printed), as downloaded from console
sa = {
    "type": "service_account",
    "project_id": "demo-" + r(string.ascii_lowercase, 6),
    "private_key_id": r(HEX, 40),
    "private_key": pem("PRIVATE KEY", 25).replace("\n", "\\n") + "\\n",
    "client_email": "svc@demo-proj.iam.gserviceaccount.com",
    "client_id": r(string.digits, 21),
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/svc%40demo-proj.iam.gserviceaccount.com",
    "universe_domain": "googleapis.com",
}
with open(os.path.join(out, "gcp_service_account__named.json"), "w") as f:
    json.dump(sa, f, indent=2)
with open(os.path.join(out, "gcp_service_account__bare.txt"), "w") as f:
    f.write("sa: " + json.dumps(sa) + "\n")
with open(os.path.join(out, "firebase_adminsdk__named.json"), "w") as f:
    sa2 = dict(sa)
    sa2["client_email"] = "firebase-adminsdk-abcde@demo-proj.iam.gserviceaccount.com"
    json.dump(sa2, f, indent=2)

print(len(plants) + 3, "plants")
