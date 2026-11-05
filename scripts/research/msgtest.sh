#!/bin/zsh
# Plants a fake token in a commit message, a tag annotation and a branch name inside a throwaway repo,
# then asks each engine in git mode whether it sees it. Prints only counts.
#
#   msgtest.sh OUT_DIR
#
# OUT_DIR must be new or empty; the repo and the engine reports are written under it. Engines are
# $KEYGUARD_BETTERLEAKS, $KEYGUARD_GITLEAKS, $KEYGUARD_TRUFFLEHOG and $KEYGUARD_TITUS, or the first
# of each on PATH (docs/STEAL.md P0-13: betterleaks 0, gitleaks 0, trufflehog 1, titus 2).
set -u
[[ $# -eq 1 ]] || { print -u2 "usage: msgtest.sh OUT_DIR"; exit 2; }
R=$1
if [[ -d $R && -n "$(ls -A $R)" ]]; then
  print -u2 "error: $R is not empty; pass a new directory"
  exit 2
fi
engine() {  # engine NAME -> its path, or exit
  local var=KEYGUARD_${(U)1}
  local p=${(P)var:-$(command -v $1)}
  [[ -n $p && -x $p ]] || { print -u2 "error: $1 not found; set $var"; exit 2; }
  print -r -- $p
}
BL=$(engine betterleaks); GL=$(engine gitleaks); TH=$(engine trufflehog); TI=$(engine titus)

mkdir -p $R/repo && cd $R/repo
# no user git config: keyguard's own hooks would, rightly, refuse to commit the fake
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
git init -q -b main .
git config user.email t@example.com; git config user.name t
TOK=$(python3 -c "
import random,string,zlib
r=random.SystemRandom();B=string.digits+string.ascii_uppercase+string.ascii_lowercase
body=''.join(r.choice(string.ascii_letters+string.digits) for _ in range(30))
n=zlib.crc32(body.encode())&0xffffffff;s=''
while n: n,x=divmod(n,62); s=B[x]+s
print('ghp_'+body+s.rjust(6,'0'))")
echo hello > a.txt; git add a.txt
git commit -q -m "fix: use token $TOK for CI"
git tag -a v1 -m "release with $TOK"
git branch "feature/$TOK"
echo "$TOK" > $R/tok.txt
count() { grep -c "$TOK" "$1" 2>/dev/null; }
# titus compiles its rules into a cache; keep it inside OUT_DIR, not the user's home
export TITUS_CACHE_DIR=$R/titus-cache; mkdir -p $TITUS_CACHE_DIR
$BL git . -f json -r $R/m-bl.json --no-banner -l error --exit-code 0; echo "betterleaks: findings=$(python3 -c "import json;print(len(json.load(open('$R/m-bl.json'))))") tokenInOutput=$(count $R/m-bl.json)"
$GL git . -f json -r $R/m-gl.json --no-banner -l error --exit-code 0; echo "gitleaks: findings=$(python3 -c "import json;print(len(json.load(open('$R/m-gl.json'))))") tokenInOutput=$(count $R/m-gl.json)"
$TH git file://$PWD --json --no-verification --no-update > $R/m-th.jsonl 2>/dev/null; echo "trufflehog: findings=$(grep -c '^{' $R/m-th.jsonl) tokenInOutput=$(count $R/m-th.jsonl)"
$TI scan . --git --format json --output :memory: -q > $R/m-ti.json 2>/dev/null; echo "titus: findings=$(python3 -c "import json;print(len(json.load(open('$R/m-ti.json'))))")"
# what does git itself expose
echo "msg-scan via git log: $(git log --all --format=%B | grep -c "$TOK") ; tag: $(git for-each-ref --format='%(contents)' refs/tags | grep -c "$TOK") ; branch: $(git for-each-ref --format='%(refname)' refs/heads | grep -c "$TOK")"
