#!/usr/bin/env bash
# The patrol, ready to be called straight from cron.
#
#   nightly_sweep.sh
#
# org_sweep.sh does the detection. This does the things it cannot do for itself:
# get a credential, work out what is in scope, feed it the repositories in
# batches, and make sure the outcome reaches a person.
#
# Written in bash rather than in the Go service on purpose. Everything here is a
# token, a list and a POST -- curl and openssl do all of it -- and the rest of
# this tool is bash. A second language would mean a compile step and a binary
# only one person touches, for no gain. The Go service exists for the PR check,
# which needs a real HTTP server; the sweep never needed it.
#
# Environment:
#   APP_ID                 required, the GitHub App's numeric id
#   PRIVATE_KEY_PATH       required, path to the App's PEM
#   SLACK_WEBHOOK_ALERT    optional, low detail, safe for a public channel
#   SLACK_WEBHOOK_DETAIL   optional, full findings, keep private
#   HEARTBEAT_PATH         default /var/lib/polinrider/last-success.json
#   BATCH_SIZE             default 30
#   KNOWN_FINDINGS         default known-findings.json beside this script
#   SWEEP_ALLOWLIST        default sweep-allowlist beside this script
#
# Exit: 0 nothing found · 1 something found · 2 the tool refused to run.
#       Never confuse the last two: "we could not check" is not "it is fine".
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SWEEP="$HERE/org_sweep.sh"
ALLOWLIST="${SWEEP_ALLOWLIST:-$HERE/sweep-allowlist}"
KNOWN="${KNOWN_FINDINGS:-$HERE/known-findings.json}"
HEARTBEAT="${HEARTBEAT_PATH:-/var/lib/polinrider/last-success.json}"
BATCH="${BATCH_SIZE:-30}"
API="${GITHUB_API:-https://api.github.com}"

log()  { printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }
die()  { printf 'ABORT %s\n' "$*" >&2; notify broken "*the sweep refused to run.* $*" ""; exit 2; }

# --- notification -----------------------------------------------------------
# A finding with nowhere to go is worse than no finding: it looks quiet. So a
# missing webhook is reported on stderr rather than passing silently.
notify() {   # $1 = info|finding|broken   $2 = headline   $3 = detail
  local icon
  case "$1" in
    finding) icon=':rotating_light:' ;;
    broken)  icon=':warning:' ;;
    *)       icon=':white_check_mark:' ;;
  esac
  local head="$icon *PolinRider sweep* — $2" sent=0

  if [ -n "${SLACK_WEBHOOK_ALERT:-}" ]; then
    # The alert destination may be a public channel, so it carries the headline
    # and never the file paths: a real hit would otherwise name the repository
    # and file to the whole workspace before anyone has triaged it.
    post "$SLACK_WEBHOOK_ALERT" "$head" && sent=$((sent+1))
  fi
  if [ -n "${SLACK_WEBHOOK_DETAIL:-}" ]; then
    local body="$head"
    [ -n "$3" ] && body="$head"$'\n''```'$'\n'"$(printf '%s' "$3" | head -c 3500)"$'\n''```'
    post "$SLACK_WEBHOOK_DETAIL" "$body" && sent=$((sent+1))
  fi
  if [ "$1" != info ] && [ "$sent" -eq 0 ]; then
    printf 'WARNING nothing was notified (no webhook configured): %s\n' "$2" >&2
  fi
}

post() {   # $1 = url, $2 = text
  python3 -c 'import json,sys; print(json.dumps({"text": sys.argv[1]}))' "$2" \
    | curl -sS -X POST -H 'Content-Type: application/json' --data @- --max-time 20 "$1" >/dev/null
}

need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }
need curl; need openssl; need git; need python3

[ -n "${APP_ID:-}" ]          || die "APP_ID is not set"
[ -n "${PRIVATE_KEY_PATH:-}" ] || die "PRIVATE_KEY_PATH is not set"
[ -r "$PRIVATE_KEY_PATH" ]     || die "cannot read the private key at $PRIVATE_KEY_PATH"
[ -x "$SWEEP" ] || [ -r "$SWEEP" ] || die "org_sweep.sh not found next to this script"

# A PEM needs its line breaks. Both keys handed to us so far arrived flattened
# onto one line by a copy-paste, and openssl's failure for that reads like a
# GitHub problem for an hour before anyone looks at the file. Say it plainly.
if ! openssl rsa -in "$PRIVATE_KEY_PATH" -noout -check >/dev/null 2>&1; then
  if ! grep -q '^-----END' "$PRIVATE_KEY_PATH" 2>/dev/null; then
    die "the private key has no line breaks - a PEM needs its header, 64-character body lines and footer on separate lines. It was probably flattened by a copy-paste."
  fi
  die "the private key at $PRIVATE_KEY_PATH is not a usable RSA key"
fi

# --- credential -------------------------------------------------------------
# Mints an installation token. Prints ONLY the token, so it can be captured into
# a variable and never reaches a log line or a process listing.
mint_token() {
  python3 - "$APP_ID" "$PRIVATE_KEY_PATH" "$API" <<'PY'
import base64, json, subprocess, sys, time, urllib.request
app_id, key, api = sys.argv[1], sys.argv[2], sys.argv[3]
b64 = lambda d: base64.urlsafe_b64encode(d).rstrip(b"=").decode()
now = int(time.time())
signing = (b64(json.dumps({"alg":"RS256","typ":"JWT"}).encode()) + "." +
           b64(json.dumps({"iat":now-30,"exp":now+300,"iss":app_id}).encode())).encode()
sig = subprocess.run(["openssl","dgst","-sha256","-sign",key],
                     input=signing, capture_output=True, check=True).stdout
jwt = signing.decode() + "." + b64(sig)

def api_get(url, auth, method="GET"):
    r = urllib.request.Request(url, method=method)
    r.add_header("Authorization", "Bearer " + auth)
    r.add_header("Accept", "application/vnd.github+json")
    with urllib.request.urlopen(r, timeout=30) as resp:
        return json.load(resp)

insts = api_get(f"{api}/app/installations", jwt)
if not insts:
    sys.exit("the App is not installed on any organisation")
print(" ".join(f'{i["id"]}:{i["account"]["login"]}' for i in insts), file=sys.stderr)
print(api_get(f'{api}/app/installations/{insts[0]["id"]}/access_tokens', jwt, "POST")["token"])
PY
}

# Lists what an installation token can actually read. Deliberately not "list the
# org's repositories": the App's own view is the truthful one, and a missing
# installation shows up here as a smaller number rather than as a permission
# error halfway through a scan. Archived repositories are excluded AND counted,
# because a silent exclusion reads as coverage.
list_repos() {   # $1 = token, $2 = file to write the count note into
  python3 - "$1" "$API" "$2" <<'PY'
import json, sys, urllib.request, pathlib
tok, api, note = sys.argv[1], sys.argv[2], sys.argv[3]
repos, archived, page = [], 0, 1
while True:
    r = urllib.request.Request(f"{api}/installation/repositories?per_page=100&page={page}")
    r.add_header("Authorization", "Bearer " + tok)
    r.add_header("Accept", "application/vnd.github+json")
    with urllib.request.urlopen(r, timeout=60) as resp:
        d = json.load(resp)
    batch = d["repositories"]
    if not batch:
        break
    for x in batch:
        if x["archived"]:
            archived += 1
        else:
            repos.append(x["full_name"])
    if len(repos) + archived >= d["total_count"]:
        break
    page += 1
pathlib.Path(note).write_text(f"{len(repos)} {archived}")
print("\n".join(sorted(repos)))
PY
}

# --- run --------------------------------------------------------------------
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
START=$(date -u '+%s')

log "START"
TOKEN=$(mint_token 2>"$WORK/insts") || die "could not mint an installation token"
log "installations: $(tr '\n' ' ' < "$WORK/insts")"

list_repos "$TOKEN" "$WORK/count" > "$WORK/repos" || die "could not list the repositories in scope"
read -r N_SCAN N_ARCH < "$WORK/count"
log "SCOPE $N_SCAN repositories to scan, $N_ARCH archived and skipped"
[ "$N_SCAN" -gt 0 ] || die "the token reaches no repositories at all"

: > "$WORK/log"
n=0; i=0
# read into an array the long way: mapfile is bash 4, and this tool supports the
# bash 3.2 that macOS ships, on purpose.
ALL=()
while IFS= read -r r; do [ -n "$r" ] && ALL+=("$r"); done < "$WORK/repos"
while [ $i -lt ${#ALL[@]} ]; do
  chunk=("${ALL[@]:$i:$BATCH}")
  n=$((n+1))
  # A fresh token per batch. Installation tokens last an hour and the clone URL
  # carries one inline, so a long run starts failing halfway through - as
  # UNKNOWN, correctly, but the work would be wasted.
  TOKEN=$(mint_token 2>/dev/null) || die "batch $n: could not refresh the token"
  log "batch $n: ${#chunk[@]} repositories"
  # tee, not redirect: the operator's log is the record of what was found. A
  # findings file in a tempdir vanishes on exit, and with no webhook configured
  # the run would leave nothing behind at all.
  GH_TOKEN="$TOKEN" bash "$SWEEP" --allowlist "$ALLOWLIST" --repos "${chunk[*]}" 2>&1 \
    | tee -a "$WORK/log"
  i=$((i+BATCH))
done

# --- report -----------------------------------------------------------------
TOOK=$(( $(date -u '+%s') - START ))
INFECTED=$(grep '^RESULT .* INFECTED'    "$WORK/log" | awk '{print $2}' | sort -u)
UNKNOWN=$( grep '^RESULT .* UNKNOWN'     "$WORK/log" | awk '{print $2}' | sort -u)
N_CLEAN=$( grep -c '^RESULT .* NO_REF_HITS' "$WORK/log" || true)
N_EMPTY=$( grep -c '^RESULT .* EMPTY'       "$WORK/log" || true)
N_SUSP=$(  grep -c '^RESULT .* SUSPICIOUS'  "$WORK/log" || true)

# Known findings are malware we have already inventoried and cannot yet remove -
# the May payload in read-only pull-request refs, waiting on GitHub Support.
# Reported and counted every night, but not an alarm: paging someone nightly for
# it is how the night something NEW appears becomes the night nobody looks.
python3 - "$KNOWN" "$WORK/log" "$WORK/novel" "$WORK/known" <<'PY'
import json, pathlib, sys, re
known_file, logf, novel_out, known_out = sys.argv[1:5]
try:
    entries = json.loads(pathlib.Path(known_file).read_text())["findings"]
except FileNotFoundError:
    entries = []                      # nothing accounted for yet: all is new
except Exception as e:
    sys.exit(f"known-findings file is unreadable: {e}")
idx = {(e["repo"], e["ref"], e["path"]) for e in entries}
repo, novel, known = "", [], []
for line in pathlib.Path(logf).read_text().splitlines():
    t = line.strip()
    m = re.match(r'^=====\s+(\S+)\s+=====$', t)
    if m: repo = m.group(1); continue
    # RESULT comes AFTER the findings for that repository, so it cannot be what
    # sets the current repo -- it only confirms it.
    m = re.match(r'^RESULT (\S+)', t)
    if m: repo = m.group(1); continue
    if not t.startswith("!!!"): continue
    tail = t.split()[-1]
    ref, _, path = tail.partition(":")
    (known if (repo, ref, path) in idx else novel).append(t)
pathlib.Path(novel_out).write_text("\n".join(novel))
pathlib.Path(known_out).write_text("\n".join(known))
PY
[ $? -eq 0 ] || die "could not read the known-findings list"

N_NOVEL=$(grep -c . "$WORK/novel" 2>/dev/null || true)
N_KNOWN=$(grep -c . "$WORK/known" 2>/dev/null || true)

SUMMARY="$N_SCAN scanned · $N_CLEAN no ref hits · $N_EMPTY empty · $N_SUSP shape-only · $(echo "$INFECTED" | grep -c . ) infected · $(echo "$UNKNOWN" | grep -c .) not scanned · $N_KNOWN known · ${TOOK}s"
log "SWEEP COMPLETE: $SUMMARY"
log "COVERAGE refs only; objects reachable from no ref are not covered by this method and cannot be enumerated"

if [ "$N_NOVEL" -gt 0 ]; then
  notify finding "*$N_NOVEL NEW finding(s).* $SUMMARY" "$(cat "$WORK/novel")"
  printf '%s\n' "$INFECTED"; exit 1
fi
if [ -n "$INFECTED" ] || [ -n "$UNKNOWN" ]; then
  notify info "nothing new; $N_KNOWN known finding(s) still pending removal. $SUMMARY" "$(cat "$WORK/known")"
  exit 1
fi

notify info "clean run. $SUMMARY" ""
mkdir -p "$(dirname "$HEARTBEAT")" 2>/dev/null
printf '{"last_success":"%s","scanned":%s,"took_seconds":%s}\n' \
  "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$N_SCAN" "$TOOK" > "$HEARTBEAT" 2>/dev/null \
  || printf 'WARNING could not write the heartbeat at %s\n' "$HEARTBEAT" >&2
exit 0
