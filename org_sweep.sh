#!/usr/bin/env bash
# Sweep dotCMS repos for the PolinRider implant.
#
#   org_sweep.sh                          # every repo in the default orgs
#   org_sweep.sh --orgs dotCMS            # one org
#   org_sweep.sh --repos dotCMS/support   # named repos only
#   org_sweep.sh --local /path/to/repo    # an existing clone, no network
#   org_sweep.sh --deep                   # every commit, not just ref tips (slow)
#
# Token: $GH_TOKEN, $GITHUB_TOKEN, or `gh auth token`. NOT argv - a token on the
# command line is visible to every user on the box via ps.
#
# Output: one machine-readable line per repo -> RESULT <repo> <verdict> <hits>
#         verdicts: INFECTED · NO_REF_HITS · UNKNOWN
# Exit:   0 no ref hits anywhere · 1 at least one INFECTED · 2 usage/engine failure
#
# THERE IS NO "CLEAN" VERDICT, deliberately. This sweep clones with --mirror,
# which fetches refs. An object reachable from no ref is never looked at, and
# GitHub keeps serving such objects by SHA long after a squash orphans them --
# four payload blobs were retrieved that way from repos this sweep had called
# clean. So the strongest thing a green run can say is NO_REF_HITS: no ref in
# this repo reaches the implant. It cannot say the implant is gone.
# --deep does not close that gap either: `git rev-list --all` still walks only
# what is reachable. Orphaned objects cannot be enumerated at all -- verifying
# them is a per-SHA check against a catalogue, not a scan.
#
# ---------------------------------------------------------------------------
# Every failure this script has had reported a poisoned repo as CLEAN, so the
# rules below are written against that direction specifically:
#
#   * The engine is self-tested before any repo is scanned. The previous version
#     called `rg` with no fallback; where rg is only a shell function (common -
#     `command -v rg` succeeds in zsh and fails inside bash) the command failed,
#     $hits came back empty, and every repo printed "HEAD clean".
#   * The campaign tag is matched as a PATTERN. The previous version grepped the
#     literal 'A9-3727', which is the obfuscator.io build. The older _$_ build
#     writes global['!']='9-3727-2' with no A and was invisible to the sweep.
#   * Whitespace padding is checked over the WHOLE file. The previous version
#     used `tail -c 2000`, but the padding sits at the START of the payload, so
#     the last 2000 bytes are pure payload containing no spaces at all.
#   * Nothing is capped silently. Ref batching, clone failures and truncation
#     are all printed. A silent cap reads as coverage.
# ---------------------------------------------------------------------------

set -uo pipefail

ORGS="dotCMS dotcms-community"
REPOS_ARG=""
LOCAL_PATH=""
DEEP=0
ALLOWLIST="${POLINRIDER_ALLOWLIST:-}"
WD="${POLINRIDER_WORKDIR:-/tmp/org_sweep}"
BATCH=100

while [ $# -gt 0 ]; do
  case "$1" in
    --orgs)    ORGS=$(echo "${2:?}" | tr ',' ' '); shift 2 ;;
    --repos)   REPOS_ARG=$(echo "${2:?}" | tr ',' ' '); shift 2 ;;
    --local)   LOCAL_PATH="${2:?}"; shift 2 ;;
    --deep)    DEEP=1; shift ;;
    --allowlist) ALLOWLIST="${2:?}"; shift 2 ;;
    --workdir) WD="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

# --- indicators -------------------------------------------------------------
# Fixed strings. Regex-escaping these is a reliable source of silent misses.
SIGS=(
  'rmcej%otb%'
  'wuqktamceigynzbosdctpusocrjhrflovnxrt'
  'helloipbot'
  "'Sec-V'"          # quoted object key; the bare form Sec-V: matches nothing real
  'AUTH_API_KEY'     # bare: also catches the .env carrier, which atob(process.env.* cannot
)
# Campaign build marker as a pattern, so it survives build-number rotation:
#   global.i="A9-3727-2"     obfuscator.io build
#   global['!']='9-3727-2'   older _$_ shuffle build
BUILD_MARKER='global(\.i|\[.!.\])[[:space:]]*=[[:space:]]*["'"'"']A?[0-9]-[0-9]{4}-[0-9]'
# Payload appended past the right edge of a diff view. Observed at 507; 200 for
# headroom. Not a line-length rule: minification strips whitespace, so vendored
# bundles have long lines and no long space runs.
WSRUN=' {200,}[^ ]'

# Verdicts are appended to a file, not a variable: scan_repo runs inside a
# subshell (cd + scan), so a counter incremented there is lost on return and the
# summary would always report zero infected.
VERDICTS=$(mktemp "${TMPDIR:-/tmp}/polinrider_verdicts.XXXXXX")
trap 'rm -f "$VERDICTS"' EXIT
note() { printf 'NOTE  %s\n' "$*" >&2; }
skip() { printf 'SKIP  %s\n' "$*" >&2; }
die()  { printf 'ABORT %s\n' "$*" >&2; exit 2; }

# Printed on EVERY exit path that is not an abort, --local included. A caveat
# that only prints on one code path is how a partial result gets read as total.
coverage_note() {
  echo "COVERAGE: refs only. Objects reachable from no ref (orphaned by a squash,"
  echo "          still served by GitHub on request by SHA) are NOT covered by this"
  echo "          run and cannot be enumerated. Verify those per-SHA against the"
  echo "          incident catalogue."
}

# The scan chdirs into each mirror clone, so a relative allowlist path would stop
# resolving there and every entry would silently stop applying. Resolve it once.
if [ -n "$ALLOWLIST" ]; then
  case "$ALLOWLIST" in
    /*) : ;;
    *)  ALLOWLIST="$PWD/$ALLOWLIST" ;;
  esac
  [ -f "$ALLOWLIST" ] || die "allowlist not found: $ALLOWLIST"
fi

# --- allowlist --------------------------------------------------------------
# Detection tooling matches its own indicators: this repo, the incident report,
# and Scott's handoff all quote the three terms as text. Without a way to say so,
# a nightly sweep is permanently red and people stop reading it.
#
# Format: one `owner/repo:path-glob` per line, plus a mandatory `# why:` comment
# on the preceding line. Entries are matched per finding and the finding is still
# PRINTED, tagged SUPPRESSED, and counted separately - it never silently
# disappears. Every entry is a permanent hole; narrow the pattern before widening
# this file, and never allowlist a whole repository.
N_SUPPRESSED=0
is_allowlisted() {   # $1 = repo label, $2 = "<ref>:<path>"
  [ -n "$ALLOWLIST" ] || return 1
  [ -f "$ALLOWLIST" ] || return 1
  local path="${2#*:}" line pat
  while IFS= read -r line; do
    case "$line" in ''|'#'*) continue ;; esac
    pat="${line%%[[:space:]]*}"
    case "$pat" in
      "$1":*) case "$path" in ${pat#*:}) return 0 ;; esac ;;
    esac
  done < "$ALLOWLIST"
  return 1
}

# --- engine self-test -------------------------------------------------------
# Proves git grep can match each rule before any repo is called clean.
selftest() {
  local t; t=$(mktemp -d); local rc=0
  git -C "$t" init -q 2>/dev/null || die "self-test: git init failed"
  printf 'x%sy\n' "$(printf '%*s' 250 '')" > "$t/pad.js"
  printf "global['!']='9-3727-2';\n" > "$t/marker.js"
  { for s in "${SIGS[@]}"; do printf '%s\n' "$s"; done; } > "$t/sigs.js"
  git -C "$t" add -A -f >/dev/null 2>&1
  git -C "$t" -c user.email=t@t -c user.name=t commit -qm t >/dev/null 2>&1 || die "self-test: commit failed"
  for s in "${SIGS[@]}"; do
    git -C "$t" grep -qlF -e "$s" HEAD -- sigs.js || { rc=1; note "self-test FAILED for literal: $s"; }
  done
  git -C "$t" grep -qlE -e "$BUILD_MARKER" HEAD -- marker.js || { rc=1; note "self-test FAILED for build marker"; }
  git -C "$t" grep -qlIE -e "$WSRUN" HEAD -- pad.js || { rc=1; note "self-test FAILED for whitespace run"; }
  git -C "$t" grep -qlIE -e "$WSRUN" HEAD -- marker.js && { rc=1; note "self-test FAILED: whitespace rule matched a negative control"; }
  rm -rf "$t"
  [ $rc -eq 0 ] || die "engine self-test failed - refusing to report anything as clean"
  note "engine self-test ok (git $(git --version | awk '{print $3}'))"
}

# --- scanning ---------------------------------------------------------------
# git grep over a batch of revs. Separates "no match" (rc 1) from "failed" (rc>1);
# a failure is reported, never treated as a clean result.
grep_revs() {   # $1=label  $2=mode(F|E|IE)  $3=pattern-or-@SIGS  rest=revs
  local label="$1" mode="$2" pat="$3"; shift 3
  local -a args=(); local err out rc
  case "$mode" in
    F)  if [ "$pat" = "@SIGS" ]; then for s in "${SIGS[@]}"; do args+=(-e "$s"); done
        else args+=(-e "$pat"); fi; args=(-lF "${args[@]}") ;;
    E)  args=(-lE -e "$pat") ;;
    IE) args=(-lIE -e "$pat") ;;
  esac
  err=$(mktemp)
  out=$(git grep "${args[@]}" "$@" 2>"$err"); rc=$?
  if [ $rc -gt 1 ]; then
    skip "$label did not run (git grep rc=$rc): $(head -1 "$err") - this repo is NOT proven clean"
    rm -f "$err"; return 2
  fi
  rm -f "$err"
  [ -n "$out" ] && printf '%s\n' "$out"
  return 0
}

scan_repo() {   # $1 = repo label, cwd = a git dir
  local label="$1" hits=0 nrefs=0 nbatch=0 failed=0
  local revfile; revfile=$(mktemp)

  if [ "$DEEP" = 1 ]; then
    git rev-list --all > "$revfile" 2>/dev/null
    note "$label: DEEP mode - every commit"
  else
    git for-each-ref --format='%(refname)' > "$revfile" 2>/dev/null
  fi
  nrefs=$(wc -l < "$revfile" | tr -d ' ')
  if [ "$nrefs" -eq 0 ]; then
    skip "$label: no refs found"; rm -f "$revfile"
    printf 'RESULT %s UNKNOWN 0\n' "$label"; printf 'UNKNOWN\n' >> "$VERDICTS"; return
  fi

  local pullrefs; pullrefs=$(grep -c '^refs/pull/' "$revfile" || true)
  note "$label: $nrefs revs to scan ($pullrefs pull refs), batches of $BATCH"

  local bdir; bdir=$(mktemp -d); split -l "$BATCH" "$revfile" "$bdir/b"
  local b
  for b in "$bdir"/b*; do
    nbatch=$((nbatch+1))
    local -a revs=(); while IFS= read -r r; do revs+=("$r"); done < "$b"
    local o line
    report() {   # $1 = finding class, stdin = "<ref>:<path>" lines
      while IFS= read -r line; do
        [ -n "$line" ] || continue
        if is_allowlisted "$label" "$line"; then
          printf '  ... SUPPRESSED %s  %s\n' "$1" "$line"
          N_SUPPRESSED=$((N_SUPPRESSED+1))
        else
          printf '  !!! %s  %s\n' "$1" "$line"
          hits=$((hits+1))
        fi
      done
    }
    o=$(grep_revs "$label sig" F @SIGS "${revs[@]}") || failed=1
    [ -n "$o" ] && report SIGNATURE <<< "$o"
    o=$(grep_revs "$label marker" E "$BUILD_MARKER" "${revs[@]}") || failed=1
    [ -n "$o" ] && report BUILD-MARKER <<< "$o"
    o=$(grep_revs "$label wsrun" IE "$WSRUN" "${revs[@]}") || failed=1
    [ -n "$o" ] && report WHITESPACE-PAD <<< "$o"
    o=$(grep_revs "$label gitignore" F 'config.bat' "${revs[@]}" -- '*.gitignore' '.gitignore') || failed=1
    [ -n "$o" ] && report GITIGNORE-CONFIG.BAT <<< "$o"
  done
  rm -rf "$bdir" "$revfile"
  note "$label: $nbatch batch(es) completed, $N_SUPPRESSED allowlisted finding(s) suppressed"

  local verdict
  if [ "$hits" -gt 0 ]; then verdict=INFECTED
  elif [ "$failed" = 1 ]; then verdict=UNKNOWN
  # NO_REF_HITS, never CLEAN: see the header. No ref reaches a signature; that
  # is not the same claim as the repo being free of the implant.
  else verdict=NO_REF_HITS; fi
  printf 'RESULT %s %s %s\n' "$label" "$verdict" "$hits"
  printf '%s\n' "$verdict" >> "$VERDICTS"
  [ "$verdict" = INFECTED ] && return 1
  return 0
}

# --- main -------------------------------------------------------------------
selftest

if [ -n "$LOCAL_PATH" ]; then
  [ -d "$LOCAL_PATH" ] || die "no such directory: $LOCAL_PATH"
  echo "===== local: $LOCAL_PATH ====="
  ( cd "$LOCAL_PATH" && scan_repo "$(basename "$LOCAL_PATH")" ) || true
  coverage_note
  grep -q '^INFECTED$' "$VERDICTS" && exit 1
  grep -q '^UNKNOWN$'  "$VERDICTS" && exit 2
  exit 0
fi

TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-$(gh auth token 2>/dev/null)}}"
[ -n "$TOKEN" ] || die "no token: set GH_TOKEN/GITHUB_TOKEN or run gh auth login"
mkdir -p "$WD" || die "cannot create workdir $WD"

REPO_LIST=$(mktemp)
if [ -n "$REPOS_ARG" ]; then
  printf '%s\n' $REPOS_ARG > "$REPO_LIST"
else
  for o in $ORGS; do
    # type=all so private repos are included; --paginate so nothing is capped.
    gh api "orgs/$o/repos?per_page=100&type=all" --paginate \
       --jq '.[] | select(.archived == false) | .full_name' >> "$REPO_LIST" 2>/dev/null \
      || skip "could not enumerate org $o - its repos are NOT covered by this run"
  done
fi
NREPOS=$(wc -l < "$REPO_LIST" | tr -d ' ')
note "sweeping $NREPOS repo(s) from: $ORGS   (archived repos excluded)"

while IFS= read -r full; do
  [ -n "$full" ] || continue
  echo "===== $full ====="
  d="$WD/$(echo "$full" | tr '/' '_').git"
  rm -rf "$d"
  # --mirror: a normal clone does not fetch refs/pull/*, and poisoned blobs are
  # still sitting in those refs. They are read-only, so they can only be reported.
  if ! git clone --mirror -q "https://x-access-token:${TOKEN}@github.com/${full}.git" "$d" 2>/dev/null; then
    skip "$full: CLONE FAILED (no access?) - NOT scanned"
    printf 'RESULT %s UNKNOWN 0\n' "$full"
    printf 'UNKNOWN\n' >> "$VERDICTS"
    continue
  fi
  ( cd "$d" && scan_repo "$full" ) || true
  rm -rf "$d"
done < "$REPO_LIST"
rm -f "$REPO_LIST"

N_INF=$(grep -c '^INFECTED$' "$VERDICTS" || true)
N_UNK=$(grep -c '^UNKNOWN$'  "$VERDICTS" || true)
N_CLN=$(grep -c '^NO_REF_HITS$' "$VERDICTS" || true)
echo
echo "SWEEP COMPLETE: $NREPOS requested | $N_CLN with no ref hits | $N_INF infected | $N_UNK not scanned"
coverage_note
# UNKNOWN is not clean. A repo that failed to clone or whose engine errored has
# been proven nothing, and saying so is the whole point of the exit codes.
[ "$N_INF" -gt 0 ] && exit 1
[ "$N_UNK" -gt 0 ] && exit 2
exit 0
