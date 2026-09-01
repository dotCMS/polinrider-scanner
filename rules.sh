#!/usr/bin/env bash
# PolinRider detection rules — the single source of truth.
#
#   . "$(dirname "$0")/rules.sh"
#
# Sourced by polinrider_scan.sh (host scan) and org_sweep.sh (repo sweep), and
# intended as the definition the PR check consumes too. Nothing else may define
# a signature inline: test_rules_single_source.sh fails the build if it does.
#
# WHY THIS FILE EXISTS
# The rules used to live in each script separately and they drifted. The sweep
# kept matching the campaign tag as the literal 'A9-3727' long after the scanner
# had generalised it, which made the sweep blind to the wave-1 variant across
# every repository it was ever run on. Nobody noticed, because the failure mode
# is a clean result.
#
# BASH 3.2. macOS ships bash 3.2 and the scanner supports it on purpose, so:
# no associative arrays, no `declare -n`, no ${var^^}.
#
# ---------------------------------------------------------------------------
# VALIDATION STATUS
# Every rule below is checked against four byte-exact carriers supplied by the
# IR lead on 2026-08-27 (SHA256-verified; live malware, held outside any repo).
# The claims in the comments are measurements, not inferences from a write-up.
# ---------------------------------------------------------------------------

POLINRIDER_RULES_VERSION="2026-08-27.1"

# ===========================================================================
# 1. HARD SIGNATURES — fixed strings, never regex.
# Regex-escaping '_$_' and the quotes in 'Sec-V' is a documented source of
# silent non-matches, so every consumer must use fixed-string matching (-F).
# ===========================================================================

# 1a. Safe as a HARD indicator in ANY context, host or repo. These two are
#     meaningless strings with no observed collision anywhere -- not in source,
#     not in documentation, not in tool caches.
POLINRIDER_SIGS_CORE=(
  'rmcej%otb%'                              # layer-1 string
  'wuqktamceigynzbosdctpusocrjhrflovnxrt'   # scrambled constructor
)

# 1b. Hard indicators for a REPO scan only.
#
#     Deliberately NOT hard on a host scan. On a workstation these appear as
#     quoted text in Claude Code transcripts (~/.claude/projects/**/*.jsonl)
#     wherever anyone had the assistant read a poisoned file, and the bare key
#     name also collides with documentation and tool caches -- both are recorded
#     FP classes, and HANDOFF.md item 8a carries a regression guard pinning the
#     bare-key behaviour. The host scanner keeps them informational.
#
#     In a repo sweep that surface does not exist, and the allowlist handles the
#     one real case: our own detection tooling and incident docs quote them.
POLINRIDER_SIGS_REPO_ONLY=(
  'helloipbot'
  "'Sec-V'"   # QUOTED object key. The bytes are  ],'Sec-V':_0x3d94ba
              # Verified at byte level. An unquoted Sec-V: matches ZERO real
              # payloads -- that exact mistake shipped in this repo's own 1c
              # rule set and was found only by re-reading the carrier bytes.
  'AUTH_API_KEY'
              # BARE, and it is the only thing that finds a .env carrier --
              # in a .env the bytes are AUTH_API_KEY=<base64>, which
              # atob(process.env.* cannot match. .env is a confirmed carrier.
  '9-3727-2'  # The campaign tag, BARE. Variant B writes A9-3727-2 and variant A
              # writes 9-3727-2, so a bare substring catches both; anchoring on
              # the A-prefixed form silently drops variant A. It is NOT a stable
              # marker -- see POLINRIDER_BUILD_MARKER -- so this literal is a
              # floor, never the only tag rule. Neither tool carried it before
              # this file existed; both relied on the marker pattern alone,
              # which requires the global-assignment context to match.
)

# 1c. Hard indicator for a HOST scan only: the implant's exact usage, narrow
#     enough not to collide with docs and caches on a developer machine.
POLINRIDER_SIGS_HOST_ONLY=(
  'atob(process.env.AUTH_API_KEY'
)

# ===========================================================================
# 2. BUILD MARKER — the tag assignment, generalised over the number itself.
# ===========================================================================
# MEASURED, not assumed: three DISTINCT build numbers exist in a single
# four-carrier sample set --
#     global['!']='9-3727-2'    tailwind.config.js   wave-1 shuffle
#     global.i="A9-3727-2"      karma.conf.js        obfuscator.io
#     global.i="A9-3727-3"      eslint.config.mjs    obfuscator.io
# so the tag is a build number that has already rotated once. The literal in
# POLINRIDER_SIGS_CORE matches two of those three.
#
# This matters because the wave-1 carrier is found by that number ALONE -- it
# carries no 'Sec-V' and no AUTH_API_KEY. Had it shipped as 9-3727-3, a
# literals-only rule set would have missed it completely.
POLINRIDER_BUILD_MARKER='global(\.i|\[.!.\])[[:space:]]*=[[:space:]]*["'"'"']A?[0-9]-[0-9]{4}-[0-9]'

# ===========================================================================
# 3. STRUCTURAL — survives re-obfuscation; no signature knowledge required.
# ===========================================================================

# Whitespace padding used to push the payload past the right edge of a diff
# view. MEASURED at exactly 507 spaces on all three obfuscated carriers;
# threshold set to 200 for headroom.
# This is NOT the rejected line-length heuristic: minification strips
# whitespace, so vendored bundles have long lines and no long space runs.
# Anchor on the RUN LENGTH, never on a column -- the payload starts at column
# 510 in two carriers and 536 in the third.
POLINRIDER_WSRUN=' {200,}[^ ]'

# The attacker appended config.bat to .gitignore in 9 of 20 repositories so a
# dropped file of that name would not appear in `git status`, and REMOVED the
# .env rule in 4 so a committed .env would be tracked. Both are findings.
POLINRIDER_GITIGNORE_ADDED='config.bat'
POLINRIDER_GITIGNORE_REMOVED='^\.env$'

# ===========================================================================
# 4. INFORMATIONAL — never drives a verdict on its own.
# Minified bundles and browser wallet extensions legitimately match these.
# ===========================================================================
POLINRIDER_RPC_HOSTS='publicnode\.com|bsc-dataseed|1rpc\.io|drpc\.org|blockscout|trongrid|aptoslabs'
POLINRIDER_OBFUSCATOR_SHAPE='_0x[0-9a-f]{4,6}'
POLINRIDER_OBFUSCATOR_CONFIRM='while *\( *!!\[\] *\)'   # required co-occurrence
POLINRIDER_ENV_B64='^[A-Z_]+="[A-Za-z0-9+/=]{20,}"'

# Real font containers have a fixed 4-byte magic. The campaign drops its
# re-infection payload as _.woff2 and runs it with `node _.woff2`.
POLINRIDER_FONT_MAGICS_HEX='774f4632 774f4646 00010000 4f54544f 74727565 74797031'

# ===========================================================================
# 5. REJECTED — recorded so they are not reintroduced.
# ===========================================================================
# awk 'length>2000'   hundreds of FPs from vendored minified bundles.
#                     POLINRIDER_WSRUN is the specific version of this idea.
# '_0x' alone         matches inside committed .jar files, and is absent from
#                     variant A entirely. Only usable with the co-occurrence
#                     confirmation above.
# 'Sec-V:'            unquoted; matches zero real payloads.
# 'A9-3727'           anchored on the A prefix; blind to variant A.
# commit metadata     author, committer and dates are all forged.

# ===========================================================================
# 2b. LOADER-FAMILY PATTERNS — informational on a host, hard in a repo sweep.
#
# These were left inline in polinrider_scan.sh when #6 moved everything else
# here: the RPC host list was migrated, 'Sec-V' and helloipbot were not, and the
# single-source guard did not notice because its list of literals was itself
# hardcoded. Two indicators in two places is how the sweep went blind to a whole
# variant in the first place.
#
# 'Sec-V' keeps its quotes: the bytes in the payload are the QUOTED object key
# `],'Sec-V':_0x3d94ba`, so the quote is part of the indicator. Unquoted Sec-V:
# matches zero real payloads.
# ===========================================================================
POLINRIDER_LOADER_FAMILY=(
  'helloipbot'
  "$POLINRIDER_RPC_HOSTS"
  "'Sec-V'"
)

# Shell-history probe: the shapes a dropper leaves behind in a shell history
# file. Behavioural rather than a signature, and a separate claim from the
# indicator sets -- but still a detection rule, so it lives here and not in a
# script.
POLINRIDER_HISTORY_RE='eval\(|atob\(|node-fetch|curl.*\|.*(ba)?sh|AUTH_API_KEY|\bwget\b.*http'

# --- helpers ---------------------------------------------------------------
# Consumers pick the set that matches their false-positive surface.
polinrider_sigs_for() {   # $1 = repo | host
  local s
  for s in "${POLINRIDER_SIGS_CORE[@]}"; do printf '%s\n' "$s"; done
  case "$1" in
    repo) for s in "${POLINRIDER_SIGS_REPO_ONLY[@]}"; do printf '%s\n' "$s"; done ;;
    host) for s in "${POLINRIDER_SIGS_HOST_ONLY[@]}"; do printf '%s\n' "$s"; done ;;
    *) echo "polinrider_sigs_for: need 'repo' or 'host', got '${1:-}'" >&2; return 2 ;;
  esac
}

# --- canary samples --------------------------------------------------------
# Known-positive carrier bytes live in their OWN file, sourced here so consumers
# still have one thing to source. The separation is not tidiness: a canary that
# shares a file with the rules it validates is not independent of them. The
# first version of this lived below, and a single find-and-replace across this
# file rewrote the rule and its own evidence in one pass -- the self-test went
# on passing with a signature that no longer matched any real carrier. Keeping
# the samples out of reach of an edit to this file is the entire mechanism.
POLINRIDER_CANARIES_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/canaries.sh"
[ -r "$POLINRIDER_CANARIES_FILE" ] || {
  echo "ERROR: missing canaries.sh at $POLINRIDER_CANARIES_FILE" >&2; return 2 2>/dev/null || exit 2; }
# shellcheck source=canaries.sh
. "$POLINRIDER_CANARIES_FILE"
