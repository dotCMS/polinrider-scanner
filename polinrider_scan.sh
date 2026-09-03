#!/usr/bin/env bash
# PolinRider / BeaverTail / InvisibleFerret detection sweep for Linux & macOS.
# Read-only: collects indicators, changes nothing.
# Uses ripgrep automatically if `rg` is on PATH (much faster); falls back to grep.
# Requires bash (not sh/dash/zsh). Run with: bash polinrider_scan.sh
# Usage: bash polinrider_scan.sh [target_dir] | tee scan_results_$(hostname)_$(date +%Y%m%d).log
#   target_dir: directory to scan (repo/project tree); defaults to $PWD.
#   Sections 2-5 are host-wide checks and always run regardless of target_dir.
set -u
if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: run with bash, not sh: bash $0" >&2
  exit 2
fi

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'
FINDINGS=$(mktemp "${TMPDIR:-/tmp}/polinrider_findings.XXXXXX")
trap 'rm -f "$FINDINGS"' EXIT
section() { echo; echo "=============== $* ==============="; }
# hit() appends to a temp file so the count survives pipes/subshells
hit() { echo "$*" >> "$FINDINGS"; echo -e "${RED}[!] $*${NC}"; }
info() { echo -e "${NC}[-] $*"; }
hitcount() { [ -f "$FINDINGS" ] && wc -l < "$FINDINGS" | tr -d ' ' || echo 0; }

# ---- 1. Implant signatures on disk -----------------------------------------
section "1. Loader signatures (repo clones, project dirs)"
# NOTE: the third signature is the implant's exact usage of the env var, matched
# as a fixed string. The bare key name on its own collided with documentation and
# tool caches and produced false positives. Exact bytes: canaries.sh.
# Signatures come from rules.sh, never from this file. They used to be defined
# here and in org_sweep.sh separately and they drifted -- the sweep kept matching
# the campaign tag as the literal 'A9-3727' long after this script generalised
# it, which made the sweep blind to the wave-1 variant on every run it ever did.
RULES_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/rules.sh"
[ -r "$RULES_FILE" ] || { echo "ERROR: missing rules.sh at $RULES_FILE" >&2; exit 2; }
# shellcheck source=rules.sh
. "$RULES_FILE"
SIGS=()
while IFS= read -r _s; do SIGS+=("$_s"); done < <(polinrider_sigs_for host)
[ ${#SIGS[@]} -gt 0 ] || { echo "ERROR: rules.sh yielded no signatures" >&2; exit 2; }
# rules.sh sources canaries.sh. A sourced file that `return`s does NOT abort its
# caller, so the failure has to be caught here or the canary silently evaporates
# and the scan runs unverified.
[ -n "${POLINRIDER_CANARY_CORE:-}" ] || {
  echo "ERROR: canary samples did not load (canaries.sh missing or unreadable)" >&2
  echo "       Refusing to scan: the rules cannot be proven to match anything." >&2; exit 2; }
SCAN_DIRS=("${1:-$PWD}")
if [ ! -d "${SCAN_DIRS[0]}" ]; then
  echo "ERROR: target directory not found: ${SCAN_DIRS[0]}" >&2
  exit 2
fi

# ripgrep if available (much faster, respects binary/ignore heuristics)
GREP_ENGINE="grep"
if command -v rg >/dev/null 2>&1; then
  GREP_ENGINE="rg"
  info "using ripgrep: $(rg --version | head -1)"
fi

# --- engine self-test (canary) -----------------------------------------------
# org_sweep.sh has had this since the rg-without-fallback failure; the host
# scanner never did, and it is the half that runs on developer machines, where
# the environment is least predictable. Same failure shape: `rg` is often only a
# shell function (Claude Code ships one), so `command -v rg` succeeds in an
# interactive zsh and the binary is absent inside this bash. The command then
# fails, output comes back empty, and empty reads as "nothing found".
#
# The fixtures are POLINRIDER_CANARY_* from rules.sh: fragments of the real
# carriers, kept deliberately apart from the signature sets. A canary generated
# from ${SIGS[@]} would only prove the rules match themselves and would pass
# with every signature silently rewritten. These are the bytes the implant
# actually ships, so a rule that stops matching real malware kills the scanner
# instead of reporting a clean host.
#
# Exercised through the same shapes the real scan uses, because those are what
# broke before:
#   * every signature in ONE rg invocation via -e (a bare second pattern is
#     silently treated as a PATH, killing multi-signature scans)
#   * the -g '!dir' bare-suffix exclude form ('!dir/**' only matches top level)
#   * the include glob, so a hit has to survive the extension filter
#   * BUILD_MARKER as a regex, which cannot ride in the fixed-string set
selftest() {
  local t rc=0
  t=$(mktemp -d) || { echo "ERROR: self-test could not create a tempdir" >&2; exit 2; }
  mkdir -p "$t/node_modules"

  printf '%s\n' "$POLINRIDER_CANARY_CORE"     > "$t/core_a.js"
  printf '%s\n' "$POLINRIDER_CANARY_HOST"     > "$t/carrier_c.js"
  printf '%s\n' "$POLINRIDER_CANARY_MARKER_A" > "$t/marker_a.js"
  printf '%s\n' "$POLINRIDER_CANARY_MARKER_B" > "$t/marker_b.js"
  printf '%s\n' "$POLINRIDER_CANARY_NEGATIVE" > "$t/negative.js"
  # a real hit that must stay excluded by the directory filter
  printf '%s\n' "$POLINRIDER_CANARY_CORE"     > "$t/node_modules/excluded.js"

  local found=""
  if [ "$GREP_ENGINE" = "rg" ]; then
    local _pa=(); for _s in "${SIGS[@]}"; do _pa+=(-e "$_s"); done
    found=$(rg -l -i -F --no-messages --hidden -g '!node_modules' -g '!.git' \
               -g '!*.min.js' -g '*.{js,mjs,cjs,ts,json}' "${_pa[@]}" "$t" 2>/dev/null)
  else
    # one pass per signature, exactly as the real grep branch below does it
    for _s in "${SIGS[@]}"; do
      found="$found
$(grep -rIlF --exclude-dir=node_modules --exclude-dir=.git \
       --include='*.js' --include='*.mjs' --include='*.cjs' \
       --include='*.ts' --include='*.json' "$_s" "$t" 2>/dev/null)"
    done
  fi

  case "$found" in
    *core_a.js*) ;;
    *) rc=1; echo "SELF-TEST FAILED: no signature matched the wave-1 core string" >&2 ;;
  esac
  case "$found" in
    *carrier_c.js*) ;;
    *) rc=1; echo "SELF-TEST FAILED: no signature matched the variant C host usage" >&2 ;;
  esac
  case "$found" in
    *negative.js*) rc=1; echo "SELF-TEST FAILED: signatures matched a clean control file" >&2 ;;
  esac
  case "$found" in
    *node_modules*) rc=1; echo "SELF-TEST FAILED: the node_modules exclude did not apply" >&2 ;;
  esac

  local m
  if [ "$GREP_ENGINE" = "rg" ]; then
    m=$(rg -l --no-messages --hidden -g '*.{js,mjs,cjs,ts,mts}' \
           -e "$POLINRIDER_BUILD_MARKER" "$t" 2>/dev/null)
  else
    m=$(grep -rIlE --include='*.js' --include='*.mjs' --include='*.cjs' \
             --include='*.ts' "$POLINRIDER_BUILD_MARKER" "$t" 2>/dev/null)
  fi
  case "$m" in
    *marker_a.js*) ;;
    *) rc=1; echo "SELF-TEST FAILED: build marker missed the wave-1 spelling" >&2 ;;
  esac
  case "$m" in
    *marker_b.js*) ;;
    *) rc=1; echo "SELF-TEST FAILED: build marker missed the obfuscator.io spelling" >&2 ;;
  esac

  rm -rf "$t"
  if [ $rc -ne 0 ]; then
    echo "ERROR: engine self-test failed with $GREP_ENGINE - refusing to scan." >&2
    echo "       A scan that cannot find a planted implant cannot report a clean host." >&2
    exit 2
  fi
  info "engine self-test ok ($GREP_ENGINE, rules $POLINRIDER_RULES_VERSION, ${#SIGS[@]} signatures)"
}
selftest

for d in "${SCAN_DIRS[@]}"; do
  info "scanning $d (this can take a while)..."
  if [ "$GREP_ENGINE" = "rg" ]; then
    # single pass, all signatures; print file + which signature matched
    # NOTE: -g '!node_modules' / '!.git' (no /**) - bare-suffix form reliably
    # excludes those dirs at any depth; '!dir/**' only matches top-level.
    # NOTE: signatures must be passed via -e (bare args after the first are
    # treated as PATHS by rg, silently breaking multi-signature scans).
    patargs=()
    for sig in "${SIGS[@]}"; do patargs+=(-e "$sig"); done
    rg -l -i -F --no-messages --hidden \
       -g '!node_modules' -g '!.git' -g '!*.min.js' \
       -g '*.{js,mjs,cjs,ts,json}' \
       "${patargs[@]}" "$d" 2>/dev/null | \
      while IFS= read -r f; do
        for sig in "${SIGS[@]}"; do
          rg -q -F --no-messages "$sig" "$f" && hit "signature '$sig' in: $f"
        done
      done
  else
    for sig in "${SIGS[@]}"; do
      while IFS= read -r f; do
        [ -n "$f" ] && hit "signature '$sig' in: $f"
      done < <(grep -rIlF --exclude-dir=node_modules --exclude-dir=.git \
                    --include='*.js' --include='*.mjs' --include='*.cjs' \
                    --include='*.ts' --include='*.json' "$sig" "$d" 2>/dev/null)
    done
  fi
done

# .env files containing base64-looking secret values
while IFS= read -r f; do
  grep -qE "$POLINRIDER_ENV_B64" "$f" 2>/dev/null && \
    hit "suspicious .env with base64-looking value: $f"
done < <(find "${SCAN_DIRS[@]}" -maxdepth 4 -name '.env' -not -path '*/node_modules/*' 2>/dev/null)

# Campaign build marker (DPRK A#-####-# scheme) as a HARD IOC:
#   two spellings, one per build tool: the obfuscator.io builds carry an A
#   prefix on the tag, the older shuffle builds do not. Exact bytes for both are
#   in canaries.sh, which is where the self-test gets them from.
# Matched as a PATTERN, not a literal, so it survives build-number rotation.
# Promoted out of the informational S1c on evidence: against the one genuinely
# infected file recovered in this incident (a karma.conf.js of ~31KB in a
# private org repo; see the internal IR record) every other
# detection path missed and this was the ONLY rule that fired - S1c could not
# change the verdict, so the scanner reported CLEAN on a real implant.
# It is regex, so it cannot ride in SIGS (those are fixed-string -F).
BUILD_MARKER_RE="$POLINRIDER_BUILD_MARKER"
while IFS= read -r f; do
  [ -n "$f" ] && hit "campaign build marker (A#-####-#) in: $f"
done < <(
  if [ "$GREP_ENGINE" = "rg" ]; then
    rg -l --no-messages --hidden -g '!node_modules' -g '!.git' -g '!*.min.js' \
       -g '*.{js,mjs,cjs,ts,mts}' -e "$BUILD_MARKER_RE" "${SCAN_DIRS[@]}" 2>/dev/null
  else
    grep -rIlE --exclude-dir=node_modules --exclude-dir=.git \
      --include='*.js' --include='*.mjs' --include='*.cjs' --include='*.ts' \
      "$BUILD_MARKER_RE" "${SCAN_DIRS[@]}" 2>/dev/null
  fi
)

# ---- 1b. Oversized config files: verify content, not just size ----------------
section "1b. Oversized config files (>2500 bytes) - content-verified"
# Classify each oversized config:
#   INFECTED  = known campaign signature inside
#   SUSPICIOUS = obfuscation markers (huge trailing whitespace padding, very long
#                single lines, hex/base64 blobs, string-shuffle calls) but no exact sig
#   OK        = large but ordinary config (prints as info only)
classify_config() {  # $1 = file
  local f="$1" run big lines
  # Loop over SIGS rather than repeating the strings: this block used to carry
  # its own hardcoded copy, which is a third place for the rules to drift to.
  local _sig
  for _sig in "${SIGS[@]}"; do
    grep -qF -e "$_sig" "$f" 2>/dev/null && { echo "INFECTED-sig"; return; }
  done
  grep -qE "$BUILD_MARKER_RE" "$f" 2>/dev/null && { echo "INFECTED-marker"; return; }
  # Whitespace padding used to push the payload past the right edge of a diff
  # view. WHOLE FILE, not `tail -c 2000`: the padding sits at the START of the
  # payload, so the last 2000 bytes are pure payload with no spaces at all and
  # the old tail-only test missed it. (Measured 2026-08-27 on all three
  # obfuscated carriers: the run is exactly 507 spaces, not the ~5,000 this
  # comment used to claim. The conclusion held; the number did not.)
  if awk '{ if (match($0,/[[:space:]]{200,}/)) found=1 } END{ exit !found }' "$f" 2>/dev/null; then
    echo "SUSPICIOUS-pad"; return
  fi
  # A monster unbroken token inside an otherwise hand-written file.
  # The old rule was `length($0)>800 && gsub(/ /," ")<=5`, which counted spaces
  # across the ENTIRE line - the real sample carries ~5,000 padding spaces on
  # that same line, so the <=5 guard rejected it. The rule was inverted against
  # exactly this evasion. Measure the longest unbroken NON-SPACE run instead,
  # then separate injection from minification structurally: a minified bundle is
  # huge on most of its lines; an injected config is normal everywhere except
  # one. (Same rule as polinrider-file-detect.sh, validated against both real
  # payload builds, clean configs, a large legit eslint.config.mjs, and real
  # minified bundles - hence the *.min.js exclusion on the find below.)
  set -- $(awk '
    { n=split($0, parts, /[[:space:]]+/); m=0
      for (i=1;i<=n;i++) if (length(parts[i])>m) m=length(parts[i])
      if (m>MAX) MAX=m
      if (length($0)>800) BIG++ }
    END { print MAX+0, BIG+0, NR+0 }' "$f" 2>/dev/null)
  run=${1:-0}; big=${2:-0}; lines=${3:-0}
  if [ "$run" -gt 800 ] && [ "$lines" -gt 5 ] && [ "$big" -le 2 ]; then
    echo "SUSPICIOUS-longline"; return
  fi
  # long hex / base64-ish literals (>=100 chars of [A-Za-z0-9+/=_-])
  if grep -qE '[A-Za-z0-9+/=_-]{100,}' "$f" 2>/dev/null; then echo "SUSPICIOUS-blob"; return; fi
  # String.raw / string-shuffle style arrays with many quoted single chars
  if grep -qE "['\"][a-zA-Z0-9%]{1,4}['\"],['\"][a-zA-Z0-9%]{1,4}['\"],['\"][a-zA-Z0-9%]{1,4}['\"],['\"]" "$f" 2>/dev/null; then
    echo "SUSPICIOUS-shuffle"; return
  fi
  echo "OK"
}
while IFS= read -r f; do
  sz=$(wc -c < "$f" 2>/dev/null | tr -dc '0-9'); sz=${sz:-0}
  [ "$sz" -gt 2500 ] || continue
  case $(classify_config "$f") in
    INFECTED-sig)        hit "INFECTED CONFIG (campaign signature present, ${sz}B): $f" ;;
    INFECTED-marker)     hit "INFECTED CONFIG (campaign build marker A#-####-#, ${sz}B): $f" ;;
    SUSPICIOUS-pad)      hit "suspicious config (${sz}B, trailing whitespace padding): $f" ;;
    SUSPICIOUS-longline) hit "suspicious config (${sz}B, >800-char unbroken token on 1-2 lines of ${sz}B = injected payload shape): $f" ;;
    SUSPICIOUS-blob)     hit "suspicious config (${sz}B, long encoded blob): $f" ;;
    SUSPICIOUS-shuffle)  hit "suspicious config (${sz}B, string-shuffle pattern): $f" ;;
    OK)                  echo -e "${YEL}[i] large config, content looks normal (${sz}B): $f${NC}" ;;
  esac
done < <(find "${SCAN_DIRS[@]}" -maxdepth 5 \( -name 'postcss.config.*' -o -name 'tailwind.config.*' \
  -o -name 'vite.config.*' -o -name 'eslint.config.*' -o -name 'next.config.*' \
  -o -name 'jest.config.*' -o -name 'babel.config.*' -o -name 'config.js' \
  -o -name 'karma.conf.*' -o -name '*.conf.js' \) \
  -not -path '*/node_modules/*' -not -name '*.min.js' \
  -not -path '*/.cache/*' -not -path '*/Library/Caches/*' -not -path '*/.bun/*' \
  -not -path '*/.cursor/*' -not -path '*/.vscode*' \
  -not -name '*.timestamp-*.mjs' -not -name '*.timestamp-*.mjs.*' 2>/dev/null)

# ---- 1b2. Disguised payload files (fake .woff2/.woff) --------------------------
section "1b2. Fake font payload files (no valid font header)"
# Campaign drops its re-infection payload as e.g. "_.woff2" and runs it with
# `node _.woff2` from a VS Code auto-run task (incident report SS3.3; Socket
# 2026-07-01 confirms .woff2 as the primary observed disguise under font/static
# asset dirs). Real font containers have a fixed 4-byte magic; accept every
# common one (WOFF2/WOFF/raw TrueType/OpenType/old-Mac-TrueType/Type1) since
# icon-font kits sometimes ship raw sfnt data renamed to .woff without actually
# WOFF-wrapping it - that's sloppy packaging, not a sign of compromise.
# Hex (not raw bytes) avoids `$(...)` mangling NUL-prefixed magics like TrueType's.
FONT_MAGICS_HEX="$POLINRIDER_FONT_MAGICS_HEX"
check_fake_font() {  # $1 = file
  local f="$1" magic sz m
  sz=$(wc -c < "$f" 2>/dev/null | tr -dc '0-9'); sz=${sz:-0}
  # FP-1 (confirmed on a clean host 2026-08-25): a file under 4 bytes has no
  # magic to compare - `od -N4` returns an empty string, which matches no entry
  # in FONT_MAGICS_HEX, so every such file used to be flagged. It also cannot
  # carry a payload. Real sources: unfetched Git LFS pointers, partial clones,
  # zero-byte build placeholders under dist/.
  [ "$sz" -lt 4 ] && return
  magic=$(od -An -tx1 -N4 "$f" 2>/dev/null | tr -d ' \n')
  for m in $FONT_MAGICS_HEX; do [ "$magic" = "$m" ] && return; done
  hit "fake $(basename "$f" | sed 's/.*\.//' | tr a-z A-Z) payload (no known font magic bytes, ${sz}B): $f"
}
while IFS= read -r f; do check_fake_font "$f"; done < <(find "${SCAN_DIRS[@]}" -maxdepth 6 \
  \( -iname '*.woff2' -o -iname '*.woff' \) -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null)

# ---- 1c. Loader-family behavior patterns (survive re-obfuscation) -------------
section "1c. Loader-family patterns (project source trees only)"
# Exact hashes/URLs rotate every wave; these structural patterns do not.
# SCOPE: project source trees only. Browser-extension dirs, app-support caches,
# and package-manager caches legitimately contain minified JS and wallet code
# that trips RPC/pattern heuristics (validated FP classes on 2026-08-25).
# Heuristic hits are INFORMATIONAL unless corroborated by a hard IOC in section 1.
is_scan_scope() {  # keep repo checkouts, drop caches/extensions/app-support
  case "$1" in
    */Library/Application\ Support/*|*/.cursor/*|*/.vscode*/*|*/.cache/*|\
    */Library/Caches/*|*/.bun/*|*/.npm/*|*/node_modules/*|*/.git/*) return 1 ;;
    *) return 0 ;;
  esac
}
# NOTE: the A#-####-# build marker used to live here. It is now a HARD IOC in
# section 1 + classify_config (see the evidence in the S1 comment); keeping it
# here as well would only double-report it as an unactionable [i] line.
# NOTE on the header-key indicator: the bytes in the payload are a QUOTED object
# key, so the quote is part of the indicator; the unquoted form matches zero real
# payloads. The pattern here used to omit it. See rules.sh and canaries.sh.
# Informational only. These are hard indicators in a REPO scan but not here:
# on a workstation they appear as quoted text in Claude Code transcripts and in
# tool caches. rules.sh records that split and the reason for it.
REGEX_PATS=("${POLINRIDER_LOADER_FAMILY[@]}")
# The alternation is built from the array. It used to be spelled out as
# ${REGEX_PATS[0]}|...|${REGEX_PATS[3]} against a 3-element array: under `set -u`
# that is an unbound variable, the subshell died before grep ran, and section 1c
# reported nothing on every host without a ripgrep BINARY (rg is frequently only
# a shell function, so `command -v rg` succeeds in zsh and fails in this script).
# A silent empty result here is indistinguishable from a clean host.
REGEX_ALT=$(IFS='|'; printf '%s' "${REGEX_PATS[*]}")
while IFS= read -r f; do
  is_scan_scope "$f" || continue
  echo -e "${YEL}[i] loader-family pattern (verify against hard IOCs): $f${NC}"
done < <(
  for d in "${SCAN_DIRS[@]}"; do
    patargs=(); for p in "${REGEX_PATS[@]}"; do patargs+=(-e "$p"); done
    # stderr is kept: an engine that fails here must not read as "no findings".
    if [ "$GREP_ENGINE" = "rg" ]; then
      rg -l --no-messages --hidden -g '!node_modules' -g '!.git' \
         -g '*.{js,mjs,cjs,ts,mts}' "${patargs[@]}" "$d"
    else
      grep -rIlE --exclude-dir=node_modules --exclude-dir=.git \
        --include='*.js' --include='*.mjs' --include='*.cjs' --include='*.ts' \
        "$REGEX_ALT" "$d"
    fi
    rc=$?
    [ $rc -gt 1 ] && echo "ENGINE ERROR in section 1c (rc=$rc) - not a clean result" >&2
  done | sort -u
)
# obfuscator.io shape: _0x hex array AND while(!![]) co-occurring in a PROJECT file.
# Minified bundles (terser/webpack) also produce _0x-style names, so this is
# informational only; the campaign loader pairs it with the patterns above.
if [ "$GREP_ENGINE" = "rg" ]; then
  candidates=$(rg -l --no-messages --hidden -g '!node_modules' -g '!.git' -g '*.{js,mjs,cjs,ts}' \
     '_0x[0-9a-f]{4,6}' "${SCAN_DIRS[@]}" 2>/dev/null)
else
  candidates=$(grep -rIlE --exclude-dir=node_modules --exclude-dir=.git \
     --include='*.js' --include='*.mjs' --include='*.cjs' --include='*.ts' \
     '_0x[0-9a-f]{4,6}' "${SCAN_DIRS[@]}" 2>/dev/null)
fi
echo "$candidates" | while IFS= read -r f; do
  [ -n "$f" ] || continue
  is_scan_scope "$f" || continue
  grep -qE "$POLINRIDER_OBFUSCATOR_CONFIRM" "$f" 2>/dev/null && \
    echo -e "${YEL}[i] obfuscator.io-like shape (minified JS also matches; verify): $f${NC}"
done | head -20

# ---- 2. Stage-3 filesystem artifacts ----------------------------------------
section "2. InvisibleFerret / BeaverTail artifacts"
for p in /tmp/app /tmp/app.exe "$HOME/.app" "$HOME/.cache/app" /tmp/.npm; do
  [ -e "$p" ] && hit "stage-3 dropper/credential-staging path exists: $p"
done
TD="${TMPDIR:-/tmp}"
# Known-benign tmpdir executable name patterns (IDE/tool artifacts)
is_benign_tmp_exe() {
  case "$1" in
    *jansi*|*jul-to-slf4j*|*native-image*|*graal*|*idea*|*IntelliJ*|\
    *vscode*|*Cursor*|*electron*|*chrome_crashpad*|*sparkler*|\
    *launchd-*|*com.apple*|*org.openjdk*|*java*.dylib|*.jnilib|*.dylib|\
    *orca-serve*|*github-copilot*|*copilot*) return 0 ;;
    *) return 1 ;;
  esac
}
# FP-2 (confirmed on a clean host 2026-08-25): yarn writes
# $TMPDIR/yarn--<epoch>-<random>/{node,yarn} on EVERY invocation - 158B and 312B
# /bin/sh wrappers holding a single exec line. Ten of them on one clean host,
# all counting toward COMPROMISED. Content-check the SHAPE rather than chase
# each tool's temp-dir naming convention: a real dropper is a binary or a large
# obfuscated script and matches neither the size nor the exec-only body.
is_tool_shim() {  # $1 = file; 0 = tiny #! wrapper whose only work is exec
  local f="$1" sz
  sz=$(wc -c < "$f" 2>/dev/null | tr -dc '0-9'); sz=${sz:-0}
  [ "$sz" -lt 1024 ] || return 1
  head -c 2 "$f" 2>/dev/null | grep -q '#!' || return 1
  # every line that is not blank and not a comment must be an exec
  grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | \
    grep -qvE '^[[:space:]]*exec[[:space:]]' && return 1
  return 0
}
find "$TD" -maxdepth 2 -type f -perm -u+x -mtime -180 2>/dev/null | \
  while IFS= read -r f; do
    is_benign_tmp_exe "$f" && continue
    is_tool_shim "$f" && continue
    hit "executable in tmpdir (review): $f"
  done

# ---- 3. Persistence mechanisms ---------------------------------------------
section "3. Persistence"
if [ "$(uname -s)" = "Darwin" ]; then
  for f in "$HOME/Library/LaunchAgents"/*.plist; do
    [ -e "$f" ] || continue
    case "$f" in
      *avatar*|*update.wake*) hit "KNOWN-BAD LaunchAgent: $f" ;;
      *) plutil -p "$f" 2>/dev/null | grep -qiE '(/tmp/|node |python|app\.exe)' && hit "suspicious LaunchAgent: $f" ;;
    esac
  done
  info "also check: sudo ls /Library/LaunchAgents /Library/LaunchDaemons"
else
  for f in "$HOME/.config/autostart"/*.desktop; do
    [ -e "$f" ] || continue
    grep -qiE '(/tmp/|node |python)' "$f" && hit "suspicious autostart: $f"
  done
  systemctl --user list-unit-files --type=service 2>/dev/null | awk '$2=="enabled"{print $1}' | \
    while IFS= read -r u; do
      case "$u" in *nvidia*|*update*|*driver*) hit "suspicious user service: $u" ;; esac
    done
fi
ct=$(crontab -l 2>/dev/null) && echo "$ct" | grep -vE '^\s*#' | grep -q . && \
  { echo "[-] crontab entries (review):"; echo "$ct"; }

# ---- 4. Re-infection vectors -------------------------------------------------
section "4. Re-infection vectors (VS Code tasks, git hooks)"
while IFS= read -r f; do
  grep -q '"runOn"[[:space:]]*:[[:space:]]*"folderOpen"' "$f" 2>/dev/null && hit "VS Code auto-run task: $f"
  grep -qE '\.woff2|/tmp/' "$f" 2>/dev/null && hit "VS Code task executing odd file: $f"
  # Socket 2026-07-01: campaign runs `node` against arbitrary non-JS-extension
  # files (fonts, images, etc), not just .woff2 - catch the general pattern too.
  grep -oE 'node[^"]*\.[A-Za-z0-9]{1,6}' "$f" 2>/dev/null | grep -qviE '\.(m?js|cjs|ts|json)$' && \
    hit "VS Code task runs node on non-JS-extension file: $f"
done < <(find "${SCAN_DIRS[@]}" -maxdepth 5 -path '*/.vscode/tasks*.json' -not -path '*/node_modules/*' 2>/dev/null)

ghp=$(git config --global core.hooksPath 2>/dev/null)
[ -n "$ghp" ] && hit "global git hooksPath set: $ghp (review hooks inside)"
# Repo hooks are common (husky, pre-commit frameworks) - only flag ones whose
# CONTENT looks like the campaign (fetch/eval/base64/node from hidden paths)
while IFS= read -r h; do
  [ -e "$h" ] || continue
  if grep -qiE "$POLINRIDER_HISTORY_RE" "$h" 2>/dev/null; then
    hit "MALICIOUS-LOOKING git hook: $h"
  else
    echo -e "${YEL}[i] repo git hook (likely husky/pre-commit, verify): $h${NC}"
  fi
done < <(find "${SCAN_DIRS[@]}" -maxdepth 6 -path '*/.git/hooks/*' -type f -perm -u+x \
           -not -name '*.sample' 2>/dev/null | head -100)

# ---- 5. Credential stores -----------------------------------------------------
section "5. SSH / npm creds"
[ -f "$HOME/.ssh/authorized_keys" ] && { echo "[-] authorized_keys (verify every line):"; sed 's/^/    /' "$HOME/.ssh/authorized_keys"; }
ls -lt "$HOME/.ssh" 2>/dev/null | head -10
[ -f "$HOME/.npmrc" ] && grep -qE '_authToken' "$HOME/.npmrc" && \
  echo -e "${YEL}[?] npm authToken present in ~/.npmrc - verify it's yours, rotate if in doubt${NC}"

# ---- 6. Connectivity evidence --------------------------------------------------
section "6. Connectivity evidence (best-effort)"
BAD_HOSTS='auth-confirm-eight.vercel.app auth-rho-dun.vercel.app data-kappa.vercel.app api.trongrid.io'
# ONE `log show` pass, not one per host. `log show --last 30d` walks the whole
# unified log and takes minutes; running it once per host made the scanner look
# hung and made the fixture suites untestable. Cap it with a timeout so a slow
# or huge log store degrades to "skipped" instead of stalling a fleet run.
if [ "$(uname -s)" = "Darwin" ] && command -v log >/dev/null 2>&1; then
  DNSLOG=$(mktemp "${TMPDIR:-/tmp}/polinrider_dns.XXXXXX")
  BAD_RE=$(echo "$BAD_HOSTS" | tr ' ' '\n' | sed 's/\./\\./g' | paste -sd'|' -)
  ( log show --last 30d --predicate 'process == "mDNSResponder"' --style compact 2>/dev/null \
      | grep -E "$BAD_RE" > "$DNSLOG" ) &
  logpid=$!
  waited=0
  while kill -0 "$logpid" 2>/dev/null && [ "$waited" -lt "${POLINRIDER_DNS_TIMEOUT:-120}" ]; do
    sleep 2; waited=$((waited + 2))
  done
  if kill -0 "$logpid" 2>/dev/null; then
    kill "$logpid" 2>/dev/null
    info "DNS cache check timed out after ${waited}s - SKIPPED (raise POLINRIDER_DNS_TIMEOUT to extend)"
  else
    for h in $BAD_HOSTS; do
      grep -qF "$h" "$DNSLOG" 2>/dev/null && \
        hit "macOS DNS cache shows resolution of $h in last 30d"
    done
  fi
  rm -f "$DNSLOG"
fi
info "MOST RELIABLE: search corporate proxy / DNS / firewall logs for:"
echo "     auth-confirm-eight.vercel.app, auth-rho-dun.vercel.app, data-kappa.vercel.app,"
echo "     api.trongrid.io, aptos RPC hosts, bsc-dataseed.binance.org, and any *.vercel.app"
echo "     hits from dev boxes or CI runners during npm test/build steps."

# ---- Summary --------------------------------------------------------------------
N=$(hitcount)
# strip whitespace/newlines so [ -gt ] always gets a single clean integer
HIGH=$(grep -cE 'stage-3 dropper path exists|KNOWN-BAD|executable in tmpdir|DNS cache shows|suspicious LaunchAgent|suspicious autostart|suspicious user service|auto-run task|executing odd file|runs node on non-JS|MALICIOUS-LOOKING git hook|INFECTED CONFIG|campaign build marker|fake (WOFF2?) payload' "$FINDINGS" 2>/dev/null | tr -dc '0-9')
HIGH=${HIGH:-0}
N=${N%%[!0-9]*}; N=${N:-0}
echo
echo "==============================================="
if [ "$HIGH" -gt 0 ]; then
  VERDICT="COMPROMISED"
  echo -e "${RED}VERDICT: $VERDICT - $HIGH high-confidence indicator(s) of active/persistent threat.$NC"
  echo "Immediate actions:"
  echo "  1. Isolate this machine from the network now"
  echo "  2. Rotate ALL credentials from a CLEAN machine (GitHub, npm, cloud, SSH, browser)"
  echo "  3. Expect re-infection: clean VS Code tasks, git hooks, LaunchAgents/autostart"
  echo "     (see OSM 'Getting Rid of PolinRider'), then re-scan"
elif [ "$N" -gt 0 ]; then
  VERDICT="SUSPECT"
  echo -e "${RED}RESULT: $N suspicious finding(s) - treat as possible compromise.$NC"
  echo "High-confidence stage-3/persistence artifacts NOT found, but implant signatures or"
  echo "lower-severity indicators are present. Review each finding above; if any signature"
  echo "ran during a build/test, escalate to COMPROMISED and rotate credentials."
  echo "Full finding list:"
  sed 's/^/  [!] /' "$FINDINGS"
else
  VERDICT="CLEAN (host-side)"
  echo -e "${GRN}RESULT: no host-side indicators found on this machine.$NC"
  echo "Caveats: this scan cannot prove the implant never ran - DNS caches are short-lived"
  echo "and the campaign rotates C2 domains. Still verify proxy/DNS logs (section 6) and"
  echo "run this on every machine that built or tested the infected branches."
fi
echo "Machine: $(hostname) | User: $(id -un) | Scanned: $(date -u '+%Y-%m-%d %H:%M UTC') | Engine: $GREP_ENGINE"
echo "VERDICT: $VERDICT"
case "$VERDICT" in
  COMPROMISED) exit 1 ;;
  SUSPECT)     exit 2 ;;
  *)           exit 0 ;;
esac

