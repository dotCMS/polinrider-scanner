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
# NOTE: third signature is the implant's exact usage (atob(process.env.AUTH_API_KEY),
# fixed-string) - a bare 'AUTH_API_KEY' key name collides with docs/caches and FP'd.
SIGS=('rmcej%otb%' 'wuqktamceigynzbosdctpusocrjhrflovnxrt' 'atob(process.env.AUTH_API_KEY')
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
  grep -qE '^[A-Z_]+="[A-Za-z0-9+/=]{20,}"' "$f" 2>/dev/null && \
    hit "suspicious .env with base64-looking value: $f"
done < <(find "${SCAN_DIRS[@]}" -maxdepth 4 -name '.env' -not -path '*/node_modules/*' 2>/dev/null)

# ---- 1b. Oversized config files: verify content, not just size ----------------
section "1b. Oversized config files (>2500 bytes) - content-verified"
# Classify each oversized config:
#   INFECTED  = known campaign signature inside
#   SUSPICIOUS = obfuscation markers (huge trailing whitespace padding, very long
#                single lines, hex/base64 blobs, string-shuffle calls) but no exact sig
#   OK        = large but ordinary config (prints as info only)
classify_config() {  # $1 = file
  local f="$1"
  grep -qF 'rmcej%otb%' "$f" 2>/dev/null && { echo "INFECTED-sig"; return; }
  grep -qF 'wuqktamceigynzbosdctpusocrjhrflovnxrt' "$f" 2>/dev/null && { echo "INFECTED-sig"; return; }
  grep -qF 'atob(process.env.AUTH_API_KEY' "$f" 2>/dev/null && { echo "INFECTED-sig"; return; }
  # trailing whitespace padding (implant hides after legit content + long space runs)
  if tail -c 2000 "$f" 2>/dev/null | grep -qE ' {80,}'; then echo "SUSPICIOUS-pad"; return; fi
  # single line >800 chars with almost no spaces = single-token obfuscation;
  # legit long lines (requires/serialized config, usually spaced) pass
  if awk 'length($0)>800 && gsub(/ /," ")<=5 {found=1} END{exit !found}' "$f" 2>/dev/null; then echo "SUSPICIOUS-longline"; return; fi
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
    SUSPICIOUS-pad)      hit "suspicious config (${sz}B, trailing whitespace padding): $f" ;;
    SUSPICIOUS-longline) hit "suspicious config (${sz}B, >800-char line = possible obfuscation): $f" ;;
    SUSPICIOUS-blob)     hit "suspicious config (${sz}B, long encoded blob): $f" ;;
    SUSPICIOUS-shuffle)  hit "suspicious config (${sz}B, string-shuffle pattern): $f" ;;
    OK)                  echo -e "${YEL}[i] large config, content looks normal (${sz}B): $f${NC}" ;;
  esac
done < <(find "${SCAN_DIRS[@]}" -maxdepth 5 \( -name 'postcss.config.*' -o -name 'tailwind.config.*' \
  -o -name 'vite.config.*' -o -name 'eslint.config.*' -o -name 'next.config.*' \
  -o -name 'jest.config.*' -o -name 'babel.config.*' -o -name 'config.js' \) \
  -not -path '*/node_modules/*' \
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
FONT_MAGICS_HEX='774f4632 774f4646 00010000 4f54544f 74727565 74797031'
check_fake_font() {  # $1 = file
  local f="$1" magic sz m
  magic=$(od -An -tx1 -N4 "$f" 2>/dev/null | tr -d ' \n')
  for m in $FONT_MAGICS_HEX; do [ "$magic" = "$m" ] && return; done
  sz=$(wc -c < "$f" 2>/dev/null | tr -dc '0-9'); sz=${sz:-0}
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
REGEX_PATS=(
  'global\.[a-zA-Z]+[[:space:]]*=[[:space:]]*["'"'"']A[0-9]+-'
  'helloipbot'
  'publicnode\.com|bsc-dataseed|1rpc\.io|drpc\.org|blockscout'
  'Sec-V:'
)
while IFS= read -r f; do
  is_scan_scope "$f" || continue
  echo -e "${YEL}[i] loader-family pattern (verify against hard IOCs): $f${NC}"
done < <(
  for d in "${SCAN_DIRS[@]}"; do
    patargs=(); for p in "${REGEX_PATS[@]}"; do patargs+=(-e "$p"); done
    if [ "$GREP_ENGINE" = "rg" ]; then
      rg -l --no-messages --hidden -g '!node_modules' -g '!.git' \
         -g '*.{js,mjs,cjs,ts,mts}' "${patargs[@]}" "$d" 2>/dev/null
    else
      grep -rIlE --exclude-dir=node_modules --exclude-dir=.git \
        --include='*.js' --include='*.mjs' --include='*.cjs' --include='*.ts' \
        "${REGEX_PATS[0]}|${REGEX_PATS[1]}|${REGEX_PATS[2]}|${REGEX_PATS[3]}" "$d" 2>/dev/null
    fi
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
  grep -qE 'while *\( *!!\[\] *\)' "$f" 2>/dev/null && \
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
find "$TD" -maxdepth 2 -type f -perm -u+x -mtime -180 2>/dev/null | \
  while IFS= read -r f; do
    is_benign_tmp_exe "$f" && continue
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
  if grep -qiE 'eval\(|atob\(|node-fetch|curl.*\|.*(ba)?sh|AUTH_API_KEY|\bwget\b.*http' "$h" 2>/dev/null; then
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
for h in $BAD_HOSTS; do
  if [ "$(uname -s)" = "Darwin" ] && command -v log >/dev/null; then
    log show --last 30d --predicate 'process == "mDNSResponder"' --style compact 2>/dev/null | \
      grep -q "$h" && hit "macOS DNS cache shows resolution of $h in last 30d"
  fi
done
info "MOST RELIABLE: search corporate proxy / DNS / firewall logs for:"
echo "     auth-confirm-eight.vercel.app, auth-rho-dun.vercel.app, data-kappa.vercel.app,"
echo "     api.trongrid.io, aptos RPC hosts, bsc-dataseed.binance.org, and any *.vercel.app"
echo "     hits from dev boxes or CI runners during npm test/build steps."

# ---- Summary --------------------------------------------------------------------
N=$(hitcount)
# strip whitespace/newlines so [ -gt ] always gets a single clean integer
HIGH=$(grep -cE 'stage-3 dropper path exists|KNOWN-BAD|executable in tmpdir|DNS cache shows|suspicious LaunchAgent|suspicious autostart|suspicious user service|auto-run task|executing odd file|runs node on non-JS|MALICIOUS-LOOKING git hook|INFECTED CONFIG|fake (WOFF2?) payload' "$FINDINGS" 2>/dev/null | tr -dc '0-9')
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

