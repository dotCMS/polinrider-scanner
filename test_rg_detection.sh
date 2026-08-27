#!/usr/bin/env bash
# Fixture + validator for polinrider_scan.sh section 1 signature detection.
#
# Runs against whichever engine the scanner itself would pick. ripgrep is
# optional: `rg` is frequently only a shell function (Claude Code ships one), so
# `command -v rg` can succeed in an interactive zsh and fail inside the scanner's
# bash. This suite therefore tests the ENGINE THE SCANNER WILL ACTUALLY USE and
# skips the rg-specific comparison when no rg BINARY exists, instead of failing
# the whole run on an environment difference.
set -u
FIX=/tmp/rgtest
rm -rf "$FIX"; mkdir -p "$FIX/sub" "$FIX/node_modules" "$FIX/.git"

# Positive cases (must be found)
printf 'const a = "rmcej%%otb%%";\n'                   > "$FIX/sub/plain.js"
printf "x = 'wuqktamceigynzbosdctpusocrjhrflovnxrt';\n" > "$FIX/sign.ts"
printf 'const src = atob(process.env.AUTH_API_KEY);\n'  > "$FIX/env.json"
printf 'nested: rmcej%%otb%% deep in mjs\n'             > "$FIX/sub/deep.mjs"

# Negative cases (must NOT be found)
printf 'totally clean file\n'                           > "$FIX/clean.js"
printf 'rmcejXXotbXX close but wrong\n'                 > "$FIX/nearmiss.ts"
# REGRESSION GUARD (HANDOFF item 8a): the third signature is the implant's exact
# usage, NOT the bare key name. A bare AUTH_API_KEY collided with docs and tool
# caches and caused false positives. It must stay unmatched.
printf 'AUTH_API_KEY="aGVsbG8="  # just the key name, from docs\n' > "$FIX/docs.js"

# --- section 1c fixtures ------------------------------------------------------
# 1c is informational, but it used to be silently DEAD on any host without a
# ripgrep binary: the grep branch spelled the alternation as
# ${REGEX_PATS[0]}|...|${REGEX_PATS[3]} against a 3-element array, so under
# `set -u` the subshell died before grep ran and the section printed nothing.
printf "var h = {'Sec-V':'1'};\n"                        > "$FIX/secv.js"
printf "const u='https://bsc-dataseed.binance.org/';\n"  > "$FIX/rpc.js"
# Negative control for the quoting fix: the bytes in the payload are the QUOTED
# key 'Sec-V':, so an unquoted Sec-V: is not the indicator and must not match.
printf 'header Sec-V: 1 unquoted, not the indicator\n'   > "$FIX/secv_unquoted.js"

# Must be skipped: node_modules / .git
printf 'rmcej%%otb%% in node_modules\n'                 > "$FIX/node_modules/dep.js"
printf 'rmcej%%otb%% in gitdir\n'                       > "$FIX/.git/config.json"

# Exactly the scanner's signatures - keep these in sync with SIGS in the scanner.
SIGS=('rmcej%otb%' 'wuqktamceigynzbosdctpusocrjhrflovnxrt' 'atob(process.env.AUTH_API_KEY')

cat > /tmp/rg_expected.txt <<'EOF'
/tmp/rgtest/env.json
/tmp/rgtest/sign.ts
/tmp/rgtest/sub/deep.mjs
/tmp/rgtest/sub/plain.js
EOF

PASS=1

# ---- engine-level check, using the engine the scanner would pick -------------
if command -v rg >/dev/null 2>&1 && [ -x "$(command -v rg 2>/dev/null)" ]; then
  echo "== raw rg behavior (same flags as the scanner) =="
  patargs=(); for s in "${SIGS[@]}"; do patargs+=(-e "$s"); done
  rg -l -i -F --no-messages --hidden \
     -g '!node_modules' -g '!.git' -g '!*.min.js' \
     -g '*.{js,mjs,cjs,ts,json}' \
     "${patargs[@]}" "$FIX" | sort > /tmp/rg_got.txt
else
  echo "== SKIP: no rg binary on PATH - testing the grep fallback the scanner will use =="
  : > /tmp/rg_got.txt
  for s in "${SIGS[@]}"; do
    grep -rIlF --exclude-dir=node_modules --exclude-dir=.git \
      --include='*.js' --include='*.mjs' --include='*.cjs' \
      --include='*.ts' --include='*.json' "$s" "$FIX" 2>/dev/null >> /tmp/rg_got.txt
  done
  sort -u /tmp/rg_got.txt -o /tmp/rg_got.txt
fi
cat /tmp/rg_got.txt

echo
if diff -u /tmp/rg_expected.txt /tmp/rg_got.txt; then
  echo "PASS(engine): exactly the 4 true positives; node_modules/.git/near-miss/bare-key excluded"
else
  echo "FAIL(engine): output did not match expected set"; PASS=0
fi

# ---- end-to-end: the real scanner against the fixture dir -------------------
echo
echo "== end-to-end scanner run =="
OUT=$(bash "$(dirname "$0")/polinrider_scan.sh" "$FIX" 2>/dev/null)
echo "$OUT" | sed 's/\x1b\[[0-9;]*m//g' | grep -E "^\[!\] signature|^RESULT:|^VERDICT:"

chk()    { echo "$OUT" | grep -qE "$2" || { echo "FAIL: $1"; PASS=0; }; }
chknot() { echo "$OUT" | grep -qE "$2" && { echo "FAIL: $1"; PASS=0; }; }
chk    "sig1 (rmcej) not reported"                    "signature 'rmcej%otb%' in: .*plain\.js"
chk    "sig1 not found in nested .mjs"                "signature 'rmcej%otb%' in: .*deep\.mjs"
chk    "sig2 (scrambled ctor) not reported"           "signature 'wuqkta.* in: .*sign\.ts"
chk    "sig3 (exact atob usage) not reported"         "signature 'atob\(process\.env\.AUTH_API_KEY' in: .*env\.json"
chknot "bare AUTH_API_KEY key name wrongly matched"   'signature .* in: .*docs\.js'
chknot "node_modules was scanned"                     'in: .*node_modules'
chknot "\.git was scanned"                            'in: .*/\.git/'
chknot "near-miss string wrongly matched"             'in: .*nearmiss\.ts'

# ---- section 1c: must produce output at all, on whichever engine is in use ----
# Guards the unbound-array regression. Before the fix these three assertions all
# failed on the grep path while the scanner still reported a clean run.
chk    "1c found the quoted 'Sec-V' key"              'loader-family pattern.*secv\.js'
chk    "1c found the blockchain RPC hostname"         'loader-family pattern.*rpc\.js'
chknot "1c matched an unquoted Sec-V:"                'loader-family pattern.*secv_unquoted\.js'

echo
[ "$PASS" -eq 1 ] && echo "PASS: signature detection and all FP guards correct" || { echo "FAILURES above"; exit 1; }
