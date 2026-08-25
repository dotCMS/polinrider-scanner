#!/usr/bin/env bash
# Test fixture generator + validator for polinrider_scan.sh ripgrep detection
set -u
FIX=/tmp/rgtest
rm -rf "$FIX"; mkdir -p "$FIX/sub" "$FIX/node_modules" "$FIX/.git"

# Positive cases (must be found)
printf 'const a = "rmcej%%otb%%";\n'                  > "$FIX/sub/plain.js"
printf "x = 'wuqktamceigynzbosdctpusocrjhrflovnxrt';\n" > "$FIX/sign.ts"
printf 'AUTH_API_KEY="aGVsbG8="\n'                     > "$FIX/env.json"
printf 'nested: rmcej%%otb%% deep in mjs\n'            > "$FIX/sub/deep.mjs"

# Negative cases (must NOT be found)
printf 'totally clean file\n'                          > "$FIX/clean.js"
printf 'rmcejXXotbXX close but wrong\n'                > "$FIX/nearmiss.ts"

# Must be skipped: node_modules / .git
printf 'rmcej%%otb%% in node_modules\n'                > "$FIX/node_modules/dep.js"
printf 'rmcej%%otb%% in gitdir\n'                      > "$FIX/.git/config.json"

SIGS=('rmcej%otb%' 'wuqktamceigynzbosdctpusocrjhrflovnxrt' 'AUTH_API_KEY')

# Run the exact scanner rg invocation (signatures via -e, as in the scanner)
echo "== raw rg behavior (same flags as the scanner) =="
patargs=()
for s in "${SIGS[@]}"; do patargs+=(-e "$s"); done
rg -l -i -F --no-messages --hidden \
   -g '!node_modules' -g '!.git' -g '!*.min.js' \
   -g '*.{js,mjs,cjs,ts,json}' \
   "${patargs[@]}" "$FIX" | sort > /tmp/rg_got.txt
cat /tmp/rg_got.txt

cat > /tmp/rg_expected.txt <<'EOF'
/tmp/rgtest/env.json
/tmp/rgtest/sign.ts
/tmp/rgtest/sub/deep.mjs
/tmp/rgtest/sub/plain.js
EOF

echo
if diff -u /tmp/rg_expected.txt /tmp/rg_got.txt; then
  echo "PASS: exactly the 4 true positives found; node_modules/.git/near-miss correctly excluded"
else
  echo "FAIL: rg output did not match expected set"
  exit 1
fi

# End-to-end: run the real scanner against the fixture dir and check the summary
echo
echo "== end-to-end scanner run =="
bash "$(dirname "$0")/polinrider_scan.sh" "$FIX" 2>/dev/null | sed -n '/RESULT:/,$p'
