#!/usr/bin/env bash
# Fixture test for re-infection vector checks: fake fonts (1b2) and
# VS Code tasks running node on non-JS files (sec 4).
set -u
FIX=/tmp/reinf_test
rm -rf "$FIX"; mkdir -p "$FIX/proj" "$FIX/proj/.vscode" "$FIX/proj/fonts"

# 1b2: real fonts (must pass - no hit)
printf 'wOF2\x00\x01\x00\x00fontdata' > "$FIX/proj/fonts/real.woff2"
printf 'wOFF\x00\x01\x00\x00fontdata' > "$FIX/proj/fonts/real.woff"
# 1b2: JS disguised as fonts (must flag + count toward COMPROMISED)
printf 'const evil = require("child_process");' > "$FIX/proj/fonts/_.woff2"
printf 'eval(atob("aGVsbG8="));' > "$FIX/proj/fonts/logo.woff"
# sec 4: benign tasks.json (must not flag the node rule)
printf '{"tasks":[{"type":"shell","command":"node build.js"}]}\n' > "$FIX/proj/.vscode/tasks.ok.json"
# sec 4: tasks running node on non-JS files (must flag)
printf '{"tasks":[{"command":"node _.woff2"}]}\n'     > "$FIX/proj/.vscode/tasks.json"
printf '{"tasks":[{"command":"node fonts/logo.png"}]}\n' > "$FIX/proj/.vscode/tasks2.json"

OUT=$(bash "$(dirname "$0")/polinrider_scan.sh" "$FIX/proj" 2>/dev/null)

echo "== fake-font detections =="
echo "$OUT" | grep -E 'fake (WOFF2|WOFF)' | sed "s|$FIX/proj/||"
echo "== node-on-non-JS task detections =="
echo "$OUT" | grep -E 'node on non-JS|odd file' | sed "s|$FIX/proj/||"

PASS=1
echo "$OUT" | grep -q 'fake WOFF2 payload.*_.woff2'      || { echo "FAIL: JS-in-woff2 not flagged"; PASS=0; }
echo "$OUT" | grep -q 'fake WOFF payload.*logo.woff'     || { echo "FAIL: JS-in-woff not flagged"; PASS=0; }
echo "$OUT" | grep -q 'fake.*real\.woff2'                && { echo "FAIL: real woff2 falsely flagged"; PASS=0; }
echo "$OUT" | grep -q 'fake.*real\.woff'                 && { echo "FAIL: real woff falsely flagged"; PASS=0; }
echo "$OUT" | grep -q 'node on non-JS.*tasks\.json'      || { echo "FAIL: node _.woff2 task not flagged"; PASS=0; }
echo "$OUT" | grep -q 'node on non-JS.*tasks2\.json'     || { echo "FAIL: node logo.png task not flagged"; PASS=0; }
echo "$OUT" | grep -q 'node on non-JS.*tasks\.ok\.json'  && { echo "FAIL: benign node build.js task flagged"; PASS=0; }
echo "$OUT" | grep -q 'VERDICT: COMPROMISED'             || { echo "FAIL: expected COMPROMISED verdict"; PASS=0; }

echo
[ "$PASS" -eq 1 ] && echo "PASS: fake-font + node-on-non-JS checks all correct" || { echo "FAILURES above"; exit 1; }
