#!/usr/bin/env bash
# Fixture tests for org_sweep.sh. Every case asserts; a case that cannot assert
# is a case that silently stops testing (see the f5bc89e post-mortem on
# test_config_classification.sh, which had no assertions and always exited 0).
#
# Run: bash test_org_sweep.sh

set -uo pipefail
SWEEP="$(cd "$(dirname "$0")" && pwd)/org_sweep.sh"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0
ok()   { printf '  PASS  %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ [ "$2" = "$3" ] && ok "$1 ($2)" || bad "$1: expected '$3', got '$2'"; }

mkrepo() {  # $1 = name -> echoes path
  local d="$TMP/$1"; mkdir -p "$d"; git -C "$d" init -q
  echo "$d"
}
commit() { git -C "$1" add -A -f >/dev/null 2>&1; git -C "$1" -c user.email=t@t -c user.name=t commit -qm "${2:-c}" >/dev/null 2>&1; }
pad() { printf '%*s' 507 ''; }

echo "== 1. variant A (no 'A' prefix on the marker) - the bug this suite guards =="
# The previous sweep grepped the literal 'A9-3727', which only exists in the
# obfuscator.io build. This is the older _$_ build. It must be caught.
R=$(mkrepo variantA)
{ echo "module.exports = {};"; printf '};%s' "$(pad)"; printf "global['!']='9-3727-2';var _\$_1e42=(function(l,e){\n"; } > "$R/tailwind.config.js"
commit "$R"
OUT=$(bash "$SWEEP" --local "$R" 2>&1); RC=$?
check "verdict"  "$(echo "$OUT" | grep -c 'RESULT .* INFECTED')" "1"
check "exit code" "$RC" "1"
echo "$OUT" | grep -q 'BUILD-MARKER' && ok "build marker fired on the no-prefix build" || bad "build marker MISSED variant A"

echo "== 2. repo with no ref hits =="
# The verdict is NO_REF_HITS, never CLEAN. A --mirror clone fetches refs, so a
# green run proves no ref reaches the implant -- not that the implant is gone.
# Four payload blobs were retrieved by SHA from repos this sweep called clean.
# Pinned here so the reassuring word cannot come back.
R=$(mkrepo norefhits)
printf 'export default { build: { outDir: "dist" } };\n' > "$R/vite.config.ts"
commit "$R"
OUT=$(bash "$SWEEP" --local "$R" 2>&1); check "exit code" "$?" "0"
check "verdict token" "$(echo "$OUT" | grep -c 'RESULT .* NO_REF_HITS')" "1"
echo "$OUT" | grep -qE 'RESULT .* CLEAN' && bad "sweep still emits a CLEAN verdict" || ok "no CLEAN verdict emitted"
echo "$OUT" | grep -q 'COVERAGE: refs only' && ok "summary states what the sweep does not cover" || bad "summary omits the coverage caveat"

echo "== 3. minified bundle is not a whitespace-pad hit =="
# Guards against reintroducing the rejected line-length heuristic: minification
# strips whitespace, so a long line is not a long space run.
R=$(mkrepo minified)
{ printf '!function(e,t){'; for i in $(seq 1 400); do printf 'var _0x%04d=1;' "$i"; done; printf '}();\n'; } > "$R/vendor.min.js"
commit "$R"
OUT=$(bash "$SWEEP" --local "$R" 2>&1)
echo "$OUT" | grep -q 'WHITESPACE-PAD' && bad "minified bundle produced a false positive" || ok "no false positive on minified bundle"

echo "== 4. .env carrier (an extension filter cannot see this) =="
R=$(mkrepo envcarrier)
printf 'NODE_ENV=production\nAUTH_API_KEY=aHR0cHM6Ly9leGFtcGxlLmludmFsaWQv\n' > "$R/.env"
commit "$R"
bash "$SWEEP" --local "$R" >/dev/null 2>&1; check "exit code" "$?" "1"

echo "== 5. config.bat added to .gitignore =="
R=$(mkrepo gitignore)
printf 'node_modules/\nconfig.bat\n' > "$R/.gitignore"
commit "$R"
OUT=$(bash "$SWEEP" --local "$R" 2>&1)
echo "$OUT" | grep -q 'GITIGNORE-CONFIG.BAT' && ok "config.bat flagged" || bad "config.bat MISSED"

echo "== 6. whitespace padding is found anywhere in the file, not just the tail =="
# The old rule read `tail -c 2000`; the padding sits at the START of the payload,
# so the last 2000 bytes are payload with no spaces at all.
R=$(mkrepo padstart)
{ printf '};%s' "$(pad)"; for i in $(seq 1 300); do printf 'PAYLOADCHUNK%04d' "$i"; done; printf '\n'; } > "$R/postcss.config.js"
commit "$R"
OUT=$(bash "$SWEEP" --local "$R" 2>&1)
echo "$OUT" | grep -q 'WHITESPACE-PAD' && ok "padding found ahead of a 4KB payload tail" || bad "padding MISSED (tail-only regression)"

echo "== 7. allowlist suppresses, prints, and does not hide a real finding =="
R=$(mkrepo allowlisted)
printf "global['!']='9-3727-2';\n" > "$R/docs-quoting-the-ioc.md"
printf "global['!']='9-3727-2';\n" > "$R/real-payload.js"
commit "$R"
AL="$TMP/al.txt"
printf '# why: documentation quotes the indicator\nallowlisted:docs-quoting-the-ioc.md\n' > "$AL"
OUT=$(bash "$SWEEP" --local "$R" --allowlist "$AL" 2>&1); RC=$?
echo "$OUT" | grep -q 'SUPPRESSED.*docs-quoting' && ok "allowlisted finding still printed" || bad "allowlisted finding vanished silently"
echo "$OUT" | grep -q '!!!.*real-payload.js'    && ok "non-allowlisted finding still fires" || bad "allowlist over-suppressed"
check "exit code still infected" "$RC" "1"

echo "== 8. rotated build number - the literals alone would miss this =="
# Validated 2026-08-27 against the four byte-exact carriers: three DISTINCT build
# IDs exist in that set ('9-3727-2', "A9-3727-2", "A9-3727-3"), so the campaign
# tag is a rotating build number, not a fixed marker. The wave-1 carrier is found
# by that number ALONE - it carries no 'Sec-V' and no AUTH_API_KEY - so one
# rotation would have made it invisible to a literals-only rule.
R=$(mkrepo rotated)
{ echo "module.exports = {};"; printf '};%s' "$(pad)"; printf "global['!']='9-3727-9';var _\$_1e42=(function(l,e){\n"; } > "$R/tailwind.config.js"
commit "$R"
grep -qF -e '9-3727-2' -e "'Sec-V'" -e AUTH_API_KEY "$R/tailwind.config.js" \
  && bad "fixture is wrong: a literal still matches, so this case proves nothing" \
  || ok "no literal matches the rotated build (the case is meaningful)"
OUT=$(bash "$SWEEP" --local "$R" 2>&1); RC=$?
echo "$OUT" | grep -q 'BUILD-MARKER' && ok "build marker caught the rotated number" || bad "rotated build number MISSED"
check "exit code" "$RC" "1"

echo "== 9b. a DRIFTED RULE refuses to report anything =="
# Distinct from a broken engine. Here git works perfectly; the rule simply no
# longer matches real malware. The self-test used to pass this, because it
# searched each carrier sample for the string it had been written from -- a
# tautology that survives any rewrite of the rules. canaries.sh is copied in
# untouched on purpose: the sabotage edits the rule, and the evidence it is
# checked against must not move with it.
D=$(mktemp -d)
cp "$(dirname "$0")/org_sweep.sh" "$(dirname "$0")/canaries.sh" "$D/"
sed 's/rmcej%otb%/BROKEN_XX/' "$(dirname "$0")/rules.sh" > "$D/rules.sh"
R=$(mkrepo drift); printf 'clean\n' > "$R/a.js"; commit "$R"
OUT=$(bash "$D/org_sweep.sh" --local "$R" 2>&1); RC=$?
check "exit code" "$RC" "2"
echo "$OUT" | grep -q 'self-test FAILED' && ok "drifted rule killed the self-test" || bad "a rule that matches no real carrier still ran"
echo "$OUT" | grep -qE 'RESULT .* (NO_REF_HITS|CLEAN)' && bad "reported a verdict despite drifted rules" || ok "no verdict emitted"
rm -rf "$D"

echo "== 9. a broken engine refuses to report clean =="
sed 's|^BUILD_MARKER=.*|BUILD_MARKER="WILL_NEVER_MATCH"|' "$SWEEP" > "$TMP/broken.sh"
R=$(mkrepo forbroken); printf 'x\n' > "$R/a.js"; commit "$R"
bash "$TMP/broken.sh" --local "$R" >/dev/null 2>&1; check "exit code" "$?" "2"

echo
echo "PASS: $PASS   FAIL: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
