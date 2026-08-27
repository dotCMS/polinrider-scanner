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

echo "== 2. clean repo =="
R=$(mkrepo clean)
printf 'export default { build: { outDir: "dist" } };\n' > "$R/vite.config.ts"
commit "$R"
bash "$SWEEP" --local "$R" >/dev/null 2>&1; check "exit code" "$?" "0"

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

echo "== 8. a broken engine refuses to report clean =="
sed 's|^BUILD_MARKER=.*|BUILD_MARKER="WILL_NEVER_MATCH"|' "$SWEEP" > "$TMP/broken.sh"
R=$(mkrepo forbroken); printf 'x\n' > "$R/a.js"; commit "$R"
bash "$TMP/broken.sh" --local "$R" >/dev/null 2>&1; check "exit code" "$?" "2"

echo
echo "PASS: $PASS   FAIL: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
